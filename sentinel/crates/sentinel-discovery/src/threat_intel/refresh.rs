//! Remote refresh + disk cache for the Sentinel threat intel feed.
//!
//! ## Fallback cascade
//!
//! [`charger_feed`] returns a [`FluxMenaces`] no matter what, using the
//! following deterministic cascade so the desktop binary is never blind to
//! known-bad MCP packages:
//!
//! ```text
//!   ┌────────────────────────────┐
//!   │ auto_refresh_enabled = ON  │
//!   │ outbound_lookups    = ON   │
//!   │ cache stale (> 24h) or     │
//!   │ missing                    │
//!   └────────────┬───────────────┘
//!                │ yes
//!                ▼
//!   ┌────────────────────────────┐  ok   ┌──────────────────────────┐
//!   │ rafraichir_feed(url)       │──────▶│ remote YAML + cache write│
//!   └────────────┬───────────────┘       └──────────────────────────┘
//!                │ err
//!                ▼
//!   ┌────────────────────────────┐  ok   ┌──────────────────────────┐
//!   │ on-disk cache              │──────▶│ cached YAML              │
//!   └────────────┬───────────────┘       └──────────────────────────┘
//!                │ missing/corrupt
//!                ▼
//!   ┌────────────────────────────┐
//!   │ FluxMenaces::par_defaut()  │   ← bundled YAML, always present
//!   └────────────────────────────┘
//! ```
//!
//! ## Cache layout
//!
//! Two files written side-by-side in `<cache_dir>`:
//!
//!   * `threat_feed_cache.yaml` — the raw YAML body fetched from `url`.
//!   * `threat_feed_cache.meta.json` — `{ sha256, fetched_at, source }`.
//!
//! The metadata is a small JSON sidecar so the UI can surface the age of
//! the feed and verify the cached YAML has not been tampered with.

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::FluxMenaces;

/// Default remote URL Sentinel pulls the threat feed from. Public GitHub
/// raw content, no auth, no secrets — safe to ship in the binary.
///
/// If the repo does not yet exist (probable on day-1), the cascade falls
/// back to the on-disk cache and ultimately to the bundled YAML, so the
/// feature still works.
pub const DEFAULT_FEED_URL: &str =
    "https://raw.githubusercontent.com/sentinel-mcp/threat-intel-feed/main/threat_feed.yaml";

/// Cache TTL: anything older than this triggers a refresh on the next
/// scheduled tick (or the next [`charger_feed`] call). Kept at 24h to match
/// the L17 registry refresh cadence.
pub const CACHE_TTL_SECS: u64 = 24 * 3600;

/// Filename of the cached YAML body inside `cache_dir`.
pub const CACHE_FILENAME: &str = "threat_feed_cache.yaml";

/// Filename of the JSON sidecar describing the cached YAML.
pub const META_FILENAME: &str = "threat_feed_cache.meta.json";

/// HTTP timeout for a single remote fetch. 15 s mirrors the registry
/// fetchers (`SourcePulseMCP`, `SourceSmithery`, …) so a flaky network
/// never blocks the background loop for more than this.
pub const HTTP_TIMEOUT_SECS: u64 = 15;

/// User-facing configuration for the remote refresh feature.
///
/// Persisted by the desktop in `settings.toml::threat_feed`. Reused by
/// [`charger_feed`] to decide whether to attempt a network call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedConfig {
    /// Remote YAML endpoint. Defaults to [`DEFAULT_FEED_URL`].
    pub url: String,
    /// When `false`, [`charger_feed`] skips the network step entirely and
    /// goes straight to the cache → bundled fallback.
    pub auto_refresh_enabled: bool,
    /// Timestamp of the last successful refresh, mirrored on disk. `None`
    /// when no refresh has ever succeeded.
    pub last_refresh_at: Option<DateTime<Utc>>,
}

impl Default for ThreatFeedConfig {
    fn default() -> Self {
        Self {
            url: DEFAULT_FEED_URL.to_string(),
            auto_refresh_enabled: true,
            last_refresh_at: None,
        }
    }
}

/// Status snapshot returned to the UI. Mirrors the `ThreatFeedStatusDto`
/// shape on the desktop side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeedStatus {
    /// Where the active feed came from: `"remote"`, `"cache"`, or
    /// `"bundled"`.
    pub source: String,
    /// ISO-8601 timestamp of the last successful refresh (remote or
    /// cache write). `None` if the active feed is bundled and no cache
    /// has ever been written.
    pub last_refresh: Option<String>,
    /// Seconds since `last_refresh`. `None` when `last_refresh` is `None`.
    pub age_seconds: Option<u64>,
    /// Number of entries in the currently loaded feed.
    pub entries_count: usize,
    /// Feed version string (`version:` key in the YAML).
    pub version: Option<String>,
}

/// Metadata sidecar persisted next to the cached YAML body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMeta {
    /// SHA-256 of the cached YAML body, hex-encoded lower-case.
    pub sha256: String,
    /// When the remote fetch returned `200 OK`.
    pub fetched_at: DateTime<Utc>,
    /// Always `"remote"` for now — kept as a free-form field so a future
    /// version can populate it with `"taxii"`, `"github-release"`, etc.
    pub source: String,
}

/// Typed error for the refresh pipeline.
#[derive(Debug, thiserror::Error)]
pub enum ThreatFeedError {
    /// Outbound networking failure: DNS, TCP, TLS, or `non-2xx` HTTP code.
    #[error("network error fetching threat feed: {0}")]
    Network(String),
    /// YAML body that does not match [`super::FluxYaml`] or is empty.
    #[error("could not parse threat feed YAML: {0}")]
    Parse(String),
    /// Filesystem I/O failure on the cache files.
    #[error("threat feed cache I/O error: {0}")]
    Io(String),
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Fetch the remote YAML, validate it, and persist it to the cache.
///
/// Always performs the HTTP request — callers wanting to honour the
/// "outbound calls" toggle must check that **before** invoking this
/// function. Both the YAML body and a small metadata sidecar are written
/// to `<cache_dir>/threat_feed_cache.{yaml,meta.json}`.
pub async fn rafraichir_feed(
    url: &str,
    cache_dir: &Path,
) -> Result<FluxMenaces, ThreatFeedError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|e| ThreatFeedError::Network(e.to_string()))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| ThreatFeedError::Network(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(ThreatFeedError::Network(format!(
            "HTTP {} from {}",
            status.as_u16(),
            url
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| ThreatFeedError::Network(e.to_string()))?;

    // Validate via the same shape the bundled feed uses. We refuse to
    // overwrite the cache with a YAML that does not parse cleanly — the
    // cache must always be a viable replacement for the bundled feed.
    let flux = FluxMenaces::depuis_yaml(&body)?;

    // Persist the YAML body and the metadata sidecar. Errors are
    // reported, not silently swallowed — the caller can decide whether
    // a parse-success/write-failure should bubble up to the user.
    ensure_dir(cache_dir)?;
    let yaml_path = cache_dir.join(CACHE_FILENAME);
    std::fs::write(&yaml_path, &body).map_err(|e| ThreatFeedError::Io(e.to_string()))?;

    let meta = CacheMeta {
        sha256: sha256_hex(body.as_bytes()),
        fetched_at: Utc::now(),
        source: "remote".to_string(),
    };
    let meta_path = cache_dir.join(META_FILENAME);
    let serialized = serde_json::to_string_pretty(&meta)
        .map_err(|e| ThreatFeedError::Io(e.to_string()))?;
    std::fs::write(&meta_path, serialized).map_err(|e| ThreatFeedError::Io(e.to_string()))?;

    Ok(flux)
}

/// Resolve the active feed using the cascade documented at the top of
/// this module.
///
/// `outbound_enabled` mirrors the global "outbound calls" toggle from
/// `settings.toml`. When `false`, the remote step is skipped entirely so
/// no network call is ever made — exactly like every other outbound-bound
/// command in the desktop binary.
pub async fn charger_feed(
    config: &ThreatFeedConfig,
    cache_dir: &Path,
    outbound_enabled: bool,
) -> (FluxMenaces, ThreatFeedStatus) {
    // Step 1 — remote fetch, gated by both toggles + cache freshness.
    let cache_yaml_path = cache_dir.join(CACHE_FILENAME);
    let cache_stale = est_cache_perime(&cache_yaml_path);
    if config.auto_refresh_enabled && outbound_enabled && cache_stale {
        match rafraichir_feed(&config.url, cache_dir).await {
            Ok(flux) => {
                let now = Utc::now();
                let status = construire_statut(&flux, "remote", Some(now));
                return (flux, status);
            }
            Err(e) => {
                tracing::warn!(
                    "threat_feed: remote refresh failed, falling back to cache: {}",
                    e
                );
            }
        }
    }

    // Step 2 — disk cache fallback.
    if let Some((flux, meta)) = lire_cache(cache_dir) {
        let status = construire_statut(&flux, "cache", Some(meta.fetched_at));
        return (flux, status);
    }

    // Step 3 — bundled YAML fallback. Always succeeds (build-time
    // guarantee on `FluxMenaces::par_defaut`).
    let flux = FluxMenaces::par_defaut();
    let status = construire_statut(&flux, "bundled", None);
    (flux, status)
}

/// Read the cached YAML + metadata sidecar from disk. Returns `None` when
/// either file is missing or unparseable — the caller should fall back to
/// the bundled YAML.
pub fn lire_cache(cache_dir: &Path) -> Option<(FluxMenaces, CacheMeta)> {
    let yaml_path = cache_dir.join(CACHE_FILENAME);
    let meta_path = cache_dir.join(META_FILENAME);
    if !yaml_path.exists() || !meta_path.exists() {
        return None;
    }
    let body = std::fs::read_to_string(&yaml_path).ok()?;
    let flux = FluxMenaces::depuis_yaml(&body).ok()?;
    let meta_raw = std::fs::read_to_string(&meta_path).ok()?;
    let meta: CacheMeta = serde_json::from_str(&meta_raw).ok()?;
    Some((flux, meta))
}

/// Build the UI-facing status DTO from a loaded flux + the source label.
pub fn construire_statut(
    flux: &FluxMenaces,
    source: &str,
    last_refresh: Option<DateTime<Utc>>,
) -> ThreatFeedStatus {
    let (last_iso, age) = match last_refresh {
        Some(ts) => {
            let age = (Utc::now() - ts).num_seconds().max(0) as u64;
            (Some(ts.to_rfc3339()), Some(age))
        }
        None => (None, None),
    };
    ThreatFeedStatus {
        source: source.to_string(),
        last_refresh: last_iso,
        age_seconds: age,
        entries_count: flux.entrees.len(),
        version: Some(flux.version_feed.clone()),
    }
}

/// Helper: return `true` when the cached YAML does not exist or is older
/// than [`CACHE_TTL_SECS`]. Any I/O error is treated as "stale" so the
/// caller falls forward to a remote refresh.
pub fn est_cache_perime(yaml_path: &Path) -> bool {
    let meta = match std::fs::metadata(yaml_path) {
        Ok(m) => m,
        Err(_) => return true,
    };
    let modified = match meta.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };
    match modified.elapsed() {
        Ok(elapsed) => elapsed.as_secs() >= CACHE_TTL_SECS,
        Err(_) => true,
    }
}

/// Helper: hex-encoded SHA-256 of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Helper: ensure the cache directory exists, creating it (and any
/// missing parents) when necessary.
fn ensure_dir(dir: &Path) -> Result<(), ThreatFeedError> {
    if !dir.exists() {
        std::fs::create_dir_all(dir).map_err(|e| ThreatFeedError::Io(e.to_string()))?;
    }
    Ok(())
}

/// Convenience: build the conventional cache directory path under an
/// app-data directory. Kept here so callers do not have to remember the
/// canonical subdirectory layout.
pub fn cache_dir_for(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("threat_feed")
}
