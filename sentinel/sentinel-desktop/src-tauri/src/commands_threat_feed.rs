//! Tauri commands exposing the threat-intel refresh pipeline to the UI.
//!
//! Two commands:
//!   * [`threat_feed_refresh`] — force a remote fetch + cache write, then
//!     return the resulting status DTO.
//!   * [`threat_feed_status`] — read the current state (source, age,
//!     entries, version) without triggering any network call.
//!
//! Both commands honour the global `privacy.outbound_lookups` toggle via
//! [`crate::outbound::ensure_outbound_enabled`]. `threat_feed_refresh`
//! returns the canonical `OUTBOUND_DISABLED_MESSAGE` when the toggle is
//! OFF; `threat_feed_status` is a read-only command and stays available
//! at all times (it surfaces the cached/bundled state without leaking any
//! data outbound).

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use sentinel_discovery::threat_intel::refresh::{
    self, ThreatFeedConfig, ThreatFeedStatus,
};

use crate::commands_settings::{Settings, ThreatFeedSettings};
use crate::outbound::ensure_outbound_enabled;

const SETTINGS_FILENAME: &str = "settings.toml";

/// UI-facing DTO mirroring [`ThreatFeedStatus`]. Kept as a separate type
/// so the field naming stays stable even if the crate-level struct grows
/// new fields later.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThreatFeedStatusDto {
    pub source: String,
    pub last_refresh: Option<String>,
    pub age_seconds: Option<u64>,
    pub entries_count: usize,
    pub version: Option<String>,
    pub url: String,
    pub auto_refresh_enabled: bool,
}

impl ThreatFeedStatusDto {
    fn from_parts(status: ThreatFeedStatus, cfg: &ThreatFeedSettings) -> Self {
        Self {
            source: status.source,
            last_refresh: status.last_refresh,
            age_seconds: status.age_seconds,
            entries_count: status.entries_count,
            version: status.version,
            url: cfg.url.clone(),
            auto_refresh_enabled: cfg.auto_refresh_enabled,
        }
    }
}

// ─── Filesystem helpers ─────────────────────────────────────────────────────

fn app_data_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    Ok(dir)
}

/// Load the persisted `Settings.threat_feed` block. Falls back to
/// [`ThreatFeedSettings::default`] when no `settings.toml` is present yet
/// or when the file fails to parse — the cascade still works because the
/// bundled YAML is the final fallback.
pub fn load_settings(app: &AppHandle) -> ThreatFeedSettings {
    let dir = match app_data_dir(app) {
        Ok(d) => d,
        Err(_) => return ThreatFeedSettings::default(),
    };
    let path = dir.join(SETTINGS_FILENAME);
    if !path.exists() {
        return ThreatFeedSettings::default();
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(_) => return ThreatFeedSettings::default(),
    };
    match toml::from_str::<Settings>(&raw) {
        Ok(s) => s.threat_feed,
        Err(_) => ThreatFeedSettings::default(),
    }
}

/// Persist a new `Settings.threat_feed` block in-place, preserving every
/// other section of `settings.toml`. Used by [`threat_feed_refresh`] to
/// stamp `last_refresh_at` after a successful fetch without touching the
/// operator's other preferences.
fn save_threat_feed_settings(
    app: &AppHandle,
    next: ThreatFeedSettings,
) -> Result<(), String> {
    let dir = app_data_dir(app)?;
    let path = dir.join(SETTINGS_FILENAME);
    let mut settings: Settings = if path.exists() {
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("could not read {:?}: {}", path, e))?;
        toml::from_str::<Settings>(&raw)
            .map_err(|e| format!("could not parse {:?}: {}", path, e))?
    } else {
        Settings::default()
    };
    settings.threat_feed = next;
    let serialized = toml::to_string_pretty(&settings)
        .map_err(|e| format!("could not serialize settings: {}", e))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))?;
    Ok(())
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Force a remote refresh of the threat intel feed.
///
/// Refuses to run when the global "Outbound calls" toggle is OFF —
/// returns the canonical [`crate::outbound::OUTBOUND_DISABLED_MESSAGE`]
/// so the UI surfaces the same tooltip wording as every other
/// outbound-bound command. On success, writes the cache files, stamps
/// `last_refresh_at` in `settings.toml`, and returns the fresh status.
#[tauri::command]
pub async fn threat_feed_refresh(app: AppHandle) -> Result<ThreatFeedStatusDto, String> {
    ensure_outbound_enabled(&app)?;

    let mut cfg = load_settings(&app);
    if cfg.url.trim().is_empty() {
        return Err("threat feed URL is empty — set one in Settings → Threat Intel Feed".into());
    }

    let dir = app_data_dir(&app)?;
    let cache_dir = refresh::cache_dir_for(&dir);
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("could not create cache dir: {}", e))?;

    let flux = refresh::rafraichir_feed(&cfg.url, &cache_dir)
        .await
        .map_err(|e| format!("threat feed refresh failed: {}", e))?;

    let now = chrono::Utc::now();
    cfg.last_refresh_at = Some(now.to_rfc3339());
    save_threat_feed_settings(&app, cfg.clone())?;

    let status = refresh::construire_statut(&flux, "remote", Some(now));
    log::info!(
        "threat_feed_refresh: {} entries, version={:?}",
        status.entries_count,
        status.version
    );
    Ok(ThreatFeedStatusDto::from_parts(status, &cfg))
}

/// Read the current threat-feed state without triggering a network call.
///
/// Uses [`refresh::charger_feed`] with `outbound_enabled = false` so the
/// cascade never reaches out: it returns the cache when present, or the
/// bundled YAML otherwise. Safe to call on the lock-screen.
#[tauri::command]
pub async fn threat_feed_status(app: AppHandle) -> Result<ThreatFeedStatusDto, String> {
    let cfg = load_settings(&app);
    let dir = app_data_dir(&app)?;
    let cache_dir = refresh::cache_dir_for(&dir);

    let crate_cfg = ThreatFeedConfig {
        url: cfg.url.clone(),
        auto_refresh_enabled: cfg.auto_refresh_enabled,
        last_refresh_at: cfg
            .last_refresh_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc)),
    };

    // Force outbound to `false` to keep this command read-only: even if
    // the toggle is ON, calling `threat_feed_status` should never trigger
    // a network call. The dedicated refresh path goes through
    // `threat_feed_refresh`.
    let (_flux, status) = refresh::charger_feed(&crate_cfg, &cache_dir, false).await;
    Ok(ThreatFeedStatusDto::from_parts(status, &cfg))
}

// ─── Tests ───────────────────────────────────────────────────────────────────
//
// Tauri commands take an `AppHandle` and are not directly unit-testable
// without a Tauri runtime. We exercise the pure helpers (settings load +
// save, status DTO conversion) and pin the gate-on-outbound invariant via
// the shared `crate::outbound::test_support` harness — exactly the same
// pattern `commands_taxii::tests` uses.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::test_support::{
        ensure_outbound_enabled_in_dir, tempdir_unique, write_settings_outbound_off,
    };
    use crate::outbound::OUTBOUND_DISABLED_MESSAGE;

    #[test]
    fn default_url_is_the_public_github_endpoint() {
        let cfg = ThreatFeedSettings::default();
        assert!(
            cfg.url.starts_with("https://raw.githubusercontent.com/"),
            "default URL must be the public GitHub raw endpoint, got {}",
            cfg.url
        );
        assert!(cfg.auto_refresh_enabled);
        assert!(cfg.last_refresh_at.is_none());
    }

    #[test]
    fn threat_feed_refresh_gate_blocks_when_outbound_off() {
        // The Tauri command itself needs a runtime, but every
        // network-bound command in this crate calls
        // `ensure_outbound_enabled` first. We pin the contract here by
        // exercising the same helper against a settings.toml with the
        // toggle OFF — exactly like `commands_taxii::tests`.
        let tmp = tempdir_unique("threat-feed-gate-off");
        write_settings_outbound_off(&tmp);
        let res = ensure_outbound_enabled_in_dir(&tmp);
        assert_eq!(res, Err(OUTBOUND_DISABLED_MESSAGE.to_string()));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn status_dto_round_trip_preserves_source_label() {
        let status = ThreatFeedStatus {
            source: "cache".to_string(),
            last_refresh: Some("2026-01-01T00:00:00Z".to_string()),
            age_seconds: Some(3600),
            entries_count: 18,
            version: Some("2026-06-01-001".to_string()),
        };
        let cfg = ThreatFeedSettings::default();
        let dto = ThreatFeedStatusDto::from_parts(status, &cfg);
        assert_eq!(dto.source, "cache");
        assert_eq!(dto.entries_count, 18);
        assert_eq!(dto.version.as_deref(), Some("2026-06-01-001"));
        assert!(dto.auto_refresh_enabled);
    }
}
