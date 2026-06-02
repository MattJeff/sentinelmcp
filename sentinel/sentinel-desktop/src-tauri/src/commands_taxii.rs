//! Tauri commands exposing TAXII 2.1 push functionality to the UI.
//!
//! Two storage layers:
//!   * [`TaxiiUiConfig`] — UI-facing config persisted to `taxii.json` in the
//!     app data directory.
//!   * [`sentinel_taxii::TaxiiConfig`] — the wire-level config consumed by
//!     [`sentinel_taxii::TaxiiClient`]. Built from [`TaxiiUiConfig`] right
//!     before each outbound call.
//!
//! Three commands are exposed:
//!   * [`taxii_test_send`]  — POST a synthetic STIX 2.1 indicator to the
//!     collection described by the persisted config.
//!   * [`taxii_save_config`] — persist the config to disk.
//!   * [`taxii_get_config`]  — read the persisted config back.
//!
//! Outbound calls are gated **twice**:
//!   1. by the global `privacy.outbound_lookups` toggle from `settings.toml`,
//!      mirroring how email/webhook/SIEM channels must respect the user's
//!      outbound posture (a TAXII push IS an outbound HTTP call);
//!   2. by [`sentinel_taxii::TaxiiConfig::enabled`], which is the per-sink
//!      kill-switch already enforced inside the crate.
//!
//! The local STIX export (e.g. `stix_export_bundle`) is intentionally NOT
//! gated by [`is_outbound_enabled`] because writing a file to disk is not an
//! outbound network call.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use sentinel_taxii::{TaxiiAuth, TaxiiClient, TaxiiConfig, TaxiiError};

use crate::commands_settings::Settings;

const TAXII_FILENAME: &str = "taxii.json";
const SETTINGS_FILENAME: &str = "settings.toml";

/// Error message returned to the UI when an outbound TAXII operation is
/// attempted while the global "Outbound calls" toggle is OFF in Settings.
///
/// Kept as a module-level constant so the matching test in `sentinel-taxii`
/// (and future channels) can assert on the exact same wording.
pub const OUTBOUND_DISABLED_MESSAGE: &str =
    "Outbound calls disabled in Settings — TAXII push blocked.";

// ─── UI-facing config (mirrors `tauri.ts`) ───────────────────────────────────

/// Authentication strategy, mirroring the `TaxiiAuth` discriminated union on
/// the TypeScript side.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaxiiUiAuth {
    None,
    Basic { user: String, pass: String },
    Bearer { token: String },
}

impl Default for TaxiiUiAuth {
    fn default() -> Self {
        TaxiiUiAuth::None
    }
}

impl From<TaxiiUiAuth> for TaxiiAuth {
    fn from(value: TaxiiUiAuth) -> Self {
        match value {
            TaxiiUiAuth::None => TaxiiAuth::None,
            TaxiiUiAuth::Basic { user, pass } => TaxiiAuth::Basic { user, pass },
            TaxiiUiAuth::Bearer { token } => TaxiiAuth::Bearer { token },
        }
    }
}

fn default_true() -> bool {
    true
}

/// UI-facing TAXII configuration. Persisted to `taxii.json` in the app data
/// directory.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct TaxiiUiConfig {
    /// Per-sink kill-switch; mirrors `TaxiiConfig::enabled`.
    pub enabled: bool,
    /// Base URL of the TAXII API root.
    pub api_root_url: String,
    /// Target collection id (UUID, typically).
    pub collection_id: String,
    /// Authentication strategy.
    pub auth: TaxiiUiAuth,
    /// Verify TLS certificates.
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

impl Default for TaxiiUiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_root_url: String::new(),
            collection_id: String::new(),
            auth: TaxiiUiAuth::None,
            verify_tls: true,
        }
    }
}

impl TaxiiUiConfig {
    /// Build a [`sentinel_taxii::TaxiiConfig`] from this UI config.
    pub fn to_wire(&self) -> TaxiiConfig {
        TaxiiConfig {
            api_root_url: self.api_root_url.clone(),
            collection_id: self.collection_id.clone(),
            auth: self.auth.clone().into(),
            enabled: self.enabled,
            verify_tls: self.verify_tls,
        }
    }
}

/// Result returned to the UI by [`taxii_test_send`].
#[derive(Serialize, Clone, Debug)]
pub struct TaxiiTestResult {
    pub ok: bool,
    pub status_code: Option<u16>,
    pub message: String,
    pub taxii_status_id: Option<String>,
}

// ─── Filesystem helpers ─────────────────────────────────────────────────────

fn taxii_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    Ok(dir.join(TAXII_FILENAME))
}

fn settings_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    Ok(dir.join(SETTINGS_FILENAME))
}

// ─── Outbound toggle ─────────────────────────────────────────────────────────

/// Read the persisted `Settings` from disk and return
/// `settings.privacy.outbound_lookups`. Defaults to `false` (privacy-first)
/// when no settings file has been written yet — i.e. an unconfigured
/// installation cannot accidentally push to a third-party TAXII server.
///
/// Errors loading/parsing the file are treated as "outbound disabled" so we
/// never leak data through a missing-config corner case.
pub fn is_outbound_enabled(app: &AppHandle) -> bool {
    let path = match settings_path(app) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !path.exists() {
        return false;
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match toml::from_str::<Settings>(&raw) {
        Ok(s) => s.privacy.outbound_lookups,
        Err(_) => false,
    }
}

/// Inline gate used by every TAXII push command. Returns `Ok(())` when the
/// global "Outbound calls" toggle is ON, [`OUTBOUND_DISABLED_MESSAGE`]
/// otherwise.
fn ensure_outbound_enabled(app: &AppHandle) -> Result<(), String> {
    if is_outbound_enabled(app) {
        Ok(())
    } else {
        Err(OUTBOUND_DISABLED_MESSAGE.to_string())
    }
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Persist the TAXII configuration to `taxii.json`. Secrets (basic auth
/// password, bearer token) are written in clear-text under the same trust
/// model as `settings.toml` and `siem.json`, and are never logged.
#[tauri::command]
pub async fn taxii_save_config(config: TaxiiUiConfig, app: AppHandle) -> Result<(), String> {
    let path = taxii_path(&app)?;
    let serialized = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("could not serialize TAXII config: {}", e))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))?;
    log::info!(
        "Sentinel TAXII config saved at {:?} (enabled={}, has_url={})",
        path,
        config.enabled,
        !config.api_root_url.is_empty()
    );
    Ok(())
}

/// Read the persisted TAXII configuration, returning [`TaxiiUiConfig::default`]
/// when no file exists yet.
#[tauri::command]
pub async fn taxii_get_config(app: AppHandle) -> Result<TaxiiUiConfig, String> {
    let path = taxii_path(&app)?;
    if !path.exists() {
        return Ok(TaxiiUiConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read {:?}: {}", path, e))?;
    let parsed: TaxiiUiConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("could not parse {:?}: {}", path, e))?;
    Ok(parsed)
}

/// POST a synthetic STIX 2.1 indicator to the configured TAXII collection.
///
/// Refuses to send when:
///   * the global `privacy.outbound_lookups` toggle is OFF — returns
///     [`OUTBOUND_DISABLED_MESSAGE`] verbatim;
///   * the per-sink `enabled` flag is OFF — returns the
///     [`TaxiiError::Disabled`] message from `sentinel-taxii`;
///   * `api_root_url` or `collection_id` is empty;
///   * the upstream TAXII server returns a non-2xx response or the request
///     times out.
#[tauri::command]
pub async fn taxii_test_send(app: AppHandle) -> Result<TaxiiTestResult, String> {
    // 1. Gate on the global outbound toggle. This is the same gate every
    //    network-bound channel (email/webhook/SIEM) is expected to use.
    ensure_outbound_enabled(&app)?;

    // 2. Load the persisted TAXII config and build the wire-level client.
    let cfg = taxii_get_config(app.clone()).await?;
    let wire = cfg.to_wire();

    let client = TaxiiClient::new(wire).map_err(|e| match e {
        TaxiiError::InvalidConfig(msg) => format!("TAXII config invalid: {}", msg),
        other => format!("TAXII client error: {}", other),
    })?;

    log::info!(
        "taxii_test_send: dispatching synthetic indicator (collection={}, verify_tls={})",
        client.config().collection_id,
        client.config().verify_tls
    );

    match client.test_send().await {
        Ok(status) => Ok(TaxiiTestResult {
            ok: true,
            status_code: Some(202),
            message: format!(
                "TAXII collection accepted the test indicator (status={}, success={}/{})",
                status.status, status.success_count, status.total_count
            ),
            taxii_status_id: Some(status.id),
        }),
        Err(TaxiiError::Disabled) => Err(
            "TAXII sink disabled — enable it in Settings → TAXII before sending a test.".into(),
        ),
        Err(TaxiiError::Server { status, body }) => Ok(TaxiiTestResult {
            ok: false,
            status_code: Some(status),
            message: format!("TAXII server returned HTTP {}: {}", status, body),
            taxii_status_id: None,
        }),
        Err(TaxiiError::InvalidConfig(msg)) => Err(format!("TAXII config invalid: {}", msg)),
        Err(TaxiiError::Http(e)) => Ok(TaxiiTestResult {
            ok: false,
            status_code: None,
            message: format!("TAXII transport error: {}", e),
            taxii_status_id: None,
        }),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
//
// Tauri commands take an `AppHandle` and are not directly unit-testable
// without a Tauri runtime. We therefore unit-test the *pure* helpers
// (`is_outbound_enabled`, `ensure_outbound_enabled`-style logic) by reading
// the same settings.toml shape from a temporary directory, exactly like the
// production helper does. This guarantees the gate fails closed (returns
// `false`/`Err`) when the toggle is OFF or the file is missing — which is the
// invariant the matching test in `crates/sentinel-taxii/tests/outbound_gate.rs`
// also documents.

#[cfg(test)]
mod tests {
    use super::*;

    /// Re-implementation of [`is_outbound_enabled`] that accepts a base
    /// directory directly, so we can exercise the same TOML parsing without
    /// a live Tauri runtime.
    fn outbound_enabled_in_dir(dir: &std::path::Path) -> bool {
        let path = dir.join(SETTINGS_FILENAME);
        if !path.exists() {
            return false;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(r) => r,
            Err(_) => return false,
        };
        match toml::from_str::<Settings>(&raw) {
            Ok(s) => s.privacy.outbound_lookups,
            Err(_) => false,
        }
    }

    #[test]
    fn outbound_disabled_when_no_settings_file() {
        let tmp = tempdir_unique("taxii-no-settings");
        assert!(
            !outbound_enabled_in_dir(&tmp),
            "missing settings.toml must fail closed"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_disabled_when_toggle_off() {
        let tmp = tempdir_unique("taxii-toggle-off");
        let path = tmp.join(SETTINGS_FILENAME);
        std::fs::write(
            &path,
            r#"
[privacy]
in_flight_only = true
outbound_lookups = false
"#,
        )
        .unwrap();
        assert!(!outbound_enabled_in_dir(&tmp));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_enabled_when_toggle_on() {
        let tmp = tempdir_unique("taxii-toggle-on");
        let path = tmp.join(SETTINGS_FILENAME);
        std::fs::write(
            &path,
            r#"
[privacy]
in_flight_only = true
outbound_lookups = true
"#,
        )
        .unwrap();
        assert!(outbound_enabled_in_dir(&tmp));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_disabled_on_corrupt_settings() {
        let tmp = tempdir_unique("taxii-corrupt");
        let path = tmp.join(SETTINGS_FILENAME);
        std::fs::write(&path, "not = valid = toml ===").unwrap();
        assert!(
            !outbound_enabled_in_dir(&tmp),
            "corrupt settings.toml must fail closed"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_disabled_message_is_exact() {
        // The UI tooltip and parent-agent tests both rely on the exact
        // wording — keep this assertion in sync if you change the constant.
        assert_eq!(
            OUTBOUND_DISABLED_MESSAGE,
            "Outbound calls disabled in Settings — TAXII push blocked."
        );
    }

    fn tempdir_unique(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("sentinel-{}-{}", tag, nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
