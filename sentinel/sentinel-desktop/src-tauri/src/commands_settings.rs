//! Tauri commands for persisting user-facing Sentinel settings.
//!
//! Settings are stored as TOML in the platform-specific app data directory
//! (on macOS: `~/Library/Application Support/com.sentinel-mcp.desktop/settings.toml`).
//! If the file does not exist yet, `get_settings` returns the defaults.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const SETTINGS_FILENAME: &str = "settings.toml";

// ─── DTO (mirrors the SettingsPage zustand store) ────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct CaptureSettings {
    pub default_mode: String,
    pub http_port: u32,
}

impl Default for CaptureSettings {
    fn default() -> Self {
        Self {
            default_mode: "fixture".to_string(),
            http_port: 8765,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct EmailSettings {
    pub enabled: bool,
    pub host: String,
    pub port: u32,
    pub from: String,
    pub to: String,
}

impl Default for EmailSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "smtp.example.com".to_string(),
            port: 587,
            from: "sentinel@example.com".to_string(),
            to: "security@example.com".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct WebhookSettings {
    pub enabled: bool,
    pub url: String,
    pub format: String,
}

impl Default for WebhookSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            format: "generic".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct AlertsSettings {
    pub email: EmailSettings,
    pub webhook: WebhookSettings,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct RetentionSettings {
    pub contacts_days: u32,
    pub findings_days: u32,
    pub alerts_days: u32,
}

impl Default for RetentionSettings {
    fn default() -> Self {
        Self {
            contacts_days: 60,
            findings_days: 180,
            alerts_days: 90,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct PrivacySettings {
    pub in_flight_only: bool,
    pub outbound_lookups: bool,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            in_flight_only: true,
            outbound_lookups: false,
        }
    }
}

/// General/UX-level toggles. Currently houses the tray "keep running in
/// background" preference. Defaults to `true` so closing the main window
/// hides the app to the menu bar — the operator can opt out from
/// Settings → General.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct GeneralSettings {
    pub keep_running_in_background: bool,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            keep_running_in_background: true,
        }
    }
}

/// Threat-intel feed refresh settings (V0.3).
///
/// Mirrors [`sentinel_discovery::threat_intel::refresh::ThreatFeedConfig`]
/// but uses a serialisable `String` for `last_refresh_at` so the TOML on
/// disk stays human-readable. Defaults to enabled with the public GitHub
/// URL; the cascade in
/// [`sentinel_discovery::threat_intel::refresh::charger_feed`] transparently
/// falls back to the disk cache or the bundled YAML when the remote
/// endpoint is unreachable.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ThreatFeedSettings {
    /// Remote URL Sentinel pulls the feed from. Empty string is treated
    /// as "use the bundled fallback only" by the cascade.
    pub url: String,
    /// When `true`, the background loop refreshes the cache every 24h
    /// (subject to the outbound-calls toggle).
    pub auto_refresh_enabled: bool,
    /// ISO-8601 timestamp of the last successful refresh. Maintained by
    /// `threat_feed_refresh`; never edited by the user directly.
    pub last_refresh_at: Option<String>,
}

impl Default for ThreatFeedSettings {
    fn default() -> Self {
        Self {
            url: sentinel_discovery::threat_intel::refresh::DEFAULT_FEED_URL.to_string(),
            auto_refresh_enabled: true,
            last_refresh_at: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Settings {
    pub capture: CaptureSettings,
    pub alerts: AlertsSettings,
    pub retention: RetentionSettings,
    pub privacy: PrivacySettings,
    pub general: GeneralSettings,
    pub threat_feed: ThreatFeedSettings,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn settings_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    Ok(dir.join(SETTINGS_FILENAME))
}

// ─── Commands ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<Settings, String> {
    let path = settings_path(&app)?;
    if !path.exists() {
        return Ok(Settings::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read {:?}: {}", path, e))?;
    let parsed: Settings = toml::from_str(&raw)
        .map_err(|e| format!("could not parse {:?}: {}", path, e))?;
    Ok(parsed)
}

#[tauri::command]
pub async fn save_settings(settings: Settings, app: AppHandle) -> Result<(), String> {
    let path = settings_path(&app)?;
    let serialized = toml::to_string_pretty(&settings)
        .map_err(|e| format!("could not serialize settings: {}", e))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))?;
    log::info!("Sentinel settings saved at {:?}", path);
    Ok(())
}

/// Read the persisted `general.keep_running_in_background` flag from
/// `settings.toml`. Returns `Some(true)` when the file is absent, malformed,
/// or any other read error occurs — i.e. fail-closed to the safe default so
/// the tray-mode behaviour stays predictable. Returns `None` only when the
/// app-data dir itself cannot be resolved.
pub fn lire_keep_running(app: &AppHandle) -> Option<bool> {
    let path = match settings_path(app) {
        Ok(p) => p,
        Err(_) => return None,
    };
    if !path.exists() {
        return Some(true);
    }
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(_) => return Some(true),
    };
    let parsed: Settings = match toml::from_str(&raw) {
        Ok(s) => s,
        Err(_) => return Some(true),
    };
    Some(parsed.general.keep_running_in_background)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_keep_running_true() {
        let s = Settings::default();
        assert!(s.general.keep_running_in_background);
    }

    #[test]
    fn parse_empty_toml_yields_defaults() {
        // Backwards-compat: a brand-new install (or an older settings.toml
        // that pre-dates the `general` block) must still parse cleanly and
        // default to "keep running in background = true".
        let parsed: Settings = toml::from_str("").expect("empty TOML must parse");
        assert!(parsed.general.keep_running_in_background);
    }

    #[test]
    fn parse_legacy_toml_without_general_block() {
        // Simulates a settings.toml written by Sentinel v0.2 (no `[general]`
        // section). The struct must hydrate, the missing block must default,
        // and the existing fields must survive round-tripping.
        let legacy = r#"
            [capture]
            default_mode = "stdio"
            http_port = 8080

            [privacy]
            in_flight_only = true
            outbound_lookups = true
        "#;
        let parsed: Settings = toml::from_str(legacy).expect("legacy TOML must parse");
        assert_eq!(parsed.capture.default_mode, "stdio");
        assert_eq!(parsed.capture.http_port, 8080);
        assert!(parsed.privacy.outbound_lookups);
        assert!(parsed.general.keep_running_in_background);
    }

    #[test]
    fn explicit_false_round_trips() {
        let mut s = Settings::default();
        s.general.keep_running_in_background = false;
        let serialized = toml::to_string_pretty(&s).expect("serialize");
        let parsed: Settings = toml::from_str(&serialized).expect("parse round-trip");
        assert!(!parsed.general.keep_running_in_background);
    }
}
