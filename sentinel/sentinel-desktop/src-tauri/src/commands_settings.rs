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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Settings {
    pub capture: CaptureSettings,
    pub alerts: AlertsSettings,
    pub retention: RetentionSettings,
    pub privacy: PrivacySettings,
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
