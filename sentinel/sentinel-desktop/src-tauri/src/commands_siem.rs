//! Tauri commands exposing SIEM sink configuration + test-send to the UI.
//!
//! Three sink kinds are supported, mirroring the V17/V18 Rust crates:
//!   * `"splunk"` — POST a synthetic alert to `<url>/services/collector/event`
//!     using `ClientSplunkHec` from `sentinel_alerts::sinks::splunk`.
//!   * `"elastic"` — POST a synthetic alert to `<url>/<index>/_doc` (HTTP Basic
//!     auth optional) using `ClientElastic` from `sentinel_alerts::sinks::elastic`.
//!   * `"syslog"` — UDP-send an RFC-5424 line containing the alert JSON using
//!     `ClientSyslogUdp` from `sentinel_alerts::sinks::syslog`.
//!
//! Configuration is persisted (without ever logging secrets) as JSON in the
//! platform-specific app data directory, i.e. on macOS:
//!
//!     ~/Library/Application Support/com.sentinel-mcp.desktop/siem.json
//!
//! Three commands are exposed:
//!   * [`siem_test_send`]  — build a synthetic alert and dispatch through the
//!     sink described by the incoming config. Does **not** persist anything.
//!   * [`siem_save_config`] — persist the last-used config to disk.
//!   * [`siem_get_config`]  — read the persisted config back; returns
//!     [`SiemConfig::default()`] when the file does not exist yet.

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Manager};

use sentinel_alerts::sinks::elastic::ClientElastic;
use sentinel_alerts::sinks::splunk::ClientSplunkHec;
use sentinel_alerts::sinks::syslog::ClientSyslogUdp;

const SIEM_FILENAME: &str = "siem.json";

/// User-facing SIEM sink configuration.
///
/// `kind` selects which fields are required:
///   * `"splunk"` — `url` (HEC base URL) and `token` (HEC token).
///   * `"elastic"` — `url` (cluster base URL) and `index`; `user`/`pass` are
///     optional HTTP Basic credentials.
///   * `"syslog"` — `addr` (`host:port`, UDP).
///
/// Unused fields for a given kind may be `None` or empty strings.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct SiemConfig {
    /// `"splunk"` | `"elastic"` | `"syslog"`.
    pub kind: String,
    /// HEC URL (Splunk) or Elastic cluster base URL.
    pub url: Option<String>,
    /// Splunk HEC token.
    pub token: Option<String>,
    /// Elastic destination index.
    pub index: Option<String>,
    /// Elastic HTTP Basic user (optional).
    pub user: Option<String>,
    /// Elastic HTTP Basic password (optional).
    pub pass: Option<String>,
    /// Syslog destination, `host:port` (UDP).
    pub addr: Option<String>,
}

fn siem_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    Ok(dir.join(SIEM_FILENAME))
}

/// Build the synthetic alert payload used by [`siem_test_send`].
fn synthetic_alert() -> serde_json::Value {
    json!({
        "id": "test",
        "title": "Sentinel SIEM test",
        "severity": "info",
        "timestamp": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

/// Dispatch a synthetic alert through the sink described by `cfg`.
///
/// Returns `Ok(())` on success, or a human-readable error string on failure
/// (network, HTTP non-2xx, missing fields, etc.). Secrets are **never**
/// echoed back in error messages.
#[tauri::command]
pub async fn siem_test_send(cfg: SiemConfig) -> Result<(), String> {
    let alert = synthetic_alert();
    log::info!(
        "siem_test_send: dispatching synthetic alert via kind={}",
        cfg.kind
    );

    match cfg.kind.as_str() {
        "splunk" => {
            let url = cfg
                .url
                .as_ref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Splunk HEC URL is required".to_string())?;
            let token = cfg
                .token
                .as_ref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Splunk HEC token is required".to_string())?;
            let client = ClientSplunkHec::nouveau(url.clone(), token.clone(), None);
            client
                .envoyer(&alert)
                .await
                .map_err(|e| format!("Splunk HEC error: {}", e))
        }
        "elastic" => {
            let url = cfg
                .url
                .as_ref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Elastic base URL is required".to_string())?;
            let index = cfg
                .index
                .as_ref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Elastic index is required".to_string())?;
            let auth = match (cfg.user.as_ref(), cfg.pass.as_ref()) {
                (Some(u), Some(p)) if !u.trim().is_empty() => {
                    Some((u.clone(), p.clone()))
                }
                _ => None,
            };
            let client = ClientElastic::nouveau(url.clone(), index.clone(), auth);
            client
                .envoyer(&alert)
                .await
                .map_err(|e| format!("Elastic error: {}", e))
        }
        "syslog" => {
            let addr = cfg
                .addr
                .as_ref()
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| "Syslog host:port is required".to_string())?;
            let client = ClientSyslogUdp::nouveau(addr.clone());
            // severity_num=6 (informational) for the synthetic test alert.
            client
                .envoyer(6, &alert)
                .map_err(|e| format!("Syslog error: {}", e))
        }
        other => Err(format!(
            "unknown SIEM kind: {} (expected splunk|elastic|syslog)",
            other
        )),
    }
}

/// Persist the last-used SIEM configuration as JSON.
///
/// Secrets are written to disk in clear-text (same trust model as the existing
/// `settings.toml`) but are never logged.
#[tauri::command]
pub async fn siem_save_config(cfg: SiemConfig, app: AppHandle) -> Result<(), String> {
    let path = siem_path(&app)?;
    let serialized = serde_json::to_string_pretty(&cfg)
        .map_err(|e| format!("could not serialize SIEM config: {}", e))?;
    std::fs::write(&path, serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))?;
    log::info!("Sentinel SIEM config saved at {:?} (kind={})", path, cfg.kind);
    Ok(())
}

/// Read the persisted SIEM configuration back, or return defaults when no
/// config has ever been saved.
#[tauri::command]
pub async fn siem_get_config(app: AppHandle) -> Result<SiemConfig, String> {
    let path = siem_path(&app)?;
    if !path.exists() {
        return Ok(SiemConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("could not read {:?}: {}", path, e))?;
    let parsed: SiemConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("could not parse {:?}: {}", path, e))?;
    Ok(parsed)
}
