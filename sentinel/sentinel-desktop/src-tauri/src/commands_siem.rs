//! Tauri commands exposing SIEM sink configuration + test-send to the UI.
//!
//! Three sink kinds are supported, mirroring the V17/V18 Rust crates:
//!   * `"splunk"` — POST a synthetic alert to `<url>/services/collector/event`
//!     using `ClientSplunkHec` from `sentinel_alerts::sinks::splunk`.
//!   * `"elastic"` — POST a synthetic alert to `<url>/<index>/_doc` (HTTP Basic
//!     auth optional) using `ClientElastic` from `sentinel_alerts::sinks::elastic`.
//!   * `"syslog"` — emit an RFC-5424 line containing the alert JSON. The
//!     transport defaults to UDP (`ClientSyslogUdp`) but the operator can
//!     opt into TCP or TLS via [`SiemConfig::transport`] — those branches
//!     wire to `ClientSyslogTcp` / `ClientSyslogTls` once they land in
//!     `sentinel-alerts/src/sinks/syslog.rs`.
//!
//! Configuration is persisted (without ever logging secrets) as JSON in the
//! platform-specific app data directory, i.e. on macOS:
//!
//!     `~/Library/Application Support/com.sentinel-mcp.desktop/siem.json`
//!
//! Four commands are exposed:
//!   * [`siem_test_send`]  — build a synthetic alert and dispatch through the
//!     sink described by the incoming config. Does **not** persist anything.
//!   * [`siem_save_config`] — persist the last-used config to disk.
//!   * [`siem_get_config`]  — read the persisted config back; returns
//!     [`SiemConfig::default()`] when the file does not exist yet.
//!   * [`siem_pick_ca_pem`] — open a native file picker so the operator can
//!     pick a custom CA PEM bundle for the Syslog/TLS transport.

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use sentinel_alerts::sinks::elastic::ClientElastic;
use sentinel_alerts::sinks::splunk::ClientSplunkHec;
use sentinel_alerts::sinks::syslog::{
    ClientSyslog, ClientSyslogTcp, ClientSyslogTls, ClientSyslogUdp,
};

const SIEM_FILENAME: &str = "siem.json";

/// User-facing SIEM sink configuration.
///
/// `kind` selects which fields are required:
///   * `"splunk"` — `url` (HEC base URL) and `token` (HEC token).
///   * `"elastic"` — `url` (cluster base URL) and `index`; `user`/`pass` are
///     optional HTTP Basic credentials.
///   * `"syslog"` — `addr` (`host:port`). The wire transport is selected by
///     [`SiemConfig::transport`] (`"udp"` default | `"tcp"` | `"tls"`). When
///     `"tls"` is selected, [`SiemConfig::tls_ca_pem_path`] may point at a
///     local PEM-encoded CA bundle used to validate the syslog collector's
///     certificate; when left empty the system trust store is used.
///
/// Unused fields for a given kind may be `None` or empty strings. Older
/// `siem.json` files without `transport` / `tls_ca_pem_path` parse cleanly
/// thanks to `#[serde(default)]` and default to UDP.
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
    /// Syslog destination, `host:port`.
    pub addr: Option<String>,
    /// Syslog transport — `"udp"` (default), `"tcp"`, or `"tls"`. A `None` /
    /// missing value preserves backward compatibility with pre-existing
    /// configs and is treated as UDP.
    pub transport: Option<String>,
    /// Filesystem path to a custom CA PEM bundle, used only when
    /// `transport == "tls"`. When `None` or empty the system trust store
    /// validates the syslog collector certificate.
    pub tls_ca_pem_path: Option<String>,
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
///
/// Refuses to dispatch when the global `privacy.outbound_lookups` toggle is
/// OFF — returns [`crate::outbound::OUTBOUND_DISABLED_MESSAGE`] verbatim,
/// matching the gate already enforced on TAXII pushes.
#[tauri::command]
pub async fn siem_test_send(app: AppHandle, cfg: SiemConfig) -> Result<(), String> {
    crate::outbound::ensure_outbound_enabled(&app)?;

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
            // Normalize the transport: missing / unknown values fall back to
            // UDP so legacy `siem.json` files keep working unchanged.
            let transport = cfg
                .transport
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "udp".to_string());

            match transport.as_str() {
                "udp" => {
                    let client = ClientSyslogUdp::nouveau(addr.clone());
                    // severity_num=6 (informational) for the synthetic test alert.
                    // The sync inherent `envoyer` is kept for backward compat
                    // with V18 and is the path of least friction here.
                    client
                        .envoyer(6, &alert)
                        .map_err(|e| format!("Syslog UDP error: {}", e))
                }
                "tcp" => {
                    let client = ClientSyslogTcp::nouveau(addr.clone());
                    <ClientSyslogTcp as ClientSyslog>::envoyer(&client, 6, &alert)
                        .await
                        .map_err(|e| format!("Syslog TCP connect failed: {}", e))
                }
                "tls" => {
                    // The CA PEM is the only failure mode the operator can fix
                    // from the Settings UI; surface its IO error explicitly
                    // before the TLS handshake to keep the diagnostic
                    // actionable.
                    let ca_pem = match cfg
                        .tls_ca_pem_path
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        Some(path) => Some(std::fs::read(path).map_err(|e| {
                            format!(
                                "Custom CA PEM file unreadable: {} — {}",
                                path, e
                            )
                        })?),
                        None => None,
                    };
                    let client = ClientSyslogTls::nouveau(addr.clone(), ca_pem);
                    <ClientSyslogTls as ClientSyslog>::envoyer(&client, 6, &alert)
                        .await
                        .map_err(|e| format!("Syslog TLS error: {}", e))
                }
                other => Err(format!(
                    "unknown syslog transport: {} (expected udp|tcp|tls)",
                    other
                )),
            }
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

/// Open a native file picker so the operator can select a custom CA PEM
/// bundle for the Syslog/TLS transport. Returns `Ok(None)` when the user
/// dismisses the dialog; returns `Ok(Some(absolute_path))` on success.
#[tauri::command]
pub async fn siem_pick_ca_pem(app: AppHandle) -> Result<Option<String>, String> {
    // The dialog plugin's async API is callback-based; we bridge it to the
    // command's async surface via a oneshot channel so the UI gets a clean
    // `Promise<string | null>`.
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<String>>();
    app.dialog()
        .file()
        .set_title("Select a custom CA bundle (PEM)")
        .add_filter("PEM / CRT / CER", &["pem", "crt", "cer"])
        .add_filter("All files", &["*"])
        .pick_file(move |maybe_path| {
            let resolved = maybe_path.and_then(|p| match p.into_path() {
                Ok(buf) => Some(buf.to_string_lossy().to_string()),
                Err(_) => None,
            });
            // Receiver dropped (window closed mid-flight) — ignore.
            let _ = tx.send(resolved);
        });
    rx.await
        .map_err(|e| format!("CA picker dialog was cancelled unexpectedly: {}", e))
}


// ─── Tests ───────────────────────────────────────────────────────────────────
//
// `siem_test_send` itself takes an `AppHandle` and cannot run without a Tauri
// runtime. We assert the gate using the same `test_support` helpers that
// `crate::outbound` exposes, on a synthetic settings.toml — guaranteeing the
// SIEM channel surfaces `OUTBOUND_DISABLED_MESSAGE` verbatim when the global
// outbound toggle is OFF, exactly like the TAXII channel.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::test_support::{
        ensure_outbound_enabled_in_dir, tempdir_unique, write_settings_outbound_off,
    };
    use crate::outbound::OUTBOUND_DISABLED_MESSAGE;
    use serde_json::json;

    #[test]
    fn siem_test_send_gate_blocks_when_outbound_off() {
        let tmp = tempdir_unique("siem-gate-off");
        write_settings_outbound_off(&tmp);
        let res = ensure_outbound_enabled_in_dir(&tmp);
        assert_eq!(res, Err(OUTBOUND_DISABLED_MESSAGE.to_string()));
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Legacy `siem.json` payloads without the new `transport` /
    /// `tls_ca_pem_path` fields must still parse cleanly, and the new
    /// fields default to `None` (which the dispatcher treats as UDP).
    #[test]
    fn siem_config_back_compat_parses_without_transport_fields() {
        let legacy = r#"{
            "kind": "syslog",
            "addr": "127.0.0.1:514"
        }"#;
        let cfg: SiemConfig = serde_json::from_str(legacy).expect("legacy config must parse");
        assert_eq!(cfg.kind, "syslog");
        assert_eq!(cfg.addr.as_deref(), Some("127.0.0.1:514"));
        assert!(cfg.transport.is_none());
        assert!(cfg.tls_ca_pem_path.is_none());
    }

    /// Round-trip a config with the new transport + CA-PEM fields populated.
    #[test]
    fn siem_config_roundtrip_with_tls_fields() {
        let cfg = SiemConfig {
            kind: "syslog".to_string(),
            addr: Some("siem.internal:6514".to_string()),
            transport: Some("tls".to_string()),
            tls_ca_pem_path: Some("/etc/sentinel/ca.pem".to_string()),
            ..SiemConfig::default()
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: SiemConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.kind, "syslog");
        assert_eq!(back.transport.as_deref(), Some("tls"));
        assert_eq!(back.tls_ca_pem_path.as_deref(), Some("/etc/sentinel/ca.pem"));
    }

    /// The TCP client must surface a clean network error (`SinkError::Reseau`
    /// → `"Syslog TCP connect failed:"` in our wrapper) when no listener is
    /// bound on the requested port. We bind/release a port to guarantee
    /// nothing is listening there.
    #[tokio::test]
    async fn siem_test_send_syslog_tcp_fails_cleanly_without_listener() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind for free-port probe");
        let port = probe.local_addr().expect("local_addr").port();
        // Drop the listener so the port becomes unbound. There's a benign
        // TOCTOU window but it's vanishingly unlikely to matter in CI.
        drop(probe);
        let addr = format!("127.0.0.1:{}", port);
        let alert = json!({ "id": "test" });
        let client = ClientSyslogTcp::nouveau(addr);
        let err = <ClientSyslogTcp as ClientSyslog>::envoyer(&client, 6, &alert)
            .await
            .expect_err("connect to an unbound port must fail");
        // The real client surfaces a `SinkError::Reseau` variant — which is
        // exactly what `siem_test_send` reformats as `"Syslog TCP connect
        // failed: …"` for the UI toast.
        let msg = err.to_string();
        assert!(
            msg.contains("réseau") || msg.contains("Reseau") || msg.contains("refused")
                || msg.contains("connection") || msg.contains("connexion"),
            "error should be a network-class failure: {}",
            msg
        );
    }
}
