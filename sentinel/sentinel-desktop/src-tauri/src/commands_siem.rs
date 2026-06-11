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

use sentinel_alerts::secrets::{self, CoffreSecrets};
use sentinel_alerts::sinks::elastic::ClientElastic;
use sentinel_alerts::sinks::splunk::ClientSplunkHec;
use sentinel_alerts::sinks::syslog::{
    ClientSyslog, ClientSyslogTcp, ClientSyslogTls, ClientSyslogUdp,
};

const SIEM_FILENAME: &str = "siem.json";

/// Keyring key (service "sentinel-mcp") for the Splunk HEC token.
const CLE_SPLUNK_TOKEN: &str = "splunk_hec_token";
/// Keyring key (service "sentinel-mcp") for the Elastic Basic-auth password.
const CLE_ELASTIC_PASS: &str = "elastic_password";

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

// ─── Keyring protection helpers ──────────────────────────────────────────────
//
// Secrets (Splunk HEC token, Elastic password) are pushed into the OS keyring
// (service "sentinel-mcp") and replaced on disk by a `"keyring:<name>"`
// reference. Set `SENTINEL_NO_KEYRING=1` to opt out (CI / headless) and keep
// the legacy clear-text file behaviour.

/// Replace clear-text secrets in `cfg` by keyring references (writing the
/// secrets into the vault). Returns `true` when at least one field changed.
fn proteger_siem(cfg: &mut SiemConfig, coffre: &dyn CoffreSecrets) -> Result<bool, String> {
    let mut change = secrets::proteger_option(coffre, CLE_SPLUNK_TOKEN, &mut cfg.token)
        .map_err(|e| format!("keyring error ({}): {}", CLE_SPLUNK_TOKEN, e))?;
    change |= secrets::proteger_option(coffre, CLE_ELASTIC_PASS, &mut cfg.pass)
        .map_err(|e| format!("keyring error ({}): {}", CLE_ELASTIC_PASS, e))?;
    Ok(change)
}

/// Resolve `"keyring:<name>"` references in `cfg` back to their secret values.
/// Strict variant — used by [`siem_test_send`] where a dangling reference is
/// a hard error (sending with an empty secret would be misleading).
fn resoudre_siem(cfg: &mut SiemConfig, coffre: &dyn CoffreSecrets) -> Result<(), String> {
    secrets::resoudre_option(coffre, &mut cfg.token)
        .map_err(|e| format!("keyring error ({}): {}", CLE_SPLUNK_TOKEN, e))?;
    secrets::resoudre_option(coffre, &mut cfg.pass)
        .map_err(|e| format!("keyring error ({}): {}", CLE_ELASTIC_PASS, e))?;
    Ok(())
}

/// Lenient variant used by config loading: a reference whose vault entry has
/// been deleted loads as an empty secret (warning logged) so the Settings
/// page never fails to render.
fn resoudre_siem_souple(cfg: &mut SiemConfig, coffre: &dyn CoffreSecrets) {
    if let Some(avert) = secrets::resoudre_option_souple(coffre, &mut cfg.token) {
        log::warn!("siem ({}): {}", CLE_SPLUNK_TOKEN, avert);
    }
    if let Some(avert) = secrets::resoudre_option_souple(coffre, &mut cfg.pass) {
        log::warn!("siem ({}): {}", CLE_ELASTIC_PASS, avert);
    }
}

/// Purge vault entries whose config field has been emptied (secret cleared,
/// or sink kind changed — the UI nulls the secrets of the other kinds).
fn purger_orphelins_siem(cfg: &SiemConfig, coffre: &dyn CoffreSecrets) -> Result<(), String> {
    secrets::purger_si_vide(coffre, CLE_SPLUNK_TOKEN, cfg.token.as_deref())
        .map_err(|e| format!("keyring error ({}): {}", CLE_SPLUNK_TOKEN, e))?;
    secrets::purger_si_vide(coffre, CLE_ELASTIC_PASS, cfg.pass.as_deref())
        .map_err(|e| format!("keyring error ({}): {}", CLE_ELASTIC_PASS, e))?;
    Ok(())
}

/// Atomic, verified write (tmp + read-back + rename). No `.bak` is ever
/// kept: the contract is "no clear-text secret ever persists on disk".
fn ecrire_siem_fichier(path: &std::path::Path, cfg: &SiemConfig) -> Result<(), String> {
    let serialized = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("could not serialize SIEM config: {}", e))?;
    secrets::ecrire_fichier_verifie(path, &serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))
}

/// Persist `cfg`, protecting secrets through the keyring when one is provided
/// and purging vault entries for secrets that have been emptied.
fn sauver_siem_fichier(
    path: &std::path::Path,
    mut cfg: SiemConfig,
    coffre: Option<&dyn CoffreSecrets>,
) -> Result<(), String> {
    if let Some(coffre) = coffre {
        purger_orphelins_siem(&cfg, coffre)?;
        proteger_siem(&mut cfg, coffre)?;
    }
    ecrire_siem_fichier(path, &cfg)
}

/// Load the persisted config. When a keyring is active, clear-text secrets
/// found on disk are migrated transparently (pushed into the vault, file
/// atomically rewritten with references — no clear-text `.bak` is kept),
/// then references are resolved so callers always see usable values. A
/// dangling reference degrades to an empty secret + warning.
fn charger_siem_fichier(
    path: &std::path::Path,
    coffre: Option<&dyn CoffreSecrets>,
) -> Result<SiemConfig, String> {
    if !path.exists() {
        return Ok(SiemConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {:?}: {}", path, e))?;
    let mut cfg: SiemConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("could not parse {:?}: {}", path, e))?;

    let Some(coffre) = coffre else {
        return Ok(cfg);
    };

    crate::commands_settings::purger_bak_en_clair(path);

    if proteger_siem(&mut cfg, coffre)? {
        ecrire_siem_fichier(path, &cfg)?;
        log::info!(
            "SIEM secrets migrated to the OS keyring; {:?} rewritten (no clear-text backup kept)",
            path
        );
    }

    resoudre_siem_souple(&mut cfg, coffre);
    Ok(cfg)
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
pub async fn siem_test_send(app: AppHandle, mut cfg: SiemConfig) -> Result<(), String> {
    crate::outbound::ensure_outbound_enabled(&app)?;

    // The UI may hand back `"keyring:<name>"` references untouched — resolve
    // them against the OS keyring before dispatching.
    if let Some(coffre) = secrets::coffre_actif() {
        resoudre_siem(&mut cfg, coffre.as_ref())?;
    }

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
/// Secrets (HEC token, Elastic password) are pushed into the OS keyring and
/// only a `"keyring:<name>"` reference is written to disk — never the
/// clear-text value (unless `SENTINEL_NO_KEYRING=1` opts out). Secrets are
/// never logged.
#[tauri::command]
pub async fn siem_save_config(cfg: SiemConfig, app: AppHandle) -> Result<(), String> {
    let path = siem_path(&app)?;
    let kind = cfg.kind.clone();
    sauver_siem_fichier(&path, cfg, secrets::coffre_actif().as_deref())?;
    log::info!("Sentinel SIEM config saved at {:?} (kind={})", path, kind);
    Ok(())
}

/// Read the persisted SIEM configuration back, or return defaults when no
/// config has ever been saved. Legacy clear-text secrets are transparently
/// migrated into the OS keyring (no clear-text backup is kept), and keyring
/// references are resolved before returning. A reference whose vault entry
/// has been deleted loads as an empty secret instead of failing.
#[tauri::command]
pub async fn siem_get_config(app: AppHandle) -> Result<SiemConfig, String> {
    let path = siem_path(&app)?;
    charger_siem_fichier(&path, secrets::coffre_actif().as_deref())
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

    use sentinel_alerts::secrets::CoffreMemoire;

    /// A legacy `siem.json` carrying a clear-text Splunk token must be
    /// migrated on load: token pushed into the vault, file atomically
    /// rewritten with a `keyring:` reference, **no** clear-text `.bak` left
    /// behind, and the returned config resolved back to the clear value.
    #[test]
    fn siem_load_migrates_clear_secret_into_keyring() {
        let tmp = tempdir_unique("siem-keyring-migrate");
        let path = tmp.join(super::SIEM_FILENAME);
        let legacy = r#"{ "kind": "splunk", "url": "https://hec.local:8088", "token": "hec-clear-token" }"#;
        std::fs::write(&path, legacy).unwrap();

        let coffre = CoffreMemoire::nouveau();
        let cfg = super::charger_siem_fichier(&path, Some(&coffre)).expect("load + migrate");

        // Caller sees the resolved secret.
        assert_eq!(cfg.token.as_deref(), Some("hec-clear-token"));
        // Vault holds the secret.
        assert_eq!(
            coffre.lire(super::CLE_SPLUNK_TOKEN).unwrap().as_deref(),
            Some("hec-clear-token")
        );
        // File now carries the reference, not the secret.
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:splunk_hec_token"), "{}", on_disk);
        assert!(!on_disk.contains("hec-clear-token"), "{}", on_disk);
        // Contract: no clear-text copy may persist on disk after migration.
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Saving from the UI never writes the clear secret to disk: the Elastic
    /// password goes to the vault and the file gets the reference.
    #[test]
    fn siem_save_protects_secrets_with_keyring() {
        let tmp = tempdir_unique("siem-keyring-save");
        let path = tmp.join(super::SIEM_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        let cfg = SiemConfig {
            kind: "elastic".to_string(),
            url: Some("https://es.local:9200".to_string()),
            index: Some("sentinel".to_string()),
            user: Some("elastic".to_string()),
            pass: Some("es-clear-pass".to_string()),
            ..SiemConfig::default()
        };
        super::sauver_siem_fichier(&path, cfg, Some(&coffre)).expect("save");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:elastic_password"), "{}", on_disk);
        assert!(!on_disk.contains("es-clear-pass"), "{}", on_disk);
        assert_eq!(
            coffre.lire(super::CLE_ELASTIC_PASS).unwrap().as_deref(),
            Some("es-clear-pass")
        );

        // Reload resolves the reference back to the clear value.
        let back = super::charger_siem_fichier(&path, Some(&coffre)).expect("reload");
        assert_eq!(back.pass.as_deref(), Some("es-clear-pass"));
        // No second migration happened (no .bak written for an already-protected file).
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Opt-out path (`SENTINEL_NO_KEYRING=1` → no vault handed in): the
    /// legacy clear-text file behaviour is preserved bit-for-bit.
    #[test]
    fn siem_save_without_keyring_keeps_clear_file_behaviour() {
        let tmp = tempdir_unique("siem-keyring-optout");
        let path = tmp.join(super::SIEM_FILENAME);

        let cfg = SiemConfig {
            kind: "splunk".to_string(),
            url: Some("https://hec.local:8088".to_string()),
            token: Some("hec-clear-token".to_string()),
            ..SiemConfig::default()
        };
        super::sauver_siem_fichier(&path, cfg, None).expect("save");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("hec-clear-token"));
        let back = super::charger_siem_fichier(&path, None).expect("reload");
        assert_eq!(back.token.as_deref(), Some("hec-clear-token"));
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A dangling `keyring:` reference (vault wiped) must degrade
    /// gracefully on load: the config comes back with an empty secret (and
    /// a warning logged) instead of blocking the whole Settings page. It
    /// must never leak the literal reference as a usable secret either.
    #[test]
    fn siem_load_degrades_gracefully_on_dangling_reference() {
        let tmp = tempdir_unique("siem-keyring-dangling");
        let path = tmp.join(super::SIEM_FILENAME);
        std::fs::write(
            &path,
            r#"{ "kind": "splunk", "url": "https://hec.local:8088", "token": "keyring:splunk_hec_token" }"#,
        )
        .unwrap();

        let coffre = CoffreMemoire::nouveau();
        let cfg = super::charger_siem_fichier(&path, Some(&coffre))
            .expect("load must not fail on a dangling reference");
        assert_eq!(cfg.token.as_deref(), Some(""));
        assert_eq!(cfg.url.as_deref(), Some("https://hec.local:8088"));

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Switching sink kind (the UI nulls the secrets of the other kinds) or
    /// clearing a secret purges the orphaned vault entries on save.
    #[test]
    fn siem_save_purges_orphaned_secrets() {
        let tmp = tempdir_unique("siem-keyring-orphans");
        let path = tmp.join(super::SIEM_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        // Seed: a Splunk config with its token in the vault.
        let splunk = SiemConfig {
            kind: "splunk".to_string(),
            url: Some("https://hec.local:8088".to_string()),
            token: Some("hec-clear-token".to_string()),
            ..SiemConfig::default()
        };
        super::sauver_siem_fichier(&path, splunk, Some(&coffre)).expect("save splunk");
        assert!(coffre.lire(super::CLE_SPLUNK_TOKEN).unwrap().is_some());

        // Operator switches to Syslog: no secret fields at all — both vault
        // entries must be purged.
        let syslog = SiemConfig {
            kind: "syslog".to_string(),
            addr: Some("127.0.0.1:514".to_string()),
            ..SiemConfig::default()
        };
        super::sauver_siem_fichier(&path, syslog, Some(&coffre)).expect("save syslog");
        assert!(coffre.lire(super::CLE_SPLUNK_TOKEN).unwrap().is_none());
        assert!(coffre.lire(super::CLE_ELASTIC_PASS).unwrap().is_none());

        std::fs::remove_dir_all(&tmp).ok();
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
