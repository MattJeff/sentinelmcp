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

use sentinel_alerts::secrets::{self, CoffreSecrets};
use sentinel_taxii::{TaxiiAuth, TaxiiClient, TaxiiConfig, TaxiiError};

use crate::outbound::ensure_outbound_enabled;

const TAXII_FILENAME: &str = "taxii.json";

/// Keyring key (service "sentinel-mcp") for the TAXII Basic-auth password.
const CLE_TAXII_PASS: &str = "taxii_password";
/// Keyring key (service "sentinel-mcp") for the TAXII Bearer token.
const CLE_TAXII_TOKEN: &str = "taxii_token";

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

// ─── Keyring protection helpers ──────────────────────────────────────────────
//
// The TAXII secret (Basic password or Bearer token) is pushed into the OS
// keyring (service "sentinel-mcp") and replaced on disk by a
// `"keyring:<name>"` reference. Set `SENTINEL_NO_KEYRING=1` to opt out
// (CI / headless) and keep the legacy clear-text file behaviour.

/// Replace the clear-text TAXII secret by a keyring reference (writing the
/// secret into the vault). Returns `true` when the config changed.
fn proteger_taxii(cfg: &mut TaxiiUiConfig, coffre: &dyn CoffreSecrets) -> Result<bool, String> {
    match &mut cfg.auth {
        TaxiiUiAuth::Basic { pass, .. } => secrets::proteger_champ(coffre, CLE_TAXII_PASS, pass)
            .map_err(|e| format!("keyring error ({}): {}", CLE_TAXII_PASS, e)),
        TaxiiUiAuth::Bearer { token } => secrets::proteger_champ(coffre, CLE_TAXII_TOKEN, token)
            .map_err(|e| format!("keyring error ({}): {}", CLE_TAXII_TOKEN, e)),
        TaxiiUiAuth::None => Ok(false),
    }
}

/// Resolve the `"keyring:<name>"` reference back to the secret value.
/// Lenient: a reference whose vault entry has been deleted loads as an empty
/// secret (warning logged) so the Settings page never fails to render.
fn resoudre_taxii(cfg: &mut TaxiiUiConfig, coffre: &dyn CoffreSecrets) {
    let avert = match &mut cfg.auth {
        TaxiiUiAuth::Basic { pass, .. } => secrets::resoudre_champ_souple(coffre, pass)
            .map(|a| format!("taxii ({}): {}", CLE_TAXII_PASS, a)),
        TaxiiUiAuth::Bearer { token } => secrets::resoudre_champ_souple(coffre, token)
            .map(|a| format!("taxii ({}): {}", CLE_TAXII_TOKEN, a)),
        TaxiiUiAuth::None => None,
    };
    if let Some(avert) = avert {
        log::warn!("{}", avert);
    }
}

/// Purge vault entries orphaned by an auth-mode change or an emptied secret:
/// only the entry backing the current mode (when non-empty) survives.
fn purger_orphelins_taxii(cfg: &TaxiiUiConfig, coffre: &dyn CoffreSecrets) -> Result<(), String> {
    let (pass, token) = match &cfg.auth {
        TaxiiUiAuth::None => (None, None),
        TaxiiUiAuth::Basic { pass, .. } => (Some(pass.as_str()), None),
        TaxiiUiAuth::Bearer { token } => (None, Some(token.as_str())),
    };
    secrets::purger_si_vide(coffre, CLE_TAXII_PASS, pass)
        .map_err(|e| format!("keyring error ({}): {}", CLE_TAXII_PASS, e))?;
    secrets::purger_si_vide(coffre, CLE_TAXII_TOKEN, token)
        .map_err(|e| format!("keyring error ({}): {}", CLE_TAXII_TOKEN, e))?;
    Ok(())
}

/// Atomic, verified write (tmp + read-back + rename). No `.bak` is ever
/// kept: the contract is "no clear-text secret ever persists on disk".
fn ecrire_taxii_fichier(path: &std::path::Path, cfg: &TaxiiUiConfig) -> Result<(), String> {
    let serialized = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("could not serialize TAXII config: {}", e))?;
    secrets::ecrire_fichier_verifie(path, &serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))
}

/// Persist `cfg`, protecting the secret through the keyring when one is
/// provided and purging vault entries orphaned by an auth-mode change or an
/// emptied secret.
fn sauver_taxii_fichier(
    path: &std::path::Path,
    mut cfg: TaxiiUiConfig,
    coffre: Option<&dyn CoffreSecrets>,
) -> Result<(), String> {
    if let Some(coffre) = coffre {
        purger_orphelins_taxii(&cfg, coffre)?;
        proteger_taxii(&mut cfg, coffre)?;
    }
    ecrire_taxii_fichier(path, &cfg)
}

/// Load the persisted config. When a keyring is active, a clear-text secret
/// found on disk is migrated transparently (pushed into the vault, file
/// atomically rewritten with the reference — no clear-text `.bak` is kept),
/// then the reference is resolved so callers always see a usable value. A
/// dangling reference degrades to an empty secret + warning.
fn charger_taxii_fichier(
    path: &std::path::Path,
    coffre: Option<&dyn CoffreSecrets>,
) -> Result<TaxiiUiConfig, String> {
    if !path.exists() {
        return Ok(TaxiiUiConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {:?}: {}", path, e))?;
    let mut cfg: TaxiiUiConfig = serde_json::from_str(&raw)
        .map_err(|e| format!("could not parse {:?}: {}", path, e))?;

    let Some(coffre) = coffre else {
        return Ok(cfg);
    };

    crate::commands_settings::purger_bak_en_clair(path);

    if proteger_taxii(&mut cfg, coffre)? {
        ecrire_taxii_fichier(path, &cfg)?;
        log::info!(
            "TAXII secret migrated to the OS keyring; {:?} rewritten (no clear-text backup kept)",
            path
        );
    }

    resoudre_taxii(&mut cfg, coffre);
    Ok(cfg)
}

// ─── Commands ────────────────────────────────────────────────────────────────

/// Persist the TAXII configuration to `taxii.json`. Secrets (basic auth
/// password, bearer token) are pushed into the OS keyring and only a
/// `"keyring:<name>"` reference is written to disk — never the clear-text
/// value (unless `SENTINEL_NO_KEYRING=1` opts out). Secrets are never logged.
#[tauri::command]
pub async fn taxii_save_config(config: TaxiiUiConfig, app: AppHandle) -> Result<(), String> {
    let path = taxii_path(&app)?;
    let enabled = config.enabled;
    let has_url = !config.api_root_url.is_empty();
    sauver_taxii_fichier(&path, config, secrets::coffre_actif().as_deref())?;
    log::info!(
        "Sentinel TAXII config saved at {:?} (enabled={}, has_url={})",
        path,
        enabled,
        has_url
    );
    Ok(())
}

/// Read the persisted TAXII configuration, returning [`TaxiiUiConfig::default`]
/// when no file exists yet. A legacy clear-text secret is transparently
/// migrated into the OS keyring (no clear-text backup is kept), and the
/// keyring reference is resolved before returning. A reference whose vault
/// entry has been deleted loads as an empty secret instead of failing.
#[tauri::command]
pub async fn taxii_get_config(app: AppHandle) -> Result<TaxiiUiConfig, String> {
    let path = taxii_path(&app)?;
    charger_taxii_fichier(&path, secrets::coffre_actif().as_deref())
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
        Err(other) => Ok(TaxiiTestResult {
            ok: false,
            status_code: None,
            message: format!("TAXII error: {}", other),
            taxii_status_id: None,
        }),
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
//
// Tauri commands take an `AppHandle` and are not directly unit-testable
// without a Tauri runtime. The pure helpers (`is_outbound_enabled`,
// `ensure_outbound_enabled`) have moved to `crate::outbound` and are unit
// tested there. The tests here pin the TAXII-side invariants that depend on
// the shared constant — i.e. that we still use the exact wording the UI and
// the crate-level test in `crates/sentinel-taxii/tests/outbound_gate.rs`
// expect.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::test_support::{
        ensure_outbound_enabled_in_dir, tempdir_unique, write_settings_outbound_off,
    };
    use crate::outbound::OUTBOUND_DISABLED_MESSAGE;
    use sentinel_alerts::secrets::CoffreMemoire;

    #[test]
    fn outbound_disabled_message_is_exact() {
        // The UI tooltip and parent-agent tests both rely on the exact
        // wording — keep this assertion in sync if you change the constant.
        assert_eq!(
            OUTBOUND_DISABLED_MESSAGE,
            "Outbound calls disabled in Settings — TAXII push blocked."
        );
    }

    #[test]
    fn taxii_gate_blocks_when_toggle_off() {
        // Exercises the same gate every TAXII outbound command relies on:
        // a settings.toml with `outbound_lookups = false` must surface the
        // shared `OUTBOUND_DISABLED_MESSAGE` verbatim.
        let tmp = tempdir_unique("taxii-gate-off");
        write_settings_outbound_off(&tmp);
        let res = ensure_outbound_enabled_in_dir(&tmp);
        assert_eq!(res, Err(OUTBOUND_DISABLED_MESSAGE.to_string()));
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A legacy `taxii.json` carrying a clear-text Basic password must be
    /// migrated on load: password pushed into the vault, file atomically
    /// rewritten with the `keyring:` reference, **no** clear-text `.bak`
    /// left behind, and the returned config resolved back to the clear
    /// value.
    #[test]
    fn taxii_load_migrates_clear_basic_password() {
        let tmp = tempdir_unique("taxii-keyring-migrate");
        let path = tmp.join(TAXII_FILENAME);
        let legacy = r#"{
            "enabled": true,
            "api_root_url": "https://taxii.local/api1",
            "collection_id": "col-1",
            "auth": { "kind": "basic", "user": "analyst", "pass": "taxii-clear-pass" }
        }"#;
        std::fs::write(&path, legacy).unwrap();

        let coffre = CoffreMemoire::nouveau();
        let cfg = charger_taxii_fichier(&path, Some(&coffre)).expect("load + migrate");

        match &cfg.auth {
            TaxiiUiAuth::Basic { user, pass } => {
                assert_eq!(user, "analyst");
                assert_eq!(pass, "taxii-clear-pass");
            }
            other => panic!("expected Basic auth, got {:?}", other),
        }
        assert_eq!(
            coffre.lire(CLE_TAXII_PASS).unwrap().as_deref(),
            Some("taxii-clear-pass")
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:taxii_password"), "{}", on_disk);
        assert!(!on_disk.contains("taxii-clear-pass"), "{}", on_disk);
        // Contract: no clear-text copy may persist on disk after migration.
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Switching the auth mode (Basic → Bearer → None) purges the vault
    /// entries that no longer back the active mode, and a dangling
    /// reference loads gracefully as an empty secret.
    #[test]
    fn taxii_auth_mode_change_purges_orphaned_secrets() {
        let tmp = tempdir_unique("taxii-keyring-orphans");
        let path = tmp.join(TAXII_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        // Seed: Basic auth, password in the vault.
        let basic = TaxiiUiConfig {
            enabled: true,
            api_root_url: "https://taxii.local/api1".to_string(),
            collection_id: "col-1".to_string(),
            auth: TaxiiUiAuth::Basic {
                user: "analyst".to_string(),
                pass: "taxii-clear-pass".to_string(),
            },
            verify_tls: true,
        };
        sauver_taxii_fichier(&path, basic, Some(&coffre)).expect("save basic");
        assert!(coffre.lire(CLE_TAXII_PASS).unwrap().is_some());

        // Switch to Bearer: the Basic password is now orphaned → purged.
        let bearer = TaxiiUiConfig {
            enabled: true,
            api_root_url: "https://taxii.local/api1".to_string(),
            collection_id: "col-1".to_string(),
            auth: TaxiiUiAuth::Bearer {
                token: "taxii-clear-token".to_string(),
            },
            verify_tls: true,
        };
        sauver_taxii_fichier(&path, bearer, Some(&coffre)).expect("save bearer");
        assert!(coffre.lire(CLE_TAXII_PASS).unwrap().is_none());
        assert!(coffre.lire(CLE_TAXII_TOKEN).unwrap().is_some());

        // Switch to None: every TAXII secret is orphaned → purged.
        let none = TaxiiUiConfig {
            enabled: false,
            api_root_url: "https://taxii.local/api1".to_string(),
            collection_id: "col-1".to_string(),
            auth: TaxiiUiAuth::None,
            verify_tls: true,
        };
        sauver_taxii_fichier(&path, none, Some(&coffre)).expect("save none");
        assert!(coffre.lire(CLE_TAXII_PASS).unwrap().is_none());
        assert!(coffre.lire(CLE_TAXII_TOKEN).unwrap().is_none());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A dangling reference (vault entry wiped out-of-band) must degrade
    /// gracefully: the config loads with an empty secret instead of failing
    /// the whole Settings page.
    #[test]
    fn taxii_load_degrades_gracefully_on_dangling_reference() {
        let tmp = tempdir_unique("taxii-keyring-dangling");
        let path = tmp.join(TAXII_FILENAME);
        std::fs::write(
            &path,
            r#"{
                "enabled": true,
                "api_root_url": "https://taxii.local/api1",
                "collection_id": "col-1",
                "auth": { "kind": "bearer", "token": "keyring:taxii_token" }
            }"#,
        )
        .unwrap();

        let coffre = CoffreMemoire::nouveau(); // vault is empty: entry lost
        let cfg = charger_taxii_fichier(&path, Some(&coffre))
            .expect("load must not fail on a dangling reference");
        match &cfg.auth {
            TaxiiUiAuth::Bearer { token } => assert_eq!(token, ""),
            other => panic!("expected Bearer auth, got {:?}", other),
        }
        assert_eq!(cfg.api_root_url, "https://taxii.local/api1");

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Saving from the UI never writes the clear Bearer token to disk.
    #[test]
    fn taxii_save_protects_bearer_token_with_keyring() {
        let tmp = tempdir_unique("taxii-keyring-save");
        let path = tmp.join(TAXII_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        let cfg = TaxiiUiConfig {
            enabled: true,
            api_root_url: "https://taxii.local/api1".to_string(),
            collection_id: "col-1".to_string(),
            auth: TaxiiUiAuth::Bearer {
                token: "taxii-clear-token".to_string(),
            },
            verify_tls: true,
        };
        sauver_taxii_fichier(&path, cfg, Some(&coffre)).expect("save");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:taxii_token"), "{}", on_disk);
        assert!(!on_disk.contains("taxii-clear-token"), "{}", on_disk);
        assert_eq!(
            coffre.lire(CLE_TAXII_TOKEN).unwrap().as_deref(),
            Some("taxii-clear-token")
        );

        // Reload resolves the reference back to the clear value, with no
        // second migration (no .bak for an already-protected file).
        let back = charger_taxii_fichier(&path, Some(&coffre)).expect("reload");
        match &back.auth {
            TaxiiUiAuth::Bearer { token } => assert_eq!(token, "taxii-clear-token"),
            other => panic!("expected Bearer auth, got {:?}", other),
        }
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Opt-out path (`SENTINEL_NO_KEYRING=1` → no vault handed in): the
    /// legacy clear-text file behaviour is preserved.
    #[test]
    fn taxii_save_without_keyring_keeps_clear_file_behaviour() {
        let tmp = tempdir_unique("taxii-keyring-optout");
        let path = tmp.join(TAXII_FILENAME);

        let cfg = TaxiiUiConfig {
            enabled: false,
            api_root_url: "https://taxii.local/api1".to_string(),
            collection_id: "col-1".to_string(),
            auth: TaxiiUiAuth::Basic {
                user: "analyst".to_string(),
                pass: "taxii-clear-pass".to_string(),
            },
            verify_tls: true,
        };
        sauver_taxii_fichier(&path, cfg, None).expect("save");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("taxii-clear-pass"));
        let back = charger_taxii_fichier(&path, None).expect("reload");
        match &back.auth {
            TaxiiUiAuth::Basic { pass, .. } => assert_eq!(pass, "taxii-clear-pass"),
            other => panic!("expected Basic auth, got {:?}", other),
        }
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
