//! Tauri commands for persisting user-facing Sentinel settings.
//!
//! Settings are stored as TOML in the platform-specific app data directory
//! (on macOS: `~/Library/Application Support/com.sentinel-mcp.desktop/settings.toml`).
//! If the file does not exist yet, `get_settings` returns the defaults.

use sentinel_alerts::secrets::{self, CoffreSecrets};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

const SETTINGS_FILENAME: &str = "settings.toml";

/// Keyring key (service "sentinel-mcp") for the SMTP password.
const CLE_SMTP_PASSWORD: &str = "smtp_password";

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
    /// SMTP auth user (optional — empty string means no auth).
    pub user: String,
    /// SMTP auth password. Never persisted in clear-text: on disk this is a
    /// `"keyring:smtp_password"` reference resolved through the OS keyring
    /// (unless `SENTINEL_NO_KEYRING=1` opts out).
    pub pass: String,
}

impl Default for EmailSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "smtp.example.com".to_string(),
            port: 587,
            from: "sentinel@example.com".to_string(),
            to: "security@example.com".to_string(),
            user: String::new(),
            pass: String::new(),
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

// ─── Keyring protection helpers ──────────────────────────────────────────────
//
// The SMTP password is pushed into the OS keyring (service "sentinel-mcp")
// and replaced on disk by the `"keyring:smtp_password"` reference. Set
// `SENTINEL_NO_KEYRING=1` to opt out (CI / headless) and keep the legacy
// clear-text file behaviour.

/// Replace the clear-text SMTP password by a keyring reference (writing the
/// secret into the vault). Returns `true` when the settings changed.
fn proteger_settings(s: &mut Settings, coffre: &dyn CoffreSecrets) -> Result<bool, String> {
    secrets::proteger_champ(coffre, CLE_SMTP_PASSWORD, &mut s.alerts.email.pass)
        .map_err(|e| format!("keyring error ({}): {}", CLE_SMTP_PASSWORD, e))
}

/// Resolve the `"keyring:smtp_password"` reference back to the secret value.
/// Lenient: a reference whose vault entry has been deleted loads as an empty
/// password (with a warning logged) instead of failing the whole Settings
/// page.
fn resoudre_settings(s: &mut Settings, coffre: &dyn CoffreSecrets) {
    if let Some(avert) = secrets::resoudre_champ_souple(coffre, &mut s.alerts.email.pass) {
        log::warn!("settings ({}): {}", CLE_SMTP_PASSWORD, avert);
    }
}

/// Atomic, verified write (tmp + read-back + rename). No `.bak` is ever
/// kept: the contract is "no clear-text secret ever persists on disk".
fn ecrire_settings_fichier(path: &std::path::Path, s: &Settings) -> Result<(), String> {
    let serialized = toml::to_string_pretty(s)
        .map_err(|e| format!("could not serialize settings: {}", e))?;
    secrets::ecrire_fichier_verifie(path, &serialized)
        .map_err(|e| format!("could not write {:?}: {}", path, e))
}

/// Replace the UI sentinel (`"********"`) by the raw on-disk value so an
/// unchanged masked password keeps the existing secret instead of
/// overwriting it. An empty incoming password means "clear the secret".
fn demasquer_settings(path: &std::path::Path, s: &mut Settings) -> Result<(), String> {
    if !secrets::est_masque(&s.alerts.email.pass) {
        return Ok(());
    }
    s.alerts.email.pass = if path.exists() {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {:?}: {}", path, e))?;
        let existant: Settings = toml::from_str(&raw)
            .map_err(|e| format!("could not parse {:?}: {}", path, e))?;
        // Raw value: either a `keyring:` reference (re-written untouched —
        // `proteger_champ` skips references) or the legacy clear value.
        existant.alerts.email.pass
    } else {
        String::new()
    };
    Ok(())
}

/// Remove a stale `<file>.bak` left behind by an earlier version of the
/// keyring migration: those backups carried the secret in clear text, which
/// violates the "no clear-text secret ever persists on disk" contract.
/// Shared by the settings/SIEM/TAXII loaders.
pub(crate) fn purger_bak_en_clair(path: &std::path::Path) {
    let bak = std::path::PathBuf::from(format!("{}.bak", path.display()));
    if bak.exists() {
        match std::fs::remove_file(&bak) {
            Ok(()) => log::info!("removed legacy clear-text backup {:?}", bak),
            Err(e) => log::warn!("could not remove legacy backup {:?}: {}", bak, e),
        }
    }
}

/// Mask the SMTP password before handing settings to the frontend: the UI
/// only ever sees the [`secrets::VALEUR_MASQUEE`] sentinel, never the secret.
fn masquer_settings(s: &mut Settings) {
    if !s.alerts.email.pass.is_empty() {
        s.alerts.email.pass = secrets::VALEUR_MASQUEE.to_string();
    }
}

/// Persist `settings`, protecting the SMTP password through the keyring when
/// one is provided. An emptied password purges the orphaned vault entry.
fn sauver_settings_fichier(
    path: &std::path::Path,
    mut settings: Settings,
    coffre: Option<&dyn CoffreSecrets>,
) -> Result<(), String> {
    if let Some(coffre) = coffre {
        secrets::purger_si_vide(
            coffre,
            CLE_SMTP_PASSWORD,
            Some(settings.alerts.email.pass.as_str()),
        )
        .map_err(|e| format!("keyring error ({}): {}", CLE_SMTP_PASSWORD, e))?;
        proteger_settings(&mut settings, coffre)?;
    }
    ecrire_settings_fichier(path, &settings)
}

/// Load the persisted settings. When a keyring is active, a clear-text SMTP
/// password found on disk is migrated transparently (pushed into the vault,
/// file atomically rewritten with the reference — no clear-text `.bak` is
/// kept), then the reference is resolved so callers always see a usable
/// value. A dangling reference degrades to an empty password + warning.
fn charger_settings_fichier(
    path: &std::path::Path,
    coffre: Option<&dyn CoffreSecrets>,
) -> Result<Settings, String> {
    if !path.exists() {
        return Ok(Settings::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {:?}: {}", path, e))?;
    let mut parsed: Settings = toml::from_str(&raw)
        .map_err(|e| format!("could not parse {:?}: {}", path, e))?;

    let Some(coffre) = coffre else {
        return Ok(parsed);
    };

    purger_bak_en_clair(path);

    if proteger_settings(&mut parsed, coffre)? {
        ecrire_settings_fichier(path, &parsed)?;
        log::info!(
            "SMTP password migrated to the OS keyring; {:?} rewritten (no clear-text backup kept)",
            path
        );
    }

    resoudre_settings(&mut parsed, coffre);
    Ok(parsed)
}

/// Resolve the real SMTP password (never the UI sentinel) for internal send
/// paths (e.g. the test-email command). Empty when no secret is stored or
/// when the vault entry has been lost.
pub fn smtp_password_reel(app: &AppHandle) -> Result<String, String> {
    let path = settings_path(app)?;
    let s = charger_settings_fichier(&path, secrets::coffre_actif().as_deref())?;
    Ok(s.alerts.email.pass)
}

// ─── Commands ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<Settings, String> {
    let path = settings_path(&app)?;
    let mut s = charger_settings_fichier(&path, secrets::coffre_actif().as_deref())?;
    // The frontend never receives the clear secret — only the sentinel.
    masquer_settings(&mut s);
    Ok(s)
}

#[tauri::command]
pub async fn save_settings(mut settings: Settings, app: AppHandle) -> Result<(), String> {
    let path = settings_path(&app)?;
    // An unchanged sentinel from the UI means "keep the existing secret".
    demasquer_settings(&path, &mut settings)?;
    sauver_settings_fichier(&path, settings, secrets::coffre_actif().as_deref())?;
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

    use crate::outbound::test_support::tempdir_unique;
    use sentinel_alerts::secrets::CoffreMemoire;

    /// A legacy settings.toml carrying a clear-text SMTP password must be
    /// migrated on load: password pushed into the vault, file atomically
    /// rewritten with the `keyring:` reference, **no** clear-text `.bak`
    /// left behind, and the returned settings resolved back to the clear
    /// value.
    #[test]
    fn settings_load_migrates_clear_smtp_password() {
        let tmp = tempdir_unique("settings-keyring-migrate");
        let path = tmp.join(SETTINGS_FILENAME);
        let legacy = r#"
            [alerts.email]
            enabled = true
            host = "smtp.local"
            port = 587
            from = "a@b.c"
            to = "d@e.f"
            user = "sentinel"
            pass = "smtp-clear-pass"
        "#;
        std::fs::write(&path, legacy).unwrap();

        let coffre = CoffreMemoire::nouveau();
        let s = charger_settings_fichier(&path, Some(&coffre)).expect("load + migrate");

        assert_eq!(s.alerts.email.pass, "smtp-clear-pass");
        assert_eq!(s.alerts.email.user, "sentinel");
        assert_eq!(
            coffre.lire(CLE_SMTP_PASSWORD).unwrap().as_deref(),
            Some("smtp-clear-pass")
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:smtp_password"), "{}", on_disk);
        assert!(!on_disk.contains("smtp-clear-pass"), "{}", on_disk);
        // Contract: no clear-text copy may persist on disk after migration.
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Saving with the unchanged `"********"` sentinel (what the UI hands
    /// back when the operator did not touch the password field) must keep
    /// the existing vault secret and the on-disk reference — never overwrite
    /// the secret with the sentinel.
    #[test]
    fn settings_save_sentinel_keeps_existing_secret() {
        let tmp = tempdir_unique("settings-keyring-sentinel");
        let path = tmp.join(SETTINGS_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        // Seed: a protected settings file + vault entry.
        let mut initial = Settings::default();
        initial.alerts.email.user = "sentinel".to_string();
        initial.alerts.email.pass = "smtp-clear-pass".to_string();
        sauver_settings_fichier(&path, initial, Some(&coffre)).expect("seed save");

        // Simulate a UI round-trip: get (masked) then save unchanged.
        let mut roundtrip = charger_settings_fichier(&path, Some(&coffre)).expect("load");
        masquer_settings(&mut roundtrip);
        assert_eq!(roundtrip.alerts.email.pass, secrets::VALEUR_MASQUEE);
        roundtrip.alerts.email.host = "smtp.changed".to_string();
        demasquer_settings(&path, &mut roundtrip).expect("demask");
        sauver_settings_fichier(&path, roundtrip, Some(&coffre)).expect("save");

        // The vault secret survived; the file still carries the reference.
        assert_eq!(
            coffre.lire(CLE_SMTP_PASSWORD).unwrap().as_deref(),
            Some("smtp-clear-pass")
        );
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:smtp_password"), "{}", on_disk);
        assert!(!on_disk.contains(secrets::VALEUR_MASQUEE), "{}", on_disk);
        assert!(on_disk.contains("smtp.changed"), "{}", on_disk);

        let back = charger_settings_fichier(&path, Some(&coffre)).expect("reload");
        assert_eq!(back.alerts.email.pass, "smtp-clear-pass");

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Clearing the password from the UI purges the orphaned vault entry.
    #[test]
    fn settings_save_empty_password_purges_keyring_entry() {
        let tmp = tempdir_unique("settings-keyring-purge");
        let path = tmp.join(SETTINGS_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        let mut initial = Settings::default();
        initial.alerts.email.pass = "smtp-clear-pass".to_string();
        sauver_settings_fichier(&path, initial, Some(&coffre)).expect("seed save");
        assert!(coffre.lire(CLE_SMTP_PASSWORD).unwrap().is_some());

        let mut cleared = Settings::default();
        cleared.alerts.email.pass = String::new();
        sauver_settings_fichier(&path, cleared, Some(&coffre)).expect("save cleared");

        assert!(coffre.lire(CLE_SMTP_PASSWORD).unwrap().is_none());
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("keyring:smtp_password"), "{}", on_disk);

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A stale `.bak` written by an earlier version of the migration (clear
    /// secret inside) must be purged on the next load.
    #[test]
    fn settings_load_purges_stale_clear_text_bak() {
        let tmp = tempdir_unique("settings-keyring-stale-bak");
        let path = tmp.join(SETTINGS_FILENAME);
        std::fs::write(
            &path,
            r#"
            [alerts.email]
            pass = "keyring:smtp_password"
            "#,
        )
        .unwrap();
        let bak = format!("{}.bak", path.display());
        std::fs::write(&bak, "pass = \"smtp-clear-pass\"").unwrap();

        let coffre = CoffreMemoire::nouveau();
        coffre.ecrire(CLE_SMTP_PASSWORD, "smtp-clear-pass").unwrap();
        let s = charger_settings_fichier(&path, Some(&coffre)).expect("load");

        assert_eq!(s.alerts.email.pass, "smtp-clear-pass");
        assert!(
            !std::path::Path::new(&bak).exists(),
            "the stale clear-text .bak must be removed on load"
        );

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// A dangling `keyring:` reference (vault entry deleted out-of-band)
    /// must degrade gracefully: settings load with an empty password instead
    /// of failing the whole Settings page.
    #[test]
    fn settings_load_degrades_gracefully_on_dangling_reference() {
        let tmp = tempdir_unique("settings-keyring-dangling");
        let path = tmp.join(SETTINGS_FILENAME);
        std::fs::write(
            &path,
            r#"
            [alerts.email]
            enabled = true
            host = "smtp.local"
            pass = "keyring:smtp_password"
            "#,
        )
        .unwrap();

        let coffre = CoffreMemoire::nouveau(); // vault is empty: entry lost
        let s = charger_settings_fichier(&path, Some(&coffre))
            .expect("load must not fail on a dangling reference");
        assert_eq!(s.alerts.email.pass, "");
        assert_eq!(s.alerts.email.host, "smtp.local");

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Saving from the UI never writes the clear SMTP password to disk, and
    /// reloading resolves the reference without a second migration.
    #[test]
    fn settings_save_protects_smtp_password_with_keyring() {
        let tmp = tempdir_unique("settings-keyring-save");
        let path = tmp.join(SETTINGS_FILENAME);
        let coffre = CoffreMemoire::nouveau();

        let mut s = Settings::default();
        s.alerts.email.user = "sentinel".to_string();
        s.alerts.email.pass = "smtp-clear-pass".to_string();
        sauver_settings_fichier(&path, s, Some(&coffre)).expect("save");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("keyring:smtp_password"), "{}", on_disk);
        assert!(!on_disk.contains("smtp-clear-pass"), "{}", on_disk);

        let back = charger_settings_fichier(&path, Some(&coffre)).expect("reload");
        assert_eq!(back.alerts.email.pass, "smtp-clear-pass");
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Opt-out path (`SENTINEL_NO_KEYRING=1` → no vault handed in): the
    /// legacy clear-text file behaviour is preserved.
    #[test]
    fn settings_save_without_keyring_keeps_clear_file_behaviour() {
        let tmp = tempdir_unique("settings-keyring-optout");
        let path = tmp.join(SETTINGS_FILENAME);

        let mut s = Settings::default();
        s.alerts.email.pass = "smtp-clear-pass".to_string();
        sauver_settings_fichier(&path, s, None).expect("save");

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("smtp-clear-pass"));
        let back = charger_settings_fichier(&path, None).expect("reload");
        assert_eq!(back.alerts.email.pass, "smtp-clear-pass");
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// An empty password (the common case — no SMTP auth) must not trigger
    /// any migration or keyring write on load.
    #[test]
    fn settings_load_without_password_does_not_touch_keyring() {
        let tmp = tempdir_unique("settings-keyring-empty");
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

        let coffre = CoffreMemoire::nouveau();
        let s = charger_settings_fichier(&path, Some(&coffre)).expect("load");
        assert_eq!(s.alerts.email.pass, "");
        assert!(coffre.lire(CLE_SMTP_PASSWORD).unwrap().is_none());
        assert!(!std::path::Path::new(&format!("{}.bak", path.display())).exists());

        std::fs::remove_dir_all(&tmp).ok();
    }
}
