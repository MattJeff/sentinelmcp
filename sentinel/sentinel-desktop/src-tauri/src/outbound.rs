//! Shared "outbound calls" gate.
//!
//! Every Tauri command that triggers an outbound network call (TAXII push,
//! SIEM dispatch, email/webhook test, registry-backed lookalike scan, …)
//! must respect the global `privacy.outbound_lookups` toggle persisted in
//! `settings.toml`. This module centralises:
//!
//!   * [`is_outbound_enabled`] — read the toggle from disk, fail-closed when
//!     the file is missing or unparseable.
//!   * [`ensure_outbound_enabled`] — inline gate returning a typed `Err`
//!     ([`OUTBOUND_DISABLED_MESSAGE`]) when the toggle is OFF.
//!   * [`OUTBOUND_DISABLED_MESSAGE`] — the exact error string surfaced to the
//!     UI; kept as a module-level constant so every command (and its tests)
//!     can agree on the wording.
//!
//! The wording is the same TAXII-flavoured one that has shipped since the
//! original `commands_taxii` gate, so existing UI tooltips and crate-level
//! tests under `crates/sentinel-taxii/tests/outbound_gate.rs` stay in sync.

use tauri::{AppHandle, Manager};

use crate::commands_settings::Settings;

const SETTINGS_FILENAME: &str = "settings.toml";

/// Error message returned to the UI when an outbound operation is attempted
/// while the global "Outbound calls" toggle is OFF in Settings.
///
/// Kept verbatim so the matching crate-level test in
/// `crates/sentinel-taxii/tests/outbound_gate.rs` and every UI tooltip stay
/// in sync. Channels other than TAXII reuse this exact wording on purpose:
/// the user only has one toggle to flip, regardless of which sink errored.
pub const OUTBOUND_DISABLED_MESSAGE: &str =
    "Outbound calls disabled in Settings — TAXII push blocked.";

fn settings_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    Ok(dir.join(SETTINGS_FILENAME))
}

/// Read the persisted `Settings` from disk and return
/// `settings.privacy.outbound_lookups`. Defaults to `false` (privacy-first)
/// when no settings file has been written yet — i.e. an unconfigured
/// installation cannot accidentally push to a third-party endpoint.
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

/// Inline gate used by every outbound-call command. Returns `Ok(())` when
/// the global "Outbound calls" toggle is ON, [`OUTBOUND_DISABLED_MESSAGE`]
/// otherwise.
pub fn ensure_outbound_enabled(app: &AppHandle) -> Result<(), String> {
    if is_outbound_enabled(app) {
        Ok(())
    } else {
        Err(OUTBOUND_DISABLED_MESSAGE.to_string())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────
//
// Tauri commands take an `AppHandle` and are not directly unit-testable
// without a Tauri runtime. We therefore unit-test the *pure* helpers
// by reading the same settings.toml shape from a temporary directory,
// exactly like the production helper does. This guarantees the gate fails
// closed (returns `false`/`Err`) when the toggle is OFF or the file is
// missing — which is the invariant the matching crate-level test in
// `crates/sentinel-taxii/tests/outbound_gate.rs` also documents.

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// Re-implementation of [`is_outbound_enabled`] that accepts a base
    /// directory directly, so callers can exercise the same TOML parsing
    /// without a live Tauri runtime.
    pub fn outbound_enabled_in_dir(dir: &std::path::Path) -> bool {
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

    /// Same shape as [`ensure_outbound_enabled`] but takes a directory.
    pub fn ensure_outbound_enabled_in_dir(dir: &std::path::Path) -> Result<(), String> {
        if outbound_enabled_in_dir(dir) {
            Ok(())
        } else {
            Err(OUTBOUND_DISABLED_MESSAGE.to_string())
        }
    }

    /// Create a unique temp dir under `std::env::temp_dir()`.
    pub fn tempdir_unique(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("sentinel-{}-{}", tag, nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Write a settings.toml with `outbound_lookups = false` into `dir`.
    pub fn write_settings_outbound_off(dir: &std::path::Path) {
        std::fs::write(
            dir.join(SETTINGS_FILENAME),
            r#"
[privacy]
in_flight_only = true
outbound_lookups = false
"#,
        )
        .unwrap();
    }

    /// Write a settings.toml with `outbound_lookups = true` into `dir`.
    #[allow(dead_code)]
    pub fn write_settings_outbound_on(dir: &std::path::Path) {
        std::fs::write(
            dir.join(SETTINGS_FILENAME),
            r#"
[privacy]
in_flight_only = true
outbound_lookups = true
"#,
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn outbound_disabled_when_no_settings_file() {
        let tmp = tempdir_unique("outbound-no-settings");
        assert!(
            !outbound_enabled_in_dir(&tmp),
            "missing settings.toml must fail closed"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_disabled_when_toggle_off() {
        let tmp = tempdir_unique("outbound-toggle-off");
        write_settings_outbound_off(&tmp);
        assert!(!outbound_enabled_in_dir(&tmp));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_enabled_when_toggle_on() {
        let tmp = tempdir_unique("outbound-toggle-on");
        write_settings_outbound_on(&tmp);
        assert!(outbound_enabled_in_dir(&tmp));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn outbound_disabled_on_corrupt_settings() {
        let tmp = tempdir_unique("outbound-corrupt");
        std::fs::write(tmp.join(SETTINGS_FILENAME), "not = valid = toml ===").unwrap();
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

    #[test]
    fn ensure_outbound_enabled_in_dir_returns_err_when_off() {
        let tmp = tempdir_unique("outbound-ensure-off");
        write_settings_outbound_off(&tmp);
        let result = ensure_outbound_enabled_in_dir(&tmp);
        assert_eq!(result, Err(OUTBOUND_DISABLED_MESSAGE.to_string()));
        std::fs::remove_dir_all(&tmp).ok();
    }
}
