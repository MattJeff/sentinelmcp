//! Goose MCP discovery source.
//!
//! Goose is Block's open-source AI agent. It stores its global configuration
//! under `~/.config/goose/` on macOS and Linux (`$XDG_CONFIG_HOME/goose/`
//! honoré sur Linux) and under `%APPDATA%\Block\goose\config\` on Windows.
//! Two YAML files matter:
//!
//!   * `config.yaml` — the modern, flat `extensions:` map.
//!   * `profiles.yaml` — older profile-based form where each
//!     profile carries its own `extensions:` block.
//!
//! Goose's YAML schema differs from most other MCP clients on a few key
//! points:
//!
//!   * the top-level key is `extensions` (not `mcpServers`);
//!   * the command field is `cmd` (not `command`);
//!   * the env field is `envs` (not `env`);
//!   * each entry has a `type` of `stdio` / `sse` / `builtin`.
//!
//! ```yaml
//! extensions:
//!   github:
//!     type: stdio
//!     cmd: npx
//!     args: ["-y", "@modelcontextprotocol/server-github"]
//!     envs: { GITHUB_TOKEN: "..." }
//!   brave:
//!     type: builtin
//!     name: brave
//! ```
//!
//! `builtin` extensions are Goose-internal — they are not MCP servers — so we
//! filter them out of [`ServeurMcpDeclare`] outputs.
//!
//! The desktop app lives at `/Applications/Goose.app`; the CLI binary lives at
//! `~/.local/bin/goose` (or on `$PATH`). We probe both and try to read
//! `goose --version`.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::{pousser_unique, ContexteOs, OsCible};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_yaml::Value as YamlValue;
use std::path::{Path, PathBuf};
use tokio::process::Command;

/// Dossiers de configuration Goose candidats selon l'OS, en ordre de
/// priorité. Fonction pure.
fn dossiers_config(ctx: &ContexteOs) -> Vec<PathBuf> {
    match ctx.os {
        OsCible::MacOs => vec![ctx.home.join(".config").join("goose")],
        OsCible::Windows => vec![
            ctx.dossier_appdata().join("Block").join("goose").join("config"),
            ctx.home.join(".config").join("goose"),
        ],
        OsCible::Linux => {
            let mut out = vec![];
            for d in ctx.dossiers_config_linux() {
                pousser_unique(&mut out, d.join("goose"));
            }
            out
        }
    }
}

/// Chemins candidats de `config.yaml` selon l'OS. Fonction pure.
pub fn chemins_config_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    dossiers_config(ctx)
        .into_iter()
        .map(|d| d.join("config.yaml"))
        .collect()
}

/// Chemins candidats de `profiles.yaml` selon l'OS. Fonction pure.
pub fn chemins_profiles_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    dossiers_config(ctx)
        .into_iter()
        .map(|d| d.join("profiles.yaml"))
        .collect()
}

pub struct SourceGoose;

#[async_trait]
impl SourceClient for SourceGoose {
    fn id(&self) -> &'static str { "goose" }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let ctx = match ContexteOs::courant() {
            Some(c) => c,
            None => return vec![],
        };
        let app = PathBuf::from("/Applications/Goose.app");
        let mut res = detecter_avec_contexte(&ctx, &app);

        // Best-effort: ask the CLI for its version. Only do this once and
        // never let a stuck binary block us.
        if let Some(c) = res.first_mut() {
            if c.version.is_none() {
                if let Some(v) = lire_version_cli().await {
                    c.version = Some(v);
                }
            }
        }
        res
    }
}

/// Pure detection helper — used by both the live source and the tests.
/// Resolves paths for the **current** OS; for per-OS tests use
/// [`detecter_avec_contexte`].
pub fn detecter_avec_chemins(home: &Path, app: &Path) -> Vec<ClientDecouvert> {
    let ctx = ContexteOs::nouveau(OsCible::courant(), home);
    detecter_avec_contexte(&ctx, app)
}

/// Variante entièrement paramétrée (OS + home injectés) — testable sur tous
/// les OS sans `cfg!`. `app` is the absolute path of the `Goose.app` bundle
/// to probe (macOS only).
pub fn detecter_avec_contexte(ctx: &ContexteOs, app: &Path) -> Vec<ClientDecouvert> {
    let home = ctx.home.as_path();
    let config_path = chemins_config_candidats(ctx)
        .into_iter()
        .find(|p| p.exists());
    let profiles_path = chemins_profiles_candidats(ctx)
        .into_iter()
        .find(|p| p.exists());
    let local_bin = home.join(".local").join("bin").join("goose");

    let app_present = app.exists();
    let local_bin_present = local_bin.exists();
    let config_present = config_path.is_some();
    let profiles_present = profiles_path.is_some();

    if !app_present
        && !local_bin_present
        && !config_present
        && !profiles_present
    {
        return vec![];
    }

    let mut decouvert = ClientDecouvert::nouveau(ClientKind::Goose);

    if app_present {
        let bin = app.join("Contents").join("MacOS").join("Goose");
        if bin.exists() {
            decouvert.binary_path = Some(bin);
        } else {
            decouvert.binary_path = Some(app.to_path_buf());
        }
        if let Some(v) = lire_version_info_plist(&app.join("Contents").join("Info.plist")) {
            decouvert.version = Some(v);
        }
    } else if local_bin_present {
        decouvert.binary_path = Some(local_bin);
    }

    if let Some(p) = &config_path {
        traiter_yaml_config(p, &mut decouvert);
    }
    if let Some(p) = &profiles_path {
        traiter_yaml_profiles(p, &mut decouvert);
    }

    if !config_present && !profiles_present && (app_present || local_bin_present) {
        decouvert.notes.push("no MCP block".to_string());
    }

    vec![decouvert]
}

/// Parse `~/.config/goose/config.yaml` (flat `extensions:` map at the root).
fn traiter_yaml_config(path: &Path, decouvert: &mut ClientDecouvert) {
    let brut = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            decouvert
                .notes
                .push(format!("failed to read {}: {}", path.display(), e));
            return;
        }
    };

    let yaml: YamlValue = match serde_yaml::from_str(&brut) {
        Ok(v) => v,
        Err(e) => {
            decouvert
                .notes
                .push(format!("failed to parse {}: {}", path.display(), e));
            return;
        }
    };

    decouvert.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "goose".to_string(),
        vu_a: Utc::now(),
    });

    extraire_extensions(&yaml, decouvert, path);
}

/// Parse `~/.config/goose/profiles.yaml` — each top-level key is a profile
/// name whose value carries its own `extensions:` block.
fn traiter_yaml_profiles(path: &Path, decouvert: &mut ClientDecouvert) {
    let brut = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            decouvert
                .notes
                .push(format!("failed to read {}: {}", path.display(), e));
            return;
        }
    };

    let yaml: YamlValue = match serde_yaml::from_str(&brut) {
        Ok(v) => v,
        Err(e) => {
            decouvert
                .notes
                .push(format!("failed to parse {}: {}", path.display(), e));
            return;
        }
    };

    decouvert.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "goose".to_string(),
        vu_a: Utc::now(),
    });

    // Try the wrapped `profiles:` form first, then fall back to the implicit
    // top-level map of profiles.
    let profiles_map = yaml
        .get("profiles")
        .and_then(|v| v.as_mapping())
        .or_else(|| yaml.as_mapping());

    let Some(map) = profiles_map else {
        decouvert
            .notes
            .push("profiles file has no profile map".to_string());
        return;
    };

    let mut compte = 0usize;
    for (_, profile) in map {
        extraire_extensions(profile, decouvert, path);
        compte += 1;
    }
    if compte == 0 {
        decouvert.notes.push("profiles file is empty".to_string());
    }
}

/// Extract the `extensions:` block from a YAML value (either the root of
/// `config.yaml` or one profile inside `profiles.yaml`).
fn extraire_extensions(
    yaml: &YamlValue,
    decouvert: &mut ClientDecouvert,
    origine: &Path,
) {
    let bloc = yaml.get("extensions");
    match bloc {
        Some(YamlValue::Mapping(map)) => {
            let mut ajoutes = 0usize;
            for (k, v) in map {
                if let Some(nom) = k.as_str() {
                    if let Some(s) = parser_extension(nom, v) {
                        decouvert.serveurs.push(s);
                        ajoutes += 1;
                    }
                }
            }
            if ajoutes == 0 && decouvert.serveurs.is_empty() {
                decouvert
                    .notes
                    .push(format!("extensions block empty in {}", origine.display()));
            }
        }
        Some(_) => {
            decouvert.notes.push(format!(
                "extensions is not a map in {}",
                origine.display()
            ));
        }
        None => {
            decouvert
                .notes
                .push(format!("no extensions block in {}", origine.display()));
        }
    }
}

/// Convert one extension entry into a [`ServeurMcpDeclare`].
///
/// Returns `None` for `builtin` extensions — those are Goose-internal, not
/// MCP servers, and should not appear in `serveurs`.
fn parser_extension(nom: &str, value: &YamlValue) -> Option<ServeurMcpDeclare> {
    let map = value.as_mapping()?;

    let type_field = map
        .get(YamlValue::String("type".to_string()))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if type_field.eq_ignore_ascii_case("builtin") {
        return None;
    }

    let disabled = map
        .get(YamlValue::String("disabled".to_string()))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let url = map
        .get(YamlValue::String("url".to_string()))
        .and_then(|v| v.as_str())
        .map(String::from);

    // Remote entry (sse / http / explicit url).
    let is_remote = matches!(type_field, "sse" | "http") || url.is_some();
    if is_remote {
        // Normalise both `sse` and explicit `http` onto the "http" transport
        // label used elsewhere in the codebase for remote MCP endpoints.
        let transport = if type_field.eq_ignore_ascii_case("sse")
            || type_field.eq_ignore_ascii_case("http")
        {
            "http".to_string()
        } else {
            "http".to_string()
        };
        return Some(ServeurMcpDeclare {
            nom: nom.to_string(),
            transport,
            commande: None,
            args: vec![],
            env_keys: vec![],
            url,
            disabled,
            scope: ScopeServeur::default(),
        });
    }

    // Stdio entry.
    let commande = map
        .get(YamlValue::String("cmd".to_string()))
        .and_then(|v| v.as_str())
        .map(String::from);

    let args = map
        .get(YamlValue::String("args".to_string()))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let env_keys = map
        .get(YamlValue::String("envs".to_string()))
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, _)| k.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(ServeurMcpDeclare {
        nom: nom.to_string(),
        transport: "stdio".to_string(),
        commande,
        args,
        env_keys,
        url: None,
        disabled,
        scope: ScopeServeur::default(),
    })
}

/// Best-effort extraction of `CFBundleShortVersionString` from a macOS
/// `Info.plist`. We avoid pulling a full plist parser and just scan the XML
/// form Goose ships with.
fn lire_version_info_plist(plist: &Path) -> Option<String> {
    let brut = std::fs::read_to_string(plist).ok()?;
    let needle = "CFBundleShortVersionString";
    let idx = brut.find(needle)?;
    let tail = &brut[idx + needle.len()..];
    let open = tail.find("<string>")?;
    let after_open = &tail[open + "<string>".len()..];
    let close = after_open.find("</string>")?;
    Some(after_open[..close].trim().to_string())
}

/// Ask the `goose` CLI (if any) for its version. Returns `None` if the binary
/// is missing or doesn't reply cleanly.
async fn lire_version_cli() -> Option<String> {
    let out = Command::new("goose").arg("--version").output().await.ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod tests_chemins {
    use super::*;

    #[test]
    fn macos() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![PathBuf::from("/Users/alice/.config/goose/config.yaml")]
        );
        assert_eq!(
            chemins_profiles_candidats(&ctx),
            vec![PathBuf::from("/Users/alice/.config/goose/profiles.yaml")]
        );
    }

    #[test]
    fn windows_appdata_block_puis_fallback() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![
                PathBuf::from("C:/Users/alice/AppData/Roaming/Block/goose/config/config.yaml"),
                PathBuf::from("C:/Users/alice/.config/goose/config.yaml"),
            ]
        );
    }

    #[test]
    fn linux_xdg_puis_config() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob")
            .avec_xdg_config_home("/home/bob/xdg");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![
                PathBuf::from("/home/bob/xdg/goose/config.yaml"),
                PathBuf::from("/home/bob/.config/goose/config.yaml"),
            ]
        );
    }
}
