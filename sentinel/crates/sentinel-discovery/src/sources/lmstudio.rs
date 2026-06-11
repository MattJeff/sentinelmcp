//! Detection source for LM Studio (macOS / Windows / Linux).
//!
//! LM Studio (https://lmstudio.ai) is a desktop runner for local LLMs. It
//! shipped MCP support in 2025; the user-managed MCP servers live in a
//! JSON file under the user's LM Studio dotfolder. We probe two candidate
//! paths because the install layout migrated between LM Studio versions:
//!
//! * `~/.lmstudio/mcp.json`  (current location, same home-relative path on
//!   every OS — `%USERPROFILE%\.lmstudio\mcp.json` on Windows)
//! * `~/.cache/lm-studio/mcp.json`  (older macOS / Linux builds)
//!
//! The app bundle (`/Applications/LM Studio.app`) and the models cache
//! (`~/.lmstudio/models/`) are independent install indicators: either one
//! is enough for us to surface "LM Studio is installed but no MCP block".
//!
//! Config schema is assumed to mirror Anthropic's `mcpServers` shape.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::{ContexteOs, OsCible};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Primary home-relative path for LM Studio's MCP config file (all OSes).
const CONFIG_REL_PRIMARY: &str = ".lmstudio/mcp.json";
/// Legacy macOS / Linux path for LM Studio's MCP config file (older builds).
const CONFIG_REL_LEGACY: &str = ".cache/lm-studio/mcp.json";
/// Models cache directory (existence implies LM Studio has been used).
const MODELS_CACHE_REL: &str = ".lmstudio/models";

/// Chemins candidats de `mcp.json` selon l'OS, en ordre de priorité.
/// Fonction pure : testable sur n'importe quelle machine.
pub fn chemins_config_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    let mut out = vec![ctx.home.join(CONFIG_REL_PRIMARY)];
    if matches!(ctx.os, OsCible::MacOs | OsCible::Linux) {
        out.push(ctx.home.join(CONFIG_REL_LEGACY));
    }
    out
}
/// macOS path to the LM Studio app bundle.
const APP_BUNDLE: &str = "/Applications/LM Studio.app";
/// macOS path to the LM Studio main binary inside the bundle.
const APP_BINARY: &str = "/Applications/LM Studio.app/Contents/MacOS/LM Studio";
/// macOS path to the LM Studio Info.plist used for version reads.
const APP_INFO_PLIST: &str = "/Applications/LM Studio.app/Contents/Info.plist";

pub struct SourceLmstudio;

#[async_trait]
impl SourceClient for SourceLmstudio {
    fn id(&self) -> &'static str {
        "lmstudio"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let ctx = match ContexteOs::courant() {
            Some(c) => c,
            None => return vec![],
        };
        let candidats = chemins_config_candidats(&ctx);
        let models = ctx.home.join(MODELS_CACHE_REL);
        detecter_aux(
            &candidats,
            &models,
            Path::new(APP_BUNDLE),
            Path::new(APP_BINARY),
            Path::new(APP_INFO_PLIST),
        )
    }
}

/// Pure-function variant of the detection used by integration tests.
///
/// `config_candidates` is searched in order; the first file that exists is
/// used. Returns at most one `ClientDecouvert`:
/// - any of (config / app bundle / models cache) is enough to declare
///   LM Studio "present",
/// - all missing → empty Vec.
pub fn detecter_aux(
    config_candidates: &[PathBuf],
    models_cache: &Path,
    app_bundle: &Path,
    app_binary: &Path,
    info_plist: &Path,
) -> Vec<ClientDecouvert> {
    let config_path = config_candidates.iter().find(|p| p.exists()).cloned();
    let app_present = app_bundle.exists();
    let models_present = models_cache.exists();

    if config_path.is_none() && !app_present && !models_present {
        return vec![];
    }

    let mut client = ClientDecouvert::nouveau(ClientKind::LmStudio);

    // ── App binary + version ───────────────────────────────────────────────
    if app_present {
        if app_binary.exists() {
            client.binary_path = Some(app_binary.to_path_buf());
        } else {
            client.binary_path = Some(app_bundle.to_path_buf());
        }
        if let Some(v) = lire_version_plist(info_plist) {
            client.version = Some(v);
        }
    }

    // ── Models cache (indicator of real use) ───────────────────────────────
    if models_present {
        client.meta.insert(
            "models_cache".to_string(),
            models_cache.display().to_string(),
        );
    }

    // ── Config file ────────────────────────────────────────────────────────
    if let Some(cfg) = config_path {
        let now = Utc::now();
        match std::fs::read_to_string(&cfg) {
            Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                Ok(json) => {
                    client.configs.push(ConfigSource {
                        config_path: cfg.clone(),
                        source_id: "lmstudio".to_string(),
                        vu_a: now,
                    });
                    extraire_serveurs(&json, &mut client);
                }
                Err(err) => {
                    client.configs.push(ConfigSource {
                        config_path: cfg.clone(),
                        source_id: "lmstudio".to_string(),
                        vu_a: now,
                    });
                    client
                        .notes
                        .push(format!("config unreadable (parse error: {err})"));
                }
            },
            Err(err) => {
                client
                    .notes
                    .push(format!("config unreadable (io error: {err})"));
            }
        }
    } else {
        client.notes.push("no MCP block".to_string());
    }

    vec![client]
}

/// Reads `mcpServers` from a parsed JSON config and pushes one
/// `ServeurMcpDeclare` per entry into `client.serveurs`.
fn extraire_serveurs(json: &Value, client: &mut ClientDecouvert) {
    let bloc = match json.get("mcpServers") {
        Some(Value::Object(map)) => map,
        Some(_) => {
            client
                .notes
                .push("mcpServers field is not an object".to_string());
            return;
        }
        None => {
            client.notes.push("no MCP block".to_string());
            return;
        }
    };

    if bloc.is_empty() {
        client.notes.push("no MCP block".to_string());
        return;
    }

    for (nom, entry) in bloc {
        let commande = entry
            .get("command")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let args = entry
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let mut env_keys: Vec<String> = entry
            .get("env")
            .and_then(|v| v.as_object())
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        env_keys.sort();

        let url = entry
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let transport = entry
            .get("transport")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                if url.is_some() && commande.is_none() {
                    "http".to_string()
                } else {
                    "stdio".to_string()
                }
            });

        let disabled = entry
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        client.serveurs.push(ServeurMcpDeclare {
            nom: nom.clone(),
            transport,
            commande,
            args,
            env_keys,
            url,
            disabled,
            scope: ScopeServeur::default(),
        });
    }
}

/// Reads `CFBundleShortVersionString` from an Info.plist using PlistBuddy.
/// Returns `None` if the file is missing or the key cannot be read.
fn lire_version_plist(info_plist: &Path) -> Option<String> {
    if !info_plist.exists() {
        return None;
    }
    let out = Command::new("/usr/libexec/PlistBuddy")
        .arg("-c")
        .arg("Print :CFBundleShortVersionString")
        .arg(info_plist)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests_chemins {
    use super::*;

    #[test]
    fn macos_et_linux_avec_legacy() {
        for os in [OsCible::MacOs, OsCible::Linux] {
            let ctx = ContexteOs::nouveau(os, "/home/user");
            assert_eq!(
                chemins_config_candidats(&ctx),
                vec![
                    PathBuf::from("/home/user/.lmstudio/mcp.json"),
                    PathBuf::from("/home/user/.cache/lm-studio/mcp.json"),
                ],
                "os = {os:?}"
            );
        }
    }

    #[test]
    fn windows_userprofile_seul() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![PathBuf::from("C:/Users/alice/.lmstudio/mcp.json")]
        );
    }
}
