//! Cursor MCP discovery source.
//!
//! Cursor stores its global MCP server declarations in `~/.cursor/mcp.json`
//! using the same `{ "mcpServers": { ... } }` shape as Anthropic's Claude
//! Desktop config. Each entry can either be a stdio command (`command`,
//! `args`, `env`) or a remote endpoint (`url`, `type` = "sse" | "http").
//!
//! The app itself lives at `/Applications/Cursor.app` on macOS; we read its
//! version from `Contents/Info.plist` and surface the binary at
//! `Contents/MacOS/Cursor`.
//!
//! For v1 we only scan the global config — per-workspace `<project>/.cursor/mcp.json`
//! is intentionally out of scope.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct SourceCursor;

#[async_trait]
impl SourceClient for SourceCursor {
    fn id(&self) -> &'static str { "cursor" }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return vec![],
        };
        let app = PathBuf::from("/Applications/Cursor.app");
        detecter_avec_chemins(&home, &app)
    }
}

/// Pure detection helper — used by both the live source and the tests.
///
/// `home` is treated as the user's home directory (so we look at
/// `<home>/.cursor/mcp.json`) and `app` is the absolute path of the
/// `Cursor.app` bundle to probe.
pub fn detecter_avec_chemins(home: &Path, app: &Path) -> Vec<ClientDecouvert> {
    let config_path = home.join(".cursor").join("mcp.json");
    let app_present = app.exists();
    let config_present = config_path.exists();

    if !app_present && !config_present {
        return vec![];
    }

    let mut decouvert = ClientDecouvert::nouveau(ClientKind::Cursor);

    if app_present {
        let bin = app.join("Contents").join("MacOS").join("Cursor");
        if bin.exists() {
            decouvert.binary_path = Some(bin);
        } else {
            decouvert.binary_path = Some(app.to_path_buf());
        }
        if let Some(v) = lire_version_info_plist(&app.join("Contents").join("Info.plist")) {
            decouvert.version = Some(v);
        }
    }

    if config_present {
        match std::fs::read_to_string(&config_path) {
            Ok(brut) => match serde_json::from_str::<Value>(&brut) {
                Ok(json) => {
                    let mcp_block = json.get("mcpServers");
                    match mcp_block {
                        Some(Value::Object(map)) => {
                            decouvert.configs.push(ConfigSource {
                                config_path: config_path.clone(),
                                source_id: "cursor".to_string(),
                                vu_a: Utc::now(),
                            });
                            for (nom, entree) in map.iter() {
                                if let Some(s) = parser_entree(nom, entree) {
                                    decouvert.serveurs.push(s);
                                }
                            }
                            if decouvert.serveurs.is_empty() {
                                decouvert.notes.push(
                                    "mcpServers block is empty".to_string(),
                                );
                            }
                        }
                        Some(_) => {
                            decouvert.configs.push(ConfigSource {
                                config_path: config_path.clone(),
                                source_id: "cursor".to_string(),
                                vu_a: Utc::now(),
                            });
                            decouvert
                                .notes
                                .push("mcpServers is not an object".to_string());
                        }
                        None => {
                            decouvert.configs.push(ConfigSource {
                                config_path: config_path.clone(),
                                source_id: "cursor".to_string(),
                                vu_a: Utc::now(),
                            });
                            decouvert
                                .notes
                                .push("no MCP block declared".to_string());
                        }
                    }
                }
                Err(e) => {
                    decouvert.notes.push(format!(
                        "failed to parse {}: {}",
                        config_path.display(),
                        e
                    ));
                }
            },
            Err(e) => {
                decouvert.notes.push(format!(
                    "failed to read {}: {}",
                    config_path.display(),
                    e
                ));
            }
        }
    } else if app_present {
        // App installed but no global MCP config file at all.
        decouvert.notes.push("no MCP block".to_string());
    }

    vec![decouvert]
}

/// Convert one entry of the `mcpServers` map into a `ServeurMcpDeclare`.
fn parser_entree(nom: &str, entree: &Value) -> Option<ServeurMcpDeclare> {
    let obj = entree.as_object()?;

    let disabled = obj
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Remote / HTTP / SSE entry.
    if let Some(url) = obj.get("url").and_then(|v| v.as_str()) {
        let transport = obj
            .get("type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "sse".to_string());
        return Some(ServeurMcpDeclare {
            nom: nom.to_string(),
            transport,
            commande: None,
            args: vec![],
            env_keys: vec![],
            url: Some(url.to_string()),
            disabled,
            scope: ScopeServeur::default(),
        });
    }

    // Stdio entry.
    let commande = obj.get("command").and_then(|v| v.as_str()).map(String::from);
    let args = obj
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let env_keys = obj
        .get("env")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect::<Vec<_>>())
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
/// `Info.plist`. We avoid pulling a full plist parser and just regex the
/// XML form Cursor (an Electron app) ships with.
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
