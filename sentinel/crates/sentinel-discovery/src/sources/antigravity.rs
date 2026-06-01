//! Detection source for **Google Antigravity** — Google's AI coding agent
//! released in late 2025 / early 2026.
//!
//! Antigravity is an Electron app built on top of a VS Code fork, so its
//! configuration layout follows the VS Code conventions but with its own
//! `Application Support` directory. As of the time of writing the exact
//! schema is not yet publicly documented; we therefore probe for **both**
//! configuration shapes seen in the ecosystem:
//!
//! * `mcp.servers` — the VS Code Insiders convention (settings.json key);
//! * `mcpServers` — the Anthropic/Claude Desktop convention.
//!
//! We look at:
//!
//! 1. `<home>/Library/Application Support/Antigravity/User/settings.json`
//!    (VS-Code-derived layout). JSONC, so we strip comments first.
//! 2. `<home>/.antigravity/mcp.json` — a plausible standalone MCP file
//!    (mirrors how Cursor/Windsurf ship their dedicated MCP config).
//! 3. `<home>/.antigravity/extensions/` — flagged in meta if present.
//! 4. App bundle at `/Applications/Antigravity.app` or
//!    `/Applications/Google Antigravity.app`. Version is read from
//!    `Contents/Info.plist`.
//!
//! ASSUMPTION: the precise key names (`mcp.servers` vs `mcpServers`) for
//! Antigravity are not officially confirmed yet, so this source recognises
//! both. If/when Google publishes a stable schema, narrow the parser.

use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::SourceClient;
use crate::sources::vscode::strip_jsonc_comments;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub struct SourceAntigravity;

#[async_trait]
impl SourceClient for SourceAntigravity {
    fn id(&self) -> &'static str { "antigravity" }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return vec![],
        };
        let apps = vec![
            PathBuf::from("/Applications/Antigravity.app"),
            PathBuf::from("/Applications/Google Antigravity.app"),
        ];
        let app = apps.into_iter().find(|p| p.exists());
        detecter_avec_chemins(&home, app.as_deref())
    }
}

/// Pure detection helper — used by both the live source and the tests.
///
/// `home` is treated as the user's home directory and `app` is the optional
/// absolute path of the `Antigravity.app` bundle.
pub fn detecter_avec_chemins(home: &Path, app: Option<&Path>) -> Vec<ClientDecouvert> {
    let settings_path = home
        .join("Library")
        .join("Application Support")
        .join("Antigravity")
        .join("User")
        .join("settings.json");
    let mcp_json_path = home.join(".antigravity").join("mcp.json");
    let extensions_dir = home.join(".antigravity").join("extensions");

    let settings_present = settings_path.exists();
    let mcp_json_present = mcp_json_path.exists();
    let extensions_present = extensions_dir.exists();
    let app_present = app.map(|p| p.exists()).unwrap_or(false);

    if !settings_present
        && !mcp_json_present
        && !extensions_present
        && !app_present
    {
        return vec![];
    }

    let mut decouvert = ClientDecouvert::nouveau(ClientKind::Antigravity);

    // -- App bundle (binary + version) --------------------------------------
    if let Some(app_path) = app {
        if app_path.exists() {
            let candidats = [
                app_path.join("Contents/MacOS/Antigravity"),
                app_path.join("Contents/MacOS/Electron"),
                app_path.join("Contents/MacOS/Code"),
            ];
            decouvert.binary_path = candidats
                .iter()
                .find(|p| p.exists())
                .cloned()
                .or_else(|| Some(app_path.to_path_buf()));
            if let Some(v) = lire_version_info_plist(&app_path.join("Contents").join("Info.plist"))
            {
                decouvert.version = Some(v);
            }
        }
    }

    let mut found_any_block = false;

    // -- settings.json (JSONC, VS Code derived) -----------------------------
    if settings_present {
        parser_fichier_jsonc(&settings_path, &mut decouvert, &mut found_any_block);
    }

    // -- ~/.antigravity/mcp.json (plain JSON, Anthropic-shape) --------------
    if mcp_json_present {
        parser_fichier_jsonc(&mcp_json_path, &mut decouvert, &mut found_any_block);
    }

    // If we know the app/config is here but no MCP block was declared at
    // all, surface a friendly note for the UI.
    if (app_present || settings_present || mcp_json_present) && !found_any_block {
        decouvert.notes.push("no MCP block".to_string());
    }

    // -- Extensions ---------------------------------------------------------
    if extensions_present {
        let mut trouvees: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&extensions_dir) {
            for ent in rd.flatten() {
                let nom = ent.file_name().to_string_lossy().to_string();
                if !nom.starts_with('.') {
                    trouvees.push(nom);
                }
            }
        }
        if !trouvees.is_empty() {
            decouvert
                .meta
                .insert("antigravity_extensions".to_string(), trouvees.join(","));
        }
    }

    vec![decouvert]
}

/// Parse a JSONC file and merge any MCP servers it declares into `decouvert`.
/// Recognises both `mcp.servers` (VS Code shape) and `mcpServers` (Anthropic
/// shape) at the top level.
fn parser_fichier_jsonc(
    path: &Path,
    decouvert: &mut ClientDecouvert,
    found_any_block: &mut bool,
) {
    let brut = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            decouvert
                .notes
                .push(format!("failed to read {}: {}", path.display(), e));
            return;
        }
    };
    let nettoye = strip_jsonc_comments(&brut);
    let json: Value = match serde_json::from_str(&nettoye) {
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
        source_id: "antigravity".to_string(),
        vu_a: Utc::now(),
    });

    // Try both known keys. We use whichever (or both) are present.
    let mut local_block_found = false;
    let mut local_servers_added = 0usize;

    for cle in ["mcp.servers", "mcpServers"] {
        match json.get(cle) {
            Some(Value::Object(map)) => {
                local_block_found = true;
                for (nom, entree) in map.iter() {
                    if let Some(s) = parser_entree(nom, entree) {
                        decouvert.serveurs.push(s);
                        local_servers_added += 1;
                    }
                }
            }
            Some(_) => {
                decouvert
                    .notes
                    .push(format!("{} in {} is not an object", cle, path.display()));
            }
            None => {}
        }
    }

    if local_block_found {
        *found_any_block = true;
        if local_servers_added == 0 {
            decouvert
                .notes
                .push(format!("MCP block in {} is empty", path.display()));
        }
    }
}

/// Convert one MCP server entry into a `ServeurMcpDeclare`.
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
            .map(String::from)
            .unwrap_or_else(|| "sse".to_string());
        return Some(ServeurMcpDeclare {
            nom: nom.to_string(),
            transport,
            commande: None,
            args: vec![],
            env_keys: vec![],
            url: Some(url.to_string()),
            disabled,
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
    })
}

/// Best-effort extraction of `CFBundleShortVersionString` from a macOS
/// `Info.plist`.
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
