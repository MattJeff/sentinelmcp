//! Detection source for **OpenAI Codex CLI** (the official OpenAI coding
//! agent, installed as `@openai/codex` from npm or via the `codex` Homebrew
//! formula).
//!
//! Codex stores its configuration on macOS as TOML:
//!   * primary: `~/.codex/config.toml`
//!   * alternate: `~/.config/openai-codex/config.toml`
//!
//! MCP servers are declared either as table-style entries:
//! ```toml
//! [mcp.servers.github]
//! command = "npx"
//! args = ["-y", "@modelcontextprotocol/server-github"]
//! env = { GITHUB_TOKEN = "..." }
//! ```
//! …or as an array-of-tables with explicit `name` field:
//! ```toml
//! [[mcp.servers]]
//! name = "github"
//! command = "npx"
//! args = ["-y", "@modelcontextprotocol/server-github"]
//! ```
//!
//! The session file `~/.codex/auth.json` is intentionally NOT read (it holds
//! the user's OAuth tokens); we only check for its existence as a "Codex is
//! configured" signal.

use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use toml::Value as TomlValue;

pub struct SourceCodex;

#[async_trait]
impl SourceClient for SourceCodex {
    fn id(&self) -> &'static str {
        "codex"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return vec![],
        };
        detecter_avec_home(&home).await
    }
}

/// Core detection routine, parameterised by `$HOME` so tests can pass a fake
/// root that doesn't depend on the real user's environment.
pub async fn detecter_avec_home(home: &Path) -> Vec<ClientDecouvert> {
    let mut client = ClientDecouvert::nouveau(ClientKind::Codex);

    // -- 1. Locate the `codex` binary ---------------------------------------
    if let Some((path, version)) = localiser_binaire(home).await {
        client.binary_path = Some(path);
        client.version = version;
    }

    // -- 2. Auth presence signal (we do NOT read its contents) ---------------
    let auth = home.join(".codex").join("auth.json");
    if auth.is_file() {
        client
            .meta
            .insert("auth_present".to_string(), "true".to_string());
    }

    // -- 3. Primary config: ~/.codex/config.toml ----------------------------
    let primary = home.join(".codex").join("config.toml");
    parser_config(&primary, &mut client);

    // -- 4. Alt config: ~/.config/openai-codex/config.toml ------------------
    let alt = home
        .join(".config")
        .join("openai-codex")
        .join("config.toml");
    parser_config(&alt, &mut client);

    // -- 5. Decide whether we actually found anything -----------------------
    // We also keep the client around if a config file exists on disk but
    // failed to parse — otherwise the "parse error" note would be silently
    // dropped and the user would have no way to see Codex is mis-configured.
    let config_file_exists = primary.is_file() || alt.is_file();
    let found_something = client.binary_path.is_some()
        || !client.configs.is_empty()
        || client.meta.contains_key("auth_present")
        || config_file_exists;
    if !found_something {
        return vec![];
    }

    if client.serveurs.is_empty() && !client.configs.is_empty() {
        client.notes.push("no MCP servers declared".to_string());
    }
    if client.configs.is_empty() && client.binary_path.is_some() {
        client.notes.push("binary present but no config file found".to_string());
    }

    vec![client]
}

/// Locate the `codex` executable, returning its path + `codex --version`.
async fn localiser_binaire(home: &Path) -> Option<(PathBuf, Option<String>)> {
    let mut path: Option<PathBuf> = None;

    if let Ok(out) = Command::new("which").arg("codex").output().await {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !txt.is_empty() {
                let p = PathBuf::from(&txt);
                if p.exists() {
                    path = Some(p);
                }
            }
        }
    }

    if path.is_none() {
        let candidates = [
            PathBuf::from("/opt/homebrew/bin/codex"),
            home.join(".codex").join("bin").join("codex"),
            PathBuf::from("/usr/local/bin/codex"),
        ];
        for p in candidates {
            if p.exists() {
                path = Some(p);
                break;
            }
        }
    }

    let p = path?;
    let version = Command::new(&p)
        .arg("--version")
        .output()
        .await
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            } else {
                None
            }
        });

    Some((p, version))
}

/// Parse a Codex `config.toml`, extracting any declared MCP servers.
fn parser_config(path: &Path, client: &mut ClientDecouvert) {
    if !path.is_file() {
        return;
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => {
            client
                .notes
                .push(format!("config not readable: {}", path.display()));
            return;
        }
    };

    let value: TomlValue = match toml::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            client
                .notes
                .push(format!("config parse error: {}", path.display()));
            return;
        }
    };

    client.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "codex".to_string(),
        vu_a: Utc::now(),
    });

    let mcp = match value.get("mcp") {
        Some(v) => v,
        None => return,
    };
    let servers = match mcp.get("servers") {
        Some(v) => v,
        None => return,
    };

    // Shape 1: [mcp.servers.<name>] table-style.
    if let Some(tbl) = servers.as_table() {
        for (nom, entry) in tbl {
            if let Some(s) = serveur_depuis_table(nom, entry) {
                client.serveurs.push(s);
            }
        }
        return;
    }

    // Shape 2: [[mcp.servers]] array-of-tables, each with an explicit `name`.
    if let Some(arr) = servers.as_array() {
        for entry in arr {
            let nom = entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if nom.is_empty() {
                continue;
            }
            if let Some(s) = serveur_depuis_table(&nom, entry) {
                client.serveurs.push(s);
            }
        }
    }
}

/// Map a single TOML entry into our flat server struct.
///
/// Supports stdio (`command` + optional `args`/`env`) and remote
/// (`url` + optional `type`) shapes.
fn serveur_depuis_table(nom: &str, entry: &TomlValue) -> Option<ServeurMcpDeclare> {
    let tbl = entry.as_table()?;

    let type_field = tbl.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let url = tbl.get("url").and_then(|v| v.as_str()).map(str::to_string);
    let disabled = tbl
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let env_keys: Vec<String> = tbl
        .get("env")
        .and_then(|v| v.as_table())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let commande = tbl
        .get("command")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let is_remote = matches!(type_field, "sse" | "http")
        || (url.is_some() && commande.is_none());

    if is_remote {
        return Some(ServeurMcpDeclare {
            nom: nom.to_string(),
            transport: "http".to_string(),
            commande: None,
            args: vec![],
            env_keys,
            url,
            disabled,
        });
    }

    if commande.is_none() && url.is_none() {
        return None;
    }

    let args: Vec<String> = tbl
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Some(ServeurMcpDeclare {
        nom: nom.to_string(),
        transport: "stdio".to_string(),
        commande,
        args,
        env_keys,
        url,
        disabled,
    })
}
