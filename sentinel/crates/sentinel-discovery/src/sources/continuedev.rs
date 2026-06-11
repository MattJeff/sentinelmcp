//! Continue.dev MCP discovery source.
//!
//! Continue keeps its global configuration under `~/.continue/`. The newer
//! versions ship a YAML file at `~/.continue/config.yaml`; older installs use
//! `~/.continue/config.json`. Both files share the same `mcpServers` shape
//! (a list of objects, not a map like Claude Desktop / Cursor):
//!
//! ```yaml
//! mcpServers:
//!   - name: github
//!     command: npx
//!     args: ["-y", "@modelcontextprotocol/server-github"]
//!     env: { GITHUB_TOKEN: "..." }
//!   - name: filesystem
//!     command: npx
//!     args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//! ```
//!
//! For SSE / HTTP variants the entry carries a `url` instead of a `command`.
//!
//! Per-workspace `<project>/.continue/config.yaml` files are out of scope for
//! v1 — we only inspect the global config.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::ContexteOs;
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_yaml::Value as YamlValue;
use std::path::{Path, PathBuf};

pub struct SourceContinuedev;

#[async_trait]
impl SourceClient for SourceContinuedev {
    fn id(&self) -> &'static str { "continuedev" }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let home = match dirs::home_dir() {
            Some(h) => h,
            None => return vec![],
        };
        detecter_avec_home(&home)
    }
}

/// Chemins candidats des configs Continue — identiques sur les trois OS
/// (`~/.continue/config.yaml` puis `~/.continue/config.json`,
/// `%USERPROFILE%\.continue\…` sur Windows). Fonction pure.
pub fn chemins_config_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    let dir = ctx.home.join(".continue");
    vec![dir.join("config.yaml"), dir.join("config.json")]
}

/// Pure detection helper — used by both the live source and the tests.
///
/// `home` is treated as the user's home directory (so we look at
/// `<home>/.continue/config.{yaml,json}`, same path on every OS).
pub fn detecter_avec_home(home: &Path) -> Vec<ClientDecouvert> {
    let continue_dir = home.join(".continue");
    let yaml_path = continue_dir.join("config.yaml");
    let json_path = continue_dir.join("config.json");

    let yaml_present = yaml_path.exists();
    let json_present = json_path.exists();

    if !yaml_present && !json_present {
        return vec![];
    }

    let mut decouvert = ClientDecouvert::nouveau(ClientKind::Continue);

    // Prefer YAML if both exist (it is the newer format), but record both.
    if yaml_present {
        traiter_yaml(&yaml_path, &mut decouvert);
    }
    if json_present {
        traiter_json(&json_path, &mut decouvert);
    }

    vec![decouvert]
}

fn traiter_yaml(path: &Path, decouvert: &mut ClientDecouvert) {
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
        source_id: "continuedev".to_string(),
        vu_a: Utc::now(),
    });

    extraire_serveurs_yaml(&yaml, decouvert);
}

fn traiter_json(path: &Path, decouvert: &mut ClientDecouvert) {
    let brut = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            decouvert
                .notes
                .push(format!("failed to read {}: {}", path.display(), e));
            return;
        }
    };

    // Parse JSON via serde_yaml — YAML is a superset of JSON, so this keeps
    // the downstream extraction logic identical and avoids carrying two
    // independent code paths for the same shape.
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
        source_id: "continuedev".to_string(),
        vu_a: Utc::now(),
    });

    extraire_serveurs_yaml(&yaml, decouvert);
}

fn extraire_serveurs_yaml(yaml: &YamlValue, decouvert: &mut ClientDecouvert) {
    let bloc = yaml.get("mcpServers");
    match bloc {
        Some(YamlValue::Sequence(seq)) => {
            for entree in seq {
                if let Some(s) = parser_entree(entree) {
                    decouvert.serveurs.push(s);
                }
            }
            if decouvert.serveurs.is_empty() {
                decouvert
                    .notes
                    .push("mcpServers list is empty".to_string());
            }
        }
        Some(YamlValue::Mapping(map)) => {
            // Tolerate the map-shaped variant (à la Claude Desktop) just in
            // case a user copy-pasted from another client.
            for (k, v) in map {
                if let Some(nom) = k.as_str() {
                    if let Some(s) = parser_entree_objet(nom, v) {
                        decouvert.serveurs.push(s);
                    }
                }
            }
            if decouvert.serveurs.is_empty() {
                decouvert
                    .notes
                    .push("mcpServers map is empty".to_string());
            }
        }
        Some(_) => {
            decouvert
                .notes
                .push("mcpServers is neither a list nor a map".to_string());
        }
        None => {
            decouvert.notes.push("no MCP block declared".to_string());
        }
    }
}

/// Parse one element of the `mcpServers` *sequence* (list form, the one
/// Continue actually uses). The element should be a mapping with at least a
/// `name` key.
fn parser_entree(entree: &YamlValue) -> Option<ServeurMcpDeclare> {
    let map = entree.as_mapping()?;
    let nom = map
        .get(YamlValue::String("name".to_string()))
        .and_then(|v| v.as_str())?
        .to_string();
    parser_entree_objet(&nom, entree)
}

/// Shared body once we have a name and a mapping-shaped value.
fn parser_entree_objet(nom: &str, value: &YamlValue) -> Option<ServeurMcpDeclare> {
    let map = value.as_mapping()?;

    let disabled = map
        .get(YamlValue::String("disabled".to_string()))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Remote (HTTP / SSE) entry.
    if let Some(url) = map
        .get(YamlValue::String("url".to_string()))
        .and_then(|v| v.as_str())
    {
        let transport = map
            .get(YamlValue::String("type".to_string()))
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
    let commande = map
        .get(YamlValue::String("command".to_string()))
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
        .get(YamlValue::String("env".to_string()))
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

// Allow downstream callers (and tests) that previously imported a non-existent
// path-based helper to still find one.
#[allow(dead_code)]
pub fn detecter_avec_chemins(home: &Path, _app: &PathBuf) -> Vec<ClientDecouvert> {
    detecter_avec_home(home)
}

#[cfg(test)]
mod tests_chemins {
    use super::*;
    use crate::sources::os_paths::OsCible;

    #[test]
    fn config_identique_sur_tous_les_os() {
        for os in OsCible::TOUS {
            let ctx = ContexteOs::nouveau(os, "/home/user");
            assert_eq!(
                chemins_config_candidats(&ctx),
                vec![
                    PathBuf::from("/home/user/.continue/config.yaml"),
                    PathBuf::from("/home/user/.continue/config.json"),
                ],
                "os = {os:?}"
            );
        }
    }
}
