//! Detection source for **Claude Code CLI** (Anthropic's official terminal coding agent).
//!
//! Claude Code stores its primary configuration in `~/.claude.json` (a single
//! large JSON file with a top-level `mcpServers` key — same shape as Claude
//! Desktop). The same home-relative path applies on Windows
//! (`%USERPROFILE%\.claude.json`) and Linux. It also supports:
//!   * an alternate user-level location: `~/.config/claude/mcp.json`
//!     (macOS / Linux, `$XDG_CONFIG_HOME` honoré sur Linux)
//!   * per-project `.mcp.json` files (merged at runtime when you open Claude
//!     Code inside that directory).
//!
//! This source probes all of the above plus tries to locate the `claude`
//! binary (via `which`, plus the standard install paths) and capture its
//! `--version` output.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::{pousser_unique, ContexteOs, OsCible};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::process::Command;

pub struct SourceClaudeCodeCli;

#[async_trait]
impl SourceClient for SourceClaudeCodeCli {
    fn id(&self) -> &'static str {
        "claude-code-cli"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let ctx = match ContexteOs::courant() {
            Some(c) => c,
            None => return vec![],
        };
        detecter_avec_contexte(&ctx).await
    }
}

/// Chemins candidats des configs globales selon l'OS. Fonction pure.
///
/// * Tous OS : `<home>/.claude.json` (primaire)
/// * macOS  : + `~/.config/claude/mcp.json`
/// * Linux  : + `$XDG_CONFIG_HOME/claude/mcp.json` (défaut `~/.config/…`)
/// * Windows: `%USERPROFILE%\.claude.json` uniquement
pub fn chemins_config_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    let mut out = vec![ctx.home.join(".claude.json")];
    match ctx.os {
        OsCible::MacOs => {
            out.push(ctx.home.join(".config").join("claude").join("mcp.json"));
        }
        OsCible::Linux => {
            for d in ctx.dossiers_config_linux() {
                pousser_unique(&mut out, d.join("claude").join("mcp.json"));
            }
        }
        OsCible::Windows => {}
    }
    out
}

/// Core detection routine that is parameterised by `$HOME` so tests can pass a
/// synthetic root. Uses the current machine's OS for the candidate paths.
pub async fn detecter_avec_home(home: &Path) -> Vec<ClientDecouvert> {
    let ctx = ContexteOs::nouveau(OsCible::courant(), home);
    detecter_avec_contexte(&ctx).await
}

/// Variante entièrement paramétrée (OS + home injectés) — testable sur tous
/// les OS sans `cfg!`.
pub async fn detecter_avec_contexte(ctx: &ContexteOs) -> Vec<ClientDecouvert> {
    let home = ctx.home.as_path();
    let mut client = ClientDecouvert::nouveau(ClientKind::ClaudeCodeCli);

    // -- 1. Locate the `claude` binary ---------------------------------------
    if let Some((path, version)) = localiser_binaire().await {
        client.binary_path = Some(path);
        client.version = version;
    }

    // -- 2./3. Global configs (primary + per-OS alternates) ------------------
    for cfg in chemins_config_candidats(ctx) {
        parser_config_globale(&cfg, &mut client);
    }

    // -- 4. Per-project .mcp.json files -------------------------------------
    // v1 scope: ~/.mcp.json + any ~/<dir>/.mcp.json one level deep.
    let root_project = home.join(".mcp.json");
    parser_project_mcp(&root_project, &mut client);

    if let Ok(mut rd) = tokio::fs::read_dir(home).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let p = entry.path();
            if p.is_dir() {
                let candidate = p.join(".mcp.json");
                if candidate.is_file() {
                    parser_project_mcp(&candidate, &mut client);
                }
            }
        }
    }

    // -- 5. Decide whether we actually found anything ------------------------
    let found_something = client.binary_path.is_some() || !client.configs.is_empty();
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

/// Locate the `claude` executable. Returns its path + `claude --version`.
async fn localiser_binaire() -> Option<(PathBuf, Option<String>)> {
    // Try `which claude` first.
    let mut path: Option<PathBuf> = None;
    if let Ok(out) = Command::new("which").arg("claude").output().await {
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
        for candidate in [
            "/opt/homebrew/bin/claude",
            "/usr/local/bin/claude",
        ] {
            let p = PathBuf::from(candidate);
            if p.exists() {
                path = Some(p);
                break;
            }
        }
        if path.is_none() {
            if let Some(home) = dirs::home_dir() {
                let p = home.join(".claude").join("local").join("claude");
                if p.exists() {
                    path = Some(p);
                }
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
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            } else {
                None
            }
        });

    Some((p, version))
}

/// Parse a global Claude config (`~/.claude.json` or `~/.config/claude/mcp.json`)
/// looking for **two** MCP locations :
///   1. `mcpServers` au top-level   → `ScopeServeur::User`
///   2. `projects.<chemin>.mcpServers` → `ScopeServeur::Project { path }`
///
/// La dédup user/project est appliquée à l'insertion : si un même nom
/// apparaît dans les deux passes, seule la version projet (plus
/// spécifique) survit.
fn parser_config_globale(path: &Path, client: &mut ClientDecouvert) {
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
    let value: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => {
            client
                .notes
                .push(format!("config not parseable: {}", path.display()));
            return;
        }
    };

    client.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "claude-code-cli".to_string(),
        vu_a: Utc::now(),
    });

    // ── 1. mcpServers top-level (scope = User) ─────────────────────────────
    if let Some(map) = value.get("mcpServers").and_then(|v| v.as_object()) {
        for (nom, entry) in map {
            if let Some(s) = serveur_depuis_entree(nom, entry, ScopeServeur::User) {
                ajouter_avec_dedup(client, s);
            }
        }
    }

    // ── 2. projects.<chemin>.mcpServers (scope = Project { path }) ─────────
    if let Some(projects) = value.get("projects").and_then(|v| v.as_object()) {
        for (chemin, project_obj) in projects {
            if let Some(servers) = project_obj.get("mcpServers").and_then(|v| v.as_object()) {
                for (nom, entry) in servers {
                    let scope = ScopeServeur::Project {
                        path: chemin.clone(),
                    };
                    if let Some(s) = serveur_depuis_entree(nom, entry, scope) {
                        ajouter_avec_dedup(client, s);
                    }
                }
            }
        }
    }
}

/// Parse a per-project `.mcp.json` file. These have the shape:
/// `{ "mcpServers": { … } }` (top-level wrapper) OR just `{ <name>: {…} }`.
///
/// Le scope appliqué est `Project { path = <dossier parent du fichier> }`
/// car ce fichier est intrinsèquement lié à un dépôt particulier (Claude
/// Code le merge à l'ouverture du répertoire correspondant).
fn parser_project_mcp(path: &Path, client: &mut ClientDecouvert) {
    if !path.is_file() {
        return;
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let value: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return,
    };

    client.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "claude-code-cli".to_string(),
        vu_a: Utc::now(),
    });

    let project_dir = path
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let scope = ScopeServeur::Project { path: project_dir };

    // Prefer wrapped form.
    let map_opt = value
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .or_else(|| value.as_object());

    if let Some(map) = map_opt {
        for (nom, entry) in map {
            // Skip non-server top-level keys when the file is unwrapped.
            if !entry.is_object() {
                continue;
            }
            if let Some(s) = serveur_depuis_entree(nom, entry, scope.clone()) {
                ajouter_avec_dedup(client, s);
            }
        }
    }
}

/// Ajoute un serveur en respectant la règle de dédup user/project :
/// si un même nom existe déjà avec scope `User` et qu'on insère
/// le même avec scope `Project`, on **remplace** ; dans l'autre
/// sens (project déjà là, entrée user) on ignore. Sinon (mêmes
/// scopes ou deux projets différents), on remplace pour rester
/// idempotent, sauf si les deux scopes Project diffèrent par leur
/// path (auquel cas on autorise la coexistence).
fn ajouter_avec_dedup(client: &mut ClientDecouvert, s: ServeurMcpDeclare) {
    if let Some(pos) = client
        .serveurs
        .iter()
        .position(|x| x.nom == s.nom && x.scope == s.scope)
    {
        // Doublon strict (même nom + même scope) : remplacement idempotent.
        client.serveurs[pos] = s;
        return;
    }
    // Sinon, chercher un autre scope sur le même nom.
    if let Some(pos) = client.serveurs.iter().position(|x| x.nom == s.nom) {
        let existant = &client.serveurs[pos].scope;
        match (existant, &s.scope) {
            (ScopeServeur::User, ScopeServeur::Project { .. }) => {
                // Project gagne, remplace l'entrée user.
                client.serveurs[pos] = s;
            }
            (ScopeServeur::Project { .. }, ScopeServeur::User) => {
                // L'existant project est plus spécifique, ignore le user.
            }
            _ => {
                // Deux projets différents : on autorise la coexistence
                // (un même nom peut être déclaré dans plusieurs repos).
                client.serveurs.push(s);
            }
        }
    } else {
        client.serveurs.push(s);
    }
}

/// Map a single `mcpServers[<name>]` JSON entry to our flat struct.
///
/// Handles three shapes:
///   * stdio: `{ "command": "npx", "args": [...], "env": {...} }`
///   * sse:   `{ "type": "sse",  "url": "https://…" }`
///   * http:  `{ "type": "http", "url": "https://…" }`
fn serveur_depuis_entree(
    nom: &str,
    entry: &Value,
    scope: ScopeServeur,
) -> Option<ServeurMcpDeclare> {
    let obj = entry.as_object()?;

    let type_field = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let url = obj.get("url").and_then(|v| v.as_str()).map(str::to_string);
    let disabled = obj
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let env_keys: Vec<String> = obj
        .get("env")
        .and_then(|v| v.as_object())
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let is_remote = matches!(type_field, "sse" | "http") || (url.is_some() && obj.get("command").is_none());

    if is_remote {
        return Some(ServeurMcpDeclare {
            nom: nom.to_string(),
            transport: "http".to_string(),
            commande: None,
            args: vec![],
            env_keys,
            url,
            disabled,
            scope,
        });
    }

    // Stdio path. If neither command nor url present, skip.
    let commande = obj
        .get("command")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if commande.is_none() && url.is_none() {
        return None;
    }
    let args: Vec<String> = obj
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    Some(ServeurMcpDeclare {
        nom: nom.to_string(),
        transport: "stdio".to_string(),
        commande,
        args,
        env_keys,
        url,
        disabled,
        scope,
    })
}

#[cfg(test)]
mod tests_chemins {
    use super::*;

    #[test]
    fn macos() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![
                PathBuf::from("/Users/alice/.claude.json"),
                PathBuf::from("/Users/alice/.config/claude/mcp.json"),
            ]
        );
    }

    #[test]
    fn windows_userprofile_seul() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![PathBuf::from("C:/Users/alice/.claude.json")]
        );
    }

    #[test]
    fn linux_avec_xdg() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob")
            .avec_xdg_config_home("/home/bob/xdg");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![
                PathBuf::from("/home/bob/.claude.json"),
                PathBuf::from("/home/bob/xdg/claude/mcp.json"),
                PathBuf::from("/home/bob/.config/claude/mcp.json"),
            ]
        );
    }
}
