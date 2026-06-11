//! Detection source for Claude Desktop (macOS / Windows / Linux).
//!
//! Claude Desktop stores its MCP servers in a single JSON file:
//!   * macOS:   `~/Library/Application Support/Claude/claude_desktop_config.json`
//!   * Windows: `%APPDATA%\Claude\claude_desktop_config.json`
//!   * Linux:   `$XDG_CONFIG_HOME/Claude/claude_desktop_config.json`
//!     (défaut `~/.config/Claude/…`, builds communautaires)
//!
//! This source parses that file and also tries to pick up the installed app
//! version from `/Applications/Claude.app/Contents/Info.plist` (macOS only)
//! so the UI can show "Claude Desktop X.Y.Z" alongside its declared MCP
//! servers.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::{premier_existant_ou_premier, ContexteOs, OsCible};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Default macOS path to the Claude Desktop app bundle.
const APP_BUNDLE: &str = "/Applications/Claude.app";
/// Default macOS path to the Claude Desktop main binary inside the bundle.
const APP_BINARY: &str = "/Applications/Claude.app/Contents/MacOS/Claude";
/// Default macOS path to the Claude Desktop Info.plist used for version reads.
const APP_INFO_PLIST: &str = "/Applications/Claude.app/Contents/Info.plist";

/// Chemins candidats du fichier `claude_desktop_config.json` selon l'OS.
/// Fonction pure : testable sur n'importe quelle machine.
pub fn chemins_config_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    match ctx.os {
        OsCible::MacOs => vec![ctx
            .home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json")],
        OsCible::Windows => vec![ctx
            .dossier_appdata()
            .join("Claude")
            .join("claude_desktop_config.json")],
        OsCible::Linux => ctx
            .dossiers_config_linux()
            .into_iter()
            .map(|d| d.join("Claude").join("claude_desktop_config.json"))
            .collect(),
    }
}

pub struct SourceClaudeDesktop;

#[async_trait]
impl SourceClient for SourceClaudeDesktop {
    fn id(&self) -> &'static str {
        "claude-desktop"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let ctx = match ContexteOs::courant() {
            Some(c) => c,
            None => return vec![],
        };
        let config_path = match premier_existant_ou_premier(&chemins_config_candidats(&ctx)) {
            Some(p) => p,
            None => return vec![],
        };
        detecter_aux(
            &config_path,
            Path::new(APP_BUNDLE),
            Path::new(APP_BINARY),
            Path::new(APP_INFO_PLIST),
        )
    }
}

/// Pure-function variant of the detection used by integration tests.
///
/// Returns at most one `ClientDecouvert`:
/// - a config file that we can read (even malformed) counts as "found",
/// - the presence of the app bundle alone also counts as "found",
/// - everything missing → empty Vec.
pub fn detecter_aux(
    config_path: &Path,
    app_bundle: &Path,
    app_binary: &Path,
    info_plist: &Path,
) -> Vec<ClientDecouvert> {
    let config_present = config_path.exists();
    let app_present = app_bundle.exists();

    if !config_present && !app_present {
        return vec![];
    }

    let mut client = ClientDecouvert::nouveau(ClientKind::ClaudeDesktop);

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

    // ── Config file ────────────────────────────────────────────────────────
    if config_present {
        let now = Utc::now();
        match std::fs::read_to_string(config_path) {
            Ok(raw) => match serde_json::from_str::<Value>(&raw) {
                Ok(json) => {
                    client.configs.push(ConfigSource {
                        config_path: config_path.to_path_buf(),
                        source_id: "claude-desktop".to_string(),
                        vu_a: now,
                    });
                    extraire_serveurs(&json, &mut client);
                }
                Err(err) => {
                    client.configs.push(ConfigSource {
                        config_path: config_path.to_path_buf(),
                        source_id: "claude-desktop".to_string(),
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
        client
            .notes
            .push("no claude_desktop_config.json on disk".to_string());
    }

    vec![client]
}

/// Extrait les serveurs MCP d'un fichier de configuration Claude.
///
/// Lit deux emplacements et applique la **dédup user/project** : si
/// un même nom apparaît au top-level (`mcpServers`) et dans un projet
/// (`projects.<chemin>.mcpServers`), seule la version projet est
/// conservée car plus spécifique.
///
/// 1. `json.mcpServers`            → scope = `User`
/// 2. `json.projects.<path>.mcpServers` → scope = `Project { path }`
fn extraire_serveurs(json: &Value, client: &mut ClientDecouvert) {
    // ── 1. Top-level (scope User) ──────────────────────────────────────────
    let bloc_user = json.get("mcpServers");
    let user_present = matches!(bloc_user, Some(Value::Object(_)));

    let mut compteur_user = 0usize;
    if let Some(Value::Object(map)) = bloc_user {
        for (nom, entry) in map {
            if let Some(s) = extraire_un_serveur(nom, entry, ScopeServeur::User) {
                ajouter_avec_dedup(client, s);
                compteur_user += 1;
            }
        }
    } else if let Some(_other) = bloc_user {
        client
            .notes
            .push("mcpServers field is not an object".to_string());
    }

    // ── 2. Per-project (scope Project { path }) ────────────────────────────
    let mut compteur_project = 0usize;
    if let Some(Value::Object(projects)) = json.get("projects") {
        for (chemin, project_obj) in projects {
            if let Some(Value::Object(servers)) = project_obj.get("mcpServers") {
                for (nom, entry) in servers {
                    let scope = ScopeServeur::Project {
                        path: chemin.clone(),
                    };
                    if let Some(s) = extraire_un_serveur(nom, entry, scope) {
                        ajouter_avec_dedup(client, s);
                        compteur_project += 1;
                    }
                }
            }
        }
    }

    // ── 3. Notes de couverture ─────────────────────────────────────────────
    // Rétrocompat : on émet "no MCP block" si aucun serveur n'a été
    // extrait, peu importe que l'absence vienne du top-level ou des
    // projects. Présence d'au moins un serveur (user OU project) :
    // pas de note.
    let _ = user_present;
    if compteur_user == 0 && compteur_project == 0 {
        client.notes.push("no MCP block".to_string());
    }
}

/// Convertit une entrée JSON unique `mcpServers[<name>]` en
/// `ServeurMcpDeclare`. Factorisé pour éviter de dupliquer la logique
/// entre la passe top-level et la passe per-project.
fn extraire_un_serveur(nom: &str, entry: &Value, scope: ScopeServeur) -> Option<ServeurMcpDeclare> {
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

    Some(ServeurMcpDeclare {
        nom: nom.to_string(),
        transport,
        commande,
        args,
        env_keys,
        url,
        disabled,
        scope,
    })
}

/// Ajoute un serveur en respectant la règle de dédup user/project :
/// si un serveur du même nom existe déjà avec scope `User` et qu'on
/// tente d'ajouter le même nom avec un scope `Project`, on remplace
/// l'entrée user (la déclaration projet est plus spécifique). Dans
/// l'autre sens (project déjà présent, user en entrée), on ignore
/// l'entrée user.
fn ajouter_avec_dedup(client: &mut ClientDecouvert, s: ServeurMcpDeclare) {
    if let Some(pos) = client.serveurs.iter().position(|x| x.nom == s.nom) {
        let existant_scope = &client.serveurs[pos].scope;
        match (existant_scope, &s.scope) {
            // Existant User, entrant Project → on remplace.
            (ScopeServeur::User, ScopeServeur::Project { .. }) => {
                client.serveurs[pos] = s;
            }
            // Existant Project, entrant User → on ignore (project gagne).
            (ScopeServeur::Project { .. }, ScopeServeur::User) => {}
            // Sinon (même scope, ou deux projects différents) : pousser
            // pour permettre la coexistence des projets entre eux.
            _ => {
                if existant_scope == &s.scope {
                    // Doublon strict (même scope, même nom) : on remplace
                    // pour garantir l'idempotence des passes successives.
                    client.serveurs[pos] = s;
                } else {
                    client.serveurs.push(s);
                }
            }
        }
    } else {
        client.serveurs.push(s);
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
    fn macos() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![PathBuf::from(
                "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json"
            )]
        );
    }

    #[test]
    fn windows_appdata() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![PathBuf::from(
                "C:/Users/alice/AppData/Roaming/Claude/claude_desktop_config.json"
            )]
        );
    }

    #[test]
    fn linux_xdg_puis_config() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob")
            .avec_xdg_config_home("/home/bob/xdg");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![
                PathBuf::from("/home/bob/xdg/Claude/claude_desktop_config.json"),
                PathBuf::from("/home/bob/.config/Claude/claude_desktop_config.json"),
            ]
        );
    }

    #[test]
    fn linux_sans_xdg() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob");
        assert_eq!(
            chemins_config_candidats(&ctx),
            vec![PathBuf::from(
                "/home/bob/.config/Claude/claude_desktop_config.json"
            )]
        );
    }
}
