//! Detection source for **Visual Studio Code** and its MCP-capable extensions.
//!
//! VS Code itself does not (yet) ship MCP support in the stable channel, but
//! Insiders builds and a growing number of community extensions wire MCP
//! servers via `settings.json`. We scan:
//!
//! 1. The user `settings.json` — per OS:
//!    * macOS: `~/Library/Application Support/Code/User/settings.json`
//!    * Windows: `%APPDATA%\Code\User\settings.json`
//!    * Linux: `$XDG_CONFIG_HOME/Code/User/settings.json`
//!      (défaut `~/.config/Code/User/settings.json`)
//!    This is JSONC (JSON with `//` line comments and `/* */` block
//!    comments), so we strip comments before handing it to `serde_json`. We
//!    look for a top-level `"mcp.servers"` block (the Insiders convention)
//!    of the shape `{ name: { command, args, env } }`.
//! 2. Installed extensions at `~/.vscode/extensions/`. Each extension lives in
//!    `<publisher>.<name>-<version>/`. We flag known MCP-capable extensions
//!    (e.g. `automatalabs.copilot-mcp`, `anthropic.claude-dev`,
//!    `saoudrizwan.claude-dev`). The `continue.continue` extension is handled
//!    by the Continue source (D5), Cursor by D3.
//! 3. The app bundle itself at `/Applications/Visual Studio Code.app` (and
//!    `VSCodium.app` as a sibling distribution) for binary path + version
//!    pulled from `Contents/Info.plist`.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::{
    pousser_unique, premier_existant_ou_premier, ContexteOs, OsCible,
};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Chemins candidats du `settings.json` utilisateur selon l'OS.
/// Fonction pure : testable sur n'importe quelle machine.
pub fn chemins_settings_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    let suffixe = |racine: PathBuf| racine.join("Code").join("User").join("settings.json");
    match ctx.os {
        OsCible::MacOs => vec![suffixe(ctx.home.join("Library").join("Application Support"))],
        OsCible::Windows => vec![suffixe(ctx.dossier_appdata())],
        OsCible::Linux => {
            let mut out = vec![];
            for d in ctx.dossiers_config_linux() {
                pousser_unique(&mut out, suffixe(d));
            }
            out
        }
    }
}

pub struct SourceVscode;

#[async_trait]
impl SourceClient for SourceVscode {
    fn id(&self) -> &'static str { "vscode" }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let ctx = match ContexteOs::courant() {
            Some(c) => c,
            None => return vec![],
        };
        let apps = vec![
            PathBuf::from("/Applications/Visual Studio Code.app"),
            PathBuf::from("/Applications/VSCodium.app"),
        ];
        let app = apps.into_iter().find(|p| p.exists());
        detecter_avec_contexte(&ctx, app.as_deref())
    }
}

/// Known MCP-capable extension publisher.name identifiers we care about.
/// `continue.continue` is intentionally excluded (handled by the Continue
/// source).
const EXTENSIONS_MCP_CONNUES: &[&str] = &[
    "automatalabs.copilot-mcp",
    "anthropic.claude-dev",
    "saoudrizwan.claude-dev",
];

/// Pure detection helper — used by both the live source and the tests.
/// Resolves the settings path for the **current** OS; for per-OS tests use
/// [`detecter_avec_contexte`].
pub fn detecter_avec_chemins(home: &Path, app: Option<&Path>) -> Vec<ClientDecouvert> {
    let ctx = ContexteOs::nouveau(OsCible::courant(), home);
    detecter_avec_contexte(&ctx, app)
}

/// Variante entièrement paramétrée (OS + home injectés) — testable sur tous
/// les OS sans `cfg!`. We read the per-OS user `settings.json` plus
/// `<home>/.vscode/extensions/`; `app` is the optional absolute path of the
/// `Visual Studio Code.app` (or `VSCodium.app`) bundle (macOS only).
pub fn detecter_avec_contexte(ctx: &ContexteOs, app: Option<&Path>) -> Vec<ClientDecouvert> {
    let home = ctx.home.as_path();
    let settings_path = match premier_existant_ou_premier(&chemins_settings_candidats(ctx)) {
        Some(p) => p,
        None => return vec![],
    };
    let extensions_dir = home.join(".vscode").join("extensions");

    let settings_present = settings_path.exists();
    let extensions_present = extensions_dir.exists();
    let app_present = app.map(|p| p.exists()).unwrap_or(false);

    if !settings_present && !extensions_present && !app_present {
        return vec![];
    }

    let mut decouvert = ClientDecouvert::nouveau(ClientKind::VsCode);

    // -- App bundle (binary + version) --------------------------------------
    if let Some(app_path) = app {
        if app_path.exists() {
            // The actual binary name depends on the distribution.
            let candidats = [
                app_path.join("Contents/MacOS/Electron"),
                app_path.join("Contents/MacOS/Code"),
                app_path.join("Contents/MacOS/Code Helper"),
            ];
            decouvert.binary_path = candidats
                .iter()
                .find(|p| p.exists())
                .cloned()
                .or_else(|| Some(app_path.to_path_buf()));
            if let Some(v) = lire_version_info_plist(&app_path.join("Contents").join("Info.plist")) {
                decouvert.version = Some(v);
            }
        }
    }

    // -- settings.json (JSONC) ----------------------------------------------
    if settings_present {
        match std::fs::read_to_string(&settings_path) {
            Ok(brut) => {
                let nettoye = strip_jsonc_comments(&brut);
                match serde_json::from_str::<Value>(&nettoye) {
                    Ok(json) => {
                        decouvert.configs.push(ConfigSource {
                            config_path: settings_path.clone(),
                            source_id: "vscode".to_string(),
                            vu_a: Utc::now(),
                        });
                        match json.get("mcp.servers") {
                            Some(Value::Object(map)) => {
                                for (nom, entree) in map.iter() {
                                    if let Some(s) = parser_entree(nom, entree) {
                                        decouvert.serveurs.push(s);
                                    }
                                }
                                if decouvert.serveurs.is_empty() {
                                    decouvert.notes.push(
                                        "mcp.servers block is empty".to_string(),
                                    );
                                }
                            }
                            Some(_) => {
                                decouvert
                                    .notes
                                    .push("mcp.servers is not an object".to_string());
                            }
                            None => {
                                decouvert
                                    .notes
                                    .push("no MCP block declared".to_string());
                            }
                        }
                    }
                    Err(e) => {
                        decouvert.notes.push(format!(
                            "failed to parse {}: {}",
                            settings_path.display(),
                            e
                        ));
                    }
                }
            }
            Err(e) => {
                decouvert.notes.push(format!(
                    "failed to read {}: {}",
                    settings_path.display(),
                    e
                ));
            }
        }
    } else if app_present {
        decouvert.notes.push("no MCP block".to_string());
    }

    // -- Extensions ---------------------------------------------------------
    if extensions_present {
        let mut trouvees: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&extensions_dir) {
            for ent in rd.flatten() {
                let nom_os = ent.file_name();
                let nom = nom_os.to_string_lossy();
                // strip trailing -<version>
                let id = match nom.rfind('-') {
                    Some(idx) => &nom[..idx],
                    None => nom.as_ref(),
                };
                if EXTENSIONS_MCP_CONNUES.iter().any(|known| *known == id) {
                    let entry = format!("{}@{}", id, &nom[id.len().min(nom.len())..].trim_start_matches('-'));
                    trouvees.push(entry);
                }
            }
        }
        if !trouvees.is_empty() {
            decouvert
                .meta
                .insert("vscode_mcp_extensions".to_string(), trouvees.join(","));
            for ext in &trouvees {
                decouvert
                    .notes
                    .push(format!("MCP-capable extension installed: {}", ext));
            }
        }
    }

    vec![decouvert]
}

/// Convert one entry of the `mcp.servers` map into a `ServeurMcpDeclare`.
fn parser_entree(nom: &str, entree: &Value) -> Option<ServeurMcpDeclare> {
    let obj = entree.as_object()?;

    let disabled = obj
        .get("disabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Remote / HTTP / SSE entry (forward-compat with newer schemas).
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

/// Strip `//` line comments and `/* */` block comments from a JSONC string.
/// Comments inside string literals are preserved. Trailing commas are NOT
/// stripped — `serde_json` is lenient enough for the well-formed configs we
/// expect from a VS Code settings.json, and aggressive comma stripping is
/// risky around nested structures.
pub fn strip_jsonc_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    let mut escape = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            out.push(b as char);
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }
        // Line comment //
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment /* */
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                i = bytes.len();
            }
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
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

#[cfg(test)]
mod tests_chemins {
    use super::*;

    #[test]
    fn macos_application_support() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/alice");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![PathBuf::from(
                "/Users/alice/Library/Application Support/Code/User/settings.json"
            )]
        );
    }

    #[test]
    fn windows_appdata() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![PathBuf::from(
                "C:/Users/alice/AppData/Roaming/Code/User/settings.json"
            )]
        );
    }

    #[test]
    fn linux_xdg_puis_config() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob")
            .avec_xdg_config_home("/home/bob/xdg");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![
                PathBuf::from("/home/bob/xdg/Code/User/settings.json"),
                PathBuf::from("/home/bob/.config/Code/User/settings.json"),
            ]
        );
    }

    #[test]
    fn linux_sans_xdg() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![PathBuf::from("/home/bob/.config/Code/User/settings.json")]
        );
    }
}
