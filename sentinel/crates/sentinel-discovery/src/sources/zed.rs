//! Zed editor discovery source.
//!
//! Zed stores its user settings as JSONC at one of:
//!   * macOS: `~/.config/zed/settings.json` (preferred, newer installs)
//!     puis `~/Library/Application Support/Zed/settings.json` (legacy)
//!   * Linux: `$XDG_CONFIG_HOME/zed/settings.json` (défaut `~/.config/zed/…`)
//!   * Windows: `%APPDATA%\Zed\settings.json`
//!
//! MCP servers in Zed are called "context servers" and live under the
//! `context_servers` top-level key. Zed also exposes a parallel notion of
//! extension-declared MCP servers under the `extensions` key — those entries
//! don't carry a launch command directly (the extension does), so we surface
//! them with a "extension-declared" note.
//!
//! The app can be shipped as `Zed.app`, `Zed Preview.app`, or
//! `Zed Nightly.app`. Version is read from the bundle's `Info.plist`.

use sentinel_protocol::ScopeServeur;
use crate::model::{
    ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare,
};
use crate::sources::os_paths::{pousser_unique, ContexteOs, OsCible};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Chemins candidats de `settings.json` selon l'OS, en ordre de priorité.
/// Fonction pure : testable sur n'importe quelle machine.
pub fn chemins_settings_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    match ctx.os {
        OsCible::MacOs => vec![
            ctx.home.join(".config/zed/settings.json"),
            ctx.home.join("Library/Application Support/Zed/settings.json"),
        ],
        OsCible::Windows => vec![ctx.dossier_appdata().join("Zed").join("settings.json")],
        OsCible::Linux => {
            let mut out = vec![];
            for d in ctx.dossiers_config_linux() {
                pousser_unique(&mut out, d.join("zed").join("settings.json"));
            }
            out
        }
    }
}

/// Detection source for the Zed editor.
pub struct SourceZed {
    /// Home directory override (used by tests).
    home: Option<PathBuf>,
    /// `/Applications` override (used by tests).
    applications: Option<PathBuf>,
}

impl SourceZed {
    /// Build the default source (probes the real user environment).
    pub const fn new() -> Self {
        Self {
            home: None,
            applications: None,
        }
    }

    /// Builder used in tests — override the home directory.
    pub fn with_home<P: Into<PathBuf>>(mut self, home: P) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Builder used in tests — override the `/Applications` location.
    pub fn with_applications<P: Into<PathBuf>>(mut self, applications: P) -> Self {
        self.applications = Some(applications.into());
        self
    }

    fn applications_dir(&self) -> PathBuf {
        self.applications
            .clone()
            .unwrap_or_else(|| PathBuf::from("/Applications"))
    }

    /// Returns the candidate settings paths in priority order, for the OS
    /// the binary is running on. A home override (tests) ignores the real
    /// environment variables to keep the probe hermetic.
    fn settings_paths(&self) -> Vec<PathBuf> {
        let ctx = match &self.home {
            Some(h) => ContexteOs::nouveau(OsCible::courant(), h.clone()),
            None => match ContexteOs::courant() {
                Some(c) => c,
                None => return vec![],
            },
        };
        chemins_settings_candidats(&ctx)
    }

    /// Returns the candidate app bundle paths (stable, preview, nightly).
    fn app_paths(&self) -> Vec<PathBuf> {
        let apps = self.applications_dir();
        vec![
            apps.join("Zed.app"),
            apps.join("Zed Preview.app"),
            apps.join("Zed Nightly.app"),
        ]
    }
}

impl Default for SourceZed {
    fn default() -> Self {
        Self::new()
    }
}

/// JSONC -> JSON. Strips `//` line comments and `/* … */` block comments,
/// preserving strings as-is so URLs like `https://…` survive intact.
fn strip_jsonc_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escape = false;

    while i < bytes.len() {
        let c = bytes[i];

        if in_string {
            out.push(c as char);
            if escape {
                escape = false;
            } else if c == b'\\' {
                escape = true;
            } else if c == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }

        // Line comment.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        // Block comment.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        out.push(c as char);
        i += 1;
    }

    out
}

/// On-disk shape of Zed `settings.json` — only the fields we care about.
#[derive(Debug, Deserialize, Default)]
struct ZedSettings {
    #[serde(default)]
    context_servers: BTreeMap<String, ZedContextServer>,
    #[serde(default)]
    extensions: BTreeMap<String, ZedExtensionEntry>,
}

#[derive(Debug, Deserialize)]
struct ZedContextServer {
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default, rename = "type")]
    typ: Option<String>,
    /// "custom", "extension", …
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    disabled: Option<bool>,
}

impl ZedContextServer {
    fn transport(&self) -> String {
        if let Some(t) = self.transport.as_deref() {
            return t.to_string();
        }
        if let Some(t) = self.typ.as_deref() {
            return t.to_string();
        }
        if self.url.is_some() {
            "http".to_string()
        } else {
            "stdio".to_string()
        }
    }

    fn is_disabled(&self) -> bool {
        if let Some(d) = self.disabled {
            return d;
        }
        if let Some(e) = self.enabled {
            return !e;
        }
        false
    }
}

/// `extensions: { "<id>": true | { "enabled": bool, … } }`
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ZedExtensionEntry {
    Flag(bool),
    Object {
        #[serde(default)]
        enabled: Option<bool>,
    },
}

impl ZedExtensionEntry {
    fn enabled(&self) -> bool {
        match self {
            ZedExtensionEntry::Flag(b) => *b,
            ZedExtensionEntry::Object { enabled } => enabled.unwrap_or(true),
        }
    }
}

/// Best-effort heuristic: does this extension id look like an MCP server?
fn extension_looks_like_mcp(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("mcp")
        || lower.contains("context-server")
        || lower.contains("context_server")
}

fn read_version_from_plist(plist_path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(plist_path).ok()?;
    let key = "CFBundleShortVersionString";
    let key_pos = raw.find(key)?;
    let after = &raw[key_pos + key.len()..];
    let open = after.find("<string>")?;
    let rest = &after[open + "<string>".len()..];
    let close = rest.find("</string>")?;
    Some(rest[..close].trim().to_string())
}

#[async_trait]
impl SourceClient for SourceZed {
    fn id(&self) -> &'static str {
        "zed"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let settings_path: Option<PathBuf> =
            self.settings_paths().into_iter().find(|p| p.exists());
        let app_path: Option<PathBuf> =
            self.app_paths().into_iter().find(|p| p.exists());

        if settings_path.is_none() && app_path.is_none() {
            return vec![];
        }

        let mut client = ClientDecouvert::nouveau(ClientKind::Zed);

        if let Some(app) = &app_path {
            let binary = app.join("Contents/MacOS/zed");
            client.binary_path = if binary.exists() {
                Some(binary)
            } else {
                Some(app.clone())
            };
            client
                .meta
                .insert("app_path".to_string(), app.display().to_string());

            let plist = app.join("Contents/Info.plist");
            if let Some(version) = read_version_from_plist(&plist) {
                client.version = Some(version);
            } else {
                client
                    .notes
                    .push("zed: could not read CFBundleShortVersionString".to_string());
            }
        } else {
            client
                .notes
                .push("zed: no Zed app bundle found in /Applications".to_string());
        }

        match settings_path {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        client
                            .notes
                            .push("zed: settings.json is empty".to_string());
                        client.configs.push(ConfigSource {
                            config_path: path.clone(),
                            source_id: self.id().to_string(),
                            vu_a: Utc::now(),
                        });
                    } else {
                        let stripped = strip_jsonc_comments(trimmed);
                        match serde_json::from_str::<ZedSettings>(&stripped) {
                            Ok(parsed) => {
                                client.configs.push(ConfigSource {
                                    config_path: path.clone(),
                                    source_id: self.id().to_string(),
                                    vu_a: Utc::now(),
                                });

                                if parsed.context_servers.is_empty()
                                    && parsed.extensions.is_empty()
                                {
                                    client.notes.push(
                                        "zed: no context_servers or extensions declared"
                                            .to_string(),
                                    );
                                }

                                // 1. Direct context_servers entries.
                                for (nom, entry) in parsed.context_servers {
                                    let env_keys: Vec<String> =
                                        entry.env.keys().cloned().collect();
                                    let srv = ServeurMcpDeclare {
                                        nom: nom.clone(),
                                        transport: entry.transport(),
                                        commande: entry.command.clone(),
                                        args: entry.args.clone(),
                                        env_keys,
                                        url: entry.url.clone(),
                                        disabled: entry.is_disabled(),
                                        scope: ScopeServeur::default(),
                                    };
                                    if matches!(
                                        entry.source.as_deref(),
                                        Some("extension")
                                    ) {
                                        client.notes.push(format!(
                                            "zed: context server '{nom}' is extension-declared"
                                        ));
                                    }
                                    client.serveurs.push(srv);
                                }

                                // 2. Extension-declared MCP servers — these
                                //    don't carry a command in the user settings
                                //    (the extension itself supplies it).
                                for (ext_name, entry) in parsed.extensions {
                                    if !entry.enabled() {
                                        continue;
                                    }
                                    if !extension_looks_like_mcp(&ext_name) {
                                        continue;
                                    }
                                    client.serveurs.push(ServeurMcpDeclare {
                                        nom: ext_name.clone(),
                                        transport: "stdio".to_string(),
                                        commande: None,
                                        args: vec![],
                                        env_keys: vec![],
                                        url: None,
                                        disabled: false,
                                        scope: ScopeServeur::default(),
                                    });
                                    client.notes.push(format!(
                                        "zed: extension '{ext_name}' is extension-declared"
                                    ));
                                }
                            }
                            Err(err) => {
                                client.notes.push(format!(
                                    "zed: failed to parse settings.json: {err}"
                                ));
                            }
                        }
                    }
                }
                Err(err) => {
                    client
                        .notes
                        .push(format!("zed: cannot read settings.json: {err}"));
                }
            },
            None => {
                client
                    .notes
                    .push("zed: no settings.json found in known locations".to_string());
            }
        }

        vec![client]
    }
}

#[cfg(test)]
mod tests_chemins {
    use super::*;

    #[test]
    fn macos_config_puis_legacy() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/alice");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![
                PathBuf::from("/Users/alice/.config/zed/settings.json"),
                PathBuf::from("/Users/alice/Library/Application Support/Zed/settings.json"),
            ]
        );
    }

    #[test]
    fn windows_appdata() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![PathBuf::from("C:/Users/alice/AppData/Roaming/Zed/settings.json")]
        );
    }

    #[test]
    fn linux_xdg_puis_config() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob")
            .avec_xdg_config_home("/home/bob/xdg");
        assert_eq!(
            chemins_settings_candidats(&ctx),
            vec![
                PathBuf::from("/home/bob/xdg/zed/settings.json"),
                PathBuf::from("/home/bob/.config/zed/settings.json"),
            ]
        );
    }
}
