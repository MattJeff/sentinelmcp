//! Windsurf (Codeium IDE) discovery source.
//!
//! Windsurf stores its MCP server configuration in
//! `~/.codeium/windsurf/mcp_config.json` (key: `mcpServers`), using the same
//! schema as Claude Desktop / Cursor. The app itself is shipped at
//! `/Applications/Windsurf.app`. We also keep an eye on the optional
//! `~/.codeium/windsurf-cli/` directory.

use crate::model::{
    ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare,
};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Detection source for Windsurf (Codeium's AI-native IDE).
pub struct SourceWindsurf {
    /// Home directory override (used by tests).
    home: Option<PathBuf>,
    /// `/Applications` override (used by tests).
    applications: Option<PathBuf>,
}

impl SourceWindsurf {
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

    fn home_dir(&self) -> Option<PathBuf> {
        if let Some(h) = &self.home {
            return Some(h.clone());
        }
        dirs::home_dir()
    }

    fn applications_dir(&self) -> PathBuf {
        self.applications
            .clone()
            .unwrap_or_else(|| PathBuf::from("/Applications"))
    }

    fn mcp_config_path(&self) -> Option<PathBuf> {
        Some(self.home_dir()?.join(".codeium/windsurf/mcp_config.json"))
    }

    fn cli_dir(&self) -> Option<PathBuf> {
        Some(self.home_dir()?.join(".codeium/windsurf-cli"))
    }

    fn windsurf_app_dir(&self) -> PathBuf {
        self.applications_dir().join("Windsurf.app")
    }

    fn binary_path(&self) -> PathBuf {
        self.windsurf_app_dir().join("Contents/MacOS/Electron")
    }

    fn info_plist_path(&self) -> PathBuf {
        self.windsurf_app_dir().join("Contents/Info.plist")
    }
}

impl Default for SourceWindsurf {
    fn default() -> Self {
        Self::new()
    }
}

/// On-disk shape of `mcp_config.json` (only the bits we care about).
#[derive(Debug, Deserialize)]
struct WindsurfConfigFile {
    #[serde(default)]
    #[serde(rename = "mcpServers")]
    mcp_servers: BTreeMap<String, WindsurfServerEntry>,
}

#[derive(Debug, Deserialize)]
struct WindsurfServerEntry {
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
    #[serde(default)]
    disabled: bool,
}

impl WindsurfServerEntry {
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
}

fn read_version_from_plist(plist_path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(plist_path).ok()?;
    // Cheap, dependency-free plist parsing: look for the
    // `CFBundleShortVersionString` key followed by its `<string>` value.
    let key = "CFBundleShortVersionString";
    let key_pos = raw.find(key)?;
    let after = &raw[key_pos + key.len()..];
    let open = after.find("<string>")?;
    let rest = &after[open + "<string>".len()..];
    let close = rest.find("</string>")?;
    Some(rest[..close].trim().to_string())
}

#[async_trait]
impl SourceClient for SourceWindsurf {
    fn id(&self) -> &'static str {
        "windsurf"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        let app_dir = self.windsurf_app_dir();
        let app_present = app_dir.exists();
        let binary = self.binary_path();
        let binary_present = binary.exists();

        let config_path = self.mcp_config_path();
        let config_exists = config_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false);

        let cli_dir = self.cli_dir();
        let cli_present = cli_dir.as_ref().map(|p| p.exists()).unwrap_or(false);

        // Nothing whatsoever points at Windsurf — stay quiet.
        if !app_present && !config_exists && !cli_present {
            return vec![];
        }

        let mut client = ClientDecouvert::nouveau(ClientKind::Windsurf);

        if app_present {
            client.binary_path = if binary_present {
                Some(binary.clone())
            } else {
                Some(app_dir.clone())
            };
            client
                .meta
                .insert("app_path".to_string(), app_dir.display().to_string());

            if let Some(version) = read_version_from_plist(&self.info_plist_path()) {
                client.version = Some(version);
            } else {
                client
                    .notes
                    .push("windsurf: could not read CFBundleShortVersionString".to_string());
            }
        } else {
            client
                .notes
                .push("windsurf: app bundle not found in /Applications".to_string());
        }

        if cli_present {
            if let Some(cli) = &cli_dir {
                client
                    .meta
                    .insert("cli_dir".to_string(), cli.display().to_string());
            }
        }

        match (&config_path, config_exists) {
            (Some(path), true) => match std::fs::read_to_string(path) {
                Ok(raw) => {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        client
                            .notes
                            .push("windsurf: mcp_config.json is empty".to_string());
                        client.configs.push(ConfigSource {
                            config_path: path.clone(),
                            source_id: self.id().to_string(),
                            vu_a: Utc::now(),
                        });
                    } else {
                        match serde_json::from_str::<WindsurfConfigFile>(trimmed) {
                            Ok(parsed) => {
                                client.configs.push(ConfigSource {
                                    config_path: path.clone(),
                                    source_id: self.id().to_string(),
                                    vu_a: Utc::now(),
                                });
                                if parsed.mcp_servers.is_empty() {
                                    client.notes.push(
                                        "windsurf: mcpServers block is empty".to_string(),
                                    );
                                }
                                for (nom, entry) in parsed.mcp_servers {
                                    let env_keys: Vec<String> =
                                        entry.env.keys().cloned().collect();
                                    client.serveurs.push(ServeurMcpDeclare {
                                        nom,
                                        transport: entry.transport(),
                                        commande: entry.command.clone(),
                                        args: entry.args.clone(),
                                        env_keys,
                                        url: entry.url.clone(),
                                        disabled: entry.disabled,
                                    });
                                }
                            }
                            Err(err) => {
                                client.notes.push(format!(
                                    "windsurf: failed to parse mcp_config.json: {err}"
                                ));
                            }
                        }
                    }
                }
                Err(err) => {
                    client
                        .notes
                        .push(format!("windsurf: cannot read mcp_config.json: {err}"));
                }
            },
            (Some(path), false) => {
                client.notes.push(format!(
                    "windsurf: no mcp config at {}",
                    path.display()
                ));
            }
            (None, _) => {
                client
                    .notes
                    .push("windsurf: home directory not available".to_string());
            }
        }

        vec![client]
    }
}
