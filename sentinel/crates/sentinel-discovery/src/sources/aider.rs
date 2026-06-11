//! Aider (paul-gauthier/aider AI pair programmer) discovery source.
//!
//! Aider keeps an optional global YAML configuration:
//!
//! - `~/.aider.conf.yml`
//! - `~/.aider/config.yml`
//!
//! It does not (yet) have a stable MCP integration in upstream releases, but
//! community forks and the experimental `--mcp-config` flag expose two ways to
//! point Aider at MCP servers from this YAML file:
//!
//! ```yaml
//! # Inline list (à la Continue / Goose).
//! mcp-servers:
//!   - name: filesystem
//!     command: npx
//!     args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
//!     env:
//!       MCP_DEBUG: "1"
//! ```
//!
//! ```yaml
//! # External JSON file (the `--mcp-config` flag shape).
//! mcp-config: ~/.aider/mcp.json
//! ```
//!
//! The external JSON uses the Claude-Desktop-style `mcpServers` map.
//!
//! Per-project `<cwd>/.aider.conf.yml` files exist too but are out of scope —
//! we only look at the user-global ones.
//!
//! Binary discovery looks at `which aider`, `/opt/homebrew/bin/aider`,
//! `~/.local/bin/aider`, and `~/.aider/bin/aider`. We also try to read
//! `aider --version` to populate the version field.

use sentinel_protocol::ScopeServeur;
use crate::model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
use crate::sources::os_paths::{ContexteOs, OsCible};
use crate::sources::SourceClient;
use async_trait::async_trait;
use chrono::Utc;
use serde_yaml::Value as YamlValue;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Detection source for Aider.
///
/// The unit-struct shape is preserved so that the orchestrator can keep
/// instantiating it as `aider::SourceAider`. Test-time overrides go through
/// the standalone [`detecter_avec_options`] helper.
pub struct SourceAider;

/// Test-friendly overrides for the Aider detection probe.
#[derive(Debug, Clone, Default)]
pub struct AiderOptions {
    /// Home directory override.
    pub home: Option<PathBuf>,
    /// Force a specific set of directories to look for an `aider` binary in.
    /// When `Some(_)`, we skip `which aider` entirely.
    pub bin_dirs: Option<Vec<PathBuf>>,
    /// Skip shelling out to `aider --version`.
    pub skip_version_probe: bool,
}

impl AiderOptions {
    pub fn with_home<P: Into<PathBuf>>(mut self, home: P) -> Self {
        self.home = Some(home.into());
        self
    }
    pub fn with_bin_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.bin_dirs = Some(dirs);
        self
    }
    pub fn without_version_probe(mut self) -> Self {
        self.skip_version_probe = true;
        self
    }
}

fn home_dir(opts: &AiderOptions) -> Option<PathBuf> {
    if let Some(h) = &opts.home {
        return Some(h.clone());
    }
    dirs::home_dir()
}

/// Chemins candidats des configs globales Aider — identiques sur les trois
/// OS (chemins relatifs au home, `%USERPROFILE%\.aider.conf.yml` sur
/// Windows). Fonction pure.
pub fn chemins_config_candidats(ctx: &ContexteOs) -> Vec<PathBuf> {
    vec![
        ctx.home.join(".aider.conf.yml"),
        ctx.home.join(".aider/config.yml"),
    ]
}

/// Nom du binaire `aider` selon l'OS.
fn nom_binaire(os: OsCible) -> &'static str {
    match os {
        OsCible::Windows => "aider.exe",
        _ => "aider",
    }
}

fn config_candidates(opts: &AiderOptions) -> Vec<PathBuf> {
    match home_dir(opts) {
        Some(h) => chemins_config_candidats(&ContexteOs::nouveau(OsCible::courant(), h)),
        None => vec![],
    }
}

fn binary_candidates(opts: &AiderOptions) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![];
    let bin = nom_binaire(OsCible::courant());

    if let Some(dirs) = &opts.bin_dirs {
        for d in dirs {
            out.push(d.join(bin));
        }
    } else {
        // `which aider` first (catches venv / pipx installs). On Windows the
        // equivalent lookup is `where`.
        let lookup = if cfg!(target_os = "windows") { "where" } else { "which" };
        if let Ok(output) = Command::new(lookup).arg("aider").output() {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !s.is_empty() {
                    out.push(PathBuf::from(s));
                }
            }
        }
        if cfg!(target_os = "macos") {
            out.push(PathBuf::from("/opt/homebrew/bin/aider"));
        }
        if let Some(h) = home_dir(opts) {
            out.push(h.join(".local/bin").join(bin));
            out.push(h.join(".aider/bin").join(bin));
        }
    }

    out
}

/// Core detection routine. Used by both the live `SourceClient` impl and the
/// integration tests.
pub fn detecter_avec_options(opts: &AiderOptions) -> Vec<ClientDecouvert> {
    let configs_present: Vec<PathBuf> = config_candidates(opts)
        .into_iter()
        .filter(|p| p.exists())
        .collect();

    let binary_present: Option<PathBuf> =
        binary_candidates(opts).into_iter().find(|p| p.exists());

    if configs_present.is_empty() && binary_present.is_none() {
        return vec![];
    }

    let mut client = ClientDecouvert::nouveau(ClientKind::Aider);

    if let Some(bin) = &binary_present {
        client.binary_path = Some(bin.clone());
        if !opts.skip_version_probe {
            if let Some(v) = probe_version(bin) {
                client.version = Some(v);
            }
        }
    } else {
        client
            .notes
            .push("aider: binary not found in PATH or known locations".to_string());
    }

    if configs_present.is_empty() {
        client.notes.push(
            "aider: no global config file (.aider.conf.yml / .aider/config.yml) found"
                .to_string(),
        );
    } else {
        for cfg_path in &configs_present {
            traiter_yaml(cfg_path, &mut client);
        }
    }

    vec![client]
}

#[async_trait]
impl SourceClient for SourceAider {
    fn id(&self) -> &'static str {
        "aider"
    }

    async fn detecter(&self) -> Vec<ClientDecouvert> {
        detecter_avec_options(&AiderOptions::default())
    }
}

fn probe_version(binary: &Path) -> Option<String> {
    let output = Command::new(binary).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = if stdout.trim().is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        stdout.to_string()
    };
    let first_line = combined.lines().next()?.trim().to_string();
    if first_line.is_empty() {
        None
    } else {
        Some(first_line)
    }
}

fn traiter_yaml(path: &Path, client: &mut ClientDecouvert) {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            client.notes.push(format!(
                "aider: failed to read {}: {}",
                path.display(),
                e
            ));
            return;
        }
    };

    let yaml: YamlValue = match serde_yaml::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            client.notes.push(format!(
                "aider: failed to parse {}: {}",
                path.display(),
                e
            ));
            return;
        }
    };

    client.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "aider".to_string(),
        vu_a: Utc::now(),
    });

    let mut found_any = false;

    // 1) Inline `mcp-servers:` (list form).
    if let Some(seq) = yaml.get("mcp-servers").and_then(|v| v.as_sequence()) {
        for entree in seq {
            if let Some(s) = parser_entree_liste(entree) {
                client.serveurs.push(s);
                found_any = true;
            }
        }
    }

    // 2) Inline `mcpServers:` (map form, tolerated).
    if let Some(map) = yaml.get("mcpServers").and_then(|v| v.as_mapping()) {
        for (k, v) in map {
            if let Some(nom) = k.as_str() {
                if let Some(s) = parser_entree_objet(nom, v) {
                    client.serveurs.push(s);
                    found_any = true;
                }
            }
        }
    }

    // 3) External `mcp-config: <path>` reference.
    if let Some(mcp_cfg) = yaml.get("mcp-config").and_then(|v| v.as_str()) {
        let external = expand_path(mcp_cfg, path);
        if external.exists() {
            match suivre_mcp_config(&external, client) {
                Ok(n) => {
                    if n > 0 {
                        found_any = true;
                    }
                }
                Err(e) => {
                    client.notes.push(format!(
                        "aider: failed to follow mcp-config {}: {}",
                        external.display(),
                        e
                    ));
                }
            }
        } else {
            client.notes.push(format!(
                "aider: mcp-config points to missing file {}",
                external.display()
            ));
        }
    }

    if !found_any
        && yaml.get("mcp-servers").is_none()
        && yaml.get("mcpServers").is_none()
        && yaml.get("mcp-config").is_none()
    {
        client.notes.push(format!(
            "aider: no MCP block declared in {}",
            path.display()
        ));
    }
}

/// Resolve a path written inside an aider yaml. Supports `~`, absolute paths,
/// and paths relative to the yaml's parent directory.
fn expand_path(raw: &str, yaml_path: &Path) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    let candidate = PathBuf::from(trimmed);
    if candidate.is_absolute() {
        return candidate;
    }
    if let Some(parent) = yaml_path.parent() {
        return parent.join(candidate);
    }
    candidate
}

/// Read an external JSON file declared by `mcp-config:` and import its
/// `mcpServers` map. Returns the number of servers imported.
fn suivre_mcp_config(path: &Path, client: &mut ClientDecouvert) -> Result<usize, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    // serde_yaml is a JSON superset, so this handles both .json and .yml.
    let value: YamlValue = serde_yaml::from_str(&raw).map_err(|e| e.to_string())?;

    client.configs.push(ConfigSource {
        config_path: path.to_path_buf(),
        source_id: "aider".to_string(),
        vu_a: Utc::now(),
    });

    let mut count = 0usize;

    if let Some(map) = value.get("mcpServers").and_then(|v| v.as_mapping()) {
        for (k, v) in map {
            if let Some(nom) = k.as_str() {
                if let Some(s) = parser_entree_objet(nom, v) {
                    client.serveurs.push(s);
                    count += 1;
                }
            }
        }
    } else if let Some(seq) = value.get("mcp-servers").and_then(|v| v.as_sequence()) {
        for entree in seq {
            if let Some(s) = parser_entree_liste(entree) {
                client.serveurs.push(s);
                count += 1;
            }
        }
    } else {
        client.notes.push(format!(
            "aider: external mcp-config {} contains no mcpServers block",
            path.display()
        ));
    }

    Ok(count)
}

fn parser_entree_liste(entree: &YamlValue) -> Option<ServeurMcpDeclare> {
    let map = entree.as_mapping()?;
    let nom = map
        .get(YamlValue::String("name".to_string()))
        .and_then(|v| v.as_str())?
        .to_string();
    parser_entree_objet(&nom, entree)
}

fn parser_entree_objet(nom: &str, value: &YamlValue) -> Option<ServeurMcpDeclare> {
    let map = value.as_mapping()?;

    let disabled = map
        .get(YamlValue::String("disabled".to_string()))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Remote (HTTP / SSE).
    if let Some(url) = map
        .get(YamlValue::String("url".to_string()))
        .and_then(|v| v.as_str())
    {
        let transport = map
            .get(YamlValue::String("transport".to_string()))
            .and_then(|v| v.as_str())
            .or_else(|| {
                map.get(YamlValue::String("type".to_string()))
                    .and_then(|v| v.as_str())
            })
            .map(|s| s.to_string())
            .unwrap_or_else(|| "http".to_string());

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

    // Stdio.
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

#[cfg(test)]
mod tests_chemins {
    use super::*;

    #[test]
    fn config_identique_sur_tous_les_os() {
        for os in OsCible::TOUS {
            let ctx = ContexteOs::nouveau(os, "/home/user");
            assert_eq!(
                chemins_config_candidats(&ctx),
                vec![
                    PathBuf::from("/home/user/.aider.conf.yml"),
                    PathBuf::from("/home/user/.aider/config.yml"),
                ],
                "os = {os:?}"
            );
        }
    }

    #[test]
    fn nom_binaire_windows_avec_exe() {
        assert_eq!(nom_binaire(OsCible::Windows), "aider.exe");
        assert_eq!(nom_binaire(OsCible::MacOs), "aider");
        assert_eq!(nom_binaire(OsCible::Linux), "aider");
    }
}
