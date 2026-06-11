//! Shared data model for discovery results.
//!
//! All discovery sources produce these types. They are designed to be
//! serialised straight into the Tauri commands consumed by the UI.

use chrono::{DateTime, Utc};
use sentinel_protocol::ScopeServeur;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Which AI client we detected on disk or in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    ClaudeDesktop,
    ClaudeCodeCli,
    Cursor,
    Windsurf,
    Continue,
    Zed,
    VsCode,
    Aider,
    Goose,
    Codex,
    Antigravity,
    LmStudio,
    OpenWebUi,
    Sketch,
    Autre,
}

impl ClientKind {
    pub fn libelle(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "Claude Desktop",
            Self::ClaudeCodeCli => "Claude Code CLI",
            Self::Cursor => "Cursor",
            Self::Windsurf => "Windsurf",
            Self::Continue => "Continue",
            Self::Zed => "Zed",
            Self::VsCode => "VS Code",
            Self::Aider => "Aider",
            Self::Goose => "Goose",
            Self::Codex => "Codex",
            Self::Antigravity => "Antigravity",
            Self::LmStudio => "LM Studio",
            Self::OpenWebUi => "Open WebUI",
            Self::Sketch => "Sketch",
            Self::Autre => "Other",
        }
    }
}

/// Where the discovery information came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSource {
    /// Absolute path of the config file on disk.
    pub config_path: PathBuf,
    /// Sentinel-friendly identifier of the source ("claude-desktop", "cursor", …).
    pub source_id: String,
    /// When we last looked at it.
    pub vu_a: DateTime<Utc>,
}

/// One MCP server entry declared by an AI client's configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServeurMcpDeclare {
    /// Human name of the server as written by the user (key in the config).
    pub nom: String,
    /// Transport type as declared by the client config.
    /// "stdio" by default — most clients use stdio MCP servers.
    pub transport: String,
    /// Stdio: the command to invoke (e.g. "npx").
    pub commande: Option<String>,
    /// Stdio: arguments passed to the command.
    pub args: Vec<String>,
    /// Stdio: environment variables (keys only — values are redacted).
    pub env_keys: Vec<String>,
    /// HTTP: endpoint URL.
    pub url: Option<String>,
    /// `true` if the entry is explicitly disabled by the client config.
    pub disabled: bool,
    /// Scope de déclaration — `User` (top-level `mcpServers`) ou
    /// `Project { path }` (`projects.<path>.mcpServers` dans
    /// `.claude.json`, ou `.mcp.json` per-projet pour Claude Code).
    /// `#[serde(default)]` pour la rétrocompat des payloads UI / JSON
    /// existants qui n'ont pas encore ce champ.
    #[serde(default)]
    pub scope: ScopeServeur,
}

/// Aggregated view of one AI client found on this Mac.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDecouvert {
    pub kind: ClientKind,
    pub libelle: String,
    /// Where its app/binary lives, if we found it.
    pub binary_path: Option<PathBuf>,
    /// Version string we managed to read (CFBundleShortVersionString, --version, …).
    pub version: Option<String>,
    /// Configs we managed to parse (a single client can have multiple).
    pub configs: Vec<ConfigSource>,
    /// MCP servers declared across all parsed configs.
    pub serveurs: Vec<ServeurMcpDeclare>,
    /// Raw notes for the UI ("config not readable", "no MCP block declared", …).
    #[serde(default)]
    pub notes: Vec<String>,
    /// Optional arbitrary key/value metadata (UI may display selectively).
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

impl ClientDecouvert {
    pub fn nouveau(kind: ClientKind) -> Self {
        Self {
            libelle: kind.libelle().to_string(),
            kind,
            binary_path: None,
            version: None,
            configs: vec![],
            serveurs: vec![],
            notes: vec![],
            meta: Default::default(),
        }
    }
}
