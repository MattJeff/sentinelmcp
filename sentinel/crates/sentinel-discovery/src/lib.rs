//! sentinel-discovery — find every AI client on this Mac that can speak MCP.
//!
//! This crate scans well-known config locations of popular AI clients (Claude
//! Desktop, Claude Code CLI, Cursor, Windsurf, Continue, Zed, VS Code, Aider,
//! Goose, Codex, Antigravity, …), parses each config, and emits a unified
//! `ClientDecouvert` describing the AI agent and the MCP servers it declares.
//!
//! Each detection source implements the [`SourceClient`] trait, so adding a
//! new client is a single-file change.

pub mod model;
pub mod sources;
pub mod orchestrator;
pub mod runtime_inspector;
pub mod active_probe;
pub mod active_probe_http;
pub mod supply_chain;
pub mod threat_intel;
pub mod trust_graph;

pub use model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
pub use orchestrator::{RapportDecouverte, OrchestrateurDecouverte};
pub use runtime_inspector::{ProcessusObserve, InspecteurRuntime};
pub use sources::SourceClient;
pub use active_probe::{EtatProbe, ProbeurActif, RapportProbe};
