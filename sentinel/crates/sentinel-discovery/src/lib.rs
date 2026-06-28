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
pub mod skills;
pub mod orchestrator;
pub mod runtime_inspector;
pub mod active_probe;
pub mod active_probe_http;
pub mod config_baseline;
pub mod static_http;
pub mod supply_chain;
pub mod threat_intel;
pub mod trust_graph;

pub use model::{ClientDecouvert, ClientKind, ConfigSource, ServeurMcpDeclare};
pub use skills::{
    inspecter_skill_complet, ConstatSkillTexte, DecouvreurSkills, ScopeSkill, SkillDecouvert,
    TypeArtefactSkill,
};
pub use orchestrator::{RapportDecouverte, OrchestrateurDecouverte};
pub use runtime_inspector::{
    correler_avec_inventaire, parser_lsof, parser_ss, ports_connus, InspecteurRuntime,
    InspecteurSockets, ProcessusObserve, SocketEnEcoute,
};
pub use sources::SourceClient;
pub use active_probe::{EtatProbe, ProbeurActif, RapportProbe};
// D13 — baseline + diff du contenu des configs MCP de projet (MCPoison).
pub use config_baseline::{comparer_config_projet, BaselineConfigsProjet};
// D14 — contrôles statiques OAuth/SSRF sur serveurs HTTP.
pub use static_http::{analyser_serveur_http, analyser_serveurs_http};
// D16 — matching threat feed flou (casse + Levenshtein).
pub use threat_intel::{CorrespondanceFloue, EntreeMenace, FluxMenaces};
