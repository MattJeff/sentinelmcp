//! Détection de signature MCP — orchestration filtre grossier + confirmation.

pub mod coarse;
pub mod confirm;

pub use coarse::filtre_grossier;
pub use confirm::{confirmer_message, SuiviSessions};
