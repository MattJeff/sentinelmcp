//! sentinel-scan — Module 1. Capture stdio/HTTP, normalisation,
//! détection de signature MCP, parsing `tools/list`, détection de portée.
//!
//! Squelette d'orchestration. Chaque sous-module est implémenté par un agent.

pub mod stdio;
pub mod http;
pub mod proxy;
pub mod event;
pub mod signature;
pub mod tools_list;
pub mod scope;
pub mod store_contract;
pub mod precision;
pub mod demo;

pub use event::{Normaliseur, normaliser_stdio, normaliser_http};
pub use signature::{filtre_grossier, confirmer_message, SuiviSessions};
pub use tools_list::{parser_reponse_tools_list, ReponseToolsList};
pub use scope::{inferer_portee, jeu_heuristiques};
pub use store_contract::{ContratScanStore, EvenementInventaire};
pub use proxy::{ConfigProxy, ConstatTempsReel, MoteurInspection, ProxyStdioTempsReel};
