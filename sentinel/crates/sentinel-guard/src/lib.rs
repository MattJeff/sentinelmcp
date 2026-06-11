//! sentinel-guard — mode « guard » temps réel.
//!
//! Wrapper stdio transparent autour d'un vrai serveur MCP : relaie le
//! trafic JSON-RPC octet-à-octet, observe les réponses `tools/list` au
//! passage, compare l'empreinte canonique (SHA-256, via sentinel-detect)
//! à la baseline approuvée du store SQLite, et — en mode `--block` —
//! remplace une réponse en dérive critique par une erreur JSON-RPC
//! `-32000` au lieu de la relayer.
//!
//! Le module [`injection`] sait réécrire une config client MCP pour
//! faire passer chaque serveur stdio par ce binaire (et revenir en
//! arrière), de façon idempotente, avec sauvegarde `.sentinel.bak`.

pub mod db;
pub mod garde;
pub mod injection;

pub use garde::{GardeStdio, CODE_BLOCAGE, MESSAGE_BLOCAGE};
pub use injection::{eject_config, inject_config};
