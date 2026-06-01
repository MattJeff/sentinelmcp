//! Capture stdio — wrapper qui enveloppe un serveur MCP stdio,
//! relaie stdin/stdout, et émet des `EvenementBrut` au passage.
//!
//! Implémenté par l'agent 1.1 (Lead capteur stdio).

pub mod wrapper;

pub use wrapper::WrapperStdio;
