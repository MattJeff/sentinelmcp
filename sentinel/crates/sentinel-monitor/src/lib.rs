//! sentinel-monitor — Module 2. Surveillance continue : baselines, journal,
//! détection de nouveaux serveurs, dérive intra/inter-session, politique de
//! changement, confidentialité, perf, contrats.

pub mod engine;
pub mod baselines;
pub mod new_servers;
pub mod intra_session;
pub mod inter_session;
pub mod derive_lente;
pub mod golden;
pub mod activity_log;
pub mod policy;
pub mod privacy;
pub mod perf;
pub mod contracts;

pub use engine::MoteurSurveillance;
pub use baselines::GestionnaireBaselines;
pub use new_servers::DetecteurNouveauxServeurs;
pub use intra_session::DetecteurIntraSession;
pub use inter_session::DetecteurInterSession;
pub use derive_lente::{BilanDeriveLente, DetecteurDeriveLente, ParametresDeriveLente, SessionEmpreintes};
pub use golden::{BilanImport, GoldenBaselines};
pub use activity_log::JournalActivite;
pub use policy::{PolitiqueChangement, DecisionPolitique};
pub use contracts::{FaitSurveillance, ContratSurveillance};
