//! sentinel-alerts — Module 4. Moteur d'alertes + canaux dashboard/email/webhook.

pub mod engine;
pub mod severity;
pub mod channels;
pub mod enrichment;
pub mod dedup;
pub mod lifecycle;
pub mod siem;
pub mod sinks;
pub mod secrets;
pub mod metrics;

pub use engine::MoteurAlertes;
pub use metrics::{
    rendre_prometheus, AgregatLatence, Metriques, RegistreMetriques, CONTENT_TYPE_PROMETHEUS,
};
pub use severity::{MatriceSeverite, ConfigSeverite};
pub use channels::{CanalEmetteur, dashboard, email, webhook};
pub use enrichment::EnrichisseurAlerte;
pub use dedup::DedupAntiBruit;
pub use lifecycle::EtatAlerteMachine;
pub use siem::{
    AdaptateurStandard, ContratSiem, EnregistrementSiem,
    gravite_siem, vers_cef, vers_leef, vers_ecs_json,
    vers_enregistrement_avec_references,
};
pub use secrets::{CoffreKeyring, CoffreMemoire, CoffreSecrets};
