//! sentinel-report — Module 5. Rapport MCP09 signé + tableau de bord + flux d'approbation.

pub mod engine;
pub mod summary;
pub mod inventory;
pub mod compliance;
pub mod signature;
pub mod pdf;
pub mod json_export;
pub mod dashboard;
pub mod approval;
pub mod remediation;

pub use engine::GenerateurRapport;
pub use summary::ResumeExecutif;
pub use inventory::{SectionInventaire, SectionJournal};
pub use compliance::{CouvertureCategorie, MoteurConformite, NiveauCouverture, Reference};
pub use signature::SignataireBundle;
pub use pdf::RenduPdf;
pub use json_export::ExportJson;
pub use dashboard::TableauBord;
pub use approval::FluxApprobation;
pub use remediation::PlanRemediation;
