//! sentinel-stix — STIX 2.1 bundle generation from Sentinel state.
//!
//! This crate maps the Sentinel internal data model (servers, findings,
//! threat-intel entries) onto STIX 2.1 SDOs/SCOs/SROs and exposes a single
//! [`export_bundle`] function that returns a self-contained [`StixBundle`].
//!
//! ## Notes on the actual Sentinel types
//!
//! The task brief referred to `ThreatIntelEntry`, `Finding` and `McpServer`,
//! but the real names in the workspace are:
//!
//! - `sentinel_discovery::threat_intel::EntreeMenace`  → threat-intel entry
//!   (NOT in `sentinel-store`; it is bundled at compile time inside
//!   `sentinel-discovery`).
//! - `sentinel_protocol::Constat`                       → finding
//! - `sentinel_protocol::Serveur`                       → MCP server
//!
//! The mapping module therefore uses these real types. `export_bundle`
//! reads servers and findings from the `Store`, and pulls the threat-intel
//! feed from `sentinel_discovery::threat_intel::FluxMenaces::par_defaut()`.

pub mod bundle;
pub mod ids;
pub mod mapping;
pub mod types;

pub use bundle::{new_bundle, StixObject};
pub use ids::{deterministic_id, random_id, STIX_UUID_NAMESPACE};
pub use types::{
    ExternalReference, Indicator, Infrastructure, ObservedData, Relationship, Software,
    StixBundle,
};

use sentinel_discovery::threat_intel::FluxMenaces;
use sentinel_protocol::Severite;
use sentinel_store::Store;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StixError {
    #[error("store error: {0}")]
    Store(String),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Builds a STIX 2.1 bundle from the current Sentinel state.
///
/// Steps:
/// 1. Read threat-intel feed (bundled, offline) → STIX `indicator` SDOs.
/// 2. Read findings with severity `Haute` or `Critique` → `observed-data` SDOs.
/// 3. Read MCP servers → `software` SCOs + `infrastructure` SDOs.
/// 4. Link each indicator that matches a known server to that server's
///    infrastructure with an `indicates` SRO.
pub fn export_bundle(store: &Store) -> Result<StixBundle, StixError> {
    let mut objects: Vec<StixObject> = Vec::new();

    // 1) Threat intel → indicators.
    let flux = FluxMenaces::par_defaut();
    let mut indicators: Vec<(String, types::Indicator)> = Vec::new();
    for entry in &flux.entrees {
        let ind = mapping::intel_entry_to_indicator(entry);
        indicators.push((entry.package_name.clone(), ind));
    }

    // 2) Findings (high / critical) → observed-data.
    let constats = store
        .lister_constats(true)
        .map_err(|e| StixError::Store(e.to_string()))?;
    for c in &constats {
        if matches!(c.severite, Severite::Haute | Severite::Critique) {
            objects.push(StixObject::ObservedData(mapping::finding_to_observed_data(
                c,
            )));
        }
    }

    // 3) Servers → software SCO + infrastructure SDO.
    let serveurs = store
        .lister_serveurs()
        .map_err(|e| StixError::Store(e.to_string()))?;
    let mut server_infra_id: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for s in &serveurs {
        let sw = mapping::server_to_software(s);
        let infra = mapping::server_to_infrastructure(s);
        server_infra_id.insert(s.endpoint.clone(), infra.id.clone());
        objects.push(StixObject::Software(sw));
        objects.push(StixObject::Infrastructure(infra));
    }

    // 4) Relationships: indicator → infrastructure (`indicates`) when the
    //    server endpoint contains the threatened package name. This is a
    //    best-effort substring match — same heuristic used by the
    //    discovery crate's `correspondances`.
    for (pkg, ind) in &indicators {
        for s in &serveurs {
            if s.endpoint.contains(pkg) {
                if let Some(infra_id) = server_infra_id.get(&s.endpoint) {
                    objects.push(StixObject::Relationship(mapping::relate(
                        &ind.id, infra_id, "indicates",
                    )));
                }
            }
        }
    }

    for (_, ind) in indicators {
        objects.push(StixObject::Indicator(ind));
    }

    Ok(new_bundle(objects))
}
