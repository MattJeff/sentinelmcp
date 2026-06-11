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
pub mod validate;

pub use bundle::{deterministic_bundle, new_bundle, StixObject};
pub use ids::{deterministic_id, random_id, STIX_UUID_NAMESPACE};
pub use types::{
    ExternalReference, Identity, Indicator, Infrastructure, ObservedData, Relationship, Sighting,
    Software, StixBundle,
};
pub use validate::{validate_bundle_value, validate_object};

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
    #[error("STIX 2.1 conformance violations: {}", .0.join("; "))]
    Validation(Vec<String>),
}

/// Builds a STIX 2.1 bundle from the current Sentinel state.
///
/// Steps:
/// 1. Emit the Sentinel `identity` SDO.
/// 2. Read threat-intel feed (bundled, offline) → STIX `indicator` SDOs.
/// 3. Read MCP servers → `software` SCOs + `infrastructure` SDOs.
/// 4. Read findings with severity `Haute` or `Critique` → one `indicator`
///    + one `observed-data` + one `sighting` each, plus an `indicates`
///    relationship to the offending server's infrastructure.
/// 5. Link each threat-intel indicator that matches a known server to that
///    server's infrastructure with an `indicates` SRO.
///
/// Every ID is a UUID v5 over canonical content and every timestamp comes
/// from stored data, so re-exporting an unchanged store produces a
/// byte-identical bundle (idempotent TAXII pushes). The resulting bundle is
/// validated field-by-field before being returned.
pub fn export_bundle(store: &Store) -> Result<StixBundle, StixError> {
    let mut objects: Vec<StixObject> = Vec::new();

    // 1) Sentinel identity.
    let identity = mapping::sentinel_identity();
    let identity_id = identity.id.clone();
    objects.push(StixObject::Identity(identity));

    // 2) Threat intel → indicators.
    let flux = FluxMenaces::par_defaut();
    let mut indicators: Vec<(String, types::Indicator)> = Vec::new();
    for entry in &flux.entrees {
        let ind = mapping::intel_entry_to_indicator(entry);
        indicators.push((entry.package_name.clone(), ind));
    }

    // 3) Servers → software SCO + infrastructure SDO.
    let serveurs = store
        .lister_serveurs()
        .map_err(|e| StixError::Store(e.to_string()))?;
    let mut infra_by_server: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    let mut endpoint_by_server: std::collections::HashMap<uuid::Uuid, String> =
        std::collections::HashMap::new();
    for s in &serveurs {
        let sw = mapping::server_to_software(s);
        let infra = mapping::server_to_infrastructure(s);
        infra_by_server.insert(s.id, infra.id.clone());
        endpoint_by_server.insert(s.id, s.endpoint.clone());
        objects.push(StixObject::Software(sw));
        objects.push(StixObject::Infrastructure(infra));
    }

    // 4) Findings (high / critical) → indicator + observed-data + sighting
    //    (+ relationship to the server's infrastructure when known).
    let constats = store
        .lister_constats(true)
        .map_err(|e| StixError::Store(e.to_string()))?;
    for c in &constats {
        if !matches!(c.severite, Severite::Haute | Severite::Critique) {
            continue;
        }
        let endpoint = endpoint_by_server.get(&c.serveur_id).map(String::as_str);
        let ind = mapping::finding_to_indicator(c, endpoint);
        let od = mapping::finding_to_observed_data(c);
        let sight = mapping::finding_to_sighting(c, &ind.id, &od.id, &identity_id);
        if let Some(infra_id) = infra_by_server.get(&c.serveur_id) {
            objects.push(StixObject::Relationship(mapping::relate(
                &ind.id, infra_id, "indicates",
            )));
        }
        objects.push(StixObject::Indicator(ind));
        objects.push(StixObject::ObservedData(od));
        objects.push(StixObject::Sighting(sight));
    }

    // 5) Relationships: threat-intel indicator → infrastructure
    //    (`indicates`) when the server endpoint contains the threatened
    //    package name. This is a best-effort substring match — same
    //    heuristic used by the discovery crate's `correspondances`.
    for (pkg, ind) in &indicators {
        for s in &serveurs {
            if s.endpoint.contains(pkg) {
                if let Some(infra_id) = infra_by_server.get(&s.id) {
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

    let bundle = deterministic_bundle(objects);
    let value = serde_json::to_value(&bundle)?;
    let violations = validate::validate_bundle_value(&value);
    if !violations.is_empty() {
        return Err(StixError::Validation(violations));
    }
    Ok(bundle)
}
