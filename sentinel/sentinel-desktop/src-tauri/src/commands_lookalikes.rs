//! Lookalike scan — cross-references declared MCP servers on this Mac
//! against the public registries (PulseMCP, Smithery, mcp.so, mcp-registry)
//! using the brand-similarity engine from `sentinel-detect`.
//!
//! Goal: surface typosquats and doppelganger packages whose names/descriptions
//! are suspiciously close to one of the user's own declared servers but are
//! NOT the exact same identifier.

use std::time::Duration;

use sentinel_detect::lookalikes::{
    similarity::similarite_combinee, ConnecteurRegistres, EntreeRegistre, SourceMcpRegistry,
    SourceMcpSo, SourcePulseMCP, SourceSmithery,
};
use sentinel_discovery::{OrchestrateurDecouverte, ServeurMcpDeclare};
use serde::Serialize;
use tokio::time::timeout;

/// One suspicious lookalike: a registry entry whose name/description is
/// quasi-identical to a server declared locally, but not byte-for-byte
/// equal (i.e. a likely typo-squat).
#[derive(Serialize)]
pub struct LookalikeMatch {
    /// Identifier of the declared package on this Mac (server name).
    pub declared_package: String,
    /// Short id of the registry where the candidate was found.
    pub registry: String,
    /// Name of the candidate as published in the registry.
    pub candidate_name: String,
    /// Description of the candidate as published in the registry.
    pub candidate_description: String,
    /// Combined similarity score in `[0.0 ; 1.0]`.
    pub similarity_score: f64,
    /// `"critical"` (≥ 0.92) / `"high"` (≥ 0.88) / `"medium"` (≥ 0.85).
    pub severity: String,
}

/// Threshold above which a candidate is reported.
const SEUIL_LOOKALIKE: f64 = 0.85;
/// Threshold above which severity is escalated to "high".
const SEUIL_HIGH: f64 = 0.88;
/// Threshold above which severity is escalated to "critical".
const SEUIL_CRITICAL: f64 = 0.92;

/// Map a similarity score to a severity bucket.
fn severite_pour_score(score: f64) -> &'static str {
    if score >= SEUIL_CRITICAL {
        "critical"
    } else if score >= SEUIL_HIGH {
        "high"
    } else {
        "medium"
    }
}

/// Build the registry connector wired with all four production sources.
fn connecteur_par_defaut() -> ConnecteurRegistres {
    let mut connecteur = ConnecteurRegistres::nouveau();
    connecteur.ajouter(SourcePulseMCP::nouveau());
    connecteur.ajouter(SourceSmithery::nouveau());
    connecteur.ajouter(SourceMcpSo::nouveau());
    connecteur.ajouter(SourceMcpRegistry::nouveau());
    connecteur
}

/// Sweep every declared MCP server on this Mac and look it up against the
/// public registries to find brand-doppelganger packages.
///
/// Returns matches with `similarity_score ≥ 0.85` where the candidate name
/// is NOT byte-equal to the declared name (typo-squat condition). Results
/// are sorted by descending score so the most suspicious lookalikes come
/// first.
#[tauri::command]
pub async fn scan_lookalikes() -> Result<Vec<LookalikeMatch>, String> {
    // 1) Discovery — gather declared servers from every AI client config.
    let orchestrator = OrchestrateurDecouverte::default();
    let report = timeout(Duration::from_secs(15), orchestrator.balayer())
        .await
        .map_err(|_| "discovery timed out after 15s".to_string())?;

    let declared: Vec<ServeurMcpDeclare> = report
        .clients
        .iter()
        .flat_map(|c| c.serveurs.clone())
        .collect();

    if declared.is_empty() {
        return Ok(Vec::new());
    }

    // 2) Fetch every registry source. Errors per source are non-fatal —
    //    we just skip that registry and keep going (mirrors the policy
    //    documented on `ConnecteurRegistres::interroger_tous`).
    let connecteur = connecteur_par_defaut();
    let resultats_par_source = timeout(Duration::from_secs(15), connecteur.interroger_tous())
        .await
        .map_err(|_| "registry lookup timed out after 15s".to_string())?;

    // Flatten into one big pool of (registry_name, entry) pairs.
    let mut entrees: Vec<(String, EntreeRegistre)> = Vec::new();
    for (nom_registre, res) in resultats_par_source {
        match res {
            Ok(liste) => {
                for entree in liste {
                    entrees.push((nom_registre.clone(), entree));
                }
            }
            Err(e) => {
                log::warn!(
                    "lookalikes: registry '{}' failed, skipping: {}",
                    nom_registre,
                    e
                );
            }
        }
    }

    // 3) For each declared server, score every registry entry and keep
    //    matches ≥ threshold with a candidate name that is NOT identical
    //    (typo-squat condition).
    let mut matches: Vec<LookalikeMatch> = Vec::new();
    for serveur in &declared {
        let nom_declare = serveur.nom.as_str();
        for (registre, entree) in &entrees {
            let score = similarite_combinee(nom_declare, "", &entree.nom, &entree.description);
            if score < SEUIL_LOOKALIKE {
                continue;
            }
            if entree.nom == nom_declare {
                // Same name byte-for-byte — that's the legitimate listing,
                // not a typo-squat. Skip.
                continue;
            }
            matches.push(LookalikeMatch {
                declared_package: nom_declare.to_string(),
                registry: registre.clone(),
                candidate_name: entree.nom.clone(),
                candidate_description: entree.description.clone(),
                similarity_score: score,
                severity: severite_pour_score(score).to_string(),
            });
        }
    }

    // 4) Sort by descending score so the most suspicious come first.
    matches.sort_by(|a, b| {
        b.similarity_score
            .partial_cmp(&a.similarity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(matches)
}
