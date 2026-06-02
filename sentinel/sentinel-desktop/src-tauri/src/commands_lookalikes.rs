//! Lookalike scan — cross-references declared MCP servers on this Mac
//! against the public registries (PulseMCP, Smithery, mcp.so, mcp-registry)
//! AND inside our own inventory using the brand-similarity engine
//! `similarite_combinee_v2` from `sentinel-detect`.
//!
//! Two sources are merged into a single result vector :
//! - `"registry"` matches : declared server (from the local SQLite
//!   inventory) vs. one of the four public registries (typo-squat /
//!   doppelganger candidate).
//! - `"intra-inventory"` matches : pair of declared servers in the local
//!   inventory whose names differ but whose tool signatures / enums make
//!   them suspiciously similar.

use std::time::Duration;

use sentinel_detect::lookalikes::{
    intra_inventory::{detecter_sosies_intra, EntreeInventaire},
    signature_outil_depuis_outil,
    similarity::{similarite_combinee_v2, ScoreCombineV2},
    ConnecteurRegistres, EntreeRegistre, SignatureOutil, SourceMcpRegistry, SourceMcpSo,
    SourcePulseMCP, SourceSmithery,
};
use serde::Serialize;
use tauri::State;
use tokio::time::timeout;

use crate::state::AppState;

/// Breakdown of the per-signal contributions to the combined similarity
/// score. Mirrors `ScoreCombineV2` minus the meta fields.
#[derive(Serialize)]
pub struct ScoreBreakdown {
    /// Jaro-Winkler on the names.
    pub name: f64,
    /// Jaccard on description tokens.
    pub description: f64,
    /// Jaccard on tool names.
    pub tools: f64,
    /// Jaccard on the union of `enums_tries`.
    pub enums: f64,
}

/// One suspicious lookalike — either against a public registry or against
/// another declared server in the local inventory.
#[derive(Serialize)]
pub struct LookalikeMatch {
    /// `"registry"` or `"intra-inventory"` — discriminator for the UI.
    pub source: String,
    /// Identifier of the declared server in the local inventory, when known.
    /// For intra-inventory matches it's the `id` of the "left" server of
    /// the pair; for registry matches it stays `None` because the
    /// discovery report does not carry a stable id.
    pub declared_id: Option<String>,
    /// Human name / package identifier of the declared server.
    pub declared_package: String,
    /// Short id of the registry where the candidate was found, or
    /// `"intra"` for intra-inventory pairs.
    pub registry: String,
    /// Name of the candidate (registry entry or other declared server).
    pub candidate_name: String,
    /// Description of the candidate, or empty string if unavailable.
    pub candidate_description: String,
    /// Combined similarity score in `[0.0 ; 1.0]`.
    pub similarity_score: f64,
    /// `"critical"` (≥ 0.92) / `"high"` (≥ 0.88) / `"medium"` (≥ 0.85).
    pub severity: String,
    /// Signals that individually crossed the 0.7 confidence threshold
    /// (`"name"`, `"description"`, `"tool-overlap"`, `"enum-overlap"`).
    pub signals: Vec<String>,
    /// Per-signal score breakdown so the UI can render a sparkbar.
    pub score_breakdown: ScoreBreakdown,
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

/// Build the breakdown DTO from a `ScoreCombineV2`.
fn breakdown_depuis(score: &ScoreCombineV2) -> ScoreBreakdown {
    ScoreBreakdown {
        name: score.nom,
        description: score.description,
        tools: score.outils,
        enums: score.enums,
    }
}

/// Sweep every declared MCP server on this Mac and look it up against the
/// public registries AND every other declared server, in order to surface
/// typo-squats / doppelgangers.
///
/// Returns matches with `similarity_score ≥ 0.85` where the candidate name
/// is NOT byte-equal to the declared name. Results are sorted by
/// descending score so the most suspicious lookalikes come first.
#[tauri::command]
pub async fn scan_lookalikes(
    state: State<'_, AppState>,
) -> Result<Vec<LookalikeMatch>, String> {
    // 1) Pull the real declared servers (with their probed tools) from the
    //    inventory store. Mirrors the same shape we feed into other
    //    backend modules (rugpull diff, baseline approval, …).
    let store = state.store.clone();
    let serveurs = store
        .lister_serveurs()
        .map_err(|e| format!("inventaire: lister_serveurs failed: {e}"))?;

    let mut inventaire: Vec<EntreeInventaire> = Vec::with_capacity(serveurs.len());
    for serveur in &serveurs {
        let outils = store
            .lister_outils(serveur.id)
            .map_err(|e| format!("inventaire: lister_outils({}) failed: {e}", serveur.id))?;

        let signatures: Vec<SignatureOutil> = outils
            .iter()
            .map(|o| {
                signature_outil_depuis_outil(
                    &o.nom,
                    o.description.as_deref(),
                    &o.input_schema,
                )
            })
            .collect();

        // For the inventory entry we use the endpoint as the "declared
        // package" label (stable across scans), and the server uuid as
        // `declared_id`. Description is not persisted on `Serveur` so we
        // leave it `None` — the score function copes with that.
        inventaire.push(EntreeInventaire {
            id: serveur.id.to_string(),
            nom: serveur.endpoint.clone(),
            description: None,
            outils: signatures,
        });
    }

    let mut matches: Vec<LookalikeMatch> = Vec::new();

    // 2) Registry pass — only if we have at least one declared server to
    //    compare against. Otherwise we skip the network calls entirely.
    if !inventaire.is_empty() {
        let connecteur = connecteur_par_defaut();
        let resultats_par_source =
            timeout(Duration::from_secs(15), connecteur.interroger_tous())
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

        // 3) For each declared server × registry entry, run the v2 combined
        //    score with all four signals (name + description + tool names
        //    + enums). Keep matches ≥ threshold whose names are not
        //    byte-equal (typo-squat condition).
        for entree_decl in &inventaire {
            for (registre, entree) in &entrees {
                if entree.nom == entree_decl.nom {
                    // Same name byte-for-byte — that's the legitimate
                    // listing, not a typo-squat. Skip.
                    continue;
                }

                let score = similarite_combinee_v2(
                    &entree_decl.nom,
                    entree_decl.description.as_deref(),
                    &entree_decl.outils,
                    &entree.nom,
                    entree.description.as_deref(),
                    entree.outils.as_deref(),
                );

                if score.score < SEUIL_LOOKALIKE {
                    continue;
                }

                matches.push(LookalikeMatch {
                    source: "registry".to_string(),
                    declared_id: Some(entree_decl.id.clone()),
                    declared_package: entree_decl.nom.clone(),
                    registry: registre.clone(),
                    candidate_name: entree.nom.clone(),
                    candidate_description: entree
                        .description
                        .clone()
                        .unwrap_or_default(),
                    similarity_score: score.score,
                    severity: severite_pour_score(score.score).to_string(),
                    signals: score.signaux.clone(),
                    score_breakdown: breakdown_depuis(&score),
                });
            }
        }
    }

    // 4) Intra-inventory pass — pair every declared server with every
    //    other and report pairs whose names differ but whose tool /
    //    enum signatures cluster them together.
    for sosie in detecter_sosies_intra(&inventaire) {
        // Recompute the breakdown so the UI can show per-signal scores
        // for intra matches too. `detecter_sosies_intra` only returns
        // the combined score + signaux, not the breakdown.
        let a = inventaire
            .iter()
            .find(|e| e.id == sosie.a_id);
        let b = inventaire
            .iter()
            .find(|e| e.id == sosie.b_id);
        let breakdown = match (a, b) {
            (Some(a), Some(b)) => {
                let s = similarite_combinee_v2(
                    &a.nom,
                    a.description.as_deref(),
                    &a.outils,
                    &b.nom,
                    b.description.as_deref(),
                    Some(&b.outils),
                );
                breakdown_depuis(&s)
            }
            _ => ScoreBreakdown {
                name: 0.0,
                description: 0.0,
                tools: 0.0,
                enums: 0.0,
            },
        };

        matches.push(LookalikeMatch {
            source: "intra-inventory".to_string(),
            declared_id: Some(sosie.a_id.clone()),
            declared_package: sosie.a_nom.clone(),
            registry: "intra".to_string(),
            candidate_name: sosie.b_nom.clone(),
            candidate_description: String::new(),
            similarity_score: sosie.score,
            severity: severite_pour_score(sosie.score).to_string(),
            signals: sosie.signaux.clone(),
            score_breakdown: breakdown,
        });
    }

    // 5) Sort by descending score so the most suspicious come first.
    matches.sort_by(|a, b| {
        b.similarity_score
            .partial_cmp(&a.similarity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(matches)
}
