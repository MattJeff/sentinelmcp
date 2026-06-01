//! Tests d'intégration — DetecteurInterSession (agent 2.5).
//!
//! Scénarios couverts :
//!   1. Aucune dérive (toute la série correspond à la baseline).
//!   2. Divergence simple (exactement 1 session diffère).
//!   3. Dérive lente (≥ 3 sessions consécutives divergentes).
//!   4. Série mixte (alternance sans 3 consécutives → Divergence, pas DeriveLente).

use chrono::Utc;
use sentinel_monitor::inter_session::{DetecteurInterSession, EmpreinteSession, NiveauDerive};
use sentinel_protocol::{Baseline, Empreinte};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Construit une baseline minimale avec l'empreinte serveur fournie.
fn baseline_avec_empreinte(valeur: &str) -> Baseline {
    Baseline {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        empreinte_serveur: Empreinte::new(valeur),
        empreintes_outils: BTreeMap::new(),
        outils: vec![],
        date_approbation: Utc::now(),
        approuve_par: "test".to_string(),
    }
}

/// Construit une EmpreinteSession avec l'empreinte fournie.
fn session(empreinte_valeur: &str) -> EmpreinteSession {
    EmpreinteSession {
        session_id: Uuid::new_v4().to_string(),
        empreinte: Empreinte::new(empreinte_valeur),
        horodatage: Utc::now(),
    }
}

// Test 1 : série entièrement conforme à la baseline → Aucune.
#[test]
fn aucune_derive_quand_toutes_sessions_conformes() {
    let baseline = baseline_avec_empreinte("hash_reference");
    let historique = vec![
        session("hash_reference"),
        session("hash_reference"),
        session("hash_reference"),
    ];

    let niveau = DetecteurInterSession::evaluer_serie(&baseline, &historique);
    assert_eq!(niveau, NiveauDerive::Aucune);
}

// Test 2 : une seule session diffère → Divergence.
#[test]
fn divergence_simple_quand_une_seule_session_differe() {
    let baseline = baseline_avec_empreinte("hash_reference");
    let historique = vec![
        session("hash_reference"),
        session("hash_modifie"),   // unique divergence
        session("hash_reference"),
        session("hash_reference"),
    ];

    let niveau = DetecteurInterSession::evaluer_serie(&baseline, &historique);
    assert_eq!(niveau, NiveauDerive::Divergence);
}

// Test 3 : trois sessions consécutives divergentes → DeriveLente.
#[test]
fn derive_lente_quand_trois_sessions_consecutives_divergent() {
    let baseline = baseline_avec_empreinte("hash_reference");
    let historique = vec![
        session("hash_reference"),   // conforme
        session("hash_derive_1"),    // diverge — début séquence
        session("hash_derive_2"),    // diverge
        session("hash_derive_3"),    // diverge — 3 consécutives atteintes
        session("hash_reference"),   // retour conforme
    ];

    let niveau = DetecteurInterSession::evaluer_serie(&baseline, &historique);
    assert_eq!(niveau, NiveauDerive::DeriveLente);
}

// Test 4 : série mixte avec deux blocs de divergences séparés mais jamais 3 consécutives.
//          Résultat attendu : Divergence (pas DeriveLente).
#[test]
fn serie_mixte_sans_trois_consecutives_renvoie_divergence() {
    let baseline = baseline_avec_empreinte("hash_reference");
    // Deux paires de divergences séparées par une session conforme.
    // Maximum consécutif = 2 → pas de DeriveLente.
    let historique = vec![
        session("hash_reference"),  // conforme
        session("hash_a"),          // diverge — bloc 1 début
        session("hash_b"),          // diverge — bloc 1 fin (2 consécutives)
        session("hash_reference"),  // conforme — coupure
        session("hash_c"),          // diverge — bloc 2 début
        session("hash_d"),          // diverge — bloc 2 fin (2 consécutives)
        session("hash_reference"),  // conforme
    ];

    let niveau = DetecteurInterSession::evaluer_serie(&baseline, &historique);
    assert_eq!(niveau, NiveauDerive::Divergence);
}

// Test 5 : historique vide → Aucune (pas de données signifie pas de dérive).
#[test]
fn historique_vide_renvoie_aucune() {
    let baseline = baseline_avec_empreinte("hash_reference");
    let niveau = DetecteurInterSession::evaluer_serie(&baseline, &[]);
    assert_eq!(niveau, NiveauDerive::Aucune);
}

// Test 6 : méthode statique `derive` correcte pour égalité et inégalité.
#[test]
fn methode_derive_detecte_correctement_egalite_et_inegalite() {
    let baseline = baseline_avec_empreinte("hash_stable");

    let emp_identique = Empreinte::new("hash_stable");
    let emp_differente = Empreinte::new("hash_change");

    assert!(
        !DetecteurInterSession::derive(&baseline, &emp_identique),
        "empreinte identique ne doit pas être marquée comme dérive"
    );
    assert!(
        DetecteurInterSession::derive(&baseline, &emp_differente),
        "empreinte différente doit être marquée comme dérive"
    );
}
