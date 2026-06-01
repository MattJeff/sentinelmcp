//! Harnais de validation du corpus d'attaques — agent 3.10.
//!
//! Couverture :
//!   1. `cas()` retourne ≥ 15 entrées.
//!   2. Tous les cas poisoning sont détectés par `InspecteurPoisoning`.
//!   3. Aucun cas bénin n'est détecté par `InspecteurPoisoning`.
//!   4. `rapport_couverture()` produit une couverture ≥ 80 %.

use sentinel_detect::corpus::{CorpusAttaques, rapport_couverture};
use sentinel_detect::poisoning::InspecteurPoisoning;

// ---------------------------------------------------------------------------
// Test 1 : le corpus contient au moins 15 cas
// ---------------------------------------------------------------------------

#[test]
fn corpus_contient_au_moins_15_cas() {
    let cas = CorpusAttaques::cas();
    assert!(
        cas.len() >= 15,
        "Le corpus doit contenir ≥ 15 cas, il en contient {}",
        cas.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2 : tous les cas poisoning sont détectés
// ---------------------------------------------------------------------------

#[test]
fn tous_les_cas_poisoning_detectes() {
    let cas = CorpusAttaques::cas();
    let cas_poisoning: Vec<_> = cas.iter()
        .filter(|c| c.categorie == "poisoning")
        .collect();

    assert!(
        !cas_poisoning.is_empty(),
        "Aucun cas poisoning dans le corpus"
    );

    let mut echecs = Vec::new();
    for c in &cas_poisoning {
        let constats = InspecteurPoisoning::inspecter(&c.outils);
        if constats.is_empty() {
            echecs.push(c.id);
        }
    }

    assert!(
        echecs.is_empty(),
        "Cas poisoning NON détectés par InspecteurPoisoning : {:?}",
        echecs
    );
}

// ---------------------------------------------------------------------------
// Test 3 : aucun cas bénin ne déclenche une fausse alarme
// ---------------------------------------------------------------------------

#[test]
fn aucun_cas_benin_detecte() {
    let cas = CorpusAttaques::cas();
    let cas_benins: Vec<_> = cas.iter()
        .filter(|c| c.categorie == "benin")
        .collect();

    assert!(
        !cas_benins.is_empty(),
        "Aucun cas bénin dans le corpus"
    );

    let mut faux_positifs: Vec<(&&str, Vec<String>)> = Vec::new();
    for c in &cas_benins {
        let constats = InspecteurPoisoning::inspecter(&c.outils);
        if !constats.is_empty() {
            let patterns: Vec<String> = constats.iter().map(|x| x.pattern.clone()).collect();
            faux_positifs.push((&c.id, patterns));
        }
    }

    assert!(
        faux_positifs.is_empty(),
        "Faux positifs détectés sur des cas bénins : {:?}",
        faux_positifs
    );
}

// ---------------------------------------------------------------------------
// Test 4 : couverture ≥ 80 %
// ---------------------------------------------------------------------------

#[test]
fn rapport_couverture_superieur_80_pourcent() {
    let rapport = rapport_couverture();

    assert!(
        rapport.couverture_pourcentage >= 80.0,
        "Couverture insuffisante : {:.1}% (seuil 80%). VP={}, FN={}, FP={}",
        rapport.couverture_pourcentage,
        rapport.vrais_positifs,
        rapport.faux_negatifs,
        rapport.faux_positifs,
    );

    assert!(
        !rapport.couverture_safe_mcp.is_empty(),
        "Aucun identifiant SAFE-MCP couvert dans le rapport"
    );

    // Vérifie que SAFE-T1001 est couvert (poisoning).
    assert!(
        rapport.couverture_safe_mcp.contains(&"SAFE-T1001".to_string()),
        "SAFE-T1001 devrait être couvert ; identifiants présents : {:?}",
        rapport.couverture_safe_mcp
    );
}
