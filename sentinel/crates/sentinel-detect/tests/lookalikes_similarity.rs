//! Tests d'intégration — similarité de marque + vérification SBOM (agent 3.9).

use sentinel_detect::lookalikes::{similarity, EntreeRegistre};
use sha2::Digest;

fn entree(nom: &str, description: &str) -> EntreeRegistre {
    EntreeRegistre {
        registre: "registre-test".to_string(),
        nom: nom.to_string(),
        description: Some(description.to_string()),
        auteur: None,
        url: None,
        outils: None,
    }
}

// ---------------------------------------------------------------------------
// Tests de `similarite_nom`
// ---------------------------------------------------------------------------

#[test]
fn similarite_nom_identique_vaut_un() {
    let score = similarity::similarite_nom("filesystem-server", "filesystem-server");
    assert!(
        (score - 1.0).abs() < f64::EPSILON,
        "score attendu 1.0, obtenu {score}"
    );
}

#[test]
fn similarite_nom_quasi_identique_superieur_a_09() {
    let score = similarity::similarite_nom("filesystem-server", "filesystern-server");
    assert!(score >= 0.9, "score attendu ≥ 0.9, obtenu {score}");
}

#[test]
fn similarite_nom_tres_differents_inferieur_a_05() {
    let score = similarity::similarite_nom("filesystem-server", "payment-gateway");
    assert!(score < 0.5, "score attendu < 0.5, obtenu {score}");
}

// ---------------------------------------------------------------------------
// Tests de `rechercher_sosies`
// ---------------------------------------------------------------------------

#[test]
fn rechercher_sosies_trie_correctement_par_score_decroissant() {
    let entrees = vec![
        entree("filesystem-server", "accès au système de fichiers"),
        entree("filesysten-server", "accès au système de fichiers"),
        entree("payment-gateway", "passerelle de paiement"),
        entree("filesysem-server", "accès fichiers"),
    ];

    let resultats = similarity::rechercher_sosies(
        "filesystem-server",
        "accès au système de fichiers",
        &entrees,
        0.7,
    );

    assert!(resultats.len() >= 2, "attendu ≥ 2 résultats, obtenu {}", resultats.len());

    for fenetre in resultats.windows(2) {
        assert!(
            fenetre[0].1 >= fenetre[1].1,
            "ordre incorrect : {:.4} avant {:.4}",
            fenetre[0].1,
            fenetre[1].1
        );
    }
}

#[test]
fn rechercher_sosies_exclut_sous_le_seuil() {
    let entrees = vec![
        entree("payment-gateway", "passerelle de paiement"),
        entree("auth-service", "service d'authentification"),
    ];

    let resultats = similarity::rechercher_sosies(
        "filesystem-server",
        "accès au système de fichiers",
        &entrees,
        0.85,
    );

    assert!(
        resultats.is_empty(),
        "aucun sosie attendu au-dessus du seuil 0.85, obtenu {}",
        resultats.len()
    );
}

// ---------------------------------------------------------------------------
// Tests de `verifier_hash_bytes`
// ---------------------------------------------------------------------------

#[test]
fn verifier_hash_bytes_accepte_hash_correct() {
    let bytes = b"binaire de reference sentinel-mcp v1.0";
    let hash = hex::encode(sha2::Sha256::digest(bytes));

    assert!(
        similarity::verifier_hash_bytes(bytes, &hash),
        "le hash correct doit être accepté"
    );
}

#[test]
fn verifier_hash_bytes_detecte_une_corruption() {
    let bytes = b"binaire de reference sentinel-mcp v1.0";
    let hash = hex::encode(sha2::Sha256::digest(bytes));

    let mut corrompus = bytes.to_vec();
    corrompus[5] ^= 0xAB;

    assert!(
        !similarity::verifier_hash_bytes(&corrompus, &hash),
        "la corruption doit être détectée"
    );
}
