//! Similarité de marque + vérification SBOM — agent 3.9.
//!
//! Fournit :
//! - `similarite_nom`       : distance Jaro-Winkler sur les noms
//! - `similarite_combinee`  : score pondéré nom (70 %) + description Jaccard (30 %)
//! - `rechercher_sosies`    : filtre les entrées de registre suspectes
//! - `verifier_sbom`        : stub de vérification par URL (délègue à `verifier_hash_bytes`)
//! - `verifier_hash_bytes`  : SHA-256 des bytes comparé à un hash hexadécimal attendu

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use strsim::jaro_winkler;

use super::EntreeRegistre;

// ---------------------------------------------------------------------------
// Similarité de noms
// ---------------------------------------------------------------------------

/// Distance de Jaro-Winkler sur les noms (entre 0.0 et 1.0).
pub fn similarite_nom(a: &str, b: &str) -> f64 {
    jaro_winkler(a, b)
}

// ---------------------------------------------------------------------------
// Similarité de descriptions (Jaccard sur les tokens)
// ---------------------------------------------------------------------------

/// Score de Jaccard sur les ensembles de mots (entre 0.0 et 1.0).
fn jaccard_description(desc_a: &str, desc_b: &str) -> f64 {
    // Cas triviaux
    if desc_a.is_empty() && desc_b.is_empty() {
        return 1.0;
    }
    if desc_a.is_empty() || desc_b.is_empty() {
        return 0.0;
    }

    let tokens_a: HashSet<&str> = desc_a.split_whitespace().collect();
    let tokens_b: HashSet<&str> = desc_b.split_whitespace().collect();

    let intersection = tokens_a.intersection(&tokens_b).count() as f64;
    let union = tokens_a.union(&tokens_b).count() as f64;

    if union == 0.0 {
        1.0
    } else {
        intersection / union
    }
}

// ---------------------------------------------------------------------------
// Score combiné
// ---------------------------------------------------------------------------

/// Score combiné nom (70 %) + description Jaccard (30 %), entre 0.0 et 1.0.
pub fn similarite_combinee(nom_a: &str, desc_a: &str, nom_b: &str, desc_b: &str) -> f64 {
    let score_nom = similarite_nom(nom_a, nom_b);
    let score_desc = jaccard_description(desc_a, desc_b);
    0.7 * score_nom + 0.3 * score_desc
}

// ---------------------------------------------------------------------------
// Recherche de sosies dans le registre
// ---------------------------------------------------------------------------

/// Retourne les entrées du registre dont le nom est suspectément proche
/// du nom cible (score ≥ seuil), triées par score décroissant.
pub fn rechercher_sosies(
    nom_cible: &str,
    description_cible: &str,
    entrees: &[EntreeRegistre],
    seuil: f64,
) -> Vec<(EntreeRegistre, f64)> {
    let mut resultats: Vec<(EntreeRegistre, f64)> = entrees
        .iter()
        .filter_map(|entree| {
            let score =
                similarite_combinee(nom_cible, description_cible, &entree.nom, &entree.description);
            if score >= seuil {
                Some((entree.clone(), score))
            } else {
                None
            }
        })
        .collect();

    // Tri décroissant par score
    resultats.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    resultats
}

// ---------------------------------------------------------------------------
// Vérification d'intégrité binaire / SBOM
// ---------------------------------------------------------------------------

/// Variante synchrone : calcule le SHA-256 des bytes et compare au hash hexadécimal attendu.
/// Retourne `true` si le hash correspond, `false` sinon.
pub fn verifier_hash_bytes(bytes: &[u8], hash_attendu: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let hash_calcule = hex::encode(hasher.finalize());
    // Comparaison insensible à la casse
    hash_calcule.eq_ignore_ascii_case(hash_attendu.trim())
}

/// Stub v1 : dans cette version la récupération HTTP n'est pas implémentée.
/// Retourne toujours `Ok(false)` avec un avertissement dans les logs.
/// En v2, cette fonction téléchargera le SBOM à `url` et calculera son hash.
pub fn verifier_sbom(url: &str, hash_attendu: &str) -> anyhow::Result<bool> {
    tracing::warn!(
        url = url,
        hash_attendu = hash_attendu,
        "verifier_sbom : téléchargement HTTP non implémenté en v1 — retourne false"
    );
    Ok(false)
}

// ---------------------------------------------------------------------------
// Tests unitaires internes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entree(nom: &str, description: &str) -> EntreeRegistre {
        EntreeRegistre {
            registre: "test-registre".to_string(),
            nom: nom.to_string(),
            description: description.to_string(),
            hash_binaire: None,
            sbom_url: None,
            publie_par: None,
            url_serveur: None,
        }
    }

    #[test]
    fn nom_identique_vaut_un() {
        let score = similarite_nom("filesystem-server", "filesystem-server");
        assert!(
            (score - 1.0).abs() < f64::EPSILON,
            "score attendu 1.0, obtenu {score}"
        );
    }

    #[test]
    fn nom_quasi_identique_superieur_a_09() {
        // "filesystern-server" : une lettre transposée
        let score = similarite_nom("filesystem-server", "filesystern-server");
        assert!(
            score >= 0.9,
            "score attendu ≥ 0.9, obtenu {score}"
        );
    }

    #[test]
    fn noms_tres_differents_proches_de_zero() {
        let score = similarite_nom("filesystem-server", "payment-gateway");
        assert!(score < 0.5, "score attendu < 0.5, obtenu {score}");
    }

    #[test]
    fn rechercher_sosies_trie_par_score_decroissant() {
        let entrees = vec![
            entree("filesystem-server", "accès au système de fichiers"),
            entree("filesysten-server", "accès au système de fichiers"),
            entree("payment-gateway", "passerelle de paiement"),
            entree("filesysem-server", "accès fichiers"),
        ];

        let resultats = rechercher_sosies(
            "filesystem-server",
            "accès au système de fichiers",
            &entrees,
            0.7,
        );

        // Au moins deux résultats au-dessus du seuil
        assert!(resultats.len() >= 2, "attendu ≥ 2 résultats, obtenu {}", resultats.len());

        // Vérification du tri décroissant
        for fenetre in resultats.windows(2) {
            assert!(
                fenetre[0].1 >= fenetre[1].1,
                "ordre incorrect : {:.4} < {:.4}",
                fenetre[0].1,
                fenetre[1].1
            );
        }

        // Le premier doit être le serveur identique (score 1.0)
        assert!(
            (resultats[0].1 - 1.0).abs() < f64::EPSILON,
            "premier résultat attendu score 1.0, obtenu {:.4}",
            resultats[0].1
        );
    }

    #[test]
    fn verifier_hash_bytes_detecte_corruption() {
        let bytes = b"contenu du binaire legitime";
        let hash_correct = hex::encode(sha2::Sha256::digest(bytes));

        // Bytes corrompus : un octet modifié
        let mut bytes_corrompus = bytes.to_vec();
        bytes_corrompus[0] ^= 0xFF;

        assert!(
            !verifier_hash_bytes(&bytes_corrompus, &hash_correct),
            "la corruption aurait dû être détectée"
        );
    }

    #[test]
    fn verifier_hash_bytes_accepte_hash_correct() {
        let bytes = b"contenu du binaire legitime";
        let hash_correct = hex::encode(sha2::Sha256::digest(bytes));

        assert!(
            verifier_hash_bytes(bytes, &hash_correct),
            "le hash correct aurait dû être accepté"
        );
    }

    #[test]
    fn verifier_hash_bytes_insensible_a_la_casse() {
        let bytes = b"test casse";
        let hash_minuscule = hex::encode(sha2::Sha256::digest(bytes));
        let hash_majuscule = hash_minuscule.to_uppercase();

        assert!(
            verifier_hash_bytes(bytes, &hash_majuscule),
            "la comparaison doit être insensible à la casse"
        );
    }
}
