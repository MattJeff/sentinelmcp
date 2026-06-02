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

use super::{EntreeRegistre, SignatureOutil};

// ---------------------------------------------------------------------------
// Score combiné v2 (avec signatures d'outils)
// ---------------------------------------------------------------------------

/// Résultat détaillé du score combiné v2 — expose la contribution de
/// chaque composante (nom, description, outils, enums) et la liste des
/// signaux dépassant le seuil de confiance individuel (≥ 0.7).
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreCombineV2 {
    /// Score combiné pondéré, normalisé entre 0.0 et 1.0.
    pub score: f64,
    /// Composante nom (Jaro-Winkler).
    pub nom: f64,
    /// Composante description (Jaccard sur tokens, 0.0 si absente).
    pub description: f64,
    /// Composante noms d'outils (Jaccard).
    pub outils: f64,
    /// Composante enums (Jaccard global sur l'union des `enums_tries`).
    pub enums: f64,
    /// Étiquettes des composantes ayant individuellement franchi le seuil 0.7
    /// (ex. `"name"`, `"tool-overlap"`, `"enum-overlap"`, `"description"`).
    pub signaux: Vec<String>,
}

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
// Similarité sur signatures d'outils
// ---------------------------------------------------------------------------

/// Jaccard générique sur deux listes de chaînes (déduplication implicite via
/// `HashSet`). Renvoie 1.0 si les deux listes sont vides, 0.0 si une seule
/// l'est, sinon |A ∩ B| / |A ∪ B|.
fn jaccard_chaines(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: HashSet<&str> = a.iter().map(String::as_str).collect();
    let set_b: HashSet<&str> = b.iter().map(String::as_str).collect();
    let inter = set_a.intersection(&set_b).count() as f64;
    let union = set_a.union(&set_b).count() as f64;
    if union == 0.0 { 1.0 } else { inter / union }
}

/// Score de Jaccard sur deux ensembles de valeurs `enum` déclarées par les
/// schémas d'outils. Pratique pour mesurer le recouvrement de domaines de
/// valeurs entre deux serveurs (`["read","write"]` vs `["read","append"]`).
pub fn similarite_enums(declared: &[String], candidate: &[String]) -> f64 {
    jaccard_chaines(declared, candidate)
}

/// Score de Jaccard sur deux ensembles de noms d'outils MCP. Utilisé comme
/// signal de corrélation : deux serveurs au nom proche mais à la palette
/// d'outils disjointe ne sont pas des sosies plausibles.
pub fn similarite_outils_noms(declared: &[String], candidate: &[String]) -> f64 {
    jaccard_chaines(declared, candidate)
}

/// Score combiné v2 incluant les signatures d'outils.
///
/// Pondérations par défaut :
/// - nom : 0.30 (Jaro-Winkler)
/// - description : 0.25 (Jaccard sur tokens)
/// - outils (noms d'outils) : 0.30 (Jaccard)
/// - enums (union des `enums_tries`) : 0.15 (Jaccard)
///
/// Si `declared_outils` est vide OU `candidate_outils` vaut `None`, les
/// poids `outils` et `enums` sont retirés et la pondération est
/// renormalisée sur `nom` + `description` uniquement (proportions 0.30 et
/// 0.25 → 0.545 et 0.455 après normalisation).
///
/// Le champ `signaux` liste les étiquettes des composantes ayant
/// individuellement franchi le seuil 0.7 :
/// - `"name"` si `nom ≥ 0.7`
/// - `"description"` si `description ≥ 0.7`
/// - `"tool-overlap"` si `outils ≥ 0.7`
/// - `"enum-overlap"` si `enums ≥ 0.7`
pub fn similarite_combinee_v2(
    declared_nom: &str,
    declared_desc: Option<&str>,
    declared_outils: &[SignatureOutil],
    candidate_nom: &str,
    candidate_desc: Option<&str>,
    candidate_outils: Option<&[SignatureOutil]>,
) -> ScoreCombineV2 {
    // Composantes individuelles
    let score_nom = similarite_nom(declared_nom, candidate_nom);
    let score_desc = jaccard_description(
        declared_desc.unwrap_or(""),
        candidate_desc.unwrap_or(""),
    );

    // Outils : Jaccard sur les noms ; enums : Jaccard sur l'union des
    // `enums_tries` de chaque côté. On utilise des valeurs neutres (0.0)
    // quand le mode dégradé s'applique pour ne pas polluer le rapport.
    let (score_outils, score_enums, mode_complet) =
        match (declared_outils.is_empty(), candidate_outils) {
            (false, Some(cand)) => {
                let noms_decl: Vec<String> =
                    declared_outils.iter().map(|o| o.nom.clone()).collect();
                let noms_cand: Vec<String> = cand.iter().map(|o| o.nom.clone()).collect();
                let so = similarite_outils_noms(&noms_decl, &noms_cand);

                let enums_decl: Vec<String> = declared_outils
                    .iter()
                    .flat_map(|o| o.enums_tries.iter().cloned())
                    .collect();
                let enums_cand: Vec<String> = cand
                    .iter()
                    .flat_map(|o| o.enums_tries.iter().cloned())
                    .collect();
                let se = similarite_enums(&enums_decl, &enums_cand);
                (so, se, true)
            }
            _ => (0.0, 0.0, false),
        };

    // Pondération
    let score = if mode_complet {
        0.30 * score_nom + 0.25 * score_desc + 0.30 * score_outils + 0.15 * score_enums
    } else {
        // Renormalisation sur nom + description (0.30 + 0.25 = 0.55).
        let total = 0.30_f64 + 0.25_f64;
        (0.30 * score_nom + 0.25 * score_desc) / total
    };

    // Signaux (composantes ≥ 0.7)
    let mut signaux = Vec::new();
    if score_nom >= 0.7 {
        signaux.push("name".to_string());
    }
    if score_desc >= 0.7 {
        signaux.push("description".to_string());
    }
    if mode_complet && score_outils >= 0.7 {
        signaux.push("tool-overlap".to_string());
    }
    if mode_complet && score_enums >= 0.7 {
        signaux.push("enum-overlap".to_string());
    }

    ScoreCombineV2 {
        score,
        nom: score_nom,
        description: score_desc,
        outils: score_outils,
        enums: score_enums,
        signaux,
    }
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
            let desc_entree = entree.description.as_deref().unwrap_or("");
            let score =
                similarite_combinee(nom_cible, description_cible, &entree.nom, desc_entree);
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
            description: Some(description.to_string()),
            auteur: None,
            url: None,
            outils: None,
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

    // ---------------------------------------------------------------------
    // Tests pour les nouvelles fonctions v2 (signatures d'outils)
    // ---------------------------------------------------------------------

    fn signature(nom: &str, enums: &[&str]) -> SignatureOutil {
        SignatureOutil {
            nom: nom.to_string(),
            enums_tries: enums.iter().map(|s| s.to_string()).collect(),
            description_empreinte: String::new(),
        }
    }

    #[test]
    fn similarite_enums_jaccard_simple() {
        let a = vec!["read".to_string(), "write".to_string(), "append".to_string()];
        let b = vec!["read".to_string(), "write".to_string()];
        // intersection = 2 ("read","write"), union = 3 → 2/3
        let score = similarite_enums(&a, &b);
        assert!(
            (score - (2.0 / 3.0)).abs() < 1e-9,
            "score Jaccard attendu 2/3, obtenu {score}"
        );

        // Deux ensembles vides → 1.0 (convention)
        let vide: Vec<String> = Vec::new();
        assert!((similarite_enums(&vide, &vide) - 1.0).abs() < f64::EPSILON);

        // Un seul ensemble vide → 0.0
        assert_eq!(similarite_enums(&vide, &a), 0.0);
    }

    #[test]
    fn similarite_outils_noms_recouvrement_partiel() {
        let declared = vec!["fs.read".to_string(), "fs.write".to_string(), "fs.stat".to_string()];
        let candidate = vec!["fs.read".to_string(), "fs.write".to_string(), "fs.del".to_string()];
        // intersection = 2, union = 4 → 0.5
        let score = similarite_outils_noms(&declared, &candidate);
        assert!(
            (score - 0.5).abs() < 1e-9,
            "score Jaccard attendu 0.5, obtenu {score}"
        );
    }

    #[test]
    fn similarite_combinee_v2_mode_complet_remonte_les_signaux() {
        let declared = vec![
            signature("fs.read", &["json", "yaml"]),
            signature("fs.write", &["json", "yaml"]),
        ];
        let candidate = vec![
            signature("fs.read", &["json", "yaml"]),
            signature("fs.write", &["json", "yaml"]),
        ];

        let res = similarite_combinee_v2(
            "filesystem-server",
            Some("accès au système de fichiers"),
            &declared,
            "filesystem-server",
            Some("accès au système de fichiers"),
            Some(&candidate),
        );

        // Toutes les composantes valent 1.0 → score combiné 1.0
        assert!((res.nom - 1.0).abs() < f64::EPSILON);
        assert!((res.description - 1.0).abs() < f64::EPSILON);
        assert!((res.outils - 1.0).abs() < f64::EPSILON);
        assert!((res.enums - 1.0).abs() < f64::EPSILON);
        assert!(
            (res.score - 1.0).abs() < 1e-9,
            "score combiné attendu 1.0, obtenu {}",
            res.score
        );

        // Les quatre signaux doivent être remontés
        assert!(res.signaux.contains(&"name".to_string()));
        assert!(res.signaux.contains(&"description".to_string()));
        assert!(res.signaux.contains(&"tool-overlap".to_string()));
        assert!(res.signaux.contains(&"enum-overlap".to_string()));
        assert_eq!(res.signaux.len(), 4);
    }

    #[test]
    fn similarite_combinee_v2_mode_degrade_renormalise_sur_nom_et_description() {
        // declared_outils vide → mode dégradé, poids renormalisés sur nom + desc.
        let declared: Vec<SignatureOutil> = Vec::new();

        let res = similarite_combinee_v2(
            "filesystem-server",
            Some("accès au système de fichiers"),
            &declared,
            "filesystem-server",
            Some("accès au système de fichiers"),
            None,
        );

        // nom = 1.0 et description = 1.0 → score renormalisé doit valoir 1.0.
        assert!((res.nom - 1.0).abs() < f64::EPSILON);
        assert!((res.description - 1.0).abs() < f64::EPSILON);
        assert!(
            (res.score - 1.0).abs() < 1e-9,
            "score renormalisé attendu 1.0, obtenu {}",
            res.score
        );

        // En mode dégradé, ni "tool-overlap" ni "enum-overlap" ne doivent
        // apparaître même si les composantes valent 0.0 (mode neutralisé).
        assert!(!res.signaux.contains(&"tool-overlap".to_string()));
        assert!(!res.signaux.contains(&"enum-overlap".to_string()));
        // Mais "name" et "description" doivent être présents (≥ 0.7).
        assert!(res.signaux.contains(&"name".to_string()));
        assert!(res.signaux.contains(&"description".to_string()));

        // Vérifie que les composantes outils/enums sont neutralisées à 0.0
        // en mode dégradé (et n'ont pas pesé dans le score).
        assert_eq!(res.outils, 0.0);
        assert_eq!(res.enums, 0.0);
    }
}
