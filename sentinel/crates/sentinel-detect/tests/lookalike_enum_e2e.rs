//! Test d'intégration end-to-end — agent L19.
//!
//! Vérifie que le pipeline de détection de sosies intra-inventaire
//! identifie un imitateur dont le nom diffère trop pour que la seule
//! distance de Jaro-Winkler atteigne 0.85 mais dont les outils et leurs
//! enums recouvrent intégralement ceux du serveur déclaré.
//!
//! Scénario :
//! - Serveur déclaré : `fs-helper` avec description "filesystem helper"
//!   exposant trois outils (`read_file`, `write_file`, `list_directory`)
//!   dont chaque schéma porte un `enum` distinct.
//! - Candidat        : `filesystem-buddy` avec exactement la même
//!   description, les mêmes noms d'outils et les mêmes enums.
//!
//! La similarité de nom (Jaro-Winkler) entre `fs-helper` et
//! `filesystem-buddy` est inférieure à 0.7 — sans le renfort apporté par
//! `tool-overlap` + `enum-overlap`, le score combiné v2 ne franchirait
//! jamais le seuil 0.85.

use sentinel_detect::lookalikes::{
    intra_inventory::{detecter_sosies_intra, EntreeInventaire},
    similarity::similarite_combinee_v2,
    SignatureOutil,
};

/// Construit la triplette `SignatureOutil` partagée par le serveur
/// déclaré et son sosie : trois outils filesystem aux noms identiques et
/// dotés des mêmes domaines de valeurs `enum`.
fn outils_filesystem() -> Vec<SignatureOutil> {
    vec![
        SignatureOutil {
            nom: "read_file".to_string(),
            enums_tries: vec!["no".to_string(), "yes".to_string()],
            description_empreinte: String::new(),
        },
        SignatureOutil {
            nom: "write_file".to_string(),
            enums_tries: vec!["force".to_string(), "safe".to_string()],
            description_empreinte: String::new(),
        },
        SignatureOutil {
            nom: "list_directory".to_string(),
            enums_tries: vec!["flat".to_string(), "recursive".to_string()],
            description_empreinte: String::new(),
        },
    ]
}

#[test]
fn enum_overlap_compense_un_nom_eloigne_dans_similarite_combinee_v2() {
    let outils = outils_filesystem();

    let res = similarite_combinee_v2(
        "fs-helper",
        Some("filesystem helper"),
        &outils,
        "filesystem-buddy",
        Some("filesystem helper"),
        Some(&outils),
    );

    // La distance de Jaro-Winkler entre les deux noms reste bien en
    // dessous du seuil individuel 0.7 : sans le renfort outils+enums le
    // signal "name" ne serait pas remonté et le score combiné ne
    // franchirait jamais 0.85.
    assert!(
        res.nom < 0.7,
        "Jaro-Winkler aurait dû rester sous 0.7 pour valider le scénario, obtenu {}",
        res.nom
    );

    // Score combiné v2 attendu :
    // 0.30*≈0.60 + 0.25*1.0 + 0.30*1.0 + 0.15*1.0 ≈ 0.88
    assert!(
        res.score >= 0.85,
        "score combiné attendu ≥ 0.85, obtenu {}",
        res.score
    );

    // Les outils et leurs enums sont parfaitement recouvrants.
    assert!((res.outils - 1.0).abs() < f64::EPSILON);
    assert!((res.enums - 1.0).abs() < f64::EPSILON);

    // Les deux signaux d'imitation par signatures doivent être remontés.
    assert!(
        res.signaux.iter().any(|s| s == "tool-overlap"),
        "signal `tool-overlap` absent : {:?}",
        res.signaux
    );
    assert!(
        res.signaux.iter().any(|s| s == "enum-overlap"),
        "signal `enum-overlap` absent : {:?}",
        res.signaux
    );
}

#[test]
fn detecter_sosies_intra_repere_la_paire_fs_helper_filesystem_buddy() {
    let outils = outils_filesystem();

    let inventaire = vec![
        EntreeInventaire {
            id: "srv-001".to_string(),
            nom: "fs-helper".to_string(),
            description: Some("filesystem helper".to_string()),
            outils: outils.clone(),
        },
        EntreeInventaire {
            id: "srv-002".to_string(),
            nom: "filesystem-buddy".to_string(),
            description: Some("filesystem helper".to_string()),
            outils,
        },
    ];

    let sosies = detecter_sosies_intra(&inventaire);

    assert_eq!(
        sosies.len(),
        1,
        "exactement une paire attendue, obtenu {:?}",
        sosies
    );

    let paire = &sosies[0];
    assert_eq!(paire.a_id, "srv-001");
    assert_eq!(paire.a_nom, "fs-helper");
    assert_eq!(paire.b_id, "srv-002");
    assert_eq!(paire.b_nom, "filesystem-buddy");
    assert!(
        paire.score >= 0.85,
        "score paire attendu ≥ 0.85, obtenu {}",
        paire.score
    );
    assert!(
        paire.signaux.iter().any(|s| s == "tool-overlap"),
        "signal `tool-overlap` absent de la paire : {:?}",
        paire.signaux
    );
    assert!(
        paire.signaux.iter().any(|s| s == "enum-overlap"),
        "signal `enum-overlap` absent de la paire : {:?}",
        paire.signaux
    );
}
