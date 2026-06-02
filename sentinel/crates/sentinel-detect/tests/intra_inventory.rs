//! Tests d'intégration — détection de sosies intra-inventaire (agent L10).

use sentinel_detect::lookalikes::intra_inventory::{detecter_sosies_intra, EntreeInventaire};
use sentinel_detect::lookalikes::SignatureOutil;

fn signature(nom: &str, enums: &[&str]) -> SignatureOutil {
    SignatureOutil {
        nom: nom.to_string(),
        enums_tries: enums.iter().map(|s| s.to_string()).collect(),
        description_empreinte: String::new(),
    }
}

fn entree(id: &str, nom: &str, description: Option<&str>, outils: Vec<SignatureOutil>) -> EntreeInventaire {
    EntreeInventaire {
        id: id.to_string(),
        nom: nom.to_string(),
        description: description.map(|s| s.to_string()),
        outils,
    }
}

#[test]
fn inventaire_vide_retourne_vide() {
    let sosies = detecter_sosies_intra(&[]);
    assert!(sosies.is_empty(), "un inventaire vide ne doit produire aucun sosie");
}

#[test]
fn deux_serveurs_outils_identiques_nom_proche_detectes_comme_sosies() {
    // Deux serveurs aux noms proches partageant exactement la même
    // palette d'outils + enums + description : couverture maximale
    // sur toutes les composantes du score combiné v2.
    let outils = vec![
        signature("fs.open", &["append", "read", "write"]),
        signature("fs.close", &["force"]),
        signature("fs.read", &["binary", "text"]),
    ];
    let inventaire = vec![
        entree(
            "srv-1",
            "filesystem-server",
            Some("accès au système de fichiers local"),
            outils.clone(),
        ),
        entree(
            "srv-2",
            "filesystern-server",
            Some("accès au système de fichiers local"),
            outils.clone(),
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert_eq!(sosies.len(), 1, "attendu exactement 1 sosie, obtenu {}", sosies.len());

    let s = &sosies[0];
    assert!(s.score >= 0.85, "score attendu ≥ 0.85, obtenu {:.4}", s.score);
    assert_ne!(s.a_nom, s.b_nom, "les noms d'une paire sosie doivent différer");
    let ids = [s.a_id.as_str(), s.b_id.as_str()];
    assert!(ids.contains(&"srv-1"));
    assert!(ids.contains(&"srv-2"));
}

#[test]
fn deux_serveurs_sans_rapport_ne_produisent_aucun_sosie() {
    let inventaire = vec![
        entree(
            "srv-1",
            "filesystem-server",
            Some("accès au système de fichiers local"),
            vec![
                signature("fs.open", &["append", "read", "write"]),
                signature("fs.close", &["force"]),
            ],
        ),
        entree(
            "srv-2",
            "payment-gateway",
            Some("passerelle de paiement par carte bancaire"),
            vec![
                signature("pay.charge", &["eur", "usd"]),
                signature("pay.refund", &["full", "partial"]),
            ],
        ),
    ];

    let sosies = detecter_sosies_intra(&inventaire);
    assert!(
        sosies.is_empty(),
        "deux serveurs sans rapport ne doivent produire aucun sosie, obtenu {}",
        sosies.len()
    );
}
