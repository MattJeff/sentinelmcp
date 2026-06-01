//! Tests d'intégration du détecteur de portée (agent 1.7).

use sentinel_protocol::{Outil, Portee};
use sentinel_scan::scope::{inferer_portee, jeu_heuristiques};
use serde_json::json;
use std::collections::BTreeMap;

/// Construit un outil minimal avec nom et description optionnelle.
fn outil(nom: &str, desc: Option<&str>) -> Outil {
    Outil {
        nom: nom.to_string(),
        description: desc.map(str::to_string),
        input_schema: json!({}),
        meta: BTreeMap::new(),
    }
}

// --- Test 1 : read_file → Filesystem + Lecture ---
#[test]
fn test_read_file_detecte_filesystem_et_lecture() {
    let outils = vec![outil("read_file", None)];
    let portees = inferer_portee(&outils);
    assert!(portees.contains(&Portee::Filesystem), "doit contenir Filesystem");
    assert!(portees.contains(&Portee::Lecture),    "doit contenir Lecture");
    assert!(!portees.contains(&Portee::Inconnu),   "ne doit pas contenir Inconnu");
}

// --- Test 2 : outil `query_records` avec description "SQL select" → BaseDonnees + Lecture ---
// Le nom `query_records` déclenche à la fois `query` (BaseDonnees) et `query_` (Lecture).
#[test]
fn test_query_sql_select_detecte_base_de_donnees_et_lecture() {
    let outils = vec![outil("query_records", Some("Execute a SQL select on the database"))];
    let portees = inferer_portee(&outils);
    assert!(portees.contains(&Portee::BaseDonnees), "doit contenir BaseDonnees");
    assert!(portees.contains(&Portee::Lecture),     "doit contenir Lecture (query_)");
}

// --- Test 3 : send_webhook → ApiExterne + Ecriture + Reseau ---
#[test]
fn test_send_webhook_detecte_api_ecriture_reseau() {
    // "send_" → Ecriture, "webhook" → ApiExterne
    // "port" dans la description → Reseau
    let outils = vec![outil(
        "send_webhook",
        Some("Sends an HTTP POST to a remote endpoint on a given port"),
    )];
    let portees = inferer_portee(&outils);
    assert!(portees.contains(&Portee::ApiExterne), "doit contenir ApiExterne");
    assert!(portees.contains(&Portee::Ecriture),   "doit contenir Ecriture");
    assert!(portees.contains(&Portee::Reseau),     "doit contenir Reseau");
}

// --- Test 4 : description mentionnant ~/.ssh → Filesystem + Secrets ---
#[test]
fn test_ssh_path_detecte_filesystem_et_secrets() {
    let outils = vec![outil(
        "get_key",
        Some("Reads the private key from ~/.ssh/id_rsa"),
    )];
    let portees = inferer_portee(&outils);
    assert!(portees.contains(&Portee::Filesystem), "doit contenir Filesystem (~/\\.ssh)");
    assert!(portees.contains(&Portee::Secrets),    "doit contenir Secrets (ssh)");
}

// --- Test 5 : outils vides → Inconnu ---
#[test]
fn test_aucun_outil_renvoie_inconnu() {
    let portees = inferer_portee(&[]);
    assert_eq!(portees, vec![Portee::Inconnu]);
}

// --- Test 6 : outil sans heuristique → Inconnu seul ---
#[test]
fn test_outil_sans_match_renvoie_inconnu() {
    let outils = vec![outil("foo_bar", Some("Does absolutely nothing recognizable"))];
    let portees = inferer_portee(&outils);
    assert_eq!(portees, vec![Portee::Inconnu]);
}

// --- Test 7 : déduplication — deux outils identiques ne doublonnent pas la portée ---
#[test]
fn test_deduplication_portees() {
    let outils = vec![
        outil("read_file", None),
        outil("read_file", Some("Read a file from the filesystem path")),
    ];
    let portees = inferer_portee(&outils);
    // Chaque portée ne doit apparaître qu'une seule fois.
    let nb_filesystem = portees.iter().filter(|&&p| p == Portee::Filesystem).count();
    let nb_lecture    = portees.iter().filter(|&&p| p == Portee::Lecture).count();
    assert_eq!(nb_filesystem, 1, "Filesystem ne doit apparaître qu'une fois");
    assert_eq!(nb_lecture, 1,    "Lecture ne doit apparaître qu'une fois");
}

// --- Test 8 : tri stable — l'ordre est toujours le même pour les mêmes portées ---
#[test]
fn test_tri_stable() {
    let outils_a = vec![
        outil("write_file", None),
        outil("http_get",   None),
    ];
    let outils_b = vec![
        outil("http_get",   None),
        outil("write_file", None),
    ];
    let portees_a = inferer_portee(&outils_a);
    let portees_b = inferer_portee(&outils_b);
    assert_eq!(portees_a, portees_b, "le tri doit être déterministe quel que soit l'ordre des outils");
}

// --- Test 9 : mix lecture-secret + écriture-externe (signal d'exfiltration pour agent 3.7) ---
#[test]
fn test_mix_lecture_secret_ecriture_externe() {
    // Scénario exfiltration : lire un token puis l'envoyer via HTTP.
    let outils = vec![
        outil("get_token",    Some("Retrieves the API token from the credential store")),
        outil("post_request", Some("Sends an HTTP request to an external URL")),
    ];
    let portees = inferer_portee(&outils);
    assert!(portees.contains(&Portee::Lecture),    "doit contenir Lecture");
    assert!(portees.contains(&Portee::Secrets),    "doit contenir Secrets");
    assert!(portees.contains(&Portee::Ecriture),   "doit contenir Ecriture");
    assert!(portees.contains(&Portee::ApiExterne), "doit contenir ApiExterne");
    // Ce jeu de portées doit déclencher le détecteur d'exfiltration (agent 3.7).
    assert!(!portees.contains(&Portee::Inconnu),   "ne doit pas contenir Inconnu");
}

// --- Test 10 : jeu_heuristiques non vide et cohérent ---
#[test]
fn test_jeu_heuristiques_non_vide() {
    let heuristiques = jeu_heuristiques();
    assert!(!heuristiques.is_empty(), "la table d'heuristiques ne doit pas être vide");
    // Chaque portée référencée doit être une variante connue (pas Inconnu).
    for (motif, portee) in &heuristiques {
        assert_ne!(*portee, Portee::Inconnu, "motif '{motif}' ne doit pas mapper vers Inconnu");
        assert!(!motif.is_empty(), "le motif ne doit pas être vide");
    }
}
