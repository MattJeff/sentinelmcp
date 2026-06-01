//! Integration tests for the trust-graph / blast-radius module (agent X4).
//!
//! Run with: `cargo test -p sentinel-discovery --test trust_graph`.

use sentinel_discovery::model::{ClientDecouvert, ClientKind, ServeurMcpDeclare};
use sentinel_discovery::trust_graph::{ConstructeurGraphe, GrapheConfiance};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serveur_stdio(nom: &str, commande: &str, args: &[&str]) -> ServeurMcpDeclare {
    ServeurMcpDeclare {
        nom: nom.to_string(),
        transport: "stdio".to_string(),
        commande: Some(commande.to_string()),
        args: args.iter().map(|s| s.to_string()).collect(),
        env_keys: vec![],
        url: None,
        disabled: false,
    }
}

fn client_avec(kind: ClientKind, serveurs: Vec<ServeurMcpDeclare>) -> ClientDecouvert {
    let mut c = ClientDecouvert::nouveau(kind);
    c.serveurs = serveurs;
    c
}

fn portees_de<'a>(g: &'a GrapheConfiance, id: &str) -> &'a [String] {
    &g.serveurs.iter().find(|s| s.id == id).expect("server").portees
}

// ---------------------------------------------------------------------------
// 1. server-filesystem + writable path => blast_radius >= 8
// ---------------------------------------------------------------------------

#[test]
fn filesystem_avec_chemin_donne_au_moins_huit_points() {
    let client = client_avec(
        ClientKind::ClaudeDesktop,
        vec![serveur_stdio(
            "fs",
            "npx",
            &[
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/Users/alice/Documents",
            ],
        )],
    );

    let g = ConstructeurGraphe::construire(&[client]);
    assert_eq!(g.clients.len(), 1, "one client expected");
    assert_eq!(g.serveurs.len(), 1, "one server expected");
    assert_eq!(g.aretes.len(), 1, "one edge expected");

    let blast = g.clients[0].blast_radius;
    assert!(
        blast >= 8.0,
        "filesystem + writable path must score >= 8, got {blast}"
    );

    let portees = portees_de(&g, &g.serveurs[0].id);
    assert!(portees.iter().any(|p| p == "filesystem"));
    assert!(portees.iter().any(|p| p == "write"));

    // `indice_max` is the max client blast radius.
    assert!((g.indice_max - blast).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// 2. Two clients sharing the same server are both edged correctly.
// ---------------------------------------------------------------------------

#[test]
fn deux_clients_partagent_un_meme_serveur() {
    let serveur = serveur_stdio(
        "gh",
        "npx",
        &["-y", "@modelcontextprotocol/server-github"],
    );

    let c1 = client_avec(ClientKind::Cursor, vec![serveur.clone()]);
    let c2 = client_avec(ClientKind::Windsurf, vec![serveur]);

    let g = ConstructeurGraphe::construire(&[c1, c2]);

    // Server is deduplicated.
    assert_eq!(
        g.serveurs.len(),
        1,
        "identical declared servers must be deduplicated"
    );
    // Both clients are present.
    assert_eq!(g.clients.len(), 2);
    // One edge per client, both pointing to the same server node.
    assert_eq!(g.aretes.len(), 2);
    let cible = &g.serveurs[0].id;
    assert!(g.aretes.iter().all(|a| &a.cible == cible));
    let sources: Vec<&str> = g.aretes.iter().map(|a| a.source.as_str()).collect();
    assert_ne!(sources[0], sources[1], "client ids must differ");

    // Both clients should have the same (>0) blast radius (github => secrets).
    assert!(g.clients[0].blast_radius >= 10.0);
    assert!(g.clients[1].blast_radius >= 10.0);
}

// ---------------------------------------------------------------------------
// 3. server-github => portee `secrets` recognised.
// ---------------------------------------------------------------------------

#[test]
fn github_implique_portee_secrets() {
    let client = client_avec(
        ClientKind::ClaudeCodeCli,
        vec![serveur_stdio(
            "gh",
            "npx",
            &["-y", "@modelcontextprotocol/server-github"],
        )],
    );

    let g = ConstructeurGraphe::construire(&[client]);
    let portees = portees_de(&g, &g.serveurs[0].id);
    assert!(
        portees.iter().any(|p| p == "secrets"),
        "github server must carry the `secrets` scope, got {portees:?}"
    );
    assert!(
        portees.iter().any(|p| p == "external_api"),
        "github server must carry the `external_api` scope, got {portees:?}"
    );
    // Secrets weight = 10 by itself.
    assert!(g.clients[0].blast_radius >= 10.0);
}

// ---------------------------------------------------------------------------
// 4. Empty client list => empty graph.
// ---------------------------------------------------------------------------

#[test]
fn liste_vide_donne_graphe_vide() {
    let g = ConstructeurGraphe::construire(&[]);
    assert!(g.clients.is_empty());
    assert!(g.serveurs.is_empty());
    assert!(g.aretes.is_empty());
    assert_eq!(g.indice_max, 0.0);
}

// ---------------------------------------------------------------------------
// Bonus: disabled servers don't inflate blast radius.
// ---------------------------------------------------------------------------

#[test]
fn serveur_desactive_ne_compte_pas() {
    let mut srv = serveur_stdio(
        "fs",
        "npx",
        &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    );
    srv.disabled = true;

    let client = client_avec(ClientKind::Zed, vec![srv]);
    let g = ConstructeurGraphe::construire(&[client]);

    assert_eq!(g.clients.len(), 1);
    assert_eq!(g.serveurs.len(), 0, "disabled servers must be skipped");
    assert_eq!(g.aretes.len(), 0);
    assert_eq!(g.clients[0].blast_radius, 0.0);
}
