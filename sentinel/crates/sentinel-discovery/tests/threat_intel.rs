//! Integration tests for the bundled threat intelligence feed.
//!
//! These tests exercise [`FluxMenaces::par_defaut`] (which is backed by
//! `include_str!("../data/threat_feed.yaml")`) and the
//! [`FluxMenaces::correspondances`] matcher against synthetic
//! [`ServeurMcpDeclare`] entries.

use sentinel_protocol::ScopeServeur;
use sentinel_discovery::model::ServeurMcpDeclare;
use sentinel_discovery::threat_intel::FluxMenaces;

fn serveur(nom: &str, args: &[&str]) -> ServeurMcpDeclare {
    ServeurMcpDeclare {
        nom: nom.to_string(),
        transport: "stdio".to_string(),
        commande: Some("npx".to_string()),
        args: args.iter().map(|s| s.to_string()).collect(),
        env_keys: vec![],
        url: None,
        disabled: false,
        scope: ScopeServeur::default(),
    }
}

#[test]
fn par_defaut_charge_au_moins_15_entrees() {
    let flux = FluxMenaces::par_defaut();
    assert!(
        flux.entrees.len() >= 15,
        "expected >= 15 threat entries, got {}",
        flux.entrees.len()
    );
    assert!(
        !flux.version_feed.is_empty(),
        "version_feed must be populated"
    );
}

#[test]
fn toutes_les_entrees_sont_bien_formees() {
    let flux = FluxMenaces::par_defaut();
    let mut vus = std::collections::HashSet::new();

    for entree in &flux.entrees {
        // Identifiers must be unique and shaped like MCP-YYYY-NNN.
        assert!(
            vus.insert(entree.identifiant.clone()),
            "duplicate identifiant: {}",
            entree.identifiant
        );
        assert!(
            entree.identifiant.starts_with("MCP-"),
            "unexpected identifiant prefix: {}",
            entree.identifiant
        );

        // Required string fields must be non-empty.
        assert!(
            !entree.package_name.is_empty(),
            "{}: empty package_name",
            entree.identifiant
        );
        assert!(
            !entree.raison.is_empty(),
            "{}: empty raison",
            entree.identifiant
        );

        // Severity must be one of our allowed values.
        let sev = entree.severite.as_str();
        assert!(
            matches!(sev, "critical" | "high" | "medium"),
            "{}: invalid severity {sev:?}",
            entree.identifiant
        );

        // chrono::NaiveDate already parses cleanly via serde; sanity check
        // the year range so we catch obviously bogus entries.
        let y = entree.publie_a.format("%Y").to_string();
        assert!(
            y == "2025" || y == "2026",
            "{}: unexpected publication year {y}",
            entree.identifiant
        );
    }
}

#[test]
fn correspondances_trouve_un_package_connu_par_nom() {
    let flux = FluxMenaces::par_defaut();

    // Exact match via the server's declared `nom`.
    let srv = serveur("mcp-helpful-assistant", &[]);
    let hits = flux.correspondances(&srv);
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one hit for mcp-helpful-assistant, got {hits:?}"
    );
    assert_eq!(hits[0].identifiant, "MCP-2026-010");
    assert_eq!(hits[0].severite, "critical");
    assert!(
        hits[0]
            .references
            .iter()
            .any(|r| r == "SAFE-T1001"),
        "expected SAFE-T1001 reference, got {:?}",
        hits[0].references
    );
}

#[test]
fn correspondances_trouve_un_package_dans_les_args_npx() {
    let flux = FluxMenaces::par_defaut();

    // Typical `npx -y <package>` invocation — package name lives in args.
    let srv = serveur(
        "filesystem",
        &["-y", "@modelcontextprotocol/server-filesystem-1", "/tmp"],
    );
    let hits = flux.correspondances(&srv);
    assert_eq!(hits.len(), 1, "expected one hit for typo-squat in args");
    assert_eq!(hits[0].identifiant, "MCP-2026-001");
    assert_eq!(hits[0].severite, "high");
}

#[test]
fn package_inconnu_retourne_vide() {
    let flux = FluxMenaces::par_defaut();

    let srv = serveur(
        "@modelcontextprotocol/server-filesystem",
        &["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
    );
    let hits = flux.correspondances(&srv);
    assert!(
        hits.is_empty(),
        "legit official package should not match the threat feed, got {hits:?}"
    );

    let srv2 = serveur("totally-unrelated-tool", &["--help"]);
    assert!(flux.correspondances(&srv2).is_empty());
}
