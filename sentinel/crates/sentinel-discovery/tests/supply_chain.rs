//! Integration tests for `sentinel_discovery::supply_chain`.
//!
//! All assertions run against a `wiremock` server so the suite has zero
//! network dependency and is deterministic. A separate `#[ignore]`-d test
//! exercises the real public npm registry for manual smoke-checks.

use sentinel_protocol::ScopeServeur;
use std::time::Duration;

use sentinel_discovery::model::ServeurMcpDeclare;
use sentinel_discovery::supply_chain::{
    extraire_paquet_npm, AttestationSupplyChain, EtatAttestation, VerifierSupplyChain,
};
use serde_json::json;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn serveur_npx(args: &[&str]) -> ServeurMcpDeclare {
    ServeurMcpDeclare {
        nom: "test-serveur".to_string(),
        transport: "stdio".to_string(),
        commande: Some("npx".to_string()),
        args: args.iter().map(|s| s.to_string()).collect(),
        env_keys: vec![],
        url: None,
        disabled: false,
        scope: ScopeServeur::default(),
    }
}

fn verifier_avec_timeout(secs: u64) -> VerifierSupplyChain {
    let client = reqwest::Client::builder()
        .user_agent("sentinel-supply-chain-test/0.1")
        .timeout(Duration::from_secs(secs))
        .build()
        .unwrap();
    VerifierSupplyChain::avec_base_urls(client, Duration::from_secs(secs))
}

// ---------------------------------------------------------------------------
// 1. Pure parser test — no network involved.
// ---------------------------------------------------------------------------

#[test]
fn extrait_paquet_avec_version_pinned() {
    let args: Vec<String> = ["-y", "@scope/pkg@1.2.3", "--root", "/tmp"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (n, v) = extraire_paquet_npm(&args).expect("paquet must be extracted");
    assert_eq!(n, "@scope/pkg");
    assert_eq!(v.as_deref(), Some("1.2.3"));
}

// ---------------------------------------------------------------------------
// 2. Non-npm commands (uvx, absolute path) → NonNpm verdict.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn commande_uvx_donne_non_npm() {
    let verifier = verifier_avec_timeout(8);
    let serveur = ServeurMcpDeclare {
        nom: "py-tool".into(),
        transport: "stdio".into(),
        commande: Some("uvx".into()),
        args: vec!["mcp-server-time".into()],
        env_keys: vec![],
        url: None,
        disabled: false,
        scope: ScopeServeur::default(),
    };
    let att: AttestationSupplyChain = verifier
        .attester_avec_endpoints(&serveur, "http://localhost:1", "http://localhost:1")
        .await;
    assert_eq!(att.etat, EtatAttestation::NonNpm);
    assert!(
        att.notes.iter().any(|n| n.contains("non-npm-python")),
        "expected python note, got {:?}",
        att.notes
    );
    assert!(att.package_name.is_none());
}

#[tokio::test]
async fn commande_binaire_local_donne_non_npm() {
    let verifier = verifier_avec_timeout(8);
    let serveur = ServeurMcpDeclare {
        nom: "local-mcp".into(),
        transport: "stdio".into(),
        commande: Some("/usr/local/bin/my-mcp".into()),
        args: vec![],
        env_keys: vec![],
        url: None,
        disabled: false,
        scope: ScopeServeur::default(),
    };
    let att = verifier
        .attester_avec_endpoints(&serveur, "http://localhost:1", "http://localhost:1")
        .await;
    assert_eq!(att.etat, EtatAttestation::NonNpm);
    assert!(att.notes.iter().any(|n| n.contains("local binary")));
}

// ---------------------------------------------------------------------------
// 3. Happy path — package resolves and metadata is captured.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_resout_metadata_et_renvoie_verifie() {
    let registry = MockServer::start().await;
    let downloads = MockServer::start().await;

    // Accept any path that mentions scope+pkg (wiremock's path matcher decodes
    // percent-encoding, but tracks segments — we use regex to be tolerant).
    Mock::given(method("GET"))
        .and(path_regex(r".*scope.*pkg.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "@scope/pkg",
            "dist-tags": { "latest": "1.2.3" },
            "versions": {
                "1.2.3": {
                    "dist": {
                        "integrity": "sha512-aaaaBBBBccccDDDDeeeeFFFFgggg==",
                        "shasum": "deadbeef"
                    }
                }
            },
            "time": { "1.2.3": "2024-05-01T12:34:56.000Z" },
            "maintainers": [
                { "name": "alice", "email": "a@x.io" },
                { "name": "bob", "email": "b@x.io" }
            ]
        })))
        .mount(&registry)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"/downloads/point/last-week/.*scope.*pkg.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "downloads": 4242u64,
            "package": "@scope/pkg"
        })))
        .mount(&downloads)
        .await;

    let verifier = verifier_avec_timeout(8);
    let serveur = serveur_npx(&["-y", "@scope/pkg@1.2.3"]);

    let att = verifier
        .attester_avec_endpoints(&serveur, &registry.uri(), &downloads.uri())
        .await;

    assert_eq!(att.etat, EtatAttestation::Verifie, "notes={:?}", att.notes);
    assert_eq!(att.package_name.as_deref(), Some("@scope/pkg"));
    assert_eq!(att.version_requise.as_deref(), Some("1.2.3"));
    assert_eq!(att.version_disponible.as_deref(), Some("1.2.3"));
    assert_eq!(
        att.tarball_sha512.as_deref(),
        Some("sha512-aaaaBBBBccccDDDDeeeeFFFFgggg==")
    );
    assert_eq!(att.maintainers, vec!["alice".to_string(), "bob".to_string()]);
    assert_eq!(att.downloads_weekly, Some(4242));
    assert!(att.publie_a.is_some());
}

// ---------------------------------------------------------------------------
// 4. 404 from registry → PackageInconnu (typosquat / unpublished).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_404_donne_package_inconnu() {
    let registry = MockServer::start().await;
    let downloads = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string(r#"{"error":"Not found"}"#))
        .mount(&registry)
        .await;

    let verifier = verifier_avec_timeout(8);
    let serveur = serveur_npx(&["-y", "totally-not-real-mcp@9.9.9"]);

    let att = verifier
        .attester_avec_endpoints(&serveur, &registry.uri(), &downloads.uri())
        .await;
    assert_eq!(att.etat, EtatAttestation::PackageInconnu);
    assert_eq!(att.package_name.as_deref(), Some("totally-not-real-mcp"));
    assert_eq!(att.version_requise.as_deref(), Some("9.9.9"));
}

// ---------------------------------------------------------------------------
// 5. 5xx from registry → ErreurReseau.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_500_donne_erreur_reseau() {
    let registry = MockServer::start().await;
    let downloads = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&registry)
        .await;

    let verifier = verifier_avec_timeout(8);
    let serveur = serveur_npx(&["-y", "any-pkg"]);

    let att = verifier
        .attester_avec_endpoints(&serveur, &registry.uri(), &downloads.uri())
        .await;
    assert_eq!(att.etat, EtatAttestation::ErreurReseau);
}

// ---------------------------------------------------------------------------
// 6. Live test against the real public npm registry — ignored by default.
// ---------------------------------------------------------------------------

/// Run manually with:
/// `cargo test -p sentinel-discovery --test supply_chain -- --ignored host_probe_live_npm --nocapture`
#[tokio::test]
#[ignore]
async fn host_probe_live_npm() {
    let verifier = VerifierSupplyChain::par_defaut();
    let serveur = serveur_npx(&["-y", "@modelcontextprotocol/server-filesystem"]);
    let att = verifier.attester(&serveur).await;
    eprintln!("live attestation = {att:#?}");
    assert!(
        matches!(
            att.etat,
            EtatAttestation::Verifie | EtatAttestation::ErreurReseau
        ),
        "unexpected etat: {:?}",
        att.etat
    );
}
