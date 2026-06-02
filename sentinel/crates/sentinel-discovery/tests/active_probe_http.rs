//! Integration tests for the Streamable HTTP active MCP probe.
//!
//! Strategy: a `wiremock` server stands in for a real MCP HTTP server. We
//! mount per-method handlers (initialize / notifications/initialized /
//! tools/list) and assert how the probe folds the responses into a
//! [`RapportProbe`](sentinel_discovery::active_probe::RapportProbe).

use std::time::Duration;

use sentinel_discovery::active_probe::EtatProbe;
use sentinel_discovery::active_probe_http::ProbeurHttp;
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Build a probe with a short timeout so the timeout test stays snappy.
fn probe_avec_timeout(secondes: u64) -> ProbeurHttp {
    let timeout = Duration::from_secs(secondes);
    let client = reqwest::Client::builder()
        .user_agent("sentinel-mcp-test/0.1")
        .timeout(timeout)
        .build()
        .expect("reqwest test client");
    ProbeurHttp { timeout, client }
}

// ---------------------------------------------------------------------------
// 1. Happy path — server returns initialize + tools/list as plain JSON.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_reussi_avec_tools_list_json() {
    let server = MockServer::start().await;

    // initialize → 200 + Mcp-Session-Id header.
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Mcp-Session-Id", "sess-abc-123")
                .insert_header("Content-Type", "application/json")
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "fake-http", "version": "0.0.1"}
                    }
                })),
        )
        .mount(&server)
        .await;

    // notifications/initialized → 202 with empty body (notifications return no result).
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    // tools/list → 200 + synthetic tools envelope.
    let tools_payload: Value = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {"name": "alpha", "description": "first",  "inputSchema": {"type": "object"}},
                {"name": "beta",  "description": "second", "inputSchema": {"type": "object"}}
            ]
        }
    });
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_json(tools_payload),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = probe_avec_timeout(8);
    let rapport = probe.probe_url("fake-http", &url).await;

    assert_eq!(
        rapport.etat,
        EtatProbe::Reussi,
        "expected Reussi, got {:?} (err={:?})",
        rapport.etat,
        rapport.erreur
    );
    assert_eq!(rapport.serveur_commande, url);
    assert_eq!(rapport.outils.len(), 2);
    assert!(rapport.empreinte_serveur.is_some());
    assert!(rapport.erreur.is_none());
    let noms: Vec<_> = rapport.outils.iter().map(|o| o.nom.as_str()).collect();
    assert!(noms.contains(&"alpha"));
    assert!(noms.contains(&"beta"));
}

// ---------------------------------------------------------------------------
// 2. Server returns 404 on initialize → EchecLancement.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_404_donne_echec_lancement() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = probe_avec_timeout(8);
    let rapport = probe.probe_url("missing-http", &url).await;

    assert_eq!(rapport.etat, EtatProbe::EchecLancement);
    assert!(rapport.erreur.is_some(), "expected error message");
    assert!(
        rapport.erreur.as_deref().unwrap().contains("404"),
        "error should mention HTTP 404, got: {:?}",
        rapport.erreur
    );
    assert!(rapport.outils.is_empty());
    assert!(rapport.empreinte_serveur.is_none());
}

// ---------------------------------------------------------------------------
// 3. Server stalls on initialize → EchecHandshake (timeout).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_timeout_donne_echec_handshake() {
    let server = MockServer::start().await;

    // Delay well past the probe's 1 s timeout to force a reqwest timeout.
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = probe_avec_timeout(1);
    let rapport = probe.probe_url("stall-http", &url).await;

    assert_eq!(
        rapport.etat,
        EtatProbe::EchecHandshake,
        "expected EchecHandshake, got {:?} (err={:?})",
        rapport.etat,
        rapport.erreur
    );
    assert!(rapport.erreur.is_some());
    assert!(rapport.outils.is_empty());
    assert!(rapport.empreinte_serveur.is_none());
}
