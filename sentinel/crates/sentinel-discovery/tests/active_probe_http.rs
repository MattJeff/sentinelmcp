//! Integration tests for the Streamable HTTP active MCP probe.
//!
//! Strategy: a `wiremock` server stands in for a real MCP HTTP server. We
//! mount per-method handlers (initialize / notifications/initialized /
//! tools/list) and assert how the probe folds the responses into a
//! [`RapportProbe`](sentinel_discovery::active_probe::RapportProbe).

use std::time::Duration;

use sentinel_discovery::active_probe::{ClassificationEchec, ConfigProbe, EtatProbe};
use sentinel_discovery::active_probe_http::ProbeurHttp;
use serde_json::{json, Value};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Short-budget probe so failure tests stay snappy.
fn config_rapide(retries: u32) -> ConfigProbe {
    ConfigProbe {
        timeout_connexion: Duration::from_millis(500),
        timeout_reponse: Duration::from_millis(800),
        timeout_total: Duration::from_secs(5),
        retries,
        backoff_initial: Duration::from_millis(50),
        concurrence_max: 4,
    }
}

/// Mount the nominal initialize + initialized handlers on `server`.
async fn monter_handshake_nominal(server: &MockServer) {
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
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202))
        .mount(server)
        .await;
}

fn enveloppe_tools() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {"name": "alpha", "description": "first",  "inputSchema": {"type": "object"}},
                {"name": "beta",  "description": "second", "inputSchema": {"type": "object"}}
            ]
        }
    })
}

// ---------------------------------------------------------------------------
// 1. Happy path — server returns initialize + tools/list as plain JSON.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_reussi_avec_tools_list_json() {
    let server = MockServer::start().await;
    monter_handshake_nominal(&server).await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_json(enveloppe_tools()),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = ProbeurHttp::avec_config(config_rapide(1));
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
    assert!(rapport.classification_echec.is_none());
    assert_eq!(rapport.tentatives, 1);
    let noms: Vec<_> = rapport.outils.iter().map(|o| o.nom.as_str()).collect();
    assert!(noms.contains(&"alpha"));
    assert!(noms.contains(&"beta"));
}

// ---------------------------------------------------------------------------
// 2. Server returns 404 on initialize → EchecLancement + ConnexionRefusee.
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
    let probe = ProbeurHttp::avec_config(config_rapide(0));
    let rapport = probe.probe_url("missing-http", &url).await;

    assert_eq!(rapport.etat, EtatProbe::EchecLancement);
    assert_eq!(
        rapport.classification_echec,
        Some(ClassificationEchec::ConnexionRefusee)
    );
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
// 3. Server stalls on initialize → EchecHandshake + Timeout.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_timeout_donne_echec_handshake() {
    let server = MockServer::start().await;

    // Delay well past the per-request budget to force a reqwest timeout.
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
    let probe = ProbeurHttp::avec_config(config_rapide(0));
    let rapport = probe.probe_url("stall-http", &url).await;

    assert_eq!(
        rapport.etat,
        EtatProbe::EchecHandshake,
        "expected EchecHandshake, got {:?} (err={:?})",
        rapport.etat,
        rapport.erreur
    );
    assert_eq!(
        rapport.classification_echec,
        Some(ClassificationEchec::Timeout)
    );
    assert!(rapport.erreur.is_some());
    assert!(rapport.outils.is_empty());
    assert!(rapport.empreinte_serveur.is_none());
}

// ---------------------------------------------------------------------------
// 4. Bearer auth — the configured token must be sent on every request.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_auth_envoie_le_bearer_sur_chaque_requete() {
    let server = MockServer::start().await;

    // Every handler requires the Authorization header — an unauthenticated
    // request falls through to wiremock's default 404 and fails the probe.
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("Authorization", "Bearer sek-ret-42"))
        .and(body_partial_json(json!({"method": "initialize"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Mcp-Session-Id", "sess-auth")
                .insert_header("Content-Type", "application/json")
                .set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": {}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("Authorization", "Bearer sek-ret-42"))
        .and(body_partial_json(json!({"method": "notifications/initialized"})))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(header("Authorization", "Bearer sek-ret-42"))
        .and(header("Mcp-Session-Id", "sess-auth"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_json(enveloppe_tools()),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = ProbeurHttp::avec_config(config_rapide(0));

    // Sans token → 404 (aucun mock ne matche) → échec.
    let sans_auth = probe.probe_url("auth-http", &url).await;
    assert_ne!(sans_auth.etat, EtatProbe::Reussi);

    // Avec token → succès.
    let rapport = probe
        .probe_url_auth("auth-http", &url, Some("sek-ret-42"))
        .await;
    assert_eq!(
        rapport.etat,
        EtatProbe::Reussi,
        "err={:?}",
        rapport.erreur
    );
    assert_eq!(rapport.outils.len(), 2);
}

// ---------------------------------------------------------------------------
// 5. SSE — tools/list answered as text/event-stream with multiple events.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_reussi_avec_tools_list_sse() {
    let server = MockServer::start().await;
    monter_handshake_nominal(&server).await;

    // Une notification d'abord, puis la vraie réponse id=2 — le probe doit
    // sélectionner l'événement portant le bon id.
    let corps_sse = format!(
        "event: message\ndata: {}\n\nevent: message\ndata: {}\n\n",
        json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}),
        enveloppe_tools()
    );
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(corps_sse, "text/event-stream"),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = ProbeurHttp::avec_config(config_rapide(0));
    let rapport = probe.probe_url("sse-http", &url).await;

    assert_eq!(
        rapport.etat,
        EtatProbe::Reussi,
        "expected Reussi over SSE, got {:?} (err={:?})",
        rapport.etat,
        rapport.erreur
    );
    assert_eq!(rapport.outils.len(), 2);
}

// ---------------------------------------------------------------------------
// 6. Retry — a transient 500 on the first attempt heals on the second.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_reessaie_apres_erreur_transitoire() {
    let server = MockServer::start().await;

    // Premier hit : 500, consommé une seule fois (priorité haute).
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;

    monter_handshake_nominal(&server).await;
    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_json(enveloppe_tools()),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = ProbeurHttp::avec_config(config_rapide(1));
    let rapport = probe.probe_url("flaky-http", &url).await;

    assert_eq!(
        rapport.etat,
        EtatProbe::Reussi,
        "expected Reussi after retry, got {:?} (err={:?})",
        rapport.etat,
        rapport.erreur
    );
    assert_eq!(rapport.tentatives, 2);
    assert_eq!(rapport.outils.len(), 2);
}

// ---------------------------------------------------------------------------
// 7. Malformed tools/list payload → EchecParseur + ReponseMalformee.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn probe_url_tools_list_malforme_donne_echec_parseur() {
    let server = MockServer::start().await;
    monter_handshake_nominal(&server).await;

    Mock::given(method("POST"))
        .and(path("/mcp"))
        .and(body_partial_json(json!({"method": "tools/list"})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_json(json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": "pas-un-tableau"}})),
        )
        .mount(&server)
        .await;

    let url = format!("{}/mcp", server.uri());
    let probe = ProbeurHttp::avec_config(config_rapide(0));
    let rapport = probe.probe_url("malforme-http", &url).await;

    assert_eq!(rapport.etat, EtatProbe::EchecParseur);
    assert_eq!(
        rapport.classification_echec,
        Some(ClassificationEchec::ReponseMalformee)
    );
    assert_eq!(rapport.tentatives, 1, "malformed responses are not retried");
}
