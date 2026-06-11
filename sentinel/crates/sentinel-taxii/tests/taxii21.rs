//! Conformité TAXII 2.1 contre un serveur HTTP factice (wiremock) :
//! discovery + sélection de collection, vérification stricte du
//! Content-Type en réception, retries/backoff (5xx, réseau, 429 avec
//! Retry-After), pagination `more`/`next`, et suivi du status resource.

use std::time::{Duration, Instant};

use sentinel_taxii::{RetryPolicy, TaxiiAuth, TaxiiClient, TaxiiConfig, TaxiiError};
use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TAXII_CT: &str = "application/taxii+json;version=2.1";

fn taxii_response(code: u16, body: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(code).set_body_raw(serde_json::to_vec(body).unwrap(), TAXII_CT)
}

fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        max_retries: 3,
        base_delay: Duration::from_millis(10),
        max_retry_after: Duration::from_secs(2),
    }
}

fn make_client(server: &MockServer, auth: TaxiiAuth) -> TaxiiClient {
    let cfg = TaxiiConfig {
        api_root_url: format!("{}/api1", server.uri()),
        collection_id: "11111111-2222-3333-4444-555555555555".to_string(),
        auth,
        enabled: true,
        verify_tls: true,
    };
    TaxiiClient::new(cfg).unwrap().with_retry_policy(fast_retry())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

async fn mount_discovery(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(header("Accept", TAXII_CT))
        .respond_with(taxii_response(
            200,
            &json!({
                "title": "Sentinel TAXII test server",
                "description": "fixture",
                "default": format!("{}/api1/", server.uri()),
                "api_roots": [
                    format!("{}/api1/", server.uri()),
                    "/api2/"
                ]
            }),
        ))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api1/collections/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "collections": [
                    {
                        "id": "11111111-2222-3333-4444-555555555555",
                        "title": "Sentinel Threats",
                        "can_read": true,
                        "can_write": true,
                        "media_types": [TAXII_CT]
                    }
                ]
            }),
        ))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api2/collections/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "collections": [
                    {
                        "id": "99999999-8888-7777-6666-555555555555",
                        "title": "Autre collection",
                        "can_read": true,
                        "can_write": false
                    }
                ]
            }),
        ))
        .mount(server)
        .await;
}

#[tokio::test]
async fn discovery_then_collections() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let client = make_client(&server, TaxiiAuth::None);
    let disc = client.discover(&server.uri()).await.expect("discovery ok");
    assert_eq!(disc.title, "Sentinel TAXII test server");
    assert_eq!(disc.api_roots.len(), 2);

    let cols = client
        .list_collections(&format!("{}/api1/", server.uri()))
        .await
        .expect("collections ok");
    assert_eq!(cols.len(), 1);
    assert!(cols[0].can_write);
}

#[tokio::test]
async fn find_collection_by_title_case_insensitive() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let client = make_client(&server, TaxiiAuth::None);
    let (root, col) = client
        .find_collection(&server.uri(), "sentinel threats")
        .await
        .expect("collection trouvée par titre");
    assert!(root.contains("/api1/"));
    assert_eq!(col.id, "11111111-2222-3333-4444-555555555555");
}

#[tokio::test]
async fn find_collection_by_id_in_relative_api_root() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let client = make_client(&server, TaxiiAuth::None);
    // La collection cible n'existe que sous l'api root RELATIF "/api2/".
    let (root, col) = client
        .find_collection(&server.uri(), "99999999-8888-7777-6666-555555555555")
        .await
        .expect("collection trouvée par id");
    assert!(root.contains("/api2/"), "api root résolu: {root}");
    assert_eq!(col.title, "Autre collection");
}

#[tokio::test]
async fn find_collection_unknown_selector_errors() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .find_collection(&server.uri(), "introuvable")
        .await
        .unwrap_err();
    assert!(matches!(err, TaxiiError::CollectionNotFound(_)));
}

#[tokio::test]
async fn find_collection_skips_api_root_in_error() {
    let server = MockServer::start().await;

    // Discovery: deux api roots, le premier refuse l'accès (multi-tenant).
    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "title": "Sentinel TAXII test server",
                "api_roots": ["/prive/", "/api2/"]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/prive/collections/"))
        .respond_with(ResponseTemplate::new(403).set_body_string("interdit"))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api2/collections/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "collections": [
                    {
                        "id": "99999999-8888-7777-6666-555555555555",
                        "title": "Autre collection",
                        "can_read": true,
                        "can_write": false
                    }
                ]
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let (root, col) = client
        .find_collection(&server.uri(), "99999999-8888-7777-6666-555555555555")
        .await
        .expect("le root en erreur doit être ignoré, pas fatal");
    assert!(root.contains("/api2/"), "api root résolu: {root}");
    assert_eq!(col.title, "Autre collection");
}

#[tokio::test]
async fn find_collection_reports_root_errors_when_nothing_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "title": "Sentinel TAXII test server",
                "api_roots": ["/prive/"]
            }),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/prive/collections/"))
        .respond_with(ResponseTemplate::new(401).set_body_string("non autorisé"))
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .find_collection(&server.uri(), "introuvable")
        .await
        .unwrap_err();
    match err {
        TaxiiError::CollectionNotFound(msg) => {
            assert!(msg.contains("introuvable"), "msg: {msg}");
            assert!(msg.contains("401"), "les roots en erreur doivent être résumés: {msg}");
        }
        other => panic!("attendu CollectionNotFound, obtenu {other:?}"),
    }
}

#[tokio::test]
async fn discovery_works_when_base_already_ends_with_taxii2() {
    let server = MockServer::start().await;
    mount_discovery(&server).await;

    let client = make_client(&server, TaxiiAuth::None);
    let base = format!("{}/taxii2/", server.uri());
    let disc = client.discover(&base).await.expect("discovery ok");
    assert_eq!(disc.title, "Sentinel TAXII test server");
}

// ---------------------------------------------------------------------------
// Content-Type strict en réception
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wrong_content_type_on_response_is_rejected() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/api1/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "id": "status--1", "status": "complete"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .push_objects(&[json!({"type": "indicator"})])
        .await
        .unwrap_err();
    assert!(
        matches!(err, TaxiiError::BadContentType(_)),
        "attendu BadContentType, obtenu {err:?}"
    );
}

#[tokio::test]
async fn wrong_taxii_version_in_content_type_is_rejected() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            serde_json::to_vec(&json!({"title": "x"})).unwrap(),
            "application/taxii+json;version=2.0",
        ))
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client.discover(&server.uri()).await.unwrap_err();
    assert!(matches!(err, TaxiiError::BadContentType(_)));
}

// ---------------------------------------------------------------------------
// Retries / backoff / Retry-After
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retries_on_5xx_then_succeeds() {
    let server = MockServer::start().await;
    let objects_path = "/api1/collections/11111111-2222-3333-4444-555555555555/objects/";

    // Deux 500 puis un 202 — le mock 500 s'épuise après 2 réponses.
    Mock::given(method("POST"))
        .and(path(objects_path))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(objects_path))
        .respond_with(taxii_response(
            202,
            &json!({"id": "status--ok", "status": "complete", "total_count": 1, "success_count": 1}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let status = client
        .push_objects(&[json!({"type": "indicator"})])
        .await
        .expect("doit réussir après retries");
    assert_eq!(status.status, "complete");
}

#[tokio::test]
async fn gives_up_after_max_retries_on_5xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/api1/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .respond_with(ResponseTemplate::new(503).set_body_string("indispo"))
        .expect(4) // 1 tentative + 3 retries
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .push_objects(&[json!({"type": "indicator"})])
        .await
        .unwrap_err();
    match err {
        TaxiiError::Server { status, .. } => assert_eq!(status, 503),
        other => panic!("attendu Server 503, obtenu {other:?}"),
    }
}

#[tokio::test]
async fn respects_retry_after_on_429() {
    let server = MockServer::start().await;
    let objects_path = "/api1/collections/11111111-2222-3333-4444-555555555555/objects/";

    Mock::given(method("POST"))
        .and(path(objects_path))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "1")
                .set_body_string("rate limited"),
        )
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path(objects_path))
        .respond_with(taxii_response(
            202,
            &json!({"id": "status--ok", "status": "complete"}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let start = Instant::now();
    let status = client
        .push_objects(&[json!({"type": "indicator"})])
        .await
        .expect("doit réussir après le 429");
    assert_eq!(status.status, "complete");
    assert!(
        start.elapsed() >= Duration::from_millis(900),
        "Retry-After: 1 doit imposer ~1s d'attente, écoulé: {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn server_error_body_truncation_respects_utf8_boundaries() {
    let server = MockServer::start().await;

    // L'octet 500 tombe au milieu du 'é' (2 octets) : un découpage
    // `&body[..500]` naïf paniquerait.
    let body = format!("{}également une erreur très détaillée", "a".repeat(499));
    assert!(!body.is_char_boundary(500));

    Mock::given(method("POST"))
        .and(path(
            "/api1/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .respond_with(ResponseTemplate::new(400).set_body_string(body))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .push_objects(&[json!({"type": "indicator"})])
        .await
        .unwrap_err();
    match err {
        TaxiiError::Server { status, body } => {
            assert_eq!(status, 400);
            assert!(body.len() <= 500, "corps tronqué à 500 octets max");
            assert!(body.starts_with("aaa"));
        }
        other => panic!("attendu Server 400, obtenu {other:?}"),
    }
}

#[tokio::test]
async fn no_retry_on_plain_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/api1/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .expect(1) // une seule tentative, pas de retry
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .push_objects(&[json!({"type": "indicator"})])
        .await
        .unwrap_err();
    assert!(matches!(err, TaxiiError::Server { status: 403, .. }));
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_objects_follows_pagination() {
    let server = MockServer::start().await;
    let objects_path = "/api1/collections/11111111-2222-3333-4444-555555555555/objects/";

    // Page 2 (montée en premier: matcher plus spécifique avec ?next=page2).
    Mock::given(method("GET"))
        .and(path(objects_path))
        .and(query_param("next", "page2"))
        .respond_with(taxii_response(
            200,
            &json!({
                "objects": [{"type": "indicator", "id": "indicator--b"}],
                "more": false
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    // Page 1.
    Mock::given(method("GET"))
        .and(path(objects_path))
        .respond_with(taxii_response(
            200,
            &json!({
                "objects": [{"type": "indicator", "id": "indicator--a"}],
                "more": true,
                "next": "page2"
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let objects = client.get_objects().await.expect("pagination ok");
    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0]["id"], "indicator--a");
    assert_eq!(objects[1]["id"], "indicator--b");
}

// ---------------------------------------------------------------------------
// Status resource
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_and_wait_follows_pending_status_until_complete() {
    let server = MockServer::start().await;
    let objects_path = "/api1/collections/11111111-2222-3333-4444-555555555555/objects/";

    Mock::given(method("POST"))
        .and(path(objects_path))
        .respond_with(taxii_response(
            202,
            &json!({
                "id": "status--pending-1",
                "status": "pending",
                "total_count": 1,
                "pending_count": 1
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    // Premier poll: encore pending.
    Mock::given(method("GET"))
        .and(path("/api1/status/status--pending-1/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "id": "status--pending-1",
                "status": "pending",
                "total_count": 1,
                "pending_count": 1
            }),
        ))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;

    // Second poll: complete.
    Mock::given(method("GET"))
        .and(path("/api1/status/status--pending-1/"))
        .respond_with(taxii_response(
            200,
            &json!({
                "id": "status--pending-1",
                "status": "complete",
                "total_count": 1,
                "success_count": 1,
                "pending_count": 0
            }),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let status = client
        .push_objects_and_wait(
            &[json!({"type": "indicator"})],
            Duration::from_millis(10),
            5,
        )
        .await
        .expect("status suivi jusqu'à complete");
    assert_eq!(status.status, "complete");
    assert_eq!(status.success_count, 1);
}

#[tokio::test]
async fn wait_for_status_times_out_when_stuck_pending() {
    let server = MockServer::start().await;
    let objects_path = "/api1/collections/11111111-2222-3333-4444-555555555555/objects/";

    Mock::given(method("POST"))
        .and(path(objects_path))
        .respond_with(taxii_response(
            202,
            &json!({"id": "status--stuck", "status": "pending"}),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api1/status/status--stuck/"))
        .respond_with(taxii_response(
            200,
            &json!({"id": "status--stuck", "status": "pending"}),
        ))
        .mount(&server)
        .await;

    let client = make_client(&server, TaxiiAuth::None);
    let err = client
        .push_objects_and_wait(
            &[json!({"type": "indicator"})],
            Duration::from_millis(5),
            2,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TaxiiError::StatusPending(2)));
}

// ---------------------------------------------------------------------------
// Auth sur les endpoints de lecture
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_sends_bearer_auth() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/taxii2/"))
        .and(header("Authorization", "Bearer jeton-secret"))
        .respond_with(taxii_response(200, &json!({"title": "ok"})))
        .expect(1)
        .mount(&server)
        .await;

    let client = make_client(
        &server,
        TaxiiAuth::Bearer {
            token: "jeton-secret".to_string(),
        },
    );
    let disc = client.discover(&server.uri()).await.expect("auth bearer ok");
    assert_eq!(disc.title, "ok");
}

#[tokio::test]
async fn disabled_blocks_discovery_and_reads() {
    let mut cfg = TaxiiConfig::new("http://127.0.0.1:1/taxii2/", "x");
    cfg.enabled = false;
    let client = TaxiiClient::new(cfg).unwrap();

    assert!(matches!(
        client.discover("http://127.0.0.1:1").await,
        Err(TaxiiError::Disabled)
    ));
    assert!(matches!(
        client.get_objects().await,
        Err(TaxiiError::Disabled)
    ));
}
