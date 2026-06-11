use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sentinel_taxii::{TaxiiAuth, TaxiiClient, TaxiiConfig, TaxiiError};
use serde_json::json;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn status_body(success: u64) -> serde_json::Value {
    json!({
        "id": "status--test-0001",
        "status": "complete",
        "request_timestamp": "2026-06-02T10:00:00Z",
        "total_count": success,
        "success_count": success,
        "failure_count": 0,
        "pending_count": 0
    })
}

/// Builds a response carrying the strict TAXII 2.1 media type — the client
/// now verifies the Content-Type of every successful response.
fn taxii_response(code: u16, body: &serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(code).set_body_raw(
        serde_json::to_vec(body).unwrap(),
        "application/taxii+json;version=2.1",
    )
}

fn make_config(server: &MockServer, auth: TaxiiAuth) -> TaxiiConfig {
    TaxiiConfig {
        api_root_url: format!("{}/taxii2", server.uri()),
        collection_id: "11111111-2222-3333-4444-555555555555".to_string(),
        auth,
        enabled: true,
        verify_tls: true,
    }
}

#[tokio::test]
async fn test_push_objects_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/taxii2/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .and(header("Accept", "application/taxii+json;version=2.1"))
        .and(header("Content-Type", "application/taxii+json;version=2.1"))
        .and(body_partial_json(json!({
            "objects": [{"type": "indicator"}]
        })))
        .respond_with(taxii_response(202, &status_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(make_config(&server, TaxiiAuth::None)).unwrap();
    let obj = json!({"type": "indicator", "spec_version": "2.1", "id": "indicator--xx"});
    let status = client.push_objects(&[obj]).await.expect("push ok");
    assert_eq!(status.status, "complete");
    assert_eq!(status.success_count, 1);
}

#[tokio::test]
async fn test_push_objects_auth_basic() {
    let server = MockServer::start().await;
    let user = "alice";
    let pass = "s3cret!";
    let expected = format!("Basic {}", BASE64_STANDARD.encode(format!("{user}:{pass}")));

    Mock::given(method("POST"))
        .and(path(
            "/taxii2/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .and(header("Authorization", expected.as_str()))
        .respond_with(taxii_response(202, &status_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(make_config(
        &server,
        TaxiiAuth::Basic {
            user: user.to_string(),
            pass: pass.to_string(),
        },
    ))
    .unwrap();
    let obj = json!({"type": "indicator"});
    client.push_objects(&[obj]).await.expect("basic auth ok");
}

#[tokio::test]
async fn test_push_objects_auth_bearer() {
    let server = MockServer::start().await;
    let token = "abc.def.ghi";

    Mock::given(method("POST"))
        .and(path(
            "/taxii2/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .and(header("Authorization", format!("Bearer {token}").as_str()))
        .respond_with(taxii_response(202, &status_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(make_config(
        &server,
        TaxiiAuth::Bearer {
            token: token.to_string(),
        },
    ))
    .unwrap();
    let obj = json!({"type": "indicator"});
    client.push_objects(&[obj]).await.expect("bearer auth ok");
}

#[tokio::test]
async fn test_push_objects_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/taxii2/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("bad request: malformed envelope"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(make_config(&server, TaxiiAuth::None)).unwrap();
    let obj = json!({"type": "indicator"});
    let err = client.push_objects(&[obj]).await.unwrap_err();
    match err {
        TaxiiError::Server { status, body } => {
            assert_eq!(status, 400);
            assert!(body.contains("bad request"), "body was: {body}");
        }
        other => panic!("expected Server error, got {other:?}"),
    }
}

#[tokio::test]
async fn test_test_send() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/taxii2/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .and(body_partial_json(json!({
            "objects": [{
                "type": "indicator",
                "spec_version": "2.1",
                "pattern": "[software:name = 'sentinel-mcp-test']",
                "pattern_type": "stix",
                "indicator_types": ["benign"]
            }]
        })))
        .respond_with(taxii_response(202, &status_body(1)))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(make_config(&server, TaxiiAuth::None)).unwrap();
    let status = client.test_send().await.expect("test_send ok");
    assert_eq!(status.status, "complete");
}

#[test]
fn test_token_redacted_in_debug() {
    let token = "supersecret-token-xyz";
    let basic_pass = "p@ssw0rd!";

    let bearer = TaxiiAuth::Bearer {
        token: token.to_string(),
    };
    let basic = TaxiiAuth::Basic {
        user: "alice".to_string(),
        pass: basic_pass.to_string(),
    };

    let bearer_dbg = format!("{:?}", bearer);
    let basic_dbg = format!("{:?}", basic);

    assert!(
        !bearer_dbg.contains(token),
        "bearer Debug leaked token: {bearer_dbg}"
    );
    assert!(
        !basic_dbg.contains(basic_pass),
        "basic Debug leaked password: {basic_dbg}"
    );
    assert!(bearer_dbg.contains("***"));
    assert!(basic_dbg.contains("***"));
    // User field is non-secret and is allowed to appear.
    assert!(basic_dbg.contains("alice"));
}

#[tokio::test]
async fn test_push_bundle_extracts_objects() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path(
            "/taxii2/collections/11111111-2222-3333-4444-555555555555/objects/",
        ))
        .and(body_partial_json(json!({
            "objects": [
                {"type": "indicator", "id": "indicator--a"},
                {"type": "malware", "id": "malware--b"}
            ]
        })))
        .respond_with(taxii_response(202, &status_body(2)))
        .expect(1)
        .mount(&server)
        .await;

    let client = TaxiiClient::new(make_config(&server, TaxiiAuth::None)).unwrap();
    let bundle = json!({
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {"type": "indicator", "id": "indicator--a"},
            {"type": "malware", "id": "malware--b"}
        ]
    });
    let status = client.push_bundle(&bundle).await.expect("bundle ok");
    assert_eq!(status.success_count, 2);
}

#[tokio::test]
async fn test_disabled_short_circuits() {
    // No mock — if the client made a call we'd get a connection error and fail.
    let cfg = TaxiiConfig {
        api_root_url: "http://127.0.0.1:1/taxii2".to_string(),
        collection_id: "deadbeef".to_string(),
        auth: TaxiiAuth::None,
        enabled: false,
        verify_tls: true,
    };
    let client = TaxiiClient::new(cfg).unwrap();
    let err = client.push_objects(&[json!({})]).await.unwrap_err();
    assert!(matches!(err, TaxiiError::Disabled));
}
