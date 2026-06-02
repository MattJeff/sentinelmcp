//! Tests d'intégration pour le sink Splunk HEC.

use sentinel_alerts::sinks::{ClientSplunkHec, SinkError};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn alerte_exemple() -> serde_json::Value {
    json!({
        "id": "11111111-1111-1111-1111-111111111111",
        "severite": "CRITIQUE",
        "titre": "Test",
        "message": "alerte de test"
    })
}

#[tokio::test]
async fn envoyer_succes_200_ok() {
    let serveur = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("Authorization", "Splunk secret-token"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"text":"Success","code":0}"#))
        .mount(&serveur)
        .await;

    let client = ClientSplunkHec::nouveau(serveur.uri(), "secret-token".to_string(), None);
    let resultat = client.envoyer(&alerte_exemple()).await;
    assert!(resultat.is_ok(), "doit réussir, got: {:?}", resultat);
}

#[tokio::test]
async fn envoyer_echec_401_non_autorise() {
    let serveur = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(ResponseTemplate::new(401).set_body_string(r#"{"text":"Unauthorized","code":3}"#))
        .mount(&serveur)
        .await;

    let client = ClientSplunkHec::nouveau(
        serveur.uri(),
        "mauvais-token".to_string(),
        Some("sentinel:alert".to_string()),
    );
    let resultat = client.envoyer(&alerte_exemple()).await;
    match resultat {
        Err(SinkError::Http { statut, .. }) => assert_eq!(statut, 401),
        autre => panic!("attendu SinkError::Http 401, obtenu: {:?}", autre),
    }
}

#[tokio::test]
async fn envoyer_echec_timeout() {
    let serveur = MockServer::start().await;

    // Délai bien supérieur au timeout de 10s.
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(15)))
        .mount(&serveur)
        .await;

    let client = ClientSplunkHec::nouveau(serveur.uri(), "token".to_string(), None);
    let resultat = client.envoyer(&alerte_exemple()).await;
    match resultat {
        Err(SinkError::Reseau(_)) => {}
        autre => panic!("attendu SinkError::Reseau pour timeout, obtenu: {:?}", autre),
    }
}
