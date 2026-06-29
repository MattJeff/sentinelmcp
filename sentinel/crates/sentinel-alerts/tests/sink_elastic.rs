//! Tests d'intégration pour le sink Elastic — agent V18.

use sentinel_alerts::sinks::elastic::ClientElastic;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn elastic_envoie_document_et_recoit_201() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/alerts/_doc"))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let client = ClientElastic::nouveau(server.uri(), "alerts".to_string(), None);

    let alert = json!({
        "id": "test-1",
        "severity": "HIGH",
        "message": "sample"
    });

    let res = client.envoyer(&alert).await;
    assert!(res.is_ok(), "envoi devait réussir, erreur: {:?}", res.err());
}

#[tokio::test]
async fn elastic_propage_erreur_sur_500() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/idx/_doc"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = ClientElastic::nouveau(server.uri(), "idx".to_string(), None);
    let res = client.envoyer(&json!({"x": 1})).await;
    assert!(res.is_err(), "500 doit produire une erreur");
}

#[tokio::test]
async fn elastic_avec_basic_auth() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/secure/_doc"))
        .and(wiremock::matchers::header(
            "authorization",
            "Basic dXNlcjpwYXNz", // base64("user:pass")
        ))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let client = ClientElastic::nouveau(
        server.uri(),
        "secure".to_string(),
        Some(("user".to_string(), "pass".to_string())),
    );

    let res = client.envoyer(&json!({"ok": true})).await;
    assert!(res.is_ok(), "envoi auth devait réussir: {:?}", res.err());
}

// Régression B11 : un mot de passe sous forme de référence `keyring:<nom>` doit
// être résolu via le coffre avant l'authentification HTTP Basic.
#[tokio::test]
async fn envoyer_resout_pass_keyring() {
    use sentinel_alerts::{CoffreMemoire, CoffreSecrets};

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/secure/_doc"))
        .and(wiremock::matchers::header(
            "authorization",
            "Basic dXNlcjp2cmFpLXBhc3M=", // base64("user:vrai-pass")
        ))
        .respond_with(ResponseTemplate::new(201))
        .expect(1)
        .mount(&server)
        .await;

    let coffre = CoffreMemoire::nouveau();
    coffre.ecrire("elastic_password", "vrai-pass").unwrap();

    // Le client reçoit la référence, jamais le secret en clair.
    let client = ClientElastic::nouveau(
        server.uri(),
        "secure".to_string(),
        Some(("user".to_string(), "keyring:elastic_password".to_string())),
    );
    let res = client
        .envoyer_avec_coffre(&json!({"ok": true}), Some(&coffre))
        .await;
    assert!(
        res.is_ok(),
        "le mot de passe keyring doit être résolu avant émission: {:?}",
        res.err()
    );
}
