//! Tests d'intégration — agent V14 : connecteurs HTTP Smithery et mcp.so.
//!
//! On utilise wiremock pour simuler les API publiques sans dépendre du
//! réseau. Pour chaque source on couvre :
//!   1. Happy path — payload nominal correctement parsé.
//!   2. 404 — la défaillance d'un registre ne doit pas casser la chaîne
//!      (Vec vide, pas de panic).

use sentinel_detect::lookalikes::sources::mcpso::lister_serveurs_depuis as lister_mcpso;
use sentinel_detect::lookalikes::sources::smithery::lister_serveurs_depuis as lister_smithery;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Smithery — Test 1 : payload nominal → entrées parsées
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smithery_parse_correctement_payload_nominal() {
    let serveur = MockServer::start().await;

    let payload = serde_json::json!({
        "servers": [
            {
                "qualifiedName": "@acme/github-mcp",
                "displayName": "GitHub MCP",
                "description": "Accès aux dépôts GitHub."
            },
            {
                "qualifiedName": "@acme/filesystem-mcp",
                "displayName": "Filesystem MCP",
                "description": "Lecture/écriture sur le FS local."
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/servers?page_size=100", serveur.uri());
    let entrees = lister_smithery(&url).await;

    assert_eq!(entrees.len(), 2);

    let github = &entrees[0];
    assert_eq!(github.registre, "smithery");
    assert_eq!(github.nom, "GitHub MCP");
    assert_eq!(github.description, "Accès aux dépôts GitHub.");
    assert!(github.hash_binaire.is_none());
    assert!(github.sbom_url.is_none());
    assert!(github.publie_par.is_none());
    assert!(github.url_serveur.is_none());

    let fs = &entrees[1];
    assert_eq!(fs.registre, "smithery");
    assert_eq!(fs.nom, "Filesystem MCP");
    assert_eq!(fs.description, "Lecture/écriture sur le FS local.");
}

// ---------------------------------------------------------------------------
// Smithery — Test 2 : statut 404 → Vec vide (pas de panic)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smithery_statut_404_renvoie_vec_vide() {
    let serveur = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/servers?page_size=100", serveur.uri());
    let entrees = lister_smithery(&url).await;

    assert!(entrees.is_empty(), "404 doit produire un Vec vide");
}

// ---------------------------------------------------------------------------
// Smithery — Test 3 : displayName absent → qualifiedName utilisé en fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smithery_fallback_sur_qualified_name() {
    let serveur = MockServer::start().await;

    let payload = serde_json::json!({
        "servers": [
            { "qualifiedName": "@only/qualified", "description": "Sans displayName." }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .mount(&serveur)
        .await;

    let url = format!("{}/servers?page_size=100", serveur.uri());
    let entrees = lister_smithery(&url).await;

    assert_eq!(entrees.len(), 1);
    assert_eq!(entrees[0].nom, "@only/qualified");
    assert_eq!(entrees[0].description, "Sans displayName.");
}

// ---------------------------------------------------------------------------
// mcp.so — Test 4 : payload nominal → entrées parsées
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcpso_parse_correctement_payload_nominal() {
    let serveur = MockServer::start().await;

    let payload = serde_json::json!({
        "data": [
            { "name": "weather-mcp", "description": "API météo." },
            { "name": "calendar-mcp", "description": "Calendrier Google." }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/api/servers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/api/servers?limit=100", serveur.uri());
    let entrees = lister_mcpso(&url).await;

    assert_eq!(entrees.len(), 2);

    let meteo = &entrees[0];
    assert_eq!(meteo.registre, "mcp.so");
    assert_eq!(meteo.nom, "weather-mcp");
    assert_eq!(meteo.description, "API météo.");
    assert!(meteo.hash_binaire.is_none());
    assert!(meteo.sbom_url.is_none());

    let cal = &entrees[1];
    assert_eq!(cal.registre, "mcp.so");
    assert_eq!(cal.nom, "calendar-mcp");
    assert_eq!(cal.description, "Calendrier Google.");
}

// ---------------------------------------------------------------------------
// mcp.so — Test 5 : statut 404 → Vec vide
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcpso_statut_404_renvoie_vec_vide() {
    let serveur = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/servers"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/api/servers?limit=100", serveur.uri());
    let entrees = lister_mcpso(&url).await;

    assert!(entrees.is_empty(), "404 doit produire un Vec vide");
}
