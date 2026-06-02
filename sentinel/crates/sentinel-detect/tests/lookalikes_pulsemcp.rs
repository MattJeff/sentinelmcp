//! Tests d'intégration — agent V13 : connecteur HTTP PulseMCP.
//!
//! On utilise wiremock pour simuler l'API publique sans dépendre du réseau.
//! Deux scénarios :
//!   1. Réponse 200 avec deux serveurs → parsée en deux `EntreeRegistre`.
//!   2. Réponse 503 → Vec vide (la défaillance d'un registre ne doit pas
//!      bloquer la chaîne de détection).

use sentinel_detect::lookalikes::sources::pulsemcp::lister_serveurs_depuis;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Test 1 : payload nominal → deux entrées parsées
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_correctement_payload_pulsemcp() {
    let serveur = MockServer::start().await;

    let payload = serde_json::json!({
        "servers": [
            {
                "name": "github-mcp",
                "short_description": "Accès aux dépôts GitHub.",
                "package_registry": "npm",
                "package_name": "@org/github-mcp"
            },
            {
                "name": "filesystem-mcp",
                "short_description": "Lecture/écriture sur le FS local.",
                "package_registry": "npm",
                "package_name": "@org/filesystem-mcp"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/v0/servers"))
        .and(query_param("count_per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/v0/servers?count_per_page=100", serveur.uri());
    let entrees = lister_serveurs_depuis(&url).await;

    assert_eq!(entrees.len(), 2);

    let github = &entrees[0];
    assert_eq!(github.registre, "pulsemcp");
    assert_eq!(github.nom, "github-mcp");
    assert_eq!(github.description, "Accès aux dépôts GitHub.");
    assert!(github.hash_binaire.is_none());
    assert!(github.sbom_url.is_none());
    assert!(github.publie_par.is_none());
    assert!(github.url_serveur.is_none());

    let fs = &entrees[1];
    assert_eq!(fs.registre, "pulsemcp");
    assert_eq!(fs.nom, "filesystem-mcp");
    assert_eq!(fs.description, "Lecture/écriture sur le FS local.");
}

// ---------------------------------------------------------------------------
// Test 2 : statut 503 → Vec vide (défaillance silencieuse, log d'avertissement)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn statut_503_renvoie_vec_vide() {
    let serveur = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v0/servers"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/v0/servers?count_per_page=100", serveur.uri());
    let entrees = lister_serveurs_depuis(&url).await;

    assert!(entrees.is_empty(), "503 doit produire un Vec vide");
}
