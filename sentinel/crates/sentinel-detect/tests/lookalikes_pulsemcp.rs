//! Tests d'intégration — agent V13 : connecteur HTTP PulseMCP.
//!
//! On utilise wiremock pour simuler l'API publique sans dépendre du réseau.
//! Deux scénarios :
//!   1. Réponse 200 avec deux serveurs → parsée en deux `EntreeRegistre`.
//!   2. Réponse 503 → Vec vide (la défaillance d'un registre ne doit pas
//!      bloquer la chaîne de détection).

use sentinel_detect::lookalikes::sources::pulsemcp::lister_serveurs_depuis;
use wiremock::matchers::{method, path, path_regex, query_param};
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

    let github = entrees
        .iter()
        .find(|e| e.nom == "github-mcp")
        .expect("entrée github-mcp présente");
    assert_eq!(github.registre, "pulsemcp");
    assert_eq!(github.nom, "github-mcp");
    assert_eq!(
        github.description.as_deref(),
        Some("Accès aux dépôts GitHub.")
    );
    assert!(github.auteur.is_none());
    assert!(github.url.is_none());
    assert!(github.outils.is_none());

    let fs = entrees
        .iter()
        .find(|e| e.nom == "filesystem-mcp")
        .expect("entrée filesystem-mcp présente");
    assert_eq!(fs.registre, "pulsemcp");
    assert_eq!(fs.nom, "filesystem-mcp");
    assert_eq!(
        fs.description.as_deref(),
        Some("Lecture/écriture sur le FS local.")
    );
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

// ---------------------------------------------------------------------------
// Test 3 : enrichissement via l'endpoint de détail — 200 OK liste (2 serveurs)
// + 200 OK détail (3 outils) → l'entrée correspondante porte `outils` rempli.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn enrichit_via_endpoint_detail() {
    let serveur = MockServer::start().await;

    let payload_liste = serde_json::json!({
        "servers": [
            {
                "name": "github-mcp",
                "short_description": "Accès aux dépôts GitHub.",
                "slug": "github-mcp"
            },
            {
                "name": "filesystem-mcp",
                "short_description": "Lecture/écriture sur le FS local.",
                "slug": "filesystem-mcp"
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/v0/servers"))
        .and(query_param("count_per_page", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload_liste))
        .mount(&serveur)
        .await;

    let payload_detail_github = serde_json::json!({
        "name": "github-mcp",
        "slug": "github-mcp",
        "tools": [
            { "name": "list_repos" },
            { "name": "create_issue" },
            { "name": "search_code" }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/v0/servers/github-mcp"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload_detail_github))
        .mount(&serveur)
        .await;

    // L'autre détail renvoie 404 : doit retomber silencieusement sur outils=None.
    Mock::given(method("GET"))
        .and(path_regex(r"^/v0/servers/filesystem-mcp$"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&serveur)
        .await;

    let url = format!("{}/v0/servers?count_per_page=100", serveur.uri());
    let entrees = lister_serveurs_depuis(&url).await;

    assert_eq!(entrees.len(), 2);

    let github = entrees
        .iter()
        .find(|e| e.nom == "github-mcp")
        .expect("entrée github-mcp présente");
    assert_eq!(
        github.outils.as_ref().map(|v| v.len()),
        Some(3),
        "github-mcp doit porter 3 outils enrichis"
    );
    let noms: Vec<&str> = github
        .outils
        .as_ref()
        .unwrap()
        .iter()
        .map(|o| o.nom.as_str())
        .collect();
    assert!(noms.contains(&"list_repos"));
    assert!(noms.contains(&"create_issue"));
    assert!(noms.contains(&"search_code"));

    let fs = entrees
        .iter()
        .find(|e| e.nom == "filesystem-mcp")
        .expect("entrée filesystem-mcp présente");
    assert!(
        fs.outils.is_none(),
        "filesystem-mcp doit garder outils=None sur 404 détail"
    );
}
