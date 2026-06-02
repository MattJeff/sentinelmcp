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

    // Les requêtes de détail sont tentées mais aucune route ne les
    // satisfait : elles retournent 404 et l'enrichissement est sauté
    // (les entrées gardent `outils: None`).
    let url = format!("{}/servers?page_size=100", serveur.uri());
    let entrees = lister_smithery(&url).await;

    assert_eq!(entrees.len(), 2);

    // Les entrées sont produites en parallèle via buffer_unordered :
    // on les retrouve par nom plutôt que par index.
    let github = entrees
        .iter()
        .find(|e| e.nom == "GitHub MCP")
        .expect("GitHub MCP présent");
    assert_eq!(github.registre, "smithery");
    assert_eq!(
        github.description.as_deref(),
        Some("Accès aux dépôts GitHub.")
    );
    assert!(github.auteur.is_none());
    assert!(github.url.is_none());
    assert!(github.outils.is_none());

    let fs = entrees
        .iter()
        .find(|e| e.nom == "Filesystem MCP")
        .expect("Filesystem MCP présent");
    assert_eq!(fs.registre, "smithery");
    assert_eq!(
        fs.description.as_deref(),
        Some("Lecture/écriture sur le FS local.")
    );
    assert!(fs.outils.is_none());
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
    assert_eq!(
        entrees[0].description.as_deref(),
        Some("Sans displayName.")
    );
    // Détail non monté → outils restent None.
    assert!(entrees[0].outils.is_none());
}

// ---------------------------------------------------------------------------
// Smithery — Test 3 bis : enrichissement par détail → SignatureOutil
//   Le payload de détail expose un tableau `tools` ; on vérifie que
//   `outils` est rempli et que les valeurs `enum` du schéma sont
//   collectées, triées et dédupliquées.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smithery_enrichit_outils_depuis_endpoint_detail() {
    let serveur = MockServer::start().await;

    // Liste : une seule entrée avec un `qualifiedName` simple (sans
    // caractères réservés, pour que la route de détail soit prévisible
    // après encodage).
    let liste = serde_json::json!({
        "servers": [
            {
                "qualifiedName": "acme-search",
                "displayName": "Acme Search",
                "description": "Moteur de recherche."
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/servers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(liste))
        .expect(1)
        .mount(&serveur)
        .await;

    // Détail enrichi : un outil `search` avec un `inputSchema` portant
    // un `enum` ["fast","slow"].
    let detail = serde_json::json!({
        "tools": [
            {
                "name": "search",
                "description": "Recherche textuelle.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "mode": { "enum": ["fast", "slow"] }
                    }
                }
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/servers/acme-search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(detail))
        .expect(1)
        .mount(&serveur)
        .await;

    let url = format!("{}/servers?page_size=100", serveur.uri());
    let entrees = lister_smithery(&url).await;

    assert_eq!(entrees.len(), 1);
    let entree = &entrees[0];
    assert_eq!(entree.nom, "Acme Search");
    let outils = entree
        .outils
        .as_ref()
        .expect("outils enrichis depuis le détail");
    assert_eq!(outils.len(), 1);
    assert_eq!(outils[0].nom, "search");
    assert_eq!(
        outils[0].enums_tries,
        vec!["fast".to_string(), "slow".to_string()]
    );
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
    assert_eq!(meteo.description.as_deref(), Some("API météo."));
    assert!(meteo.auteur.is_none());
    assert!(meteo.url.is_none());
    assert!(meteo.outils.is_none());

    let cal = &entrees[1];
    assert_eq!(cal.registre, "mcp.so");
    assert_eq!(cal.nom, "calendar-mcp");
    assert_eq!(cal.description.as_deref(), Some("Calendrier Google."));
    assert!(cal.outils.is_none());
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
