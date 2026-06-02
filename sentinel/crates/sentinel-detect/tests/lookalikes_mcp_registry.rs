//! Tests d'intégration — connecteur HTTP « registre officiel MCP ».
//!
//! On utilise wiremock pour simuler GitHub. Trois scénarios couverts :
//!
//!   1. `registry.json` répond 200 → parsing JSON direct, deux entrées.
//!   2. `registry.json` répond 404 → repli sur l'API README, parsing
//!      Markdown, deux entrées extraites de la liste à puces.
//!   3. Les deux endpoints répondent 404 → Vec vide (défaillance silencieuse).

use base64::engine::general_purpose::STANDARD as B64_STD;
use base64::Engine;
use sentinel_detect::lookalikes::sources::mcp_registry::lister_serveurs_depuis;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Test 1 : registry.json renvoyé directement (chemin nominal)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_registry_json_direct() {
    let serveur = MockServer::start().await;

    let payload = serde_json::json!({
        "servers": [
            {
                "name": "github-mcp",
                "description": "Accès aux dépôts GitHub.",
                "url": "https://github.com/example/github-mcp",
                "publisher": "example"
            },
            {
                "name": "filesystem-mcp",
                "description": "Lecture/écriture sur le FS local."
            }
        ]
    });

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .expect(1)
        .mount(&serveur)
        .await;

    let url_registry = format!("{}/registry.json", serveur.uri());
    let url_readme = format!("{}/readme-api", serveur.uri());
    let entrees = lister_serveurs_depuis(&url_registry, &url_readme).await;

    assert_eq!(entrees.len(), 2, "deux serveurs attendus : {:?}", entrees);

    let github = &entrees[0];
    assert_eq!(github.registre, "mcp-registry");
    assert_eq!(github.nom, "github-mcp");
    assert_eq!(github.description.as_deref(), Some("Accès aux dépôts GitHub."));
    assert_eq!(
        github.url.as_deref(),
        Some("https://github.com/example/github-mcp")
    );
    assert_eq!(github.auteur.as_deref(), Some("example"));
    assert!(github.outils.is_none());

    let fs = &entrees[1];
    assert_eq!(fs.registre, "mcp-registry");
    assert_eq!(fs.nom, "filesystem-mcp");
    assert_eq!(
        fs.description.as_deref(),
        Some("Lecture/écriture sur le FS local.")
    );
    assert!(fs.url.is_none());
    assert!(fs.auteur.is_none());
    assert!(fs.outils.is_none());
}

// ---------------------------------------------------------------------------
// Test 2 : registry.json en 404 → repli README + parsing Markdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repli_readme_quand_registry_json_absent() {
    let serveur = MockServer::start().await;

    let readme = "\
# Model Context Protocol servers

Quelques implémentations de référence :

- [github-mcp](https://github.com/example/github-mcp) - Accès aux dépôts GitHub.
- **[filesystem-mcp](https://github.com/example/fs-mcp)** — Lecture/écriture sur le FS local.
- Texte qui n'est pas une entrée de serveur.
";

    let payload = serde_json::json!({
        "name": "README.md",
        "encoding": "base64",
        "content": B64_STD.encode(readme.as_bytes()),
    });

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&serveur)
        .await;

    Mock::given(method("GET"))
        .and(path("/readme-api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .expect(1)
        .mount(&serveur)
        .await;

    let url_registry = format!("{}/registry.json", serveur.uri());
    let url_readme = format!("{}/readme-api", serveur.uri());
    let entrees = lister_serveurs_depuis(&url_registry, &url_readme).await;

    assert_eq!(
        entrees.len(),
        2,
        "deux entrées attendues, obtenu : {:?}",
        entrees
    );

    assert_eq!(entrees[0].registre, "mcp-registry");
    assert_eq!(entrees[0].nom, "github-mcp");
    assert_eq!(
        entrees[0].description.as_deref(),
        Some("Accès aux dépôts GitHub.")
    );

    assert_eq!(entrees[1].registre, "mcp-registry");
    assert_eq!(entrees[1].nom, "filesystem-mcp");
    assert_eq!(
        entrees[1].description.as_deref(),
        Some("Lecture/écriture sur le FS local.")
    );
}

// ---------------------------------------------------------------------------
// Test 4 : extraction des noms d'outils depuis les puces sous chaque entrée
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extrait_outils_depuis_sous_bullets_readme() {
    let serveur = MockServer::start().await;

    // Le README liste deux outils en sous-bullets sous l'entrée
    // filesystem-mcp : `read_file` et `write_file`. L'entrée github-mcp
    // ne déclare aucun outil et doit conserver `outils == None`.
    let readme = "\
# Model Context Protocol servers

- [github-mcp](https://github.com/example/github-mcp) - Accès aux dépôts GitHub.
- [filesystem-mcp](https://github.com/example/fs-mcp) - Lecture/écriture sur le FS local.
  - `read_file` : lit un fichier texte.
  - `write_file` : écrit un fichier texte.
";

    let payload = serde_json::json!({
        "name": "README.md",
        "encoding": "base64",
        "content": B64_STD.encode(readme.as_bytes()),
    });

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&serveur)
        .await;

    Mock::given(method("GET"))
        .and(path("/readme-api"))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload))
        .expect(1)
        .mount(&serveur)
        .await;

    let url_registry = format!("{}/registry.json", serveur.uri());
    let url_readme = format!("{}/readme-api", serveur.uri());
    let entrees = lister_serveurs_depuis(&url_registry, &url_readme).await;

    assert_eq!(entrees.len(), 2, "deux entrées attendues : {:?}", entrees);

    // github-mcp n'a pas de sous-bullets → outils == None.
    assert_eq!(entrees[0].nom, "github-mcp");
    assert!(
        entrees[0].outils.is_none(),
        "github-mcp ne doit avoir aucun outil, obtenu : {:?}",
        entrees[0].outils
    );

    // filesystem-mcp expose `read_file` et `write_file`.
    assert_eq!(entrees[1].nom, "filesystem-mcp");
    let outils = entrees[1]
        .outils
        .as_ref()
        .expect("filesystem-mcp doit exposer des outils");
    let noms: Vec<&str> = outils.iter().map(|o| o.nom.as_str()).collect();
    assert_eq!(noms, vec!["read_file", "write_file"]);
    for o in outils {
        assert!(o.enums_tries.is_empty());
        assert!(o.description_empreinte.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Test 3 : 404 partout → Vec vide (défaillance silencieuse)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn double_404_renvoie_vec_vide() {
    let serveur = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/registry.json"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&serveur)
        .await;

    Mock::given(method("GET"))
        .and(path("/readme-api"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&serveur)
        .await;

    let url_registry = format!("{}/registry.json", serveur.uri());
    let url_readme = format!("{}/readme-api", serveur.uri());
    let entrees = lister_serveurs_depuis(&url_registry, &url_readme).await;

    assert!(
        entrees.is_empty(),
        "404 + 404 doit produire un Vec vide, obtenu : {:?}",
        entrees
    );
}
