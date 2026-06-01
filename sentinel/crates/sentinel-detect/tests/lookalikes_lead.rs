//! Tests d'intégration — agent 3.8 : connecteur registres et architecture mode C.

use sentinel_detect::lookalikes::{
    ConnecteurRegistres, EntreeRegistre, SourceMcpRegistry, SourceMcpSo, SourcePulseMCP,
    SourceSmithery, SourceStatique,
};

// ---------------------------------------------------------------------------
// Utilitaire
// ---------------------------------------------------------------------------

fn entree(registre: &str, nom: &str) -> EntreeRegistre {
    EntreeRegistre {
        registre: registre.to_string(),
        nom: nom.to_string(),
        description: format!("Description de {}", nom),
        hash_binaire: None,
        sbom_url: None,
        publie_par: None,
        url_serveur: None,
    }
}

// ---------------------------------------------------------------------------
// Test 1 : ConnecteurRegistres collecte les entrées de N sources
// ---------------------------------------------------------------------------

#[tokio::test]
async fn collecte_entrees_de_plusieurs_sources() {
    let source_a = SourceStatique::nouveau(
        "registre-a",
        vec![entree("registre-a", "serveur-alpha"), entree("registre-a", "serveur-beta")],
    );
    let source_b = SourceStatique::nouveau(
        "registre-b",
        vec![entree("registre-b", "serveur-gamma")],
    );

    let mut connecteur = ConnecteurRegistres::nouveau();
    connecteur.ajouter(source_a);
    connecteur.ajouter(source_b);

    let entrees_a = connecteur.interroger("registre-a").await.unwrap();
    let entrees_b = connecteur.interroger("registre-b").await.unwrap();

    assert_eq!(entrees_a.len(), 2);
    assert_eq!(entrees_b.len(), 1);
    assert_eq!(entrees_a[0].nom, "serveur-alpha");
    assert_eq!(entrees_b[0].nom, "serveur-gamma");
}

// ---------------------------------------------------------------------------
// Test 2 : interroger_tous retourne autant de résultats que de sources
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interroger_tous_retourne_autant_de_resultats_que_de_sources() {
    let mut connecteur = ConnecteurRegistres::nouveau();
    connecteur.ajouter(SourceStatique::nouveau("src-1", vec![entree("src-1", "outil-1")]));
    connecteur.ajouter(SourceStatique::nouveau("src-2", vec![]));
    connecteur.ajouter(SourceStatique::nouveau("src-3", vec![
        entree("src-3", "outil-x"),
        entree("src-3", "outil-y"),
    ]));

    let resultats = connecteur.interroger_tous().await;

    assert_eq!(resultats.len(), 3, "doit y avoir exactement 3 résultats");

    // Vérifie les noms dans l'ordre d'insertion
    assert_eq!(resultats[0].0, "src-1");
    assert_eq!(resultats[1].0, "src-2");
    assert_eq!(resultats[2].0, "src-3");

    // Vérifie les contenus
    assert_eq!(resultats[0].1.as_ref().unwrap().len(), 1);
    assert_eq!(resultats[1].1.as_ref().unwrap().len(), 0);
    assert_eq!(resultats[2].1.as_ref().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Test 3 : SourceStatique fonctionne (champs complets round-trip)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn source_statique_round_trip_champs_complets() {
    let attendue = EntreeRegistre {
        registre: "test-reg".to_string(),
        nom: "mcp-filesystem".to_string(),
        description: "Accès au système de fichiers local".to_string(),
        hash_binaire: Some("abc123".to_string()),
        sbom_url: Some("https://example.com/sbom.json".to_string()),
        publie_par: Some("anthropic".to_string()),
        url_serveur: Some("https://github.com/anthropic/mcp-filesystem".to_string()),
    };

    let source = SourceStatique::nouveau("test-reg", vec![attendue.clone()]);
    let entrees = source.lister().await.unwrap();

    assert_eq!(entrees.len(), 1);
    assert_eq!(entrees[0], attendue);
    assert_eq!(source.nom(), "test-reg");
}

// ---------------------------------------------------------------------------
// Test 4 : interroger("nom-inconnu") retourne une erreur
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interroger_registre_inconnu_retourne_erreur() {
    let mut connecteur = ConnecteurRegistres::nouveau();
    connecteur.ajouter(SourceStatique::nouveau("existant", vec![]));

    let resultat = connecteur.interroger("registre-qui-nexiste-pas").await;

    assert!(resultat.is_err(), "doit retourner Err pour un registre inconnu");
    let message = resultat.unwrap_err().to_string();
    assert!(
        message.contains("registre-qui-nexiste-pas"),
        "le message d'erreur doit mentionner le nom fourni, obtenu : {}",
        message
    );
}

// ---------------------------------------------------------------------------
// Test 5 : les 4 sources prédéfinies ont les noms attendus et retournent Ok
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sources_predefinies_noms_et_ok() {
    let sources: Vec<Box<dyn Fn() -> std::sync::Arc<dyn sentinel_detect::lookalikes::SourceRegistre>>> = vec![
        Box::new(|| SourcePulseMCP::nouveau()),
        Box::new(|| SourceMcpRegistry::nouveau()),
        Box::new(|| SourceSmithery::nouveau()),
        Box::new(|| SourceMcpSo::nouveau()),
    ];

    let noms_attendus = ["pulsemcp", "mcp-registry", "smithery", "mcp.so"];

    for (fabrique, nom_attendu) in sources.iter().zip(noms_attendus.iter()) {
        let source = fabrique();
        assert_eq!(source.nom(), *nom_attendu, "nom inattendu pour la source {}", nom_attendu);
        let res = source.lister().await;
        assert!(res.is_ok(), "lister() doit retourner Ok pour {}", nom_attendu);
    }
}

// ---------------------------------------------------------------------------
// Test 6 : connecteur vide — interroger_tous retourne slice vide
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connecteur_vide_interroger_tous_retourne_vide() {
    let connecteur = ConnecteurRegistres::nouveau();
    let resultats = connecteur.interroger_tous().await;
    assert!(resultats.is_empty());
}
