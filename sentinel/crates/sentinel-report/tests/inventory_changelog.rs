//! Tests agent 5.3 — Inventaire et journal des changements.

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Portee, Serveur, Severite, StatutServeur, Transport,
    TypeConstat,
};
use sentinel_report::{SectionInventaire, SectionJournal};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serveur(endpoint: &str, couleur: Couleur, statut: StatutServeur) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: endpoint.to_string(),
        transport: Transport::Http,
        portees: vec![Portee::ApiExterne],
        statut,
        couleur,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    }
}

fn constat(serveur_id: uuid::Uuid, type_constat: TypeConstat, diff: Option<&str>) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id,
        outil_nom: None,
        type_constat,
        severite: Severite::Haute,
        titre: "Constat de test".to_string(),
        detail: "Détail du constat.".to_string(),
        diff: diff.map(|s| s.to_string()),
        references_conformite: vec!["OWASP MCP09".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

// ---------------------------------------------------------------------------
// Test 1 : inventaire vide → markdown propre
// ---------------------------------------------------------------------------

#[test]
fn test_inventaire_vide() {
    let section = SectionInventaire::construire(vec![]);
    assert!(
        section.serveurs.is_empty(),
        "aucun serveur attendu"
    );
    assert!(
        section.markdown.contains("## MCP server inventory"),
        "l'en-tête de section doit être présent"
    );
    assert!(
        section.markdown.contains("No servers detected"),
        "message vide attendu"
    );
    // Pas de tableau ni de sous-section critique
    assert!(
        !section.markdown.contains("| Endpoint |"),
        "aucun tableau attendu pour un inventaire vide"
    );
}

// ---------------------------------------------------------------------------
// Test 2 : 3 serveurs dont 1 rouge → tableau + sous-section détail
// ---------------------------------------------------------------------------

#[test]
fn test_inventaire_trois_serveurs_un_rouge() {
    let s_vert = serveur("https://vert.example.com", Couleur::Vert, StatutServeur::Approuve);
    let s_orange = serveur("https://orange.example.com", Couleur::Orange, StatutServeur::Inconnu);
    let mut s_rouge = serveur("https://rouge.example.com", Couleur::Rouge, StatutServeur::Suspect);
    s_rouge.empreinte_courante = Some("deadbeef".to_string());

    let section = SectionInventaire::construire(vec![
        s_vert.clone(),
        s_orange.clone(),
        s_rouge.clone(),
    ]);

    assert_eq!(section.serveurs.len(), 3, "3 serveurs attendus");

    // Tableau présent avec les trois endpoints
    assert!(section.markdown.contains("| Endpoint |"), "tableau attendu");
    assert!(section.markdown.contains("https://vert.example.com"));
    assert!(section.markdown.contains("https://orange.example.com"));
    assert!(section.markdown.contains("https://rouge.example.com"));

    // Sous-section critique présente
    assert!(
        section.markdown.contains("### Critical servers (red)"),
        "sous-section critique attendue"
    );
    assert!(
        section.markdown.contains("#### `https://rouge.example.com`"),
        "détail rouge attendu"
    );
    assert!(
        section.markdown.contains("deadbeef"),
        "empreinte attendue dans le détail"
    );

    // Les serveurs non rouges ne doivent pas apparaître dans les détails critiques
    let detail_critique = section
        .markdown
        .split("### Critical servers")
        .nth(1)
        .unwrap_or("");
    assert!(
        !detail_critique.contains("https://vert.example.com"),
        "le serveur vert ne doit pas apparaître dans les détails critiques"
    );
}

// ---------------------------------------------------------------------------
// Test 3 : journal vide → "Aucun changement"
// ---------------------------------------------------------------------------

#[test]
fn test_journal_vide() {
    let section = SectionJournal::construire(&[], &[]);
    assert!(
        section.entrees.is_empty(),
        "aucune entrée attendue"
    );
    assert!(
        section.markdown.contains("## Change log"),
        "en-tête de section attendu"
    );
    assert!(
        section.markdown.contains("No change recorded"),
        "message vide attendu"
    );
}

// ---------------------------------------------------------------------------
// Test 4 : journal avec diff → diff inclus dans le markdown
// ---------------------------------------------------------------------------

#[test]
fn test_journal_avec_diff() {
    let s = serveur("https://cible.example.com", Couleur::Rouge, StatutServeur::Suspect);
    let diff_texte = "-  description: ancienne description\n+  description: nouvelle description malveillante";
    let c = constat(s.id, TypeConstat::RugPull, Some(diff_texte));

    let section = SectionJournal::construire(&[c], &[s.clone()]);

    assert_eq!(section.entrees.len(), 1);
    assert_eq!(section.entrees[0].serveur_endpoint, "https://cible.example.com");
    assert!(
        section.entrees[0].diff.is_some(),
        "diff attendu dans l'entrée"
    );

    // Diff inclus dans le markdown avec bloc ```diff
    assert!(
        section.markdown.contains("```diff"),
        "bloc diff attendu dans le markdown"
    );
    assert!(
        section.markdown.contains("ancienne description"),
        "contenu diff attendu"
    );
    assert!(
        section.markdown.contains("nouvelle description malveillante"),
        "contenu diff attendu"
    );
    assert!(
        section.markdown.contains("https://cible.example.com"),
        "endpoint attendu dans le journal"
    );
    assert!(
        section.markdown.contains("Rug pull"),
        "type de constat attendu dans le journal"
    );
}

// ---------------------------------------------------------------------------
// Test 5 : journal trié par horodatage décroissant
// ---------------------------------------------------------------------------

#[test]
fn test_journal_tri_decroissant() {
    use chrono::Duration;

    let s = serveur("https://tri.example.com", Couleur::Orange, StatutServeur::Inconnu);
    let maintenant = Utc::now();

    let mut c_ancien = constat(s.id, TypeConstat::NouveauServeur, None);
    c_ancien.horodatage = maintenant - Duration::hours(2);
    c_ancien.titre = "Événement ancien".to_string();

    let mut c_recent = constat(s.id, TypeConstat::ShadowMcp, None);
    c_recent.horodatage = maintenant;
    c_recent.titre = "Événement récent".to_string();

    let section = SectionJournal::construire(&[c_ancien, c_recent], &[s]);

    assert_eq!(section.entrees.len(), 2);
    // La première entrée doit être la plus récente
    assert_eq!(
        section.entrees[0].titre, "Événement récent",
        "tri décroissant attendu : le plus récent en premier"
    );
    assert_eq!(
        section.entrees[1].titre, "Événement ancien",
        "tri décroissant attendu : le plus ancien en second"
    );

    // Dans le markdown, "récent" doit apparaître avant "ancien"
    let pos_recent = section.markdown.find("Événement récent").unwrap();
    let pos_ancien = section.markdown.find("Événement ancien").unwrap();
    assert!(
        pos_recent < pos_ancien,
        "le récent doit précéder l'ancien dans le markdown"
    );
}
