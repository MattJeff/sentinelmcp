//! Tests du résumé exécutif — agent 5.2.

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Severite, Serveur, StatutServeur, Transport, TypeConstat,
};
use sentinel_report::ResumeExecutif;
use uuid::Uuid;

// ------------------------------------------------------------------ //
//  Helpers                                                             //
// ------------------------------------------------------------------ //

fn serveur(statut: StatutServeur, couleur: Couleur) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: "http://test.internal:8080".into(),
        transport: Transport::Http,
        portees: vec![],
        statut,
        couleur,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    }
}

fn constat(severite: Severite) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: None,
        type_constat: TypeConstat::ShadowMcp,
        severite,
        titre: "Constat test".into(),
        detail: "Détail test".into(),
        diff: None,
        references_conformite: vec![],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

// ------------------------------------------------------------------ //
//  Tests                                                               //
// ------------------------------------------------------------------ //

/// Test 1 : aucun serveur → texte contient "Aucun serveur MCP détecté".
#[test]
fn test_zero_serveurs() {
    let resume = ResumeExecutif::construire(&[], &[]);

    assert_eq!(resume.serveurs_total, 0);
    assert_eq!(resume.serveurs_approuves, 0);
    assert_eq!(resume.serveurs_non_approuves, 0);
    assert_eq!(resume.serveurs_a_risque, 0);
    assert!(
        resume.texte.contains("No MCP server detected"),
        "texte inattendu : {}",
        resume.texte
    );
    assert!(resume.appel_action.is_none(), "aucun appel à l'action attendu sans serveur");
}

/// Test 2 : 5 serveurs dont 2 rouges → résumé contient "2" et le texte mentionne le risque.
#[test]
fn test_cinq_serveurs_deux_rouges() {
    let serveurs = vec![
        serveur(StatutServeur::Approuve, Couleur::Vert),
        serveur(StatutServeur::Approuve, Couleur::Vert),
        serveur(StatutServeur::Inconnu, Couleur::Orange),
        serveur(StatutServeur::Suspect, Couleur::Rouge),
        serveur(StatutServeur::Suspect, Couleur::Rouge),
    ];
    let resume = ResumeExecutif::construire(&serveurs, &[]);

    assert_eq!(resume.serveurs_total, 5);
    assert_eq!(resume.serveurs_approuves, 2);
    assert_eq!(resume.serveurs_non_approuves, 3);
    assert_eq!(resume.serveurs_a_risque, 2);

    // Le texte doit mentionner "2 à risque" (sous une forme ou une autre)
    assert!(
        resume.texte.contains("2"),
        "le texte doit mentionner le nombre 2 : {}",
        resume.texte
    );
    assert!(
        resume.texte.to_lowercase().contains("risk"),
        "le texte doit mentionner le risque : {}",
        resume.texte
    );
}

/// Test 3 : markdown contient le tableau KPI (ligne d'en-tête et séparateur).
#[test]
fn test_markdown_contient_tableau_kpi() {
    let serveurs = vec![serveur(StatutServeur::Approuve, Couleur::Vert)];
    let resume = ResumeExecutif::construire(&serveurs, &[]);
    let md = resume.vers_markdown();

    assert!(md.contains("| Metric | Value |"), "en-tête de tableau absent : {}", md);
    assert!(md.contains("|---|---|"), "séparateur de tableau absent : {}", md);
    assert!(md.contains("Servers detected"), "KPI serveurs absent : {}", md);
    assert!(md.contains("Critical findings"), "KPI constats absent : {}", md);
}

/// Test 4 : texte plain ne contient pas de syntaxe Markdown.
#[test]
fn test_texte_plain_sans_markdown() {
    let serveurs = vec![
        serveur(StatutServeur::Suspect, Couleur::Rouge),
        serveur(StatutServeur::Inconnu, Couleur::Orange),
    ];
    let constats = vec![constat(Severite::Critique)];
    let resume = ResumeExecutif::construire(&serveurs, &constats);
    let plain = resume.vers_texte_plain();

    // Pas de syntaxe Markdown : pas de #, |, **, >
    assert!(!plain.contains("# "), "balise # trouvée dans le plain : {}", plain);
    assert!(!plain.contains("| "), "pipe trouvé dans le plain : {}", plain);
    assert!(!plain.contains("**"), "gras markdown trouvé : {}", plain);
    assert!(!plain.contains("> "), "blockquote markdown trouvé : {}", plain);
}

/// Test 5 : appel_action présent seulement si risque > 0 ou critiques > 0.
#[test]
fn test_appel_action_conditionnel() {
    // Cas sans risque → None
    let serveurs_sains = vec![
        serveur(StatutServeur::Approuve, Couleur::Vert),
        serveur(StatutServeur::Approuve, Couleur::Vert),
    ];
    let resume_sain = ResumeExecutif::construire(&serveurs_sains, &[]);
    assert!(
        resume_sain.appel_action.is_none(),
        "appel_action doit être None quand tout est vert : {:?}",
        resume_sain.appel_action
    );

    // Cas avec 1 serveur rouge → Some
    let serveurs_risque = vec![
        serveur(StatutServeur::Approuve, Couleur::Vert),
        serveur(StatutServeur::Suspect, Couleur::Rouge),
    ];
    let resume_risque = ResumeExecutif::construire(&serveurs_risque, &[]);
    assert!(
        resume_risque.appel_action.is_some(),
        "appel_action doit être Some quand un serveur est rouge"
    );
    assert!(
        resume_risque
            .appel_action
            .as_ref()
            .unwrap()
            .contains("Immediate action"),
        "appel_action doit mentionner 'action immédiate' : {:?}",
        resume_risque.appel_action
    );

    // Cas avec constat critique seulement (pas de rouge) → Some
    let serveurs_verts = vec![serveur(StatutServeur::Approuve, Couleur::Vert)];
    let constats_critiques = vec![constat(Severite::Critique)];
    let resume_critique = ResumeExecutif::construire(&serveurs_verts, &constats_critiques);
    assert!(
        resume_critique.appel_action.is_some(),
        "appel_action doit être Some quand il y a un constat critique"
    );
}

/// Test 6 : comptage fin des sévérités de constats.
#[test]
fn test_comptage_constats_par_severite() {
    let constats = vec![
        constat(Severite::Critique),
        constat(Severite::Critique),
        constat(Severite::Haute),
        constat(Severite::Moyenne),
        constat(Severite::Moyenne),
        constat(Severite::Moyenne),
        constat(Severite::Info), // Info ignoré du résumé non-technique
    ];
    let resume = ResumeExecutif::construire(&[], &constats);

    assert_eq!(resume.constats_critiques, 2);
    assert_eq!(resume.constats_hauts, 1);
    assert_eq!(resume.constats_moyens, 3);
}

/// Test 7 : markdown contient l'appel à l'action en blockquote quand risque > 0.
#[test]
fn test_markdown_blockquote_appel_action() {
    let serveurs = vec![serveur(StatutServeur::Suspect, Couleur::Rouge)];
    let resume = ResumeExecutif::construire(&serveurs, &[]);
    let md = resume.vers_markdown();

    assert!(
        md.contains("> **Action required"),
        "blockquote d'action absent du markdown : {}",
        md
    );
}
