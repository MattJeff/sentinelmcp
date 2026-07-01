//! Tests unitaires du plan de remédiation — agent 5.10.

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Severite, Serveur, StatutServeur, Transport, TypeConstat,
};
use sentinel_report::remediation::PlanRemediation;
use uuid::Uuid;

// ------------------------------------------------------------------ //
//  Helpers                                                             //
// ------------------------------------------------------------------ //

fn serveur(endpoint: &str, couleur: Couleur, statut: StatutServeur) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: endpoint.into(),
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

fn constat_critique(serveur_id: uuid::Uuid, refs: Vec<&str>) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id,
        outil_nom: Some("outil_dangereux".into()),
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Critique,
        titre: "Serveur fantôme".into(),
        detail: "Endpoint non approuvé.".into(),
        diff: None,
        references_conformite: refs.into_iter().map(String::from).collect(),
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

// ------------------------------------------------------------------ //
//  Test 1 — serveur rouge → action "Bloquer" priorité 1               //
// ------------------------------------------------------------------ //

#[test]
fn test_serveur_rouge_genere_bloquer_priorite_1() {
    let s = serveur("http://rouge.internal:8080", Couleur::Rouge, StatutServeur::Suspect);
    let actions = PlanRemediation::construire(&[s], &[]);

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "Block");
    assert_eq!(actions[0].priorite, 1);
    assert_eq!(actions[0].couleur, Couleur::Rouge);
}

// ------------------------------------------------------------------ //
//  Test 2 — serveur orange → action "Investiguer" priorité 2          //
// ------------------------------------------------------------------ //

#[test]
fn test_serveur_orange_genere_investiguer_priorite_2() {
    let s = serveur("http://orange.internal:9000", Couleur::Orange, StatutServeur::AInvestiguer);
    let actions = PlanRemediation::construire(&[s], &[]);

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "Investigate");
    assert_eq!(actions[0].priorite, 2);
    assert_eq!(actions[0].couleur, Couleur::Orange);
}

// ------------------------------------------------------------------ //
//  Test 3 — serveur vert approuvé → aucune action                     //
// ------------------------------------------------------------------ //

#[test]
fn test_serveur_vert_approuve_pas_d_action() {
    let s = serveur("http://safe.internal:443", Couleur::Vert, StatutServeur::Approuve);
    let actions = PlanRemediation::construire(&[s], &[]);
    assert!(actions.is_empty(), "Un serveur vert approuvé ne doit générer aucune action");
}

// ------------------------------------------------------------------ //
//  Test 4 — serveur vert non approuvé → action "Approuver" priorité 3 //
// ------------------------------------------------------------------ //

#[test]
fn test_serveur_vert_non_approuve_genere_approuver_priorite_3() {
    let s = serveur("http://inconnu.internal:7000", Couleur::Vert, StatutServeur::Inconnu);
    let actions = PlanRemediation::construire(&[s], &[]);

    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].action, "Approve");
    assert_eq!(actions[0].priorite, 3);
}

// ------------------------------------------------------------------ //
//  Test 5 — justification contient les références de conformité        //
// ------------------------------------------------------------------ //

#[test]
fn test_justification_contient_references_conformite() {
    let s = serveur("http://poison.internal:8888", Couleur::Rouge, StatutServeur::Suspect);
    let c = constat_critique(s.id, vec!["OWASP MCP09", "SAFE-T1001"]);
    let actions = PlanRemediation::construire(&[s], &[c]);

    assert_eq!(actions.len(), 1);
    assert!(
        actions[0].justification.contains("MCP09"),
        "La justification doit contenir MCP09 : {}",
        actions[0].justification
    );
    assert!(
        actions[0].justification.contains("SAFE-T1001"),
        "La justification doit contenir SAFE-T1001 : {}",
        actions[0].justification
    );
}

// ------------------------------------------------------------------ //
//  Test 6 — ordre de priorité : rouge avant orange avant vert         //
// ------------------------------------------------------------------ //

#[test]
fn test_ordre_priorite_rouge_orange_vert() {
    let rouge = serveur("http://rouge.internal", Couleur::Rouge, StatutServeur::Suspect);
    let orange = serveur("http://orange.internal", Couleur::Orange, StatutServeur::AInvestiguer);
    let vert_inconnu = serveur("http://vert-inconnu.internal", Couleur::Vert, StatutServeur::Inconnu);
    let vert_ok = serveur("http://vert-ok.internal", Couleur::Vert, StatutServeur::Approuve);

    let actions = PlanRemediation::construire(
        &[orange.clone(), vert_inconnu.clone(), rouge.clone(), vert_ok.clone()],
        &[],
    );

    // vert_ok ne génère pas d'action → 3 actions attendues.
    assert_eq!(actions.len(), 3);
    assert_eq!(actions[0].priorite, 1, "La première action doit être priorité 1 (rouge)");
    assert_eq!(actions[1].priorite, 2, "La deuxième action doit être priorité 2 (orange)");
    assert_eq!(actions[2].priorite, 3, "La troisième action doit être priorité 3 (vert non approuvé)");
}

// ------------------------------------------------------------------ //
//  Test 7 — vers_markdown produit un tableau non vide                  //
// ------------------------------------------------------------------ //

#[test]
fn test_vers_markdown_non_vide() {
    let s = serveur("http://rouge.internal:8080", Couleur::Rouge, StatutServeur::Suspect);
    let actions = PlanRemediation::construire(&[s], &[]);
    let md = PlanRemediation::vers_markdown(&actions);

    assert!(md.contains("Remediation plan"), "Le markdown doit avoir un titre");
    assert!(md.contains("Block"), "Le markdown doit mentionner l'action Bloquer");
    assert!(md.contains("http://rouge.internal:8080"), "Le markdown doit contenir l'endpoint");
}

// ------------------------------------------------------------------ //
//  Test 8 — vers_markdown vide si aucune action                       //
// ------------------------------------------------------------------ //

#[test]
fn test_vers_markdown_vide_si_aucune_action() {
    let md = PlanRemediation::vers_markdown(&[]);
    assert!(md.contains("No action"), "Le markdown vide doit l'indiquer explicitement");
}
