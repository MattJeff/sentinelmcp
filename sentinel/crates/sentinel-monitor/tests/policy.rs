//! Tests de la politique de qualification des changements — agent 2.7.

use sentinel_monitor::policy::{Changement, DecisionPolitique, PolitiqueChangement};

// ── Tests de qualifier() ──────────────────────────────────────────────────────

#[test]
fn test_aucun_changement_retourne_ignorer() {
    let c = Changement::vide();
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Ignorer);
}

#[test]
fn test_motif_suspect_retourne_escalader() {
    let mut c = Changement::vide();
    c.motifs_suspects_detectes = vec!["SYSTEM prompt injection".to_string()];
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Escalader);
}

#[test]
fn test_modification_description_retourne_alerter() {
    let mut c = Changement::vide();
    c.modification_description = true;
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Alerter);
}

#[test]
fn test_modification_input_schema_retourne_alerter() {
    let mut c = Changement::vide();
    c.modification_input_schema = true;
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Alerter);
}

#[test]
fn test_ajout_outil_seul_retourne_alerter() {
    let mut c = Changement::vide();
    c.ajout_outil = true;
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Alerter);
}

#[test]
fn test_suppression_outil_seule_retourne_alerter() {
    let mut c = Changement::vide();
    c.suppression_outil = true;
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Alerter);
}

#[test]
fn test_suspect_prioritaire_sur_modification_schema() {
    // Même si le schema a changé, la présence d'un motif suspect doit escalader.
    let mut c = Changement::vide();
    c.modification_input_schema = true;
    c.motifs_suspects_detectes = vec![".env leak".to_string()];
    assert_eq!(PolitiqueChangement::qualifier(&c), DecisionPolitique::Escalader);
}

// ── Tests de qualifier_resume() ──────────────────────────────────────────────

#[test]
fn test_resume_avec_system_escalade() {
    let decision = PolitiqueChangement::qualifier_resume("Injection SYSTEM prompt détectée");
    assert_eq!(decision, DecisionPolitique::Escalader);
}

#[test]
fn test_resume_avec_env_escalade() {
    let decision = PolitiqueChangement::qualifier_resume("lecture de fichier .env détectée");
    assert_eq!(decision, DecisionPolitique::Escalader);
}

#[test]
fn test_resume_avec_ssh_escalade() {
    let decision = PolitiqueChangement::qualifier_resume("accès clé SSH privée");
    assert_eq!(decision, DecisionPolitique::Escalader);
}

#[test]
fn test_resume_sans_motif_critique_alerte() {
    let decision = PolitiqueChangement::qualifier_resume("ajout de l'outil calculatrice v2");
    assert_eq!(decision, DecisionPolitique::Alerter);
}

#[test]
fn test_resume_vide_alerte() {
    let decision = PolitiqueChangement::qualifier_resume("");
    assert_eq!(decision, DecisionPolitique::Alerter);
}
