//! Tests de complétude — agent 4.6 (enrichissement d'alertes).

use chrono::Utc;
use sentinel_alerts::enrichment::EnrichisseurAlerte;
use sentinel_protocol::{
    Alerte, CanalAlerte, Constat, EtatConstat, Severite, TypeConstat,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn constat_base(severite: Severite, diff: Option<&str>) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: None,
        type_constat: TypeConstat::RugPull,
        severite,
        titre: "Outil modifié silencieusement".to_string(),
        detail: "La description de l'outil a changé entre deux sessions.".to_string(),
        diff: diff.map(|s| s.to_string()),
        references_conformite: vec![],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

fn alerte_base(severite: Severite) -> Alerte {
    Alerte {
        id: Uuid::new_v4(),
        constat_id: Uuid::new_v4(),
        canal: CanalAlerte::Dashboard,
        severite,
        titre: "Alerte rug-pull".to_string(),
        message: "Un outil a changé de description.".to_string(),
        diff: None,
        horodatage: Utc::now(),
        envoyee: false,
        tentatives: 0,
    }
}

// ---------------------------------------------------------------------------
// Test 1 : un constat avec diff enrichit correctement l'alerte.
// ---------------------------------------------------------------------------

#[test]
fn test_diff_copie_dans_alerte() {
    let diff_texte = "-ancien comportement\n+nouveau comportement";
    let constat = constat_base(Severite::Critique, Some(diff_texte));
    let mut alerte = alerte_base(Severite::Critique);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert_eq!(
        alerte.diff.as_deref(),
        Some(diff_texte),
        "Le diff du constat doit être copié dans l'alerte"
    );
}

// ---------------------------------------------------------------------------
// Test 2 : alerte critique sans diff — note d'incomplétude ajoutée.
// ---------------------------------------------------------------------------

#[test]
fn test_critique_sans_diff_note_incomplete() {
    let constat = constat_base(Severite::Critique, None);
    let mut alerte = alerte_base(Severite::Critique);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert!(
        alerte.message.contains("Contexte actionnable incomplet"),
        "Le message doit signaler l'incomplétude pour une alerte critique sans diff"
    );
    assert!(
        alerte.diff.is_none(),
        "Le diff doit rester absent quand le constat n'en a pas"
    );
}

// ---------------------------------------------------------------------------
// Test 3 : les références conformité sont ajoutées au message.
// ---------------------------------------------------------------------------

#[test]
fn test_references_conformite_ajoutees() {
    let constat = constat_base(Severite::Haute, Some("- ligne supprimée"));
    let mut alerte = alerte_base(Severite::Haute);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert!(
        alerte.message.contains("Références :"),
        "Le message doit contenir la section références"
    );
    assert!(
        alerte.message.contains("SAFE-T1001"),
        "SAFE-T1001 doit être présente dans les références"
    );
    assert!(
        alerte.message.contains("OWASP MCP09"),
        "OWASP MCP09 doit être présente dans les références"
    );
}

// ---------------------------------------------------------------------------
// Test 4 : verifier_completude rejette une alerte critique sans diff ni pattern.
// ---------------------------------------------------------------------------

#[test]
fn test_verifier_completude_rejette_critique_vide() {
    let alerte = alerte_base(Severite::Critique);
    // Pas de diff, pas de mention SAFE/OWASP dans le message de base.

    let resultat = EnrichisseurAlerte::verifier_completude(&alerte);

    assert!(
        resultat.is_err(),
        "verifier_completude doit retourner une erreur pour une alerte critique sans contexte"
    );
    let message_erreur = resultat.unwrap_err();
    assert!(
        message_erreur.contains("contexte actionnable"),
        "L'erreur doit mentionner le contexte actionnable manquant"
    );
}

// ---------------------------------------------------------------------------
// Test 5 : verifier_completude accepte une alerte critique avec diff.
// ---------------------------------------------------------------------------

#[test]
fn test_verifier_completude_accepte_critique_avec_diff() {
    let mut alerte = alerte_base(Severite::Critique);
    alerte.diff = Some("-ancien\n+nouveau".to_string());

    let resultat = EnrichisseurAlerte::verifier_completude(&alerte);

    assert!(
        resultat.is_ok(),
        "verifier_completude doit accepter une alerte critique avec diff"
    );
}

// ---------------------------------------------------------------------------
// Test 6 : verifier_completude accepte toujours une alerte Haute ou Moyenne.
// ---------------------------------------------------------------------------

#[test]
fn test_verifier_completude_accepte_non_critique() {
    let alerte_haute = alerte_base(Severite::Haute);
    let alerte_moyenne = alerte_base(Severite::Moyenne);

    assert!(
        EnrichisseurAlerte::verifier_completude(&alerte_haute).is_ok(),
        "Une alerte Haute sans diff doit passer la vérification"
    );
    assert!(
        EnrichisseurAlerte::verifier_completude(&alerte_moyenne).is_ok(),
        "Une alerte Moyenne sans diff doit passer la vérification"
    );
}

// ---------------------------------------------------------------------------
// Test 7 : resume_actionnable combine titre, détail, diff tronqué, références.
// ---------------------------------------------------------------------------

#[test]
fn test_resume_actionnable_complet() {
    let diff_long = "x".repeat(400);
    let constat = constat_base(Severite::Critique, Some(&diff_long));

    let resume = EnrichisseurAlerte::resume_actionnable(&constat);

    assert!(resume.contains("Outil modifié silencieusement"), "Doit contenir le titre");
    assert!(resume.contains("La description de l'outil"), "Doit contenir le détail");
    assert!(resume.contains("tronqué"), "Un diff > 300 chars doit être tronqué");
    assert!(resume.contains("Références :"), "Doit contenir les références");
    assert!(resume.contains("SAFE-T1001"), "Doit contenir SAFE-T1001");
}

// ---------------------------------------------------------------------------
// Test 8 : enrichir n'ajoute pas la note d'incomplétude pour les niveaux < Critique.
// ---------------------------------------------------------------------------

#[test]
fn test_pas_de_note_incomplete_pour_haute() {
    let constat = constat_base(Severite::Haute, None);
    let mut alerte = alerte_base(Severite::Haute);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert!(
        !alerte.message.contains("Contexte actionnable incomplet"),
        "La note d'incomplétude ne doit pas apparaître pour une alerte Haute"
    );
}
