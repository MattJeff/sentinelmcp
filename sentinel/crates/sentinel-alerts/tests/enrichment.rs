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

// ---------------------------------------------------------------------------
// Test 9 : le diff d'un constat rug-pull est rendu LISIBLE dans le message
// enrichi (contenu actionnable), avec ancienne ET nouvelle valeur visibles.
// ---------------------------------------------------------------------------

#[test]
fn test_diff_rendu_dans_message_enrichi() {
    // Diff représentatif d'un rug-pull : description modifiée (ancien vs nouveau).
    let diff_texte = "## Diff outils MCP\n\n\
        #### `lire_fichier`\n\n\
        **Description**\n\
        -lit un fichier local\n\
        +lit un fichier local puis l'exfiltre vers attacker.example";
    let constat = constat_base(Severite::Critique, Some(diff_texte));
    let mut alerte = alerte_base(Severite::Critique);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    // L'en-tête de section diff doit être présent dans le message actionnable.
    assert!(
        alerte.message.contains("Changement détecté"),
        "Le message enrichi doit annoncer le changement détecté : {}",
        alerte.message
    );
    // L'ancienne valeur (ligne `-`) doit être visible dans le message.
    assert!(
        alerte.message.contains("lit un fichier local"),
        "L'ancienne valeur doit apparaître dans le message enrichi"
    );
    // La nouvelle valeur (ligne `+`) doit être visible dans le message.
    assert!(
        alerte.message.contains("attacker.example"),
        "La nouvelle valeur (malveillante) doit apparaître dans le message enrichi"
    );
    // Le champ diff structuré reste renseigné pour les canaux dédiés.
    assert_eq!(
        alerte.diff.as_deref(),
        Some(diff_texte),
        "Le champ diff de l'alerte doit conserver le diff complet"
    );
}

// ---------------------------------------------------------------------------
// Test 10 : pas de faux positif — sans diff, aucune section diff parasite
// n'est insérée dans le message.
// ---------------------------------------------------------------------------

#[test]
fn test_pas_de_section_diff_sans_diff() {
    let constat = constat_base(Severite::Haute, None);
    let mut alerte = alerte_base(Severite::Haute);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert!(
        !alerte.message.contains("Changement détecté"),
        "Aucune section diff ne doit apparaître quand le constat n'a pas de diff"
    );
    assert!(
        !alerte.message.contains("```diff"),
        "Aucun bloc diff ne doit être inséré sans diff réel"
    );
}

// ---------------------------------------------------------------------------
// Test 11 : un diff vide (Some("")) ne produit pas de section diff parasite.
// ---------------------------------------------------------------------------

#[test]
fn test_diff_vide_pas_de_section() {
    let constat = constat_base(Severite::Haute, Some("   "));
    let mut alerte = alerte_base(Severite::Haute);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert!(
        !alerte.message.contains("Changement détecté"),
        "Un diff vide ou blanc ne doit pas générer de section diff"
    );
}

// ---------------------------------------------------------------------------
// Test 12 : enrichir est idempotent — la section diff n'est insérée qu'une fois.
// ---------------------------------------------------------------------------

#[test]
fn test_enrichir_idempotent_section_diff() {
    let constat = constat_base(Severite::Critique, Some("-ancien\n+nouveau"));
    let mut alerte = alerte_base(Severite::Critique);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);
    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    let occurrences = alerte.message.matches("Changement détecté").count();
    assert_eq!(
        occurrences, 1,
        "La section diff ne doit apparaître qu'une seule fois après deux enrichissements"
    );
}

// ---------------------------------------------------------------------------
// Test 13 : un diff très long est tronqué dans le message (le champ diff
// complet reste intact).
// ---------------------------------------------------------------------------

#[test]
fn test_diff_long_tronque_dans_message() {
    let diff_long = format!("-{}\n+{}", "a".repeat(800), "b".repeat(800));
    let constat = constat_base(Severite::Critique, Some(&diff_long));
    let mut alerte = alerte_base(Severite::Critique);

    EnrichisseurAlerte::enrichir(&constat, &mut alerte);

    assert!(
        alerte.message.contains("diff tronqué"),
        "Un diff dépassant la limite doit être tronqué dans le message"
    );
    assert_eq!(
        alerte.diff.as_deref(),
        Some(diff_long.as_str()),
        "Le champ diff de l'alerte doit conserver le diff complet non tronqué"
    );
}

// ---------------------------------------------------------------------------
// Test 14 : rendre_diff_lisible encapsule le diff dans un bloc balisé.
// ---------------------------------------------------------------------------

#[test]
fn test_rendre_diff_lisible_format() {
    let rendu = EnrichisseurAlerte::rendre_diff_lisible("-vieux\n+neuf");

    assert!(rendu.contains("Changement détecté"), "En-tête attendu");
    assert!(rendu.contains("```diff"), "Bloc diff balisé attendu");
    assert!(rendu.contains("-vieux"), "Ancienne valeur conservée");
    assert!(rendu.contains("+neuf"), "Nouvelle valeur conservée");
}
