//! Tests de contrat surveillance ↔ détection ↔ alertes — agent 2.10.
//!
//! Vérifie :
//!   1. `ContratMpsc` livre bien le fait au récepteur Tokio.
//!   2. `ContratMock` collecte les faits en mémoire.
//!   3. Affichage Debug stable (champs présents, ordre cohérent).
//!   4. Compatibilité ascendante : `FaitSurveillance::nouveau` produit
//!      des valeurs par défaut valides pour les champs v1.0.0.
//!   5. Version du contrat visible et conforme.

use sentinel_monitor::contracts::{
    ContratMock, ContratMpsc, ContratSurveillance, FaitSurveillance, VERSION_CONTRAT,
};
use sentinel_protocol::{Empreinte, Outil, Severite, TypeConstat};
use tokio::sync::mpsc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fait_minimal() -> FaitSurveillance {
    FaitSurveillance::nouveau(
        Uuid::new_v4(),
        TypeConstat::NouveauServeur,
        "session-test-001",
        "fait de test unitaire",
    )
}

fn fait_complet() -> FaitSurveillance {
    let outil = Outil {
        nom: "exec_cmd".to_string(),
        description: Some("exécute une commande shell".to_string()),
        input_schema: serde_json::json!({ "type": "object", "properties": { "cmd": { "type": "string" } } }),
        meta: Default::default(),
    };
    FaitSurveillance {
        serveur_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        type_fait: TypeConstat::RugPull,
        empreinte_courante: Some(Empreinte::new("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")),
        baseline: Some(Empreinte::new("0000000000000000000000000000000000000000000000000000000000000000")),
        session_id: "session-rug-pull-42".to_string(),
        detail: "liste d'outils modifiée entre deux sessions".to_string(),
        outils_courants: vec![outil],
        severite_suggeree: Severite::Critique,
    }
}

// ---------------------------------------------------------------------------
// Test 1 : ContratMpsc livre le fait au récepteur
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_contrat_mpsc_livre_fait() {
    let (tx, mut rx) = mpsc::channel::<FaitSurveillance>(4);
    let contrat = ContratMpsc(tx);

    let fait = fait_complet();
    let session_id_attendu = fait.session_id.clone();
    let serveur_id_attendu = fait.serveur_id;

    contrat.emettre(fait).await.expect("emettre ne doit pas échouer");

    let recu = rx.recv().await.expect("le récepteur doit recevoir un fait");
    assert_eq!(recu.session_id, session_id_attendu);
    assert_eq!(recu.serveur_id, serveur_id_attendu);
    assert_eq!(recu.severite_suggeree, Severite::Critique);
    assert_eq!(recu.outils_courants.len(), 1);
    assert_eq!(recu.outils_courants[0].nom, "exec_cmd");
}

// ---------------------------------------------------------------------------
// Test 2 : ContratMpsc retourne une erreur si le canal est fermé
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_contrat_mpsc_erreur_canal_ferme() {
    let (tx, rx) = mpsc::channel::<FaitSurveillance>(1);
    // On ferme le récepteur avant d'envoyer.
    drop(rx);

    let contrat = ContratMpsc(tx);
    let resultat = contrat.emettre(fait_minimal()).await;
    assert!(resultat.is_err(), "doit retourner une erreur quand le canal est fermé");
}

// ---------------------------------------------------------------------------
// Test 3 : ContratMock collecte plusieurs faits en mémoire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_contrat_mock_collecte_faits() {
    let mock = ContratMock::nouveau();

    assert_eq!(mock.nb_faits(), 0);

    mock.emettre(fait_minimal()).await.unwrap();
    mock.emettre(fait_minimal()).await.unwrap();
    mock.emettre(fait_complet()).await.unwrap();

    assert_eq!(mock.nb_faits(), 3);

    {
        let faits = mock.faits.lock().unwrap();
        // Le troisième fait est le fait_complet.
        assert_eq!(faits[2].type_fait, TypeConstat::RugPull);
        assert_eq!(faits[2].severite_suggeree, Severite::Critique);
    }

    mock.vider();
    assert_eq!(mock.nb_faits(), 0, "vider() doit effacer tous les faits");
}

// ---------------------------------------------------------------------------
// Test 4 : stabilité du format Debug (champs requis présents)
// ---------------------------------------------------------------------------

#[test]
fn test_debug_stable_champs_presents() {
    let fait = fait_complet();
    let debug = format!("{:?}", fait);

    // Champs historiques.
    assert!(debug.contains("serveur_id"), "serveur_id manquant dans Debug");
    assert!(debug.contains("type_fait"), "type_fait manquant dans Debug");
    assert!(debug.contains("empreinte_courante"), "empreinte_courante manquant dans Debug");
    assert!(debug.contains("baseline"), "baseline manquant dans Debug");
    assert!(debug.contains("session_id"), "session_id manquant dans Debug");
    assert!(debug.contains("detail"), "detail manquant dans Debug");

    // Champs v1.0.0.
    assert!(debug.contains("outils_courants"), "outils_courants manquant dans Debug");
    assert!(debug.contains("severite_suggeree"), "severite_suggeree manquant dans Debug");
}

// ---------------------------------------------------------------------------
// Test 5 : FaitSurveillance::nouveau produit des défauts valides
// ---------------------------------------------------------------------------

#[test]
fn test_nouveau_valeurs_par_defaut() {
    let fait = fait_minimal();

    assert!(fait.empreinte_courante.is_none(), "empreinte_courante doit être None par défaut");
    assert!(fait.baseline.is_none(), "baseline doit être None par défaut");
    assert!(fait.outils_courants.is_empty(), "outils_courants doit être vide par défaut");
    assert_eq!(fait.severite_suggeree, Severite::Info, "severite_suggeree doit être Info par défaut");
    assert_eq!(fait.session_id, "session-test-001");
    assert_eq!(fait.detail, "fait de test unitaire");
}

// ---------------------------------------------------------------------------
// Test 6 : version du contrat
// ---------------------------------------------------------------------------

#[test]
fn test_version_contrat() {
    assert_eq!(VERSION_CONTRAT, "1.0.0");
}
