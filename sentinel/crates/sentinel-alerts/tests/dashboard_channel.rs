//! Tests d'intégration du canal tableau de bord (agent 4.3).

use sentinel_alerts::channels::dashboard::CanalDashboard;
use sentinel_alerts::channels::CanalEmetteur;
use sentinel_protocol::{Alerte, CanalAlerte, Severite};
use uuid::Uuid;
use chrono::Utc;

/// Construit une alerte de test avec la sévérité indiquée.
fn alerte_test(severite: Severite) -> Alerte {
    Alerte {
        id: Uuid::new_v4(),
        constat_id: Uuid::new_v4(),
        canal: CanalAlerte::Dashboard,
        severite,
        titre: "Test alerte".to_string(),
        message: "Message de test".to_string(),
        diff: None,
        horodatage: Utc::now(),
        envoyee: false,
        tentatives: 0,
    }
}

/// Un abonné reçoit bien l'événement après émission.
#[tokio::test]
async fn test_abonne_recoit_alerte() {
    let canal = CanalDashboard::nouveau();
    let mut rx = canal.abonner();

    let alerte = alerte_test(Severite::Critique);
    canal.emettre(&alerte).await.expect("émission échouée");

    let evt = rx.recv().await.expect("aucun événement reçu");
    assert_eq!(evt.alerte.id, alerte.id);
    assert_eq!(evt.alerte.titre, "Test alerte");
}

/// Les compteurs de badges s'incrémentent correctement selon la sévérité.
#[tokio::test]
async fn test_compteurs_increment_par_severite() {
    let canal = CanalDashboard::nouveau();

    // Aucun abonné — les envois doivent quand même réussir.
    canal.emettre(&alerte_test(Severite::Critique)).await.unwrap();
    canal.emettre(&alerte_test(Severite::Critique)).await.unwrap();
    canal.emettre(&alerte_test(Severite::Haute)).await.unwrap();
    canal.emettre(&alerte_test(Severite::Moyenne)).await.unwrap();
    canal.emettre(&alerte_test(Severite::Info)).await.unwrap();

    let (critique, haute, moyenne) = canal.compteurs();
    assert_eq!(critique, 2, "deux alertes critiques attendues");
    assert_eq!(haute, 1, "une alerte haute attendue");
    assert_eq!(moyenne, 1, "une alerte moyenne attendue");
}

/// Les compteurs dans l'événement reflètent l'état cumulé au moment de l'émission.
#[tokio::test]
async fn test_evenement_porte_compteurs_courants() {
    let canal = CanalDashboard::nouveau();
    let mut rx = canal.abonner();

    canal.emettre(&alerte_test(Severite::Critique)).await.unwrap();
    let evt1 = rx.recv().await.unwrap();
    assert_eq!(evt1.badge_count_critique, 1);

    canal.emettre(&alerte_test(Severite::Critique)).await.unwrap();
    let evt2 = rx.recv().await.unwrap();
    assert_eq!(evt2.badge_count_critique, 2);
}

/// Deux abonnés indépendants reçoivent tous deux le même événement.
#[tokio::test]
async fn test_deux_abonnes_recoivent_tous_deux() {
    let canal = CanalDashboard::nouveau();
    let mut rx1 = canal.abonner();
    let mut rx2 = canal.abonner();

    let alerte = alerte_test(Severite::Haute);
    canal.emettre(&alerte).await.expect("émission échouée");

    let evt1 = rx1.recv().await.expect("abonné 1 : aucun événement");
    let evt2 = rx2.recv().await.expect("abonné 2 : aucun événement");

    assert_eq!(evt1.alerte.id, alerte.id);
    assert_eq!(evt2.alerte.id, alerte.id);
    assert_eq!(evt1.badge_count_haute, 1);
    assert_eq!(evt2.badge_count_haute, 1);
}

/// Le canal retourne bien "dashboard" comme nom.
#[tokio::test]
async fn test_nom_canal() {
    let canal = CanalDashboard::nouveau();
    assert_eq!(canal.nom(), "dashboard");
}
