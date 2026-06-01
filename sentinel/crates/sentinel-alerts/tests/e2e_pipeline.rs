//! Tests de bout en bout du pipeline alerte — agent 4.10.
//!
//! Couvre : constat → MoteurAlertes → canal(x) → réception vérifiée.

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use sentinel_alerts::{
    channels::{
        dashboard::CanalDashboard,
        email::{CanalEmail, ConfigEmail},
        webhook::{CanalWebhook, TypeWebhook},
    },
    MoteurAlertes,
};
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Serveur, Severite, StatutServeur, Transport, TypeConstat,
};
use sentinel_store::Store;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Construit un constat de test.
/// Utilise `TypeConstat::Poisoning` pour garantir la sévérité Critique dans la
/// matrice par défaut (ShadowMcp → Moyenne, Poisoning → Critique).
fn constat_test(severite: Severite, titre: &str, diff: Option<&str>) -> Constat {
    constat_test_avec_type(TypeConstat::Poisoning, severite, titre, diff)
}

fn constat_test_avec_type(
    type_constat: TypeConstat,
    severite: Severite,
    titre: &str,
    diff: Option<&str>,
) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: Some("outil_e2e".into()),
        type_constat,
        severite,
        titre: titre.into(),
        detail: "Détail e2e du constat de test.".into(),
        diff: diff.map(|s| s.into()),
        references_conformite: vec!["OWASP-MCP09".into(), "SAFE-T1001".into()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

fn store_temporaire() -> Store {
    let store = Store::in_memory().expect("store en mémoire");
    // On insère un serveur factice pour satisfaire les contraintes FK.
    let serveur = Serveur {
        id: Uuid::new_v4(),
        endpoint: "http://e2e-test".into(),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Rouge,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
    };
    store.upsert_serveur(&serveur).expect("upsert serveur");
    store
}

fn config_email_test() -> ConfigEmail {
    ConfigEmail {
        smtp_host: "localhost".into(),
        smtp_port: 2525,
        utilisateur: None,
        mot_de_passe: None,
        expediteur: "sentinel@exemple.com".into(),
        destinataire: "securite@exemple.com".into(),
    }
}

// ── Test 1 : E2E dashboard ────────────────────────────────────────────────────

#[tokio::test]
async fn e2e_dashboard_constat_critique_recoit_evenement_en_moins_de_100ms() {
    let store = store_temporaire();
    let canal = Arc::new(CanalDashboard::nouveau());
    let mut rx = canal.abonner();

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(Arc::clone(&canal) as Arc<dyn sentinel_alerts::channels::CanalEmetteur>);

    // TypeConstat::Poisoning → Critique dans la matrice par défaut.
    let constat = constat_test(Severite::Critique, "Poisoning E2E dashboard", Some("+ outil malveillant\n- outil légitime"));

    let debut = std::time::Instant::now();
    let ids = moteur
        .traiter_constat(&constat)
        .await
        .expect("traiter_constat ne doit pas échouer");
    let duree = debut.elapsed();

    // L'alerte est persistée.
    assert_eq!(ids.len(), 1, "une alerte persistée attendue");

    // L'événement est disponible sur le canal broadcast.
    let evt = rx.try_recv().expect("l'événement dashboard doit être disponible immédiatement");
    assert_eq!(evt.alerte.constat_id, constat.id, "constat_id incorrect");
    assert_eq!(evt.alerte.titre, constat.titre, "titre incorrect");
    assert!(evt.alerte.diff.is_some(), "le diff doit être propagé");
    assert_eq!(evt.badge_count_critique, 1, "badge critique doit valoir 1");

    // Latence totale inférieure à 100 ms.
    assert!(
        duree.as_millis() < 100,
        "latence E2E dashboard trop élevée : {} ms",
        duree.as_millis()
    );
}

// ── Test 2 : E2E email dry-run ────────────────────────────────────────────────

#[tokio::test]
async fn e2e_email_dry_run_cree_fichier_eml() {
    let store = store_temporaire();
    let canal = Arc::new(CanalEmail::dry_run(config_email_test()));

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(Arc::clone(&canal) as Arc<dyn sentinel_alerts::channels::CanalEmetteur>);

    let constat = constat_test(
        Severite::Critique,
        "Rug-pull détecté",
        Some("-description légitime\n+description poisonée"),
    );

    moteur
        .traiter_constat(&constat)
        .await
        .expect("traiter_constat email ne doit pas échouer");

    // Vérification de la présence du fichier .eml.
    // L'alerte est créée avec un UUID interne : on vérifie qu'au moins un fichier
    // a été créé dans le dossier depuis le début du test.
    let dossier = std::path::Path::new("/tmp/sentinel-emails");
    assert!(
        dossier.exists(),
        "le dossier /tmp/sentinel-emails doit exister"
    );

    let mut trouvee = false;
    let mut chemin_eml = None;
    if let Ok(entrees) = std::fs::read_dir(dossier) {
        for entree in entrees.flatten() {
            let p = entree.path();
            if p.extension().and_then(|e| e.to_str()) == Some("eml") {
                let contenu = std::fs::read_to_string(&p).unwrap_or_default();
                if contenu.contains("Sentinel MCP") {
                    trouvee = true;
                    chemin_eml = Some(p);
                    break;
                }
            }
        }
    }
    assert!(trouvee, "aucun fichier .eml Sentinel MCP trouvé dans /tmp/sentinel-emails/");

    // Nettoyage.
    if let Some(chemin) = chemin_eml {
        let _ = std::fs::remove_file(chemin);
    }
}

// ── Test 3 : E2E webhook dry-run Slack ───────────────────────────────────────

#[tokio::test]
async fn e2e_webhook_dry_run_slack_capture_url_et_body() {
    let url_attendue = "https://hooks.slack.com/sentinel-e2e-test".to_string();
    let store = store_temporaire();
    let canal = Arc::new(CanalWebhook::dry_run(
        url_attendue.clone(),
        TypeWebhook::Slack,
    ));

    let captures = Arc::clone(&canal);

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(Arc::clone(&canal) as Arc<dyn sentinel_alerts::channels::CanalEmetteur>);

    let constat = constat_test(Severite::Critique, "Poisoning détecté E2E", None);

    moteur
        .traiter_constat(&constat)
        .await
        .expect("traiter_constat webhook ne doit pas échouer");

    let captures_verrou = captures.captures.lock().unwrap();
    assert_eq!(
        captures_verrou.len(),
        1,
        "une capture webhook attendue"
    );

    let (url_cap, body_cap) = &captures_verrou[0];
    assert_eq!(url_cap, &url_attendue, "l'URL capturée doit correspondre");

    // Le body doit être du JSON Slack valide avec le champ "text".
    let valeur: serde_json::Value =
        serde_json::from_str(body_cap).expect("le body capturé doit être du JSON valide");
    assert!(
        valeur["text"].as_str().is_some(),
        "le body Slack doit contenir le champ 'text'"
    );
    assert!(
        valeur["text"].as_str().unwrap().contains("CRITIQUE"),
        "le champ 'text' doit mentionner la sévérité CRITIQUE"
    );
}

// ── Test 4 : E2E multi-canal ──────────────────────────────────────────────────

#[tokio::test]
async fn e2e_multi_canal_un_constat_genere_une_alerte_par_canal() {
    use std::sync::{Arc, Mutex};
    use async_trait::async_trait;
    use sentinel_protocol::Alerte;

    // Canal mock qui collecte les alertes reçues.
    struct CanalMock {
        nom_canal: &'static str,
        alertes: Arc<Mutex<Vec<Alerte>>>,
    }

    #[async_trait]
    impl sentinel_alerts::channels::CanalEmetteur for CanalMock {
        async fn emettre(&self, alerte: &Alerte) -> anyhow::Result<()> {
            self.alertes.lock().unwrap().push(alerte.clone());
            Ok(())
        }
        fn nom(&self) -> &'static str {
            self.nom_canal
        }
    }

    let store = store_temporaire();
    let buf_dash = Arc::new(Mutex::new(Vec::<Alerte>::new()));
    let buf_email = Arc::new(Mutex::new(Vec::<Alerte>::new()));
    let buf_webhook = Arc::new(Mutex::new(Vec::<Alerte>::new()));

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(Arc::new(CanalMock {
        nom_canal: "dashboard",
        alertes: Arc::clone(&buf_dash),
    }));
    moteur.ajouter_canal(Arc::new(CanalMock {
        nom_canal: "email",
        alertes: Arc::clone(&buf_email),
    }));
    moteur.ajouter_canal(Arc::new(CanalMock {
        nom_canal: "webhook",
        alertes: Arc::clone(&buf_webhook),
    }));

    let constat = constat_test(Severite::Critique, "Alerte multi-canal", Some("diff test"));
    let ids = moteur
        .traiter_constat(&constat)
        .await
        .expect("traiter_constat multi-canal ne doit pas échouer");

    // Trois canaux → trois alertes persistées.
    assert_eq!(ids.len(), 3, "trois alertes persistées attendues (une par canal)");
    assert_eq!(buf_dash.lock().unwrap().len(), 1, "dashboard : 1 alerte");
    assert_eq!(buf_email.lock().unwrap().len(), 1, "email : 1 alerte");
    assert_eq!(buf_webhook.lock().unwrap().len(), 1, "webhook : 1 alerte");

    // Chaque canal reçoit bien l'identifiant du constat source.
    assert_eq!(
        buf_dash.lock().unwrap()[0].constat_id,
        constat.id,
        "constat_id incorrect sur le canal dashboard"
    );
    assert_eq!(
        buf_email.lock().unwrap()[0].constat_id,
        constat.id,
        "constat_id incorrect sur le canal email"
    );
    assert_eq!(
        buf_webhook.lock().unwrap()[0].constat_id,
        constat.id,
        "constat_id incorrect sur le canal webhook"
    );
}
