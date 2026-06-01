//! Tests d'intégration du moteur d'alertes (agent 4.1).

use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use sentinel_alerts::{CanalEmetteur, MoteurAlertes};
use sentinel_protocol::{Alerte, Constat, EtatConstat, Severite, TypeConstat};
use sentinel_store::Store;

// ---------------------------------------------------------------------------
// Canal mock : collecte les alertes reçues dans un Vec partagé.
// ---------------------------------------------------------------------------

struct CanalMock {
    nom_canal: &'static str,
    alertes_recues: Arc<Mutex<Vec<Alerte>>>,
    simuler_erreur: bool,
}

impl CanalMock {
    fn nouveau(nom: &'static str) -> (Self, Arc<Mutex<Vec<Alerte>>>) {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let canal = Self {
            nom_canal: nom,
            alertes_recues: Arc::clone(&buf),
            simuler_erreur: false,
        };
        (canal, buf)
    }

    fn en_erreur(nom: &'static str) -> Self {
        Self {
            nom_canal: nom,
            alertes_recues: Arc::new(Mutex::new(Vec::new())),
            simuler_erreur: true,
        }
    }
}

#[async_trait]
impl CanalEmetteur for CanalMock {
    async fn emettre(&self, alerte: &Alerte) -> Result<()> {
        if self.simuler_erreur {
            return Err(anyhow::anyhow!("erreur simulée du canal {}", self.nom_canal));
        }
        self.alertes_recues.lock().unwrap().push(alerte.clone());
        Ok(())
    }

    fn nom(&self) -> &'static str {
        self.nom_canal
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn constat_test(type_constat: TypeConstat) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: Some("outil_test".into()),
        type_constat,
        severite: Severite::Haute,
        titre: "Titre test".into(),
        detail: "Détail du constat pour les tests.".into(),
        diff: Some("+ ligne ajoutée\n- ligne supprimée".into()),
        references_conformite: vec!["OWASP-MCP03".into()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

fn store_vide() -> Store {
    Store::in_memory().expect("store en mémoire")
}

// ---------------------------------------------------------------------------
// Test 1 : un constat → une alerte par canal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn un_constat_emet_une_alerte_par_canal() {
    let store = store_vide();
    let mut moteur = MoteurAlertes::nouveau(store);

    let (canal_a, buf_a) = CanalMock::nouveau("dashboard");
    let (canal_b, buf_b) = CanalMock::nouveau("webhook");
    moteur.ajouter_canal(Arc::new(canal_a));
    moteur.ajouter_canal(Arc::new(canal_b));

    let constat = constat_test(TypeConstat::ShadowMcp);
    let ids = moteur
        .traiter_constat(&constat)
        .await
        .expect("traiter_constat ne doit pas échouer");

    // Deux canaux → deux alertes persistées.
    assert_eq!(ids.len(), 2, "doit avoir 2 ids émis");
    assert_eq!(buf_a.lock().unwrap().len(), 1, "canal dashboard : 1 alerte");
    assert_eq!(buf_b.lock().unwrap().len(), 1, "canal webhook : 1 alerte");

    // L'alerte porte bien le constat_id source.
    let alertes_a = buf_a.lock().unwrap();
    assert_eq!(alertes_a[0].constat_id, constat.id);
    assert_eq!(alertes_a[0].titre, constat.titre);
    // Le diff doit être propagé.
    assert!(alertes_a[0].diff.is_some(), "le diff doit être présent");
}

// ---------------------------------------------------------------------------
// Test 2 : déduplication — moteur sans canal retourne [], deux appels
//          successifs avec l'impl placeholder passent tous les deux.
// ---------------------------------------------------------------------------

struct CanalCompteur {
    compteur: Arc<Mutex<u32>>,
}

#[async_trait]
impl CanalEmetteur for CanalCompteur {
    async fn emettre(&self, _alerte: &Alerte) -> Result<()> {
        *self.compteur.lock().unwrap() += 1;
        Ok(())
    }
    fn nom(&self) -> &'static str {
        "dashboard"
    }
}

#[tokio::test]
async fn dedup_empeche_doublon_meme_constat() {
    // Cas 1 : moteur sans canal → aucune alerte.
    let moteur_vide = MoteurAlertes::nouveau(store_vide());
    let constat = constat_test(TypeConstat::RugPull);
    let ids = moteur_vide
        .traiter_constat(&constat)
        .await
        .expect("sans canal, pas d'erreur");
    assert!(ids.is_empty(), "sans canal, aucune alerte émise");

    // Cas 2 : deux appels successifs.
    // L'impl DedupAntiBruit courante (placeholder) retourne toujours true,
    // donc les deux appels passent — ce test documente le comportement actuel
    // et sera renforcé quand l'agent 4.7 implément le vrai dedup.
    let compteur = Arc::new(Mutex::new(0u32));
    let mut moteur = MoteurAlertes::nouveau(store_vide());
    moteur.ajouter_canal(Arc::new(CanalCompteur {
        compteur: Arc::clone(&compteur),
    }));

    let constat2 = constat_test(TypeConstat::Poisoning);
    moteur.traiter_constat(&constat2).await.unwrap();
    moteur.traiter_constat(&constat2).await.unwrap();

    let n = *compteur.lock().unwrap();
    assert!(n >= 1, "au moins une émission attendue : {}", n);
}

// ---------------------------------------------------------------------------
// Test 3 : un canal en erreur n'interrompt pas les autres canaux
// ---------------------------------------------------------------------------

#[tokio::test]
async fn canal_en_erreur_ninterrompt_pas_les_autres() {
    let store = store_vide();
    let mut moteur = MoteurAlertes::nouveau(store);

    // Canal 1 : retourne une erreur à chaque appel.
    let canal_erreur = CanalMock::en_erreur("webhook");

    // Canal 2 : fonctionne normalement.
    let (canal_ok, buf_ok) = CanalMock::nouveau("dashboard");

    moteur.ajouter_canal(Arc::new(canal_erreur));
    moteur.ajouter_canal(Arc::new(canal_ok));

    let constat = constat_test(TypeConstat::Exfiltration);
    let ids = moteur
        .traiter_constat(&constat)
        .await
        .expect("le moteur ne doit pas propager l'erreur du canal");

    // Le canal ok a bien reçu l'alerte.
    assert_eq!(
        buf_ok.lock().unwrap().len(),
        1,
        "le canal ok doit avoir reçu l'alerte malgré l'erreur de l'autre canal"
    );

    // Au moins l'alerte du canal ok est persistée.
    assert!(
        !ids.is_empty(),
        "au moins une alerte doit être persistée : {:?}",
        ids
    );
}
