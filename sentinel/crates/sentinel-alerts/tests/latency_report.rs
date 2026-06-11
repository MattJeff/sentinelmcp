//! Rapport de latence et fiabilité du pipeline alerte — agent 4.10.
//!
//! Tests 5 et 6 : mesure de latence E2E + rapport de fiabilité 99 %.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use sentinel_alerts::{channels::CanalEmetteur, MoteurAlertes};
use sentinel_protocol::{
    Alerte, Constat, Couleur, EtatConstat, Serveur, Severite, StatutServeur, Transport,
    TypeConstat,
};
use sentinel_store::Store;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn constat_latence(n: u32) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        outil_nom: Some(format!("outil_latence_{}", n)),
        type_constat: TypeConstat::Poisoning,
        severite: Severite::Critique,
        titre: format!("Constat latence #{}", n),
        detail: "Test de latence du pipeline E2E.".into(),
        diff: Some(format!("+ diff_{}", n)),
        references_conformite: vec!["OWASP-MCP03".into()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

fn store_latence() -> Store {
    let store = Store::in_memory().expect("store en mémoire");
    let serveur = Serveur {
        id: Uuid::new_v4(),
        endpoint: "http://latence-test".into(),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Rouge,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    };
    store.upsert_serveur(&serveur).expect("upsert serveur latence");
    store
}

/// Canal mock ultra-léger : ne fait rien sauf compter.
struct CanalNoop {
    compteur: Arc<Mutex<u32>>,
    /// Si Some(n), retourne une erreur une fois toutes les n émissions.
    erreur_toutes_les: Option<u32>,
}

#[async_trait]
impl CanalEmetteur for CanalNoop {
    async fn emettre(&self, _alerte: &Alerte) -> anyhow::Result<()> {
        let mut c = self.compteur.lock().unwrap();
        *c += 1;
        if let Some(freq) = self.erreur_toutes_les {
            if freq > 0 && *c % freq == 0 {
                return Err(anyhow::anyhow!("erreur simulée toutes les {} appels", freq));
            }
        }
        Ok(())
    }
    fn nom(&self) -> &'static str {
        "dashboard"
    }
}

// ── Test 5 : Latence E2E — 10 constats < 5 secondes ─────────────────────────

#[tokio::test]
async fn latence_e2e_10_constats_sous_5_secondes() {
    let store = store_latence();
    let compteur = Arc::new(Mutex::new(0u32));
    let canal = Arc::new(CanalNoop {
        compteur: Arc::clone(&compteur),
        erreur_toutes_les: None,
    });

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(canal);

    let debut = std::time::Instant::now();

    for i in 0..10u32 {
        let constat = constat_latence(i);
        moteur
            .traiter_constat(&constat)
            .await
            .expect("traiter_constat ne doit pas échouer");
    }

    let duree_totale = debut.elapsed();

    // Vérification : 10 appels reçus par le canal.
    assert_eq!(
        *compteur.lock().unwrap(),
        10,
        "le canal doit avoir reçu exactement 10 alertes"
    );

    // Contrainte de latence : < 5 secondes pour 10 constats en mode dry-run.
    assert!(
        duree_totale.as_secs() < 5,
        "latence E2E trop élevée : {:.2} s pour 10 constats (limite : 5 s)",
        duree_totale.as_secs_f64()
    );

    // Mesures de latence individuelles affichées pour le rapport.
    let latence_moy_ms = duree_totale.as_millis() / 10;
    eprintln!(
        "[latence_report] 10 constats traités en {:.2} ms — moyenne : {} ms/constat",
        duree_totale.as_millis(),
        latence_moy_ms
    );
}

// ── Test 6 : Rapport de fiabilité — 100 appels ≥ 99 % de succès ─────────────

#[tokio::test]
async fn fiabilite_100_constats_99_pourcent_succes() {
    const N_TOTAL: u32 = 100;
    const SEUIL_SUCCES: u32 = 99; // ≥ 99 %

    let store = store_latence();
    let compteur_succes = Arc::new(Mutex::new(0u32));
    let canal = Arc::new(CanalNoop {
        compteur: Arc::clone(&compteur_succes),
        // Pas d'erreurs simulées : on teste la fiabilité nominale.
        erreur_toutes_les: None,
    });

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(canal);

    let mut nb_succes = 0u32;
    let mut nb_echecs = 0u32;

    for i in 0..N_TOTAL {
        let constat = constat_latence(i);
        match moteur.traiter_constat(&constat).await {
            Ok(ids) if !ids.is_empty() => nb_succes += 1,
            Ok(_) => {
                // Aucun id émis : canal filtré ou dédup — compte quand même comme succès
                // fonctionnel (le moteur n'a pas paniqué).
                nb_succes += 1;
            }
            Err(_) => nb_echecs += 1,
        }
    }

    eprintln!(
        "[fiabilite_report] {} appels — succès : {} ({:.1} %) — échecs : {}",
        N_TOTAL,
        nb_succes,
        nb_succes as f64 / N_TOTAL as f64 * 100.0,
        nb_echecs
    );

    assert!(
        nb_succes >= SEUIL_SUCCES,
        "fiabilité insuffisante : {} succès sur {} (seuil : {} %)",
        nb_succes,
        N_TOTAL,
        SEUIL_SUCCES
    );

    // Vérification complémentaire : le canal a bien reçu autant d'alertes que de succès.
    let nb_emis = *compteur_succes.lock().unwrap();
    assert_eq!(
        nb_emis, nb_succes,
        "le canal doit avoir reçu exactement {} alertes (reçu : {})",
        nb_succes, nb_emis
    );
}

// ── Test bonus : latence par canal — dashboard broadcast sans abonné ──────────

#[tokio::test]
async fn latence_dashboard_pur_sans_abonne_sous_100ms_par_constat() {
    use sentinel_alerts::channels::dashboard::CanalDashboard;

    let store = store_latence();
    let canal = Arc::new(CanalDashboard::nouveau());
    // Pas d'abonné : le broadcast ignore les envois sans récepteur.

    let mut moteur = MoteurAlertes::nouveau(store);
    moteur.ajouter_canal(Arc::clone(&canal) as Arc<dyn CanalEmetteur>);

    let mut latences_ms = Vec::with_capacity(10);

    for i in 0..10u32 {
        let constat = constat_latence(i);
        let debut = std::time::Instant::now();
        moteur
            .traiter_constat(&constat)
            .await
            .expect("traiter_constat dashboard ne doit pas échouer");
        latences_ms.push(debut.elapsed().as_millis());
    }

    let max_ms = *latences_ms.iter().max().unwrap_or(&0);
    let moy_ms: u128 = latences_ms.iter().sum::<u128>() / latences_ms.len() as u128;

    eprintln!(
        "[latence_dashboard] 10 constats — max : {} ms — moy : {} ms",
        max_ms, moy_ms
    );

    // Chaque constat individuel doit être traité en moins de 100 ms.
    assert!(
        max_ms < 100,
        "latence maximale trop élevée sur le canal dashboard pur : {} ms (limite : 100 ms)",
        max_ms
    );
}
