//! Lead moteur d'alertes — agent 4.1.
//!
//! Lit les constats ouverts du store, les enrichit, les déduplique,
//! puis les émet vers chaque canal enregistré.

use std::sync::Arc;

use anyhow::Result;
use chrono::Utc;
use tracing::{error, info, warn};
use uuid::Uuid;

use sentinel_protocol::{
    Alerte, AlerteId, CanalAlerte, Constat,
};
use sentinel_store::Store;

use crate::channels::CanalEmetteur;
use crate::dedup::DedupAntiBruit;
use crate::enrichment::EnrichisseurAlerte;
use crate::metrics::{label_severite, RegistreMetriques};
use crate::severity::MatriceSeverite;

/// Intervalle de polling par défaut (en secondes).
const INTERVALLE_POLL_SEC: u64 = 10;

/// Moteur d'alertes : orchestre la lecture des constats, l'enrichissement,
/// la déduplication et l'émission vers les canaux.
pub struct MoteurAlertes {
    pub store: Store,
    pub canaux: Vec<Arc<dyn CanalEmetteur>>,
    pub severite: MatriceSeverite,
    pub dedup: std::sync::Mutex<DedupAntiBruit>,
    /// Registre d'observabilité (latence d'envoi par canal, alertes émises).
    /// Partagé via `Arc` afin que la CLI puisse l'exposer en `/metrics`.
    pub registre: Arc<RegistreMetriques>,
}

impl MoteurAlertes {
    /// Construit un moteur avec les valeurs par défaut.
    pub fn nouveau(store: Store) -> Self {
        Self {
            store,
            canaux: Vec::new(),
            severite: MatriceSeverite::par_defaut(),
            dedup: std::sync::Mutex::new(DedupAntiBruit::default()),
            registre: Arc::new(RegistreMetriques::nouveau()),
        }
    }

    /// Enregistre un nouveau canal d'émission.
    pub fn ajouter_canal(&mut self, canal: Arc<dyn CanalEmetteur>) {
        self.canaux.push(canal);
    }

    /// Référence partagée vers le registre de métriques d'observabilité.
    /// Permet de construire un export Prometheus runtime (latence/alertes).
    pub fn registre_metriques(&self) -> Arc<RegistreMetriques> {
        self.registre.clone()
    }

    /// Traite un seul constat : enrichit, déduplique, émet vers tous les canaux.
    ///
    /// Retourne la liste des `AlerteId` effectivement persistés.
    pub async fn traiter_constat(&self, constat: &Constat) -> Result<Vec<AlerteId>> {
        let mut ids_emis = Vec::new();

        // Le SQLite bundled active SQLITE_DEFAULT_FOREIGN_KEYS=1, donc les FK
        // sont vérifiées. L'ordre d'insertion doit respecter :
        //   serveurs → constats → alertes
        //
        // Garantie préalable : le serveur et le constat existent dans le store
        // avant toute insertion d'alerte.  Ces opérations sont idempotentes
        // (ON CONFLICT / ignoré si déjà présent).
        self.garantir_serveur_et_constat(constat);

        for canal in &self.canaux {
            // Construction de l'alerte pour ce canal.
            let mut alerte = Alerte {
                id: Uuid::new_v4(),
                constat_id: constat.id,
                canal: nom_vers_canal(canal.nom()),
                severite: self.severite.severite_pour(&constat.type_constat),
                titre: constat.titre.clone(),
                message: constat.detail.clone(),
                diff: constat.diff.clone(),
                horodatage: Utc::now(),
                envoyee: false,
                tentatives: 0,
            };

            // Enrichissement (ajoute diff/raison si présent dans le constat).
            EnrichisseurAlerte::enrichir(constat, &mut alerte);

            // Déduplication : filtre les doublons récents.
            // On récupère le garde même si le mutex est empoisonné : le panic
            // d'un autre thread ne doit pas faire échouer toute la chaîne
            // d'alertes (le pire cas est un état de dédup légèrement incohérent).
            let doit_emettre = {
                let mut guard = self.dedup.lock().unwrap_or_else(|e| e.into_inner());
                guard.doit_emettre(&alerte)
            };

            if !doit_emettre {
                info!(
                    alerte_id = %alerte.id,
                    canal = canal.nom(),
                    "alerte filtrée par déduplication"
                );
                continue;
            }

            // Émission : une erreur de canal n'interrompt pas les suivants.
            // Mesure additive de la latence d'envoi (observabilité), sans
            // changer le comportement : on entoure l'appel d'un `Instant`.
            let debut_envoi = std::time::Instant::now();
            let resultat_envoi = canal.emettre(&alerte).await;
            let duree_envoi = debut_envoi.elapsed();
            self.registre
                .observer_latence_canal(canal.nom(), duree_envoi);
            // Comptabilise l'alerte effectivement traitée (post-dédup) par sévérité.
            self.registre.incr_alerte(label_severite(alerte.severite));

            let envoyee = match resultat_envoi {
                Ok(()) => {
                    info!(
                        alerte_id = %alerte.id,
                        canal = canal.nom(),
                        "alerte émise"
                    );
                    true
                }
                Err(e) => {
                    warn!(
                        alerte_id = %alerte.id,
                        canal = canal.nom(),
                        erreur = %e,
                        "échec d'émission canal"
                    );
                    false
                }
            };

            alerte.envoyee = envoyee;
            alerte.tentatives += 1;

            // Persistance dans le store indépendamment du succès d'émission.
            if let Err(e) = self.store.enregistrer_alerte(&alerte) {
                error!(
                    alerte_id = %alerte.id,
                    erreur = %e,
                    "impossible de persister l'alerte dans le store"
                );
            } else {
                ids_emis.push(alerte.id);
            }
        }

        Ok(ids_emis)
    }

    /// Boucle de polling : lit les constats ouverts toutes les
    /// `INTERVALLE_POLL_SEC` secondes et les traite.
    ///
    /// S'arrête uniquement sur interruption externe (Ctrl-C / signal).
    pub async fn boucle(&self) -> Result<()> {
        info!("moteur d'alertes démarré (poll={}s)", INTERVALLE_POLL_SEC);

        loop {
            let constats = {
                let store = self.store.clone();
                tokio::task::spawn_blocking(move || store.lister_constats_ouverts()).await??
            };

            for constat in &constats {
                if let Err(e) = self.traiter_constat(constat).await {
                    error!(
                        constat_id = %constat.id,
                        erreur = %e,
                        "erreur lors du traitement du constat"
                    );
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(INTERVALLE_POLL_SEC)).await;
        }
    }

    // ── Helpers privés ────────────────────────────────────────────────────────

    /// Insère le serveur fantôme (upsert) et le constat dans le store si
    /// absents, de façon à satisfaire les contraintes FK avant l'alerte.
    fn garantir_serveur_et_constat(&self, constat: &Constat) {
        // Upsert du serveur : no-op si le serveur existe déjà avec cet id.
        let serveur_fantome = sentinel_protocol::Serveur {
            id: constat.serveur_id,
            endpoint: format!("interne:{}", constat.serveur_id),
            transport: sentinel_protocol::Transport::Http,
            portees: vec![],
            statut: sentinel_protocol::StatutServeur::Inconnu,
            couleur: sentinel_protocol::Couleur::Orange,
            premiere_vue: Utc::now(),
            derniere_vue: Utc::now(),
            empreinte_courante: None,
            tags: vec![],
            scope: sentinel_protocol::ScopeServeur::default(),
        };
        if let Err(e) = self.store.upsert_serveur(&serveur_fantome) {
            warn!(erreur = %e, "upsert serveur fantôme échoué");
        }

        // Insertion du constat : ignore l'erreur de doublon (UNIQUE sur id).
        // On ne peut pas faire ON CONFLICT IGNORE depuis ici sans modifier le
        // store, donc on tolère silencieusement l'erreur de contrainte UNIQUE.
        let _ = self.store.enregistrer_constat(constat);
    }
}

/// Convertit le nom d'un canal (str) en `CanalAlerte`.
///
/// Convention : le nom retourné par `CanalEmetteur::nom()` doit correspondre
/// à l'une des valeurs reconnues ; toute valeur inconnue est traitée comme
/// `CanalAlerte::Dashboard` par défaut.
fn nom_vers_canal(nom: &str) -> CanalAlerte {
    match nom {
        "dashboard" => CanalAlerte::Dashboard,
        "email" => CanalAlerte::Email,
        "webhook" => CanalAlerte::Webhook,
        "siem" => CanalAlerte::Siem,
        autre => {
            warn!(nom = autre, "canal inconnu, fallback Dashboard");
            CanalAlerte::Dashboard
        }
    }
}
