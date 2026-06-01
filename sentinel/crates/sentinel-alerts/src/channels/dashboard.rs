//! Canal tableau de bord — agent 4.3.
//! Émet un flux broadcast temps réel (badge + événements) vers les abonnés UI.

use super::CanalEmetteur;
use async_trait::async_trait;
use sentinel_protocol::{Alerte, Severite};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Capacité du canal broadcast (256 événements en attente).
const CAPACITE_BROADCAST: usize = 256;

/// Événement transmis aux abonnés du tableau de bord.
#[derive(Debug, Clone)]
pub struct EvenementDashboard {
    pub alerte: Alerte,
    pub badge_count_critique: u64,
    pub badge_count_haute: u64,
    pub badge_count_moyenne: u64,
}

/// Compteurs persistants par sévérité pour les badges.
#[derive(Debug, Default)]
struct CompteursBadge {
    critique: u64,
    haute: u64,
    moyenne: u64,
}

/// Canal tableau de bord : diffuse chaque alerte vers les abonnés WebSocket.
pub struct CanalDashboard {
    /// Flux broadcast vers les abonnés (UI websocket).
    pub flux: broadcast::Sender<EvenementDashboard>,
    /// Compteurs persistants par sévérité.
    compteurs: Arc<Mutex<CompteursBadge>>,
}

impl CanalDashboard {
    /// Crée un nouveau canal avec un broadcast de capacité 256.
    pub fn nouveau() -> Self {
        let (tx, _) = broadcast::channel(CAPACITE_BROADCAST);
        Self {
            flux: tx,
            compteurs: Arc::new(Mutex::new(CompteursBadge::default())),
        }
    }

    /// Retourne un nouveau récepteur abonné au flux.
    pub fn abonner(&self) -> broadcast::Receiver<EvenementDashboard> {
        self.flux.subscribe()
    }

    /// Retourne les compteurs courants : (critique, haute, moyenne).
    pub fn compteurs(&self) -> (u64, u64, u64) {
        let c = self.compteurs.lock().expect("mutex compteurs empoisonné");
        (c.critique, c.haute, c.moyenne)
    }
}

#[async_trait]
impl CanalEmetteur for CanalDashboard {
    async fn emettre(&self, alerte: &Alerte) -> anyhow::Result<()> {
        // Incrémente le compteur correspondant à la sévérité.
        let (critique, haute, moyenne) = {
            let mut c = self.compteurs.lock().expect("mutex compteurs empoisonné");
            match alerte.severite {
                Severite::Critique => c.critique += 1,
                Severite::Haute => c.haute += 1,
                Severite::Moyenne => c.moyenne += 1,
                Severite::Info => {}
            }
            (c.critique, c.haute, c.moyenne)
        };

        let evenement = EvenementDashboard {
            alerte: alerte.clone(),
            badge_count_critique: critique,
            badge_count_haute: haute,
            badge_count_moyenne: moyenne,
        };

        // Ignore l'erreur si aucun abonné n'est connecté.
        let _ = self.flux.send(evenement);

        Ok(())
    }

    fn nom(&self) -> &'static str {
        "dashboard"
    }
}
