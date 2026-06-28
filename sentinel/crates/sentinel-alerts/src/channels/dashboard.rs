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
        // Récupère le garde même si le mutex est empoisonné (un panic d'un
        // autre thread ne doit pas rendre les badges inaccessibles).
        let c = self.compteurs.lock().unwrap_or_else(|e| e.into_inner());
        (c.critique, c.haute, c.moyenne)
    }
}

#[async_trait]
impl CanalEmetteur for CanalDashboard {
    async fn emettre(&self, alerte: &Alerte) -> anyhow::Result<()> {
        // Incrémente le compteur correspondant à la sévérité.
        // Récupère le garde même si le mutex est empoisonné : l'émission ne
        // doit jamais paniquer à cause d'un panic survenu sur un autre thread.
        let (critique, haute, moyenne) = {
            let mut c = self.compteurs.lock().unwrap_or_else(|e| e.into_inner());
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_protocol::CanalAlerte;
    use uuid::Uuid;

    fn alerte_test(severite: Severite) -> Alerte {
        Alerte {
            id: Uuid::new_v4(),
            constat_id: Uuid::new_v4(),
            canal: CanalAlerte::Dashboard,
            severite,
            titre: "t".to_string(),
            message: "m".to_string(),
            diff: None,
            horodatage: Utc::now(),
            envoyee: false,
            tentatives: 0,
        }
    }

    /// Régression B9 : un mutex de compteurs empoisonné (panic d'un autre
    /// thread) ne doit faire paniquer ni `compteurs()` ni `emettre()`.
    #[tokio::test]
    async fn mutex_compteurs_empoisonne_ne_panique_pas() {
        let canal = CanalDashboard::nouveau();

        // Empoisonne volontairement le mutex en paniquant garde tenu.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = canal.compteurs.lock().unwrap();
            panic!("empoisonnement volontaire du mutex compteurs");
        }));
        assert!(r.is_err(), "le panic doit empoisonner le mutex");
        assert!(canal.compteurs.is_poisoned(), "le mutex doit être empoisonné");

        // `compteurs()` ne doit pas paniquer malgré l'empoisonnement.
        let _ = canal.compteurs();

        // `emettre()` ne doit pas paniquer et doit incrémenter le compteur.
        canal
            .emettre(&alerte_test(Severite::Critique))
            .await
            .expect("emettre doit survivre à un mutex empoisonné");
        let (critique, _, _) = canal.compteurs();
        assert_eq!(critique, 1, "le compteur critique doit avoir été incrémenté");
    }
}
