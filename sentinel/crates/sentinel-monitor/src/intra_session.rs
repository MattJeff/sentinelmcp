//! Détection de changement intra-session — agent 2.4.
//!
//! Compare l'empreinte courante à la baseline à chaque nouvelle réponse
//! `tools/list` ou notification `notifications/tools/list_changed`.

use sentinel_protocol::{Baseline, Empreinte, MessageMcp, MethodeMcp};

pub struct DetecteurIntraSession;

/// Signal émis après évaluation d'une suite de messages de session.
#[derive(Debug, PartialEq)]
pub enum SignalChangement {
    /// Aucun changement détecté.
    Aucun,
    /// `notifications/tools/list_changed` reçu, empreinte conforme.
    NotificationOfficielle,
    /// Nouvelle réponse `tools/list` sans notification préalable — suspect.
    ChangementSilencieux,
    /// Empreinte courante diverge de la baseline — priorité maximale.
    DivergenceEmpreinte,
}

impl DetecteurIntraSession {
    /// Retourne `true` si l'empreinte courante diffère de la baseline.
    pub fn diverge(courant: &Empreinte, baseline: &Baseline) -> bool {
        courant != &baseline.empreinte_serveur
    }

    /// Évalue une suite de messages d'une même session.
    ///
    /// Priorités (de la plus haute à la plus basse) :
    /// 1. `DivergenceEmpreinte`  — empreinte ≠ baseline
    /// 2. `ChangementSilencieux` — `ToolsList` sans `ToolsListChanged` préalable
    /// 3. `NotificationOfficielle` — `ToolsListChanged` reçu, pas de divergence
    /// 4. `Aucun`
    pub fn evaluer(
        messages: &[MessageMcp],
        baseline: Option<&Baseline>,
        empreinte_courante: Option<&Empreinte>,
    ) -> SignalChangement {
        // Priorité 1 : divergence d'empreinte.
        if let (Some(empreinte), Some(base)) = (empreinte_courante, baseline) {
            if Self::diverge(empreinte, base) {
                return SignalChangement::DivergenceEmpreinte;
            }
        }

        let mut notification_recue = false;
        let mut tools_list_reponse_vue = false;

        for msg in messages {
            match &msg.methode {
                MethodeMcp::ToolsListChanged => {
                    notification_recue = true;
                }
                MethodeMcp::ToolsList => {
                    // On ne considère que les réponses serveur→client.
                    if msg.direction == sentinel_protocol::Direction::ServeurVersClient {
                        tools_list_reponse_vue = true;
                    }
                }
                _ => {}
            }
        }

        // Priorité 2 : changement silencieux — réponse tools/list sans notification.
        if tools_list_reponse_vue && !notification_recue {
            return SignalChangement::ChangementSilencieux;
        }

        // Priorité 3 : notification officielle reçue.
        if notification_recue {
            return SignalChangement::NotificationOfficielle;
        }

        SignalChangement::Aucun
    }
}
