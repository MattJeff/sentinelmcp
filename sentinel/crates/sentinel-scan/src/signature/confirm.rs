//! Confirmation de signature MCP — Agent 1.5.
//!
//! Après le filtre grossier (agent 1.4), ce module confirme qu'un événement
//! JSON-RPC est bien du MCP, soit par méthode explicitement connue, soit par
//! appartenance à une session déjà ouverte par un `initialize` validé.

use chrono::{DateTime, Utc};
use sentinel_protocol::{EvenementBrut, MessageMcp, MethodeMcp};
use std::collections::HashMap;
use std::time::Duration;

/// Informations sur une session MCP active.
#[derive(Debug, Clone)]
pub struct InfoSession {
    pub serveur: String,
    pub ouverte_a: DateTime<Utc>,
    pub initialize_vu: bool,
    pub derniere_activite: DateTime<Utc>,
}

/// Table des sessions MCP actives, indexées par `session_id`.
#[derive(Default)]
pub struct SuiviSessions {
    pub sessions_actives: HashMap<String, InfoSession>,
}

impl SuiviSessions {
    /// Crée un nouveau suivi vide.
    pub fn nouveau() -> Self {
        Self {
            sessions_actives: HashMap::new(),
        }
    }

    /// Enregistre (ou rouvre) une session suite à un `initialize` valide.
    pub fn marquer_initialize(&mut self, session_id: &str, serveur: &str) {
        let maintenant = Utc::now();
        self.sessions_actives.insert(
            session_id.to_string(),
            InfoSession {
                serveur: serveur.to_string(),
                ouverte_a: maintenant,
                initialize_vu: true,
                derniere_activite: maintenant,
            },
        );
    }

    /// Met à jour l'horodatage d'activité d'une session existante.
    pub fn marquer_activite(&mut self, session_id: &str) {
        if let Some(info) = self.sessions_actives.get_mut(session_id) {
            info.derniere_activite = Utc::now();
        }
    }

    /// Supprime les sessions dont la dernière activité dépasse `max_age`.
    pub fn purger_inactives(&mut self, max_age: Duration) {
        let maintenant = Utc::now();
        self.sessions_actives.retain(|_, info| {
            let age = maintenant
                .signed_duration_since(info.derniere_activite)
                .to_std()
                .unwrap_or(Duration::MAX);
            age <= max_age
        });
    }
}

/// Confirme qu'un événement brut est un message MCP légitime.
///
/// Retourne `Some(MessageMcp)` si :
/// - la méthode est une méthode MCP connue (pas `Autre`), ou
/// - l'événement appartient à une session déjà ouverte par `initialize`.
///
/// Met à jour le suivi en cas de confirmation.
pub fn confirmer_message(e: &EvenementBrut, suivi: &mut SuiviSessions) -> Option<MessageMcp> {
    // Extraire la méthode depuis le champ `methode` de l'événement ou depuis
    // le payload JSON-RPC (champ "method").
    let methode_str: Option<String> = e.methode.clone().or_else(|| {
        e.payload
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    // Extraire l'id JSON-RPC optionnel.
    let id_jsonrpc = e.payload.get("id").cloned();

    // Classifier la méthode.
    let methode_classifiee: Option<MethodeMcp> = methode_str.as_deref().map(MethodeMcp::from_str);

    // Décider si l'on confirme.
    let methode_confirmee: Option<MethodeMcp> = match &methode_classifiee {
        // Méthode MCP connue : confirmation directe.
        Some(m) if !matches!(m, MethodeMcp::Autre(_)) => Some(m.clone()),
        // Méthode inconnue ou absente : accepter seulement si session ouverte.
        _ => {
            if suivi.sessions_actives.contains_key(&e.session_id) {
                // On réutilise la méthode telle quelle (Autre ou None → Autre("")).
                Some(methode_classifiee.unwrap_or_else(|| MethodeMcp::Autre(String::new())))
            } else {
                return None;
            }
        }
    };

    let methode = methode_confirmee?;

    // Mettre à jour le suivi des sessions.
    match &methode {
        MethodeMcp::Initialize => {
            suivi.marquer_initialize(&e.session_id, &e.serveur);
        }
        _ => {
            suivi.marquer_activite(&e.session_id);
        }
    }

    Some(MessageMcp {
        session_id: e.session_id.clone(),
        transport: e.transport,
        serveur: e.serveur.clone(),
        direction: e.direction,
        methode,
        id_jsonrpc,
        payload: e.payload.clone(),
        horodatage: e.horodatage,
    })
}
