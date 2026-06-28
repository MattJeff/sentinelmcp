//! Suivi des sessions HTTP par `Mcp-Session-Id`.
//!
//! Une session HTTP MCP naît sur `initialize`, porte un identifiant opaque
//! transmis dans l'en-tête `Mcp-Session-Id`, et associe le client à un
//! serveur upstream particulier. Ce module maintient ce mapping en mémoire.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

/// Informations conservées pour une session HTTP active.
#[derive(Debug, Clone)]
pub struct InfoSession {
    /// Identifiant brut de la session (valeur de `Mcp-Session-Id`).
    pub id: String,
    /// URL upstream associée à cette session.
    pub upstream: String,
    /// Horodatage du premier message observé.
    pub premier_contact: DateTime<Utc>,
    /// Horodatage du dernier message observé.
    pub dernier_contact: DateTime<Utc>,
    /// Nombre de messages observés.
    pub nb_messages: u64,
}

/// Table des sessions HTTP actives, partagée entre les tâches du proxy.
///
/// Thread-safe via `Arc<Mutex<_>>`.
#[derive(Debug, Clone)]
pub struct SuiviSessionsHttp {
    sessions: Arc<Mutex<HashMap<String, InfoSession>>>,
    upstream_defaut: String,
}

impl SuiviSessionsHttp {
    /// Crée un nouveau suivi avec l'URL upstream par défaut.
    pub fn nouveau(upstream_defaut: impl Into<String>) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            upstream_defaut: upstream_defaut.into(),
        }
    }

    /// Enregistre ou met à jour une session à partir d'un `Mcp-Session-Id`.
    ///
    /// Retourne l'URL upstream à utiliser pour cette session.
    pub fn enregistrer(&self, session_id: &str) -> String {
        let maintenant = Utc::now();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());

        let info = sessions.entry(session_id.to_string()).or_insert_with(|| InfoSession {
            id: session_id.to_string(),
            upstream: self.upstream_defaut.clone(),
            premier_contact: maintenant,
            dernier_contact: maintenant,
            nb_messages: 0,
        });

        info.dernier_contact = maintenant;
        info.nb_messages += 1;
        info.upstream.clone()
    }

    /// Retourne une copie de l'info session si elle existe.
    pub fn obtenir(&self, session_id: &str) -> Option<InfoSession> {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.get(session_id).cloned()
    }

    /// Retourne l'upstream par défaut (utile quand aucun `Mcp-Session-Id` n'est présent).
    pub fn upstream_defaut(&self) -> &str {
        &self.upstream_defaut
    }

    /// Retourne le nombre de sessions actives.
    pub fn nb_sessions(&self) -> usize {
        let sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enregistrement_et_recuperation() {
        let suivi = SuiviSessionsHttp::nouveau("http://localhost:3000");
        let upstream = suivi.enregistrer("session-abc");
        assert_eq!(upstream, "http://localhost:3000");

        let info = suivi.obtenir("session-abc").expect("session doit exister");
        assert_eq!(info.id, "session-abc");
        assert_eq!(info.nb_messages, 1);
    }

    #[test]
    fn incrementation_messages() {
        let suivi = SuiviSessionsHttp::nouveau("http://localhost:3000");
        suivi.enregistrer("session-xyz");
        suivi.enregistrer("session-xyz");
        suivi.enregistrer("session-xyz");

        let info = suivi.obtenir("session-xyz").unwrap();
        assert_eq!(info.nb_messages, 3);
    }

    #[test]
    fn session_inconnue_retourne_none() {
        let suivi = SuiviSessionsHttp::nouveau("http://localhost:3000");
        assert!(suivi.obtenir("inexistant").is_none());
    }

    #[test]
    fn recuperation_sur_mutex_empoisonne() {
        // Un mutex empoisonné (panic d'une autre tâche tenant le verrou) ne doit
        // pas paralyser le suivi des sessions : récupération via `into_inner`.
        let suivi = SuiviSessionsHttp::nouveau("http://localhost:3000");
        suivi.enregistrer("avant");

        // Empoisonne le mutex partagé en paniquant alors qu'il est verrouillé.
        let suivi_clone = suivi.clone();
        let h = std::thread::spawn(move || {
            let _garde = suivi_clone.sessions.lock().unwrap();
            panic!("empoisonnement volontaire du mutex sessions");
        });
        assert!(h.join().is_err(), "le thread doit avoir paniqué");

        // Sans récupération, ces appels paniqueraient (`.expect`).
        let upstream = suivi.enregistrer("apres");
        assert_eq!(upstream, "http://localhost:3000");
        assert!(suivi.obtenir("avant").is_some());
        assert_eq!(suivi.nb_sessions(), 2);
    }
}
