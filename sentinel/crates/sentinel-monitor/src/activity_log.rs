//! Journal d'activité — agent 2.6.
//!
//! Enregistre chaque contact (qui, quand, quelle méthode) par serveur MCP.
//! Persistance via `store.enregistrer_contact` ; agrégats statistiques maintenus
//! en mémoire dans un `Mutex<HashMap>` pour des lectures sans I/O.
//!
//! Alimente l'agent 5.3 (rapport) via [`JournalActivite::stats`] et la liste
//! complète des serveurs actifs via [`JournalActivite::tous_les_serveurs`].

use anyhow::Result;
use chrono::{DateTime, Utc};
use sentinel_protocol::ServeurId;
use sentinel_store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Statistiques agrégées pour un serveur sur la durée de vie du process.
#[derive(Debug, Clone)]
pub struct StatsServeur {
    pub serveur_id: ServeurId,
    /// Horodatage du tout premier contact enregistré (depuis le démarrage du process).
    pub premiere_vue: Option<DateTime<Utc>>,
    /// Horodatage du dernier contact enregistré.
    pub derniere_vue: Option<DateTime<Utc>>,
    /// Nombre total de contacts enregistrés depuis le démarrage.
    pub nombre_contacts: u64,
    /// Fréquence en contacts/heure, calculée sur la fenêtre [premiere_vue, derniere_vue].
    /// Vaut `0.0` si un seul contact ou fenêtre nulle.
    pub frequence_par_heure: f64,
}

/// Entrée interne du compteur en mémoire.
#[derive(Debug, Clone)]
struct EntreeInterne {
    premiere_vue: DateTime<Utc>,
    derniere_vue: DateTime<Utc>,
    nombre_contacts: u64,
}

impl EntreeInterne {
    fn nouveau(horodatage: DateTime<Utc>) -> Self {
        Self {
            premiere_vue: horodatage,
            derniere_vue: horodatage,
            nombre_contacts: 1,
        }
    }

    fn mettre_a_jour(&mut self, horodatage: DateTime<Utc>) {
        if horodatage < self.premiere_vue {
            self.premiere_vue = horodatage;
        }
        if horodatage > self.derniere_vue {
            self.derniere_vue = horodatage;
        }
        self.nombre_contacts += 1;
    }

    fn frequence_par_heure(&self) -> f64 {
        let duree_secs = (self.derniere_vue - self.premiere_vue).num_seconds();
        if duree_secs <= 0 || self.nombre_contacts <= 1 {
            return 0.0;
        }
        let duree_heures = duree_secs as f64 / 3600.0;
        self.nombre_contacts as f64 / duree_heures
    }
}

/// Journal d'activité par serveur.
///
/// Thread-safe : peut être partagé via `Arc<JournalActivite>` entre tâches Tokio.
pub struct JournalActivite {
    pub store: Store,
    compteurs: Arc<Mutex<HashMap<ServeurId, EntreeInterne>>>,
}

impl JournalActivite {
    /// Crée un nouveau journal associé au store donné.
    pub fn nouveau(store: Store) -> Self {
        Self {
            store,
            compteurs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Enregistre un contact : persiste dans le store ET met à jour les stats en mémoire.
    ///
    /// Ne stocke pas le contenu des arguments d'appel (règle non négociable).
    pub fn enregistrer(
        &self,
        serveur_id: ServeurId,
        session_id: &str,
        methode: &str,
        horodatage: DateTime<Utc>,
    ) -> Result<()> {
        // Persistance dans le store SQLite.
        self.store
            .enregistrer_contact(serveur_id, session_id, methode, horodatage)?;

        // Mise à jour des compteurs en mémoire.
        // Récupération sur mutex empoisonné : un panic ailleurs ne doit pas
        // figer le journal d'activité.
        let mut compteurs = self.compteurs.lock().unwrap_or_else(|e| e.into_inner());
        compteurs
            .entry(serveur_id)
            .and_modify(|e| e.mettre_a_jour(horodatage))
            .or_insert_with(|| EntreeInterne::nouveau(horodatage));

        Ok(())
    }

    /// Retourne les statistiques agrégées pour un serveur donné.
    ///
    /// Si le serveur n'a jamais été contacté depuis le démarrage du process,
    /// retourne des stats vides (nombre_contacts = 0).
    pub fn stats(&self, serveur_id: ServeurId) -> Result<StatsServeur> {
        let compteurs = self.compteurs.lock().unwrap_or_else(|e| e.into_inner());
        match compteurs.get(&serveur_id) {
            None => Ok(StatsServeur {
                serveur_id,
                premiere_vue: None,
                derniere_vue: None,
                nombre_contacts: 0,
                frequence_par_heure: 0.0,
            }),
            Some(entree) => Ok(StatsServeur {
                serveur_id,
                premiere_vue: Some(entree.premiere_vue),
                derniere_vue: Some(entree.derniere_vue),
                nombre_contacts: entree.nombre_contacts,
                frequence_par_heure: entree.frequence_par_heure(),
            }),
        }
    }

    /// Liste tous les serveurs ayant au moins un contact enregistré depuis le démarrage.
    ///
    /// Utilisé par l'agent 5.3 pour itérer sur la section historique du rapport.
    pub fn tous_les_serveurs(&self) -> Vec<ServeurId> {
        let compteurs = self.compteurs.lock().unwrap_or_else(|e| e.into_inner());
        compteurs.keys().copied().collect()
    }
}
