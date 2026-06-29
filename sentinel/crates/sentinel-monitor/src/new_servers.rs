//! Détection de nouveaux serveurs — agent 2.3.
//!
//! Compare en continu les serveurs observés à ceux déjà connus et émet un
//! `Constat` de type `NouveauServeur` dès qu'un endpoint inédit apparaît.
//! La déduplication est assurée par `deja_signales` : un même endpoint ne
//! génère jamais deux constats distincts pour la même instance du détecteur.

use std::collections::HashSet;
use std::sync::Mutex;

use chrono::Utc;
use uuid::Uuid;

use sentinel_protocol::{
    Constat, EtatConstat, Severite, Serveur, TypeConstat,
};

/// Détecteur avec état interne de déduplication.
pub struct DetecteurNouveauxServeurs {
    /// Ensemble des endpoints déjà signalés dans cette instance.
    deja_signales: Mutex<HashSet<String>>,
}

impl DetecteurNouveauxServeurs {
    /// Crée un détecteur vierge (aucun endpoint connu).
    pub fn nouveau() -> Self {
        Self {
            deja_signales: Mutex::new(HashSet::new()),
        }
    }

    /// Renvoie un `Constat` si `observe` n'a jamais été signalé auparavant.
    ///
    /// Retourne `None` si :
    /// - l'endpoint figure dans `connus`, ou
    /// - l'endpoint a déjà été signalé par cette instance.
    pub fn evaluer(&self, observe: &Serveur, connus: &[Serveur]) -> Option<Constat> {
        if !Self::nouveau_serveur(observe, connus) {
            return None;
        }

        // Récupération sur mutex empoisonné : un panic ailleurs ne doit pas
        // empêcher la détection de nouveaux serveurs.
        let mut signales = self.deja_signales.lock().unwrap_or_else(|e| e.into_inner());
        if signales.contains(&observe.endpoint) {
            return None;
        }

        signales.insert(observe.endpoint.clone());

        let constat = Constat {
            id: Uuid::new_v4(),
            serveur_id: observe.id,
            outil_nom: None,
            type_constat: TypeConstat::NouveauServeur,
            severite: Severite::Moyenne,
            titre: "Nouveau serveur MCP inconnu détecté".to_string(),
            detail: format!(
                "Endpoint: {} (transport {:?})",
                observe.endpoint, observe.transport
            ),
            diff: None,
            references_conformite: vec!["OWASP MCP09".into()],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        };

        Some(constat)
    }

    /// Helper sans état : `true` si l'endpoint d'`observe` est absent de `connus`.
    pub fn nouveau_serveur(observe: &Serveur, connus: &[Serveur]) -> bool {
        !connus
            .iter()
            .any(|c| c.endpoint == observe.endpoint)
    }
}
