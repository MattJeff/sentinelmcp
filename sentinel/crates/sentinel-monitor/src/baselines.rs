//! Gestion des baselines — agent 2.2.
//!
//! Quand un opérateur approuve un serveur, on fige son empreinte via
//! [`GestionnaireBaselines::approuver`]. La baseline est persistée dans le
//! store avec traçabilité (approuvé_par, date_approbation). La détection de
//! rug-pull se base sur [`GestionnaireBaselines::empreinte_diverge`].

use anyhow::Result;
use sentinel_protocol::{Baseline, Empreinte, Outil, ServeurId};
use sentinel_store::Store;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

pub struct GestionnaireBaselines {
    pub store: Store,
}

impl GestionnaireBaselines {
    pub fn nouveau(store: Store) -> Self {
        Self { store }
    }

    /// Calcule les empreintes outil+serveur (hash SHA-256 placeholder),
    /// crée la [`Baseline`], et l'enregistre dans le store.
    ///
    /// Hash placeholder : SHA-256 de `serde_json::to_string(outil)`.
    /// La canonicalisation propre (clés triées, etc.) arrivera avec l'agent 3.1.
    pub fn approuver(
        &self,
        serveur_id: ServeurId,
        outils: Vec<Outil>,
        empreinte_serveur: Empreinte,
        approuve_par: &str,
    ) -> Result<Baseline> {
        let empreintes_outils: BTreeMap<String, Empreinte> = outils
            .iter()
            .map(|outil| {
                let json = serde_json::to_string(outil)
                    .unwrap_or_else(|_| format!("{}", outil.nom));
                let hash = hex::encode(Sha256::digest(json.as_bytes()));
                (outil.nom.clone(), Empreinte::new(hash))
            })
            .collect();

        let baseline = Baseline {
            id: Uuid::new_v4(),
            serveur_id,
            empreinte_serveur,
            empreintes_outils,
            outils,
            date_approbation: chrono::Utc::now(),
            approuve_par: approuve_par.to_string(),
        };

        self.store.enregistrer_baseline(&baseline)?;
        Ok(baseline)
    }

    /// Renvoie la baseline la plus récente pour ce serveur, ou `None` si aucune.
    pub fn derniere_baseline(&self, serveur_id: ServeurId) -> Result<Option<Baseline>> {
        self.store.derniere_baseline(serveur_id)
    }

    /// Indique si l'empreinte courante diverge de la baseline approuvée.
    /// Renvoie `false` si aucune baseline n'existe (pas encore approuvé).
    pub fn empreinte_diverge(
        &self,
        serveur_id: ServeurId,
        empreinte_courante: &Empreinte,
    ) -> Result<bool> {
        match self.store.derniere_baseline(serveur_id)? {
            None => Ok(false),
            Some(baseline) => Ok(baseline.empreinte_serveur != *empreinte_courante),
        }
    }
}
