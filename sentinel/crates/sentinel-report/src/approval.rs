//! Flux d'approbation d'inventaire — agent 5.9.
//!
//! Permet à un opérateur de marquer chaque serveur comme :
//!   - `Approuve`     : fige une baseline (module 2.2), couleur → Vert.
//!   - `AInvestiguer` : statut intermédiaire, pas de baseline.
//!   - `Bloque`       : statut bloqué, couleur → Rouge, pas de baseline.
//!
//! L'historique est posé en API (v1 renvoie toujours une liste vide —
//! pas de table dédiée encore).

use anyhow::Result;
use chrono::{DateTime, Utc};
use sentinel_detect::{empreinte_serveur, empreintes_par_outil};
use sentinel_protocol::{
    Baseline, BaselineId, Couleur, Serveur, ServeurId, StatutServeur,
};
use sentinel_store::Store;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------------------

/// Décision qu'un opérateur peut prendre sur un serveur inventorié.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionApprobation {
    Approuve,
    AInvestiguer,
    Bloque,
}

/// Trace d'une décision (v1 : construite à la volée, non persistée).
#[derive(Debug, Clone)]
pub struct DecisionTrace {
    pub serveur_id: ServeurId,
    pub decision: DecisionApprobation,
    pub operateur: String,
    pub horodatage: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// FluxApprobation
// ---------------------------------------------------------------------------

/// Point d'entrée du flux d'approbation.
pub struct FluxApprobation {
    pub store: Store,
}

impl FluxApprobation {
    /// Construit un flux à partir d'un store existant.
    pub fn nouveau(store: Store) -> Self {
        Self { store }
    }

    /// Applique une décision sur un serveur identifié par `serveur_id`.
    ///
    /// - Met à jour `serveur.statut` (et la couleur associée) dans le store.
    /// - Si `Approuve` : calcule l'empreinte courante des outils et enregistre
    ///   une `Baseline` via `store.enregistrer_baseline`.
    pub fn appliquer(
        &self,
        serveur_id: ServeurId,
        decision: DecisionApprobation,
        operateur: &str,
    ) -> Result<Serveur> {
        // Récupère le serveur courant.
        let serveurs = self.store.lister_serveurs()?;
        let mut serveur = serveurs
            .into_iter()
            .find(|s| s.id == serveur_id)
            .ok_or_else(|| anyhow::anyhow!("serveur introuvable : {serveur_id}"))?;

        // Met à jour statut + couleur selon la décision.
        match decision {
            DecisionApprobation::Approuve => {
                serveur.statut = StatutServeur::Approuve;
                serveur.couleur = Couleur::Vert;
            }
            DecisionApprobation::AInvestiguer => {
                serveur.statut = StatutServeur::AInvestiguer;
                // Couleur inchangée (orange par défaut).
            }
            DecisionApprobation::Bloque => {
                serveur.statut = StatutServeur::Bloque;
                serveur.couleur = Couleur::Rouge;
            }
        }

        serveur.derniere_vue = Utc::now();
        self.store.upsert_serveur(&serveur)?;

        // Si approuvé : calcule empreinte + enregistre baseline.
        if decision == DecisionApprobation::Approuve {
            let outils = self.store.lister_outils(serveur_id)?;
            let emp_serveur = empreinte_serveur(&outils);
            let emp_outils = empreintes_par_outil(&outils);

            let baseline = Baseline {
                id: Uuid::new_v4() as BaselineId,
                serveur_id,
                empreinte_serveur: emp_serveur,
                empreintes_outils: emp_outils,
                outils,
                date_approbation: Utc::now(),
                approuve_par: operateur.to_string(),
            };
            self.store.enregistrer_baseline(&baseline)?;
        }

        Ok(serveur)
    }

    /// Historique des décisions pour un serveur donné.
    ///
    /// V1 : aucune table dédiée — renvoie toujours une liste vide.
    /// L'API est posée pour les modules en aval (agent 4.8, agent 5.8).
    pub fn historique(&self, _serveur_id: ServeurId) -> Result<Vec<DecisionTrace>> {
        Ok(vec![])
    }
}
