//! Orchestrator that runs every detection source in parallel and aggregates.

use crate::model::ClientDecouvert;
use crate::skills::{rattacher_aux_clients, DecouvreurSkills};
use crate::sources::{sources_par_defaut, SourceClient};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Aggregated report produced by a discovery sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RapportDecouverte {
    pub clients: Vec<ClientDecouvert>,
    pub demarre_a: DateTime<Utc>,
    pub termine_a: DateTime<Utc>,
}

pub struct OrchestrateurDecouverte {
    sources: Vec<Box<dyn SourceClient>>,
    /// Découverte des skills/agents (voir [`crate::skills`]) activée par
    /// défaut — désactivable via [`Self::sans_skills`].
    inclure_skills: bool,
}

impl Default for OrchestrateurDecouverte {
    fn default() -> Self {
        Self { sources: sources_par_defaut(), inclure_skills: true }
    }
}

impl OrchestrateurDecouverte {
    pub fn nouveau(sources: Vec<Box<dyn SourceClient>>) -> Self {
        Self { sources, inclure_skills: true }
    }

    /// Désactive la découverte des skills/agents (utile pour les tests qui
    /// ne veulent balayer que des sources synthétiques).
    pub fn sans_skills(mut self) -> Self {
        self.inclure_skills = false;
        self
    }

    /// Runs every source concurrently and produces a sweep report. Les
    /// skills/agents découverts sont rattachés aux `ClientDecouvert`
    /// correspondants (champ `skills`).
    pub async fn balayer(&self) -> RapportDecouverte {
        let demarre_a = Utc::now();
        let futures = self.sources.iter().map(|s| s.detecter());
        let resultats = futures::future::join_all(futures).await;
        let mut clients: Vec<ClientDecouvert> = resultats.into_iter().flatten().collect();
        if self.inclure_skills {
            // Scan disque synchrone — déporté hors du runtime async.
            let skills = tokio::task::spawn_blocking(|| DecouvreurSkills.decouvrir())
                .await
                .unwrap_or_default();
            rattacher_aux_clients(&mut clients, skills);
        }
        let termine_a = Utc::now();
        RapportDecouverte { clients, demarre_a, termine_a }
    }
}
