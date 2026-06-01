//! Orchestrator that runs every detection source in parallel and aggregates.

use crate::model::ClientDecouvert;
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
}

impl Default for OrchestrateurDecouverte {
    fn default() -> Self {
        Self { sources: sources_par_defaut() }
    }
}

impl OrchestrateurDecouverte {
    pub fn nouveau(sources: Vec<Box<dyn SourceClient>>) -> Self {
        Self { sources }
    }

    /// Runs every source concurrently and produces a sweep report.
    pub async fn balayer(&self) -> RapportDecouverte {
        let demarre_a = Utc::now();
        let futures = self.sources.iter().map(|s| s.detecter());
        let resultats = futures::future::join_all(futures).await;
        let clients = resultats.into_iter().flatten().collect();
        let termine_a = Utc::now();
        RapportDecouverte { clients, demarre_a, termine_a }
    }
}
