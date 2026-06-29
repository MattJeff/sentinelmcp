//! Orchestrator that runs every detection source in parallel and aggregates.

use crate::model::ClientDecouvert;
use crate::skills::{rattacher_aux_clients, DecouvreurSkills, SkillDecouvert};
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
            let skills = decouvrir_skills_loggue(|| DecouvreurSkills.decouvrir()).await;
            rattacher_aux_clients(&mut clients, skills);
        }
        let termine_a = Utc::now();
        RapportDecouverte { clients, demarre_a, termine_a }
    }
}

/// Exécute le scan des skills/agents dans une tâche bloquante et rend
/// **visible** tout échec du join (panic/cancellation) via un log `error!`
/// avant de retomber sur un `Vec` vide. Les skills sont une surface d'attaque
/// majeure : un `Vec` vide muet serait un faux négatif silencieux.
async fn decouvrir_skills_loggue<F>(scan: F) -> Vec<SkillDecouvert>
where
    F: FnOnce() -> Vec<SkillDecouvert> + Send + 'static,
{
    match tokio::task::spawn_blocking(scan).await {
        Ok(skills) => skills,
        Err(e) => {
            tracing::error!(
                erreur = %e,
                "découverte des skills/agents échouée (tâche bloquante) — \
                 rapport produit sans skills"
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Souscripteur de test minimal : lève un drapeau dès qu'un évènement de
    /// niveau `ERROR` est émis.
    struct CaptureErreur(Arc<AtomicBool>);

    impl tracing::Subscriber for CaptureErreur {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::ERROR {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Un panic du scan (→ `JoinError`) doit retomber sur un `Vec` vide ET
    /// émettre un log d'erreur — sans ce log on aurait un faux négatif muet.
    #[tokio::test]
    async fn join_error_loggue_et_retombe_sur_vide() {
        let flag = Arc::new(AtomicBool::new(false));
        let _guard = tracing::subscriber::set_default(CaptureErreur(flag.clone()));

        let skills = decouvrir_skills_loggue(|| panic!("scan disque cassé")).await;

        assert!(skills.is_empty());
        assert!(
            flag.load(Ordering::SeqCst),
            "un échec du join doit émettre un log de niveau ERROR"
        );
    }

    /// Cas nominal : le résultat du scan est transmis tel quel, sans log
    /// d'erreur.
    #[tokio::test]
    async fn succes_transmet_le_resultat() {
        let flag = Arc::new(AtomicBool::new(false));
        let _guard = tracing::subscriber::set_default(CaptureErreur(flag.clone()));

        let skills = decouvrir_skills_loggue(Vec::new).await;

        assert!(skills.is_empty());
        assert!(!flag.load(Ordering::SeqCst), "aucun ERROR attendu en cas de succès");
    }
}
