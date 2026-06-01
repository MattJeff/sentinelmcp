//! Dérive inter-session — agent 2.5 (différenciateur).
//!
//! Compare les empreintes de sessions successives à une baseline persistante
//! pour détecter les dérives lentes (≥ 3 sessions consécutives divergentes)
//! et les divergences directes par rapport à la baseline approuvée.

use chrono::{DateTime, Utc};
use sentinel_protocol::{Baseline, Empreinte};

/// Empreinte observée lors d'une session donnée.
#[derive(Debug, Clone)]
pub struct EmpreinteSession {
    pub session_id: String,
    pub empreinte: Empreinte,
    pub horodatage: DateTime<Utc>,
}

/// Niveau de dérive détecté après évaluation d'une série de sessions.
#[derive(Debug, PartialEq)]
pub enum NiveauDerive {
    /// Toutes les sessions correspondent à la baseline.
    Aucune,
    /// Trois sessions consécutives ou plus divergent de la baseline sans rupture franche.
    DeriveLente,
    /// Au moins une session diffère directement de la baseline (cas général).
    Divergence,
}

/// Moteur de détection de dérive inter-session.
pub struct DetecteurInterSession;

impl DetecteurInterSession {
    /// Retourne `true` si l'empreinte de session diffère de la baseline.
    pub fn derive(baseline: &Baseline, empreinte_session: &Empreinte) -> bool {
        baseline.empreinte_serveur != *empreinte_session
    }

    /// Évalue une série chronologique d'empreintes de session.
    ///
    /// Règles (par ordre de priorité) :
    /// 1. Série vide ou toutes égales à la baseline → `Aucune`.
    /// 2. Exactement 1 session diffère → `Divergence`.
    /// 3. ≥ 3 sessions consécutives diffèrent → `DeriveLente`.
    /// 4. Tout autre cas avec au moins une différence → `Divergence`.
    pub fn evaluer_serie(baseline: &Baseline, historique: &[EmpreinteSession]) -> NiveauDerive {
        if historique.is_empty() {
            return NiveauDerive::Aucune;
        }

        // Marquer chaque session comme divergente ou non.
        let divergences: Vec<bool> = historique
            .iter()
            .map(|s| Self::derive(baseline, &s.empreinte))
            .collect();

        let nombre_divergentes = divergences.iter().filter(|&&d| d).count();

        // Règle 1 : aucune session divergente.
        if nombre_divergentes == 0 {
            return NiveauDerive::Aucune;
        }

        // Règle 2 : exactement 1 session divergente → Divergence.
        if nombre_divergentes == 1 {
            return NiveauDerive::Divergence;
        }

        // Règle 3 : chercher une séquence consécutive d'au moins 3 divergences.
        let longueur_max_consecutive = Self::longueur_max_sequence_vraie(&divergences);
        if longueur_max_consecutive >= 3 {
            return NiveauDerive::DeriveLente;
        }

        // Règle 4 : plusieurs divergences mais pas 3 consécutives → Divergence.
        NiveauDerive::Divergence
    }

    /// Calcule la longueur maximale d'une séquence consécutive de `true`.
    fn longueur_max_sequence_vraie(serie: &[bool]) -> usize {
        let mut max = 0usize;
        let mut courant = 0usize;
        for &valeur in serie {
            if valeur {
                courant += 1;
                if courant > max {
                    max = courant;
                }
            } else {
                courant = 0;
            }
        }
        max
    }
}
