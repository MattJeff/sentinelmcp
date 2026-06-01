//! Matrice de sévérité — agent 4.2.
//!
//! Mapping configurable TypeConstat → Severite.
//! Les règles par défaut suivent la spec Sentinel MCP v1.
//! L'opérateur peut surcharger n'importe quelle règle via [`ConfigSeverite::definir`].

use sentinel_protocol::{Severite, TypeConstat};
use std::collections::HashMap;

/// Configuration déclarative de la matrice de sévérité.
/// Ordre des règles : la dernière définition d'un même TypeConstat l'emporte.
#[derive(Debug, Default, Clone)]
pub struct ConfigSeverite {
    /// Liste ordonnée des règles (TypeConstat, Severite).
    pub regles: Vec<(TypeConstat, Severite)>,
}

impl ConfigSeverite {
    /// Construit la configuration par défaut selon la spec.
    pub fn par_defaut() -> Self {
        use Severite::*;
        use TypeConstat::*;
        Self {
            regles: vec![
                (NouveauServeur, Moyenne),
                (ShadowMcp, Moyenne),
                (RugPull, Critique),
                (Poisoning, Critique),
                (Sosie, Haute),
                (Exfiltration, Critique),
                (SansAuthentification, Haute),
                (DeriveInterSession, Haute),
                (Autre, Moyenne),
            ],
        }
    }

    /// Surcharge ou ajoute une règle pour le type donné.
    /// Si le type existe déjà dans la liste, la règle existante est mise à jour.
    /// Sinon, la règle est ajoutée à la fin.
    pub fn definir(&mut self, t: TypeConstat, s: Severite) {
        if let Some(regle) = self.regles.iter_mut().find(|(tc, _)| tc == &t) {
            regle.1 = s;
        } else {
            self.regles.push((t, s));
        }
    }
}

/// Moteur de sévérité : index HashMap pour lookup O(1).
pub struct MatriceSeverite {
    pub config: ConfigSeverite,
    index: HashMap<TypeConstat, Severite>,
}

impl MatriceSeverite {
    /// Construit la matrice avec les règles par défaut.
    pub fn par_defaut() -> Self {
        Self::depuis_config(ConfigSeverite::par_defaut())
    }

    /// Construit la matrice depuis une configuration opérateur.
    pub fn depuis_config(config: ConfigSeverite) -> Self {
        let index: HashMap<TypeConstat, Severite> = config.regles.iter().cloned().collect();
        Self { config, index }
    }

    /// Retourne la sévérité associée au type de constat.
    /// Si le type est absent de la configuration, retourne Moyenne par défaut.
    pub fn severite_pour(&self, t: &TypeConstat) -> Severite {
        self.index.get(t).copied().unwrap_or(Severite::Moyenne)
    }
}
