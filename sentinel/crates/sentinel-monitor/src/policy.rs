//! Politique « changement légitime vs attaque » — agent 2.7.
//!
//! Logique de qualification :
//! 1. Motifs suspects détectés dans le diff → Escalader
//! 2. Modification description ou schema (sans suspect) → Alerter
//! 3. Ajout ou suppression d'outil uniquement → Alerter (la v1 laisse trancher)
//! 4. Aucun changement → Ignorer

/// Décision de la politique pour un changement donné.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionPolitique {
    /// Changement bénin ou nul, ne déclenche pas d'alerte.
    Ignorer,
    /// Changement notable, ouvre un constat (défaut).
    Alerter,
    /// Changement critique, alerte avec sévérité Critique.
    Escalader,
}

/// Représentation structurée d'un changement détecté sur un serveur MCP.
#[derive(Debug, Clone)]
pub struct Changement {
    pub description: String,
    pub ajout_outil: bool,
    pub suppression_outil: bool,
    pub modification_description: bool,
    pub modification_input_schema: bool,
    /// Patterns de poisoning détectés par le diff (ex. "SYSTEM", ".env", "ssh").
    pub motifs_suspects_detectes: Vec<String>,
}

impl Changement {
    /// Construit un `Changement` sans aucun changement (tous les booléens à false).
    pub fn vide() -> Self {
        Self {
            description: String::new(),
            ajout_outil: false,
            suppression_outil: false,
            modification_description: false,
            modification_input_schema: false,
            motifs_suspects_detectes: vec![],
        }
    }
}

pub struct PolitiqueChangement;

impl PolitiqueChangement {
    /// Qualifie un changement structuré.
    pub fn qualifier(c: &Changement) -> DecisionPolitique {
        // Règle 1 : présence de motifs suspects → escalade immédiate.
        if !c.motifs_suspects_detectes.is_empty() {
            return DecisionPolitique::Escalader;
        }

        // Règle 2 : toute modification de la surface sémantique → alerte.
        if c.modification_description || c.modification_input_schema {
            return DecisionPolitique::Alerter;
        }

        // Règle 3 : ajout ou suppression d'outil → alerte (la v1 laisse trancher).
        if c.ajout_outil || c.suppression_outil {
            return DecisionPolitique::Alerter;
        }

        // Règle 4 : aucun changement détecté.
        DecisionPolitique::Ignorer
    }

    /// API simple historique conservée pour compatibilité avec l'agent 3.3.
    ///
    /// Parse naïvement le texte : cherche "SYSTEM", ".env" ou "ssh"
    /// (insensible à la casse) → Escalader, sinon Alerter.
    pub fn qualifier_resume(diff_resume: &str) -> DecisionPolitique {
        let texte_bas = diff_resume.to_lowercase();
        let motifs_critiques = ["system", ".env", "ssh"];
        for motif in &motifs_critiques {
            if texte_bas.contains(motif) {
                return DecisionPolitique::Escalader;
            }
        }
        DecisionPolitique::Alerter
    }
}
