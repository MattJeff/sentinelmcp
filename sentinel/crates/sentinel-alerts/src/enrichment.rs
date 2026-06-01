//! Enrichissement d'alertes (diff/raison) — agent 4.6.
//!
//! Règle absolue : toute alerte critique porte toujours le diff ou la raison précise.

use sentinel_protocol::{Alerte, Constat, Severite};

/// Références conformité ajoutées systématiquement aux alertes critiques.
const REFERENCES_CONFORMITE: &str = "SAFE-T1001, OWASP MCP09";

/// Note d'incomplétude insérée quand une alerte critique n'a pas de diff.
const NOTE_INCOMPLETE: &str =
    "⚠ Contexte actionnable incomplet — voir le constat";

pub struct EnrichisseurAlerte;

impl EnrichisseurAlerte {
    /// Enrichit l'alerte avec le diff/raison du constat.
    ///
    /// - Si `constat.diff` est présent, le copie dans `alerte.diff`.
    /// - Si la sévérité est Critique et que `alerte.diff` est vide après copie,
    ///   ajoute un message d'incomplétude dans `alerte.message`.
    /// - Ajoute en suffixe au `message` la liste des références conformité.
    pub fn enrichir(constat: &Constat, alerte: &mut Alerte) {
        // 1. Copier le diff du constat vers l'alerte.
        if constat.diff.is_some() {
            alerte.diff = constat.diff.clone();
        }

        // 2. Si critique et toujours sans diff, noter l'incomplétude.
        if alerte.severite == Severite::Critique && alerte.diff.is_none() {
            if !alerte.message.contains(NOTE_INCOMPLETE) {
                alerte.message.push_str(&format!("\n\n{NOTE_INCOMPLETE}"));
            }
        }

        // 3. Ajouter les références conformité en suffixe.
        let suffixe = format!("\n\nRéférences : {REFERENCES_CONFORMITE}");
        if !alerte.message.contains(&suffixe) {
            alerte.message.push_str(&suffixe);
        }
    }

    /// Vérifie qu'une alerte critique porte bien un contexte actionnable.
    ///
    /// Renvoie `Err` si l'alerte est Critique, sans diff et sans mention de
    /// pattern dans le message.
    pub fn verifier_completude(alerte: &Alerte) -> Result<(), String> {
        if alerte.severite != Severite::Critique {
            return Ok(());
        }
        if alerte.diff.is_some() {
            return Ok(());
        }
        // Mention d'un pattern (nom de règle SAFE ou OWASP) dans le message.
        let message_lower = alerte.message.to_lowercase();
        let contient_pattern = message_lower.contains("safe-t")
            || message_lower.contains("owasp")
            || message_lower.contains("mcp0")
            || message_lower.contains("pattern");
        if contient_pattern {
            return Ok(());
        }
        Err(format!(
            "Alerte critique '{}' (id={}) sans contexte actionnable : diff absent et aucun pattern de conformité trouvé dans le message.",
            alerte.titre, alerte.id
        ))
    }

    /// Construit un résumé actionnable texte à partir d'un Constat.
    ///
    /// Combine : titre + détail + diff résumé (300 premiers caractères) + références.
    pub fn resume_actionnable(constat: &Constat) -> String {
        let mut parties: Vec<String> = Vec::new();

        parties.push(format!("## {}", constat.titre));
        parties.push(constat.detail.clone());

        if let Some(diff) = &constat.diff {
            let extrait = if diff.chars().count() > 300 {
                let tronque: String = diff.chars().take(300).collect();
                format!("```diff\n{tronque}\n… (tronqué)\n```")
            } else {
                format!("```diff\n{diff}\n```")
            };
            parties.push(format!("### Diff\n{extrait}"));
        }

        // Références : d'abord celles du constat, puis les références fixes.
        let refs = if constat.references_conformite.is_empty() {
            REFERENCES_CONFORMITE.to_string()
        } else {
            let jointes = constat.references_conformite.join(", ");
            format!("{jointes}, {REFERENCES_CONFORMITE}")
        };
        parties.push(format!("Références : {refs}"));

        parties.join("\n\n")
    }
}
