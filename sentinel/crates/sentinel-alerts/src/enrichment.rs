//! Enrichissement d'alertes (diff/raison) — agent 4.6.
//!
//! Règle absolue : toute alerte critique porte toujours le diff ou la raison précise.

use sentinel_protocol::{Alerte, Constat, Severite};

/// Références conformité ajoutées systématiquement aux alertes critiques.
const REFERENCES_CONFORMITE: &str = "SAFE-T1001, OWASP MCP09";

/// Note d'incomplétude insérée quand une alerte critique n'a pas de diff.
const NOTE_INCOMPLETE: &str =
    "⚠ Contexte actionnable incomplet — voir le constat";

/// En-tête de la section diff insérée dans le message actionnable.
/// Sert aussi de garde d'idempotence : la section n'est ajoutée qu'une fois.
const EN_TETE_DIFF: &str = "### Changement détecté (ancien vs nouveau)";

/// Longueur maximale (en caractères) du diff inséré dans le message.
/// Au-delà, le diff est tronqué dans le message — le champ `Alerte.diff`
/// conserve de toute façon le diff complet pour les canaux qui le rendent.
const MAX_DIFF_MESSAGE: usize = 1000;

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

        // 2. Rendre le diff lisible directement dans le contenu actionnable
        //    (le message) pour qu'un opérateur voie immédiatement ce qui a
        //    changé : description, paramètres, défauts, enums — ancienne vs
        //    nouvelle valeur. Le champ `alerte.diff` conserve le diff complet
        //    brut pour les canaux qui le rendent séparément ; ici on garantit
        //    que même un consommateur ne lisant que le message voit le diff.
        if let Some(diff) = alerte.diff.as_deref() {
            if !diff.trim().is_empty() && !alerte.message.contains(EN_TETE_DIFF) {
                let section = Self::rendre_diff_lisible(diff);
                alerte.message.push_str(&format!("\n\n{section}"));
            }
        }

        // 3. Si critique et toujours sans diff, noter l'incomplétude.
        if alerte.severite == Severite::Critique && alerte.diff.is_none() {
            if !alerte.message.contains(NOTE_INCOMPLETE) {
                alerte.message.push_str(&format!("\n\n{NOTE_INCOMPLETE}"));
            }
        }

        // 4. Ajouter les références conformité en suffixe.
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

    /// Rend un diff brut sous une forme lisible insérable dans le message
    /// actionnable d'une alerte de rug-pull / drift.
    ///
    /// Le diff porte typiquement des lignes préfixées `-` (ancienne valeur) et
    /// `+` (nouvelle valeur) — description, paramètres, défauts, enums. La
    /// sortie encapsule ce diff dans un bloc ` ```diff ` précédé d'un en-tête
    /// explicite (ancien vs nouveau), et le tronque au-delà de
    /// [`MAX_DIFF_MESSAGE`] caractères pour garder le message lisible.
    pub fn rendre_diff_lisible(diff: &str) -> String {
        let diff = diff.trim();
        let corps = if diff.chars().count() > MAX_DIFF_MESSAGE {
            let tronque: String = diff.chars().take(MAX_DIFF_MESSAGE).collect();
            format!("{tronque}\n… (diff tronqué — voir le diff complet de l'alerte)")
        } else {
            diff.to_string()
        };
        format!("{EN_TETE_DIFF}\n```diff\n{corps}\n```")
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
