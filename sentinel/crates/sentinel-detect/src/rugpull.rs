//! Détecteur de rug-pull — agent 3.4 (SAFE-T1201).
//!
//! Orchestre l'empreinte (3.2), le diff (3.3) et la détection du changement
//! silencieux pour produire un `Constat` de type `RugPull`.

use chrono::Utc;
use uuid::Uuid;

use sentinel_protocol::{
    Baseline, Constat, EtatConstat, Outil, Severite, ServeurId, TypeConstat,
};

use crate::diff::{diff_outils, RenduDiff};
use crate::fingerprint::empreinte_serveur;

// ---------------------------------------------------------------------------
// Motifs d'escalade vers Critique (présents dans le texte brut du diff)
// ---------------------------------------------------------------------------

const MOTIFS_CRITIQUES: &[&str] = &[".env", "ssh", "system"];

// ---------------------------------------------------------------------------
// Structures publiques
// ---------------------------------------------------------------------------

pub struct DetecteurRugPull;

/// Contexte enrichi pour la détection de rug-pull, incluant le signal de
/// notification.
#[derive(Debug, Clone)]
pub struct ContexteRugPull {
    /// `true` si `notifications/tools/list_changed` a été reçu avant le
    /// `tools/list` courant ; `false` = changement silencieux.
    pub notification_recue: bool,
    /// Baseline approuvée en référence.
    pub baseline: Baseline,
    /// Liste d'outils observée au moment du contrôle.
    pub outils_courants: Vec<Outil>,
}

// ---------------------------------------------------------------------------
// Implémentation
// ---------------------------------------------------------------------------

impl DetecteurRugPull {
    /// Version simple : compare les empreintes et produit un constat si elles
    /// diffèrent. La sévérité est Haute par défaut (pas d'information sur la
    /// notification).
    pub fn evaluer(baseline: &Baseline, courants: &[Outil]) -> Option<Constat> {
        let ctx = ContexteRugPull {
            notification_recue: true, // suppose annoncé → sévérité Haute
            baseline: baseline.clone(),
            outils_courants: courants.to_vec(),
        };
        Self::evaluer_contexte(&ctx, baseline.serveur_id)
    }

    /// Version enrichie : prend en compte le changement silencieux.
    pub fn evaluer_contexte(ctx: &ContexteRugPull, serveur_id: ServeurId) -> Option<Constat> {
        let empreinte_courante = empreinte_serveur(&ctx.outils_courants);

        // Aucun changement → aucun constat.
        if empreinte_courante == ctx.baseline.empreinte_serveur {
            return None;
        }

        // Calcul du diff lisible.
        let rendu: RenduDiff = diff_outils(&ctx.baseline.outils, &ctx.outils_courants);

        // Sévérité : Critique si changement silencieux OU si motifs sensibles
        // détectés dans le texte du diff.
        let contient_motif_sensible = MOTIFS_CRITIQUES
            .iter()
            .any(|m| rendu.texte_brut.contains(m) || rendu.markdown.contains(m));

        let severite = if !ctx.notification_recue || contient_motif_sensible {
            Severite::Critique
        } else {
            Severite::Haute
        };

        let detail = format!(
            "Empreinte baseline : {}\nEmpreinte courante : {}\nNotification reçue : {}",
            ctx.baseline.empreinte_serveur.as_str(),
            empreinte_courante.as_str(),
            ctx.notification_recue,
        );

        let constat = Constat {
            id: Uuid::new_v4(),
            serveur_id,
            outil_nom: None,
            type_constat: TypeConstat::RugPull,
            severite,
            titre: "Rug-pull détecté : empreinte modifiée depuis approbation".to_string(),
            detail,
            diff: if rendu.markdown.is_empty() {
                None
            } else {
                Some(rendu.markdown.clone())
            },
            references_conformite: vec![
                "SAFE-T1201".to_string(),
                "OWASP MCP03".to_string(),
            ],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        };

        Some(constat)
    }
}
