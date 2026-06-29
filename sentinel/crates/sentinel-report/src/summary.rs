//! Résumé exécutif — agent 5.2.
//!
//! Génère une page lisible par un non-technique à partir des agrégats du store :
//! compte de serveurs, serveurs non approuvés, serveurs à risque, constats par sévérité.

use sentinel_protocol::{Constat, Couleur, Serveur, Severite, StatutServeur};

/// Résumé exécutif d'une page, destiné à l'auditeur ou au DSI.
#[derive(Debug, Default, Clone)]
pub struct ResumeExecutif {
    pub serveurs_total: u64,
    pub serveurs_approuves: u64,
    pub serveurs_non_approuves: u64,
    pub serveurs_a_risque: u64,
    pub constats_critiques: u64,
    pub constats_hauts: u64,
    pub constats_moyens: u64,
    pub texte: String,
    pub appel_action: Option<String>,
}

impl ResumeExecutif {
    /// Construit le résumé à partir des tranches de données du store.
    pub fn construire(serveurs: &[Serveur], constats: &[Constat]) -> Self {
        let serveurs_total = serveurs.len() as u64;

        let serveurs_approuves = serveurs
            .iter()
            .filter(|s| s.statut == StatutServeur::Approuve)
            .count() as u64;

        let serveurs_non_approuves = serveurs_total - serveurs_approuves;

        let serveurs_a_risque = serveurs
            .iter()
            .filter(|s| s.couleur == Couleur::Rouge)
            .count() as u64;

        let constats_critiques = constats
            .iter()
            .filter(|c| c.severite == Severite::Critique)
            .count() as u64;

        let constats_hauts = constats
            .iter()
            .filter(|c| c.severite == Severite::Haute)
            .count() as u64;

        let constats_moyens = constats
            .iter()
            .filter(|c| c.severite == Severite::Moyenne)
            .count() as u64;

        let mut texte = Self::generer_texte(
            serveurs_total,
            serveurs_non_approuves,
            serveurs_a_risque,
            constats_critiques,
            constats_hauts,
            constats_moyens,
        );

        // Met en avant les détections avancées (Vague D) lorsqu'elles sont
        // présentes : trifecta létale, CVE connue, OAuth/SSRF, cross-server
        // shadowing, socket fantôme. Texte en prose pure (aucun Markdown).
        if let Some(phrase) = Self::phrase_detections_avancees(constats) {
            texte.push(' ');
            texte.push_str(&phrase);
        }

        let appel_action = if serveurs_a_risque > 0 || constats_critiques > 0 {
            Some(format!(
                "Une action immédiate est requise sur {} serveur{}.",
                serveurs_a_risque,
                if serveurs_a_risque > 1 { "s" } else { "" }
            ))
        } else {
            None
        };

        Self {
            serveurs_total,
            serveurs_approuves,
            serveurs_non_approuves,
            serveurs_a_risque,
            constats_critiques,
            constats_hauts,
            constats_moyens,
            texte,
            appel_action,
        }
    }

    /// Détecte la présence des natures de constats « Vague D » et produit une
    /// phrase de synthèse pour le résumé exécutif. Retourne `None` si aucune
    /// détection avancée n'est présente (le résumé reste alors inchangé).
    ///
    /// Les natures sont reconnues via les marqueurs déposés dans
    /// `references_conformite` par les détecteurs, car plusieurs partagent un
    /// même `TypeConstat` (CVE / OAuth-SSRF → `Autre`, cross-server shadowing →
    /// `Poisoning`, trifecta → `Exfiltration`).
    fn phrase_detections_avancees(constats: &[Constat]) -> Option<String> {
        let marque = |c: &Constat, aiguille: &str| {
            c.references_conformite.iter().any(|r| r.contains(aiguille))
        };

        let trifecta = constats
            .iter()
            .filter(|c| marque(c, "ATT&CK T1567"))
            .count();
        let cve = constats.iter().filter(|c| marque(c, "CVE-")).count();
        let confused = constats
            .iter()
            .filter(|c| marque(c, "confused-deputy") || marque(c, "RFC 8707") || marque(c, "SSRF"))
            .count();
        let shadowing = constats
            .iter()
            .filter(|c| marque(c, "SAFE-T1102"))
            .count();
        let socket = constats
            .iter()
            .filter(|c| marque(c, "shadow-mcp"))
            .count();

        let mut parties: Vec<String> = Vec::new();
        if trifecta > 0 {
            parties.push(format!("trifecta létale d'exfiltration ({trifecta})"));
        }
        if cve > 0 {
            parties.push(format!("vulnérabilité CVE connue ({cve})"));
        }
        if confused > 0 {
            parties.push(format!("OAuth confused deputy / SSRF ({confused})"));
        }
        if shadowing > 0 {
            parties.push(format!("cross-server shadowing ({shadowing})"));
        }
        if socket > 0 {
            parties.push(format!("socket fantôme en écoute ({socket})"));
        }

        if parties.is_empty() {
            return None;
        }
        Some(format!(
            "Détections avancées : {}.",
            parties.join(", ")
        ))
    }

    fn generer_texte(
        total: u64,
        non_approuves: u64,
        a_risque: u64,
        critiques: u64,
        hauts: u64,
        moyens: u64,
    ) -> String {
        if total == 0 {
            return "Aucun serveur MCP détecté sur la période d'observation.".to_string();
        }

        let mut lignes: Vec<String> = Vec::new();

        lignes.push(format!(
            "Sur {} serveur{} MCP détecté{}, {} ne sont pas approuvé{}.",
            total,
            if total > 1 { "s" } else { "" },
            if total > 1 { "s" } else { "" },
            non_approuves,
            if non_approuves > 1 { "s" } else { "" },
        ));

        if a_risque > 0 {
            lignes.push(format!(
                "{} {} à risque élevé (signalé{} en rouge).",
                a_risque,
                if a_risque > 1 { "sont" } else { "est" },
                if a_risque > 1 { "s" } else { "" },
            ));
        } else {
            lignes.push(
                "Aucun serveur n'est actuellement classé à risque élevé.".to_string(),
            );
        }

        let total_constats = critiques + hauts + moyens;
        if total_constats > 0 {
            lignes.push(format!(
                "Le pipeline a produit {} constat{} : {} critique{}, {} haut{} et {} moyen{}.",
                total_constats,
                if total_constats > 1 { "s" } else { "" },
                critiques,
                if critiques > 1 { "s" } else { "" },
                hauts,
                if hauts > 1 { "s" } else { "" },
                moyens,
                if moyens > 1 { "s" } else { "" },
            ));
        } else {
            lignes.push("Aucun constat de sévérité significative n'a été enregistré.".to_string());
        }

        lignes.push(
            "Ce rapport couvre les contrôles OWASP MCP09 (Shadow MCP) et MCP03 (Tool Poisoning), \
             ainsi que SAFE-T1001 et SAFE-T1201."
                .to_string(),
        );

        lignes.join(" ")
    }

    /// Rendu Markdown : titre, tableau de KPI, paragraphe explicatif, appel à l'action.
    pub fn vers_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# Résumé exécutif — Sentinel MCP\n\n");

        // Tableau KPI
        md.push_str("| Indicateur | Valeur |\n");
        md.push_str("|---|---|\n");
        md.push_str(&format!("| Serveurs détectés | {} |\n", self.serveurs_total));
        md.push_str(&format!("| Serveurs approuvés | {} |\n", self.serveurs_approuves));
        md.push_str(&format!("| Serveurs non approuvés | {} |\n", self.serveurs_non_approuves));
        md.push_str(&format!("| Serveurs à risque (rouge) | {} |\n", self.serveurs_a_risque));
        md.push_str(&format!("| Constats critiques | {} |\n", self.constats_critiques));
        md.push_str(&format!("| Constats hauts | {} |\n", self.constats_hauts));
        md.push_str(&format!("| Constats moyens | {} |\n", self.constats_moyens));
        md.push('\n');

        // Paragraphe explicatif
        md.push_str(&self.texte);
        md.push_str("\n\n");

        // Appel à l'action
        if let Some(ref aa) = self.appel_action {
            md.push_str(&format!("> **Action requise :** {}\n", aa));
        }

        md
    }

    /// Version texte plain, sans syntaxe Markdown, pour envoi par mail brut.
    pub fn vers_texte_plain(&self) -> String {
        let mut out = String::new();

        out.push_str("RÉSUMÉ EXÉCUTIF — Sentinel MCP\n");
        out.push_str(&"=".repeat(40));
        out.push('\n');

        out.push_str(&format!("Serveurs détectés       : {}\n", self.serveurs_total));
        out.push_str(&format!("Serveurs approuvés      : {}\n", self.serveurs_approuves));
        out.push_str(&format!("Serveurs non approuvés  : {}\n", self.serveurs_non_approuves));
        out.push_str(&format!("Serveurs à risque       : {}\n", self.serveurs_a_risque));
        out.push_str(&format!("Constats critiques      : {}\n", self.constats_critiques));
        out.push_str(&format!("Constats hauts          : {}\n", self.constats_hauts));
        out.push_str(&format!("Constats moyens         : {}\n", self.constats_moyens));
        out.push('\n');

        out.push_str(&self.texte);
        out.push('\n');

        if let Some(ref aa) = self.appel_action {
            out.push('\n');
            out.push_str(&format!("ACTION REQUISE : {}\n", aa));
        }

        out
    }
}
