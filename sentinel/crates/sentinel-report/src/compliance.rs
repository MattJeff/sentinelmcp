//! Moteur de mapping de conformité — agent 5.4.
//!
//! Mapping constat → référentiels : OWASP MCP, SAFE-MCP, SOC 2, ISO 27001.
//! Version de la table : 2026-beta-1.
//!
//! ATTENTION : un mapping faux est pire que pas de rapport.
//! Toute modification doit être validée par relecture experte OWASP.

use sentinel_protocol::{Constat, Severite, TypeConstat};

/// Version de la table de mapping. Incrémenter à chaque modification.
pub const VERSION_TABLE: &str = "2026-beta-1";

/// Référence vers un contrôle d'un référentiel de conformité.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// Nom court du cadre : "OWASP MCP", "SAFE-MCP", "SOC 2", "ISO 27001".
    pub cadre: &'static str,
    /// Identifiant du contrôle dans le cadre (ex. "MCP09", "SAFE-T1001", "CC6.1").
    pub identifiant: &'static str,
    /// Titre humain du contrôle.
    pub titre: &'static str,
    /// URL canonique vers la spécification (None si le contrôle n'est pas encore publié).
    pub url: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Constantes — une seule définition par référence, évite les divergences.
// ---------------------------------------------------------------------------

const OWASP_MCP09: Reference = Reference {
    cadre: "OWASP MCP",
    identifiant: "MCP09",
    titre: "Shadow MCP Server",
    url: Some("https://owasp.org/www-project-mcp-top-10/"),
};

const OWASP_MCP03: Reference = Reference {
    cadre: "OWASP MCP",
    identifiant: "MCP03",
    titre: "Tool Poisoning",
    url: Some("https://owasp.org/www-project-mcp-top-10/"),
};

const OWASP_A07: Reference = Reference {
    cadre: "OWASP",
    identifiant: "A07",
    titre: "Identification and Authentication Failures",
    url: Some("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
};

const SAFE_T1001: Reference = Reference {
    cadre: "SAFE-MCP",
    identifiant: "SAFE-T1001",
    titre: "Tool Description Poisoning",
    url: Some("https://safemcp.io/techniques/T1001"),
};

const SAFE_T1201: Reference = Reference {
    cadre: "SAFE-MCP",
    identifiant: "SAFE-T1201",
    titre: "Rug Pull — Tool Behavior Change",
    url: Some("https://safemcp.io/techniques/T1201"),
};

const SOC2_CC6_1: Reference = Reference {
    cadre: "SOC 2",
    identifiant: "CC6.1",
    titre: "Logical and Physical Access Controls",
    url: None,
};

const SOC2_CC7_1: Reference = Reference {
    cadre: "SOC 2",
    identifiant: "CC7.1",
    titre: "System Operations — Change Management",
    url: None,
};

const SOC2_CC7_2: Reference = Reference {
    cadre: "SOC 2",
    identifiant: "CC7.2",
    titre: "System Operations — Anomaly Detection",
    url: None,
};

const ISO_A12_4_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.12.4.1",
    titre: "Event Logging",
    url: None,
};

const ISO_A14_2_2: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.14.2.2",
    titre: "System Change Control Procedures",
    url: None,
};

const ISO_A12_6_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.12.6.1",
    titre: "Management of Technical Vulnerabilities",
    url: None,
};

const ISO_A8_1_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.8.1.1",
    titre: "Inventory of Assets",
    url: None,
};

const ISO_A13_1_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.13.1.1",
    titre: "Network Controls",
    url: None,
};

const ISO_A12_4_3: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.12.4.3",
    titre: "Administrator and Operator Logs",
    url: None,
};

// ---------------------------------------------------------------------------
// Moteur
// ---------------------------------------------------------------------------

pub struct MoteurConformite;

impl MoteurConformite {
    /// Retourne la liste de références applicables à un type de constat.
    ///
    /// L'ordre est significatif : les références les plus spécifiques au risque
    /// MCP apparaissent en premier (OWASP MCP puis SAFE-MCP), suivies des
    /// contrôles opérationnels généraux (SOC 2, ISO 27001).
    pub fn references_pour(t: &TypeConstat) -> Vec<Reference> {
        match t {
            // Serveur inconnu observé pour la première fois — Shadow MCP.
            TypeConstat::NouveauServeur | TypeConstat::ShadowMcp => vec![
                OWASP_MCP09.clone(),
                SOC2_CC6_1.clone(),
                ISO_A12_4_1.clone(),
            ],
            // Changement de comportement entre deux observations d'un serveur approuvé.
            TypeConstat::RugPull => vec![
                OWASP_MCP03.clone(),
                SAFE_T1201.clone(),
                SOC2_CC7_1.clone(),
                ISO_A14_2_2.clone(),
            ],
            // Instruction cachée dans la description ou le schéma d'un outil.
            TypeConstat::Poisoning => vec![
                OWASP_MCP03.clone(),
                SAFE_T1001.clone(),
                SOC2_CC7_2.clone(),
                ISO_A12_6_1.clone(),
            ],
            // Serveur qui usurpe le nom ou l'empreinte d'un serveur légitime.
            TypeConstat::Sosie => vec![
                OWASP_MCP09.clone(),
                ISO_A8_1_1.clone(),
            ],
            // Paramètre d'appel acheminant des données vers une destination externe.
            TypeConstat::Exfiltration => vec![
                SAFE_T1201.clone(),
                OWASP_MCP03.clone(),
                ISO_A13_1_1.clone(),
            ],
            // Serveur accessible sans mécanisme d'authentification.
            TypeConstat::SansAuthentification => vec![
                OWASP_A07.clone(),
                SOC2_CC6_1.clone(),
            ],
            // Divergence de comportement observée entre deux sessions distinctes.
            TypeConstat::DeriveInterSession => vec![
                SAFE_T1201.clone(),
                ISO_A12_4_3.clone(),
            ],
            // Constat non catégorisé — aucune référence applicable.
            TypeConstat::Autre => vec![],
        }
    }

    /// Retourne les références applicables en fonction de la sévérité seule.
    ///
    /// Usage : enrichir un constat lorsque son type fin n'est pas disponible
    /// (ex. agrégation de métriques globales). Ne pas utiliser à la place de
    /// `references_pour` quand le `TypeConstat` est connu.
    pub fn references_par_severite(s: &Severite) -> Vec<Reference> {
        match s {
            Severite::Critique | Severite::Haute => vec![
                OWASP_MCP03.clone(),
                OWASP_MCP09.clone(),
            ],
            Severite::Moyenne => vec![
                OWASP_MCP09.clone(),
            ],
            Severite::Info => vec![],
        }
    }

    /// Tableau complet : tous les types de constats et leurs références.
    ///
    /// Utilisé par l'agent 5.6 (PDF) et 5.7 (JSON) pour générer l'annexe
    /// de couverture de conformité du rapport.
    pub fn tableau_complet() -> Vec<(TypeConstat, Vec<Reference>)> {
        let types = [
            TypeConstat::NouveauServeur,
            TypeConstat::ShadowMcp,
            TypeConstat::RugPull,
            TypeConstat::Poisoning,
            TypeConstat::Sosie,
            TypeConstat::Exfiltration,
            TypeConstat::SansAuthentification,
            TypeConstat::DeriveInterSession,
            TypeConstat::Autre,
        ];
        types
            .into_iter()
            .map(|t| {
                let refs = Self::references_pour(&t);
                (t, refs)
            })
            .collect()
    }

    /// Génère la section conformité d'un rapport Markdown.
    ///
    /// Produit un tableau : `| Constat | Cadre | Identifiant | Titre |`
    /// Un constat sans référence n'est pas listé (pas de ligne vide trompeuse).
    pub fn markdown_section(constats: &[Constat]) -> String {
        let mut lignes: Vec<String> = Vec::new();

        lignes.push(format!(
            "## Conformité (table v{})\n",
            VERSION_TABLE
        ));
        lignes.push(
            "| Constat | Cadre | Identifiant | Titre |".to_string(),
        );
        lignes.push("|---------|-------|-------------|-------|".to_string());

        for constat in constats {
            let refs = Self::references_pour(&constat.type_constat);
            for r in &refs {
                let identifiant = match r.url {
                    Some(url) => format!("[{}]({})", r.identifiant, url),
                    None => r.identifiant.to_string(),
                };
                lignes.push(format!(
                    "| {} | {} | {} | {} |",
                    constat.titre, r.cadre, identifiant, r.titre
                ));
            }
        }

        lignes.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Implémentation de Clone pour Reference (nécessaire pour les .clone() ci-dessus).
// ---------------------------------------------------------------------------
// Reference dérive Clone, donc les constantes peuvent être clonées directement.

#[cfg(test)]
mod tests_internes {
    use super::*;

    #[test]
    fn version_table_non_vide() {
        assert!(!VERSION_TABLE.is_empty());
    }

    #[test]
    fn autre_vide() {
        assert!(MoteurConformite::references_pour(&TypeConstat::Autre).is_empty());
    }
}
