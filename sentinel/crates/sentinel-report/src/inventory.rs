//! Inventaire et journal des changements — agent 5.3.
//!
//! Produit deux sections Markdown destinées au rapport signé :
//! - `SectionInventaire` : tableau complet des serveurs MCP + détail des rouges.
//! - `SectionJournal`    : journal horodaté des constats avec diffs.

use chrono::{DateTime, Utc};
use sentinel_protocol::{Constat, Couleur, Serveur, StatutServeur, Transport, TypeConstat};

// ---------------------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------------------

/// Section inventaire destinée au rapport.
#[derive(Debug, Default, Clone)]
pub struct SectionInventaire {
    pub serveurs: Vec<Serveur>,
    pub markdown: String,
}

/// Section journal destinée au rapport.
#[derive(Debug, Default, Clone)]
pub struct SectionJournal {
    pub entrees: Vec<EntreeJournal>,
    pub markdown: String,
}

/// Une entrée dans le journal des changements.
#[derive(Debug, Clone)]
pub struct EntreeJournal {
    pub horodatage: DateTime<Utc>,
    pub serveur_endpoint: String,
    pub type_constat: TypeConstat,
    pub titre: String,
    pub diff: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers de rendu
// ---------------------------------------------------------------------------

fn libelle_couleur(couleur: Couleur) -> &'static str {
    match couleur {
        Couleur::Vert => "Green",
        Couleur::Orange => "Orange",
        Couleur::Rouge => "Red",
    }
}

fn libelle_statut(statut: StatutServeur) -> &'static str {
    match statut {
        StatutServeur::Approuve => "Approved",
        StatutServeur::Inconnu => "Unknown",
        StatutServeur::Suspect => "Suspect",
        StatutServeur::AInvestiguer => "To investigate",
        StatutServeur::Bloque => "Blocked",
    }
}

fn libelle_transport(transport: Transport) -> &'static str {
    match transport {
        Transport::Stdio => "stdio",
        Transport::Http => "HTTP",
    }
}

fn libelle_type_constat(tc: &TypeConstat) -> &'static str {
    match tc {
        TypeConstat::NouveauServeur => "New server",
        TypeConstat::ShadowMcp => "Shadow MCP (MCP09)",
        TypeConstat::RugPull => "Rug pull (SAFE-T1201)",
        TypeConstat::Poisoning => "Tool poisoning (MCP03 / SAFE-T1001)",
        TypeConstat::Sosie => "Lookalike",
        TypeConstat::Exfiltration => "Exfiltration",
        TypeConstat::SansAuthentification => "No authentication",
        TypeConstat::DeriveInterSession => "Inter-session drift",
        TypeConstat::AbusSampling => "Sampling abuse",
        TypeConstat::ElicitationSensible => "Sensitive elicitation",
        TypeConstat::Autre => "Other",
    }
}

fn horodatage_iso(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// ---------------------------------------------------------------------------
// SectionInventaire
// ---------------------------------------------------------------------------

impl SectionInventaire {
    /// Construit la section à partir d'un vecteur de serveurs.
    pub fn construire(serveurs: Vec<Serveur>) -> Self {
        let markdown = generer_markdown_inventaire(&serveurs);
        Self { serveurs, markdown }
    }
}

fn generer_markdown_inventaire(serveurs: &[Serveur]) -> String {
    let mut md = String::from("## MCP server inventory\n\n");

    if serveurs.is_empty() {
        md.push_str("_No servers detected._\n");
        return md;
    }

    // Tableau principal
    md.push_str("| Endpoint | Transport | Status | Criticality | First seen | Last seen |\n");
    md.push_str("|----------|-----------|--------|-----------|--------------|-------------|\n");

    for s in serveurs {
        md.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            s.endpoint,
            libelle_transport(s.transport),
            libelle_statut(s.statut),
            libelle_couleur(s.couleur),
            horodatage_iso(&s.premiere_vue),
            horodatage_iso(&s.derniere_vue),
        ));
    }

    // Sous-sections détaillées pour chaque serveur rouge
    let rouges: Vec<&Serveur> = serveurs
        .iter()
        .filter(|s| s.couleur == Couleur::Rouge)
        .collect();

    if !rouges.is_empty() {
        md.push_str("\n### Critical servers (red)\n\n");
        for s in rouges {
            md.push_str(&format!("#### `{}`\n\n", s.endpoint));
            md.push_str(&format!("- **ID**: `{}`\n", s.id));
            md.push_str(&format!("- **Transport**: {}\n", libelle_transport(s.transport)));
            md.push_str(&format!("- **Status**: {}\n", libelle_statut(s.statut)));
            if !s.portees.is_empty() {
                let portees: Vec<String> = s.portees.iter().map(|p| format!("{:?}", p)).collect();
                md.push_str(&format!("- **Scopes**: {}\n", portees.join(", ")));
            }
            md.push_str(&format!("- **First seen**: {}\n", horodatage_iso(&s.premiere_vue)));
            md.push_str(&format!("- **Last seen**: {}\n", horodatage_iso(&s.derniere_vue)));
            if let Some(ref emp) = s.empreinte_courante {
                md.push_str(&format!("- **Fingerprint**: `{}`\n", emp));
            }
            md.push('\n');
        }
    }

    md
}

// ---------------------------------------------------------------------------
// SectionJournal
// ---------------------------------------------------------------------------

impl SectionJournal {
    /// Construit le journal à partir des constats, en résolvant l'endpoint
    /// via la liste de serveurs.
    pub fn construire(constats: &[Constat], serveurs: &[Serveur]) -> Self {
        if constats.is_empty() {
            let markdown = "## Change log\n\n_No change recorded._\n"
                .to_string();
            return Self {
                entrees: vec![],
                markdown,
            };
        }

        // Trier par horodatage décroissant
        let mut tries: Vec<&Constat> = constats.iter().collect();
        tries.sort_by(|a, b| b.horodatage.cmp(&a.horodatage));

        let entrees: Vec<EntreeJournal> = tries
            .iter()
            .map(|c| {
                let endpoint = serveurs
                    .iter()
                    .find(|s| s.id == c.serveur_id)
                    .map(|s| s.endpoint.clone())
                    .unwrap_or_else(|| c.serveur_id.to_string());
                EntreeJournal {
                    horodatage: c.horodatage,
                    serveur_endpoint: endpoint,
                    type_constat: c.type_constat.clone(),
                    titre: c.titre.clone(),
                    diff: c.diff.clone(),
                }
            })
            .collect();

        let markdown = generer_markdown_journal(&entrees);
        Self { entrees, markdown }
    }
}

fn generer_markdown_journal(entrees: &[EntreeJournal]) -> String {
    let mut md = String::from("## Change log\n\n");

    for (i, e) in entrees.iter().enumerate() {
        md.push_str(&format!(
            "### {}. {} — `{}`\n\n",
            i + 1,
            horodatage_iso(&e.horodatage),
            e.serveur_endpoint,
        ));
        md.push_str(&format!("- **Type**: {}\n", libelle_type_constat(&e.type_constat)));
        md.push_str(&format!("- **Title**: {}\n", e.titre));

        if let Some(ref diff) = e.diff {
            md.push_str("\n**Diff:**\n\n");
            md.push_str("```diff\n");
            md.push_str(diff);
            if !diff.ends_with('\n') {
                md.push('\n');
            }
            md.push_str("```\n");
        }

        md.push('\n');
    }

    md
}
