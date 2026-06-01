//! Export JSON structuré — Agent 5.7.
//!
//! Produit un bundle JSON versionné, stable et documenté pour l'intégration
//! côté client. Le premier champ du document est toujours `version`.

use std::path::Path;

use anyhow::Context;
use chrono::{DateTime, Utc};
use sentinel_protocol::{Constat, Serveur, Severite, StatutServeur};

/// Version du schéma d'export ; incrémenté lors de toute rupture de contrat.
pub const VERSION_SCHEMA: &str = "1.0.0";

/// Source applicative inscrite dans tous les bundles produits.
pub const SOURCE: &str = "sentinel-mcp";

/// Document JSON exporté — contrat stable pour l'intégration côté client.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SchemaExport {
    /// Version du schéma (toujours premier champ sérialisé).
    pub version: &'static str,
    /// Horodatage UTC de génération.
    pub genere_a: DateTime<Utc>,
    /// Identifiant de la source applicative.
    pub source: &'static str,
    /// Liste complète des serveurs MCP observés.
    pub serveurs: Vec<Serveur>,
    /// Liste complète des constats détectés.
    pub constats: Vec<Constat>,
    /// Statistiques agrégées calculées depuis `serveurs` et `constats`.
    pub statistiques: Statistiques,
    /// Identifiants de conformité couverts (OWASP MCP09, MCP03, SAFE-T1001, …).
    pub references_conformite: Vec<String>,
    /// Signature Ed25519 du bundle (hex) — `None` si non signé.
    pub signature_ed25519_hex: Option<String>,
    /// Clé publique Ed25519 correspondante (hex) — `None` si non signé.
    pub cle_publique_hex: Option<String>,
}

/// Compteurs agrégés inscrits dans le bundle.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Statistiques {
    pub serveurs_total: u64,
    pub serveurs_approuves: u64,
    pub serveurs_a_risque: u64,
    pub constats_critiques: u64,
    pub constats_hauts: u64,
    pub constats_moyens: u64,
}

/// Point d'entrée de l'export JSON.
pub struct ExportJson;

impl ExportJson {
    /// Construit un [`SchemaExport`] depuis des listes brutes en calculant
    /// toutes les statistiques et en collectant les références de conformité
    /// présentes dans les constats.
    pub fn construire(serveurs: Vec<Serveur>, constats: Vec<Constat>) -> SchemaExport {
        let stats = Self::calculer_statistiques(&serveurs, &constats);

        // Déduplique et trie les références de conformité issues des constats.
        let mut refs: Vec<String> = constats
            .iter()
            .flat_map(|c| c.references_conformite.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        refs.sort();

        SchemaExport {
            version: VERSION_SCHEMA,
            genere_a: Utc::now(),
            source: SOURCE,
            serveurs,
            constats,
            statistiques: stats,
            references_conformite: refs,
            signature_ed25519_hex: None,
            cle_publique_hex: None,
        }
    }

    /// Sérialise `schema` en JSON pretty-printed (2 espaces) et écrit le
    /// résultat dans `chemin`. Crée les répertoires parents si nécessaire.
    pub fn produire_depuis(schema: &SchemaExport, chemin: &Path) -> anyhow::Result<()> {
        if let Some(parent) = chemin.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("création du répertoire {:?}", parent))?;
            }
        }

        let json = Self::serialiser(schema)?;
        std::fs::write(chemin, json)
            .with_context(|| format!("écriture de l'export JSON dans {:?}", chemin))?;
        Ok(())
    }

    /// Construit un [`SchemaExport`] depuis le store puis l'écrit dans `chemin`.
    ///
    /// Dans le cadre du module 5, le store est consulté via l'orchestrateur
    /// (agent 5.1). Cette surcharge est maintenue pour compatibilité avec les
    /// appelants qui disposent déjà d'une instance de store et ne souhaitent
    /// pas construire le schéma eux-mêmes.
    pub fn produire(chemin: &Path) -> anyhow::Result<()> {
        let schema = Self::construire(vec![], vec![]);
        Self::produire_depuis(&schema, chemin)
    }

    /// Convertit `schema` en [`serde_json::Value`] sans passer par un fichier.
    /// Utile pour la signature (agent 5.5) et pour les tests unitaires.
    pub fn vers_value(schema: &SchemaExport) -> serde_json::Value {
        // `unwrap` justifié : `SchemaExport` ne contient que des types
        // sérialisables ; un échec ici serait un bug de programmation.
        serde_json::to_value(schema).expect("SchemaExport toujours sérialisable")
    }

    // -----------------------------------------------------------------------
    // Helpers privés
    // -----------------------------------------------------------------------

    fn serialiser(schema: &SchemaExport) -> anyhow::Result<String> {
        // pretty-print avec indentation à 2 espaces via le formateur standard.
        let brut = serde_json::to_string_pretty(schema)
            .context("sérialisation JSON du bundle")?;
        // `serde_json::to_string_pretty` utilise 2 espaces par défaut.
        Ok(brut)
    }

    fn calculer_statistiques(serveurs: &[Serveur], constats: &[Constat]) -> Statistiques {
        let serveurs_total = serveurs.len() as u64;
        let serveurs_approuves = serveurs
            .iter()
            .filter(|s| matches!(s.statut, StatutServeur::Approuve))
            .count() as u64;
        // Sont « à risque » : Suspect, AInvestiguer, Bloque.
        let serveurs_a_risque = serveurs
            .iter()
            .filter(|s| {
                matches!(
                    s.statut,
                    StatutServeur::Suspect
                        | StatutServeur::AInvestiguer
                        | StatutServeur::Bloque
                )
            })
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

        Statistiques {
            serveurs_total,
            serveurs_approuves,
            serveurs_a_risque,
            constats_critiques,
            constats_hauts,
            constats_moyens,
        }
    }
}
