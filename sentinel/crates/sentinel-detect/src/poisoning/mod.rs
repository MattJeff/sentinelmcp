//! Inspecteur de poisoning — agent 3.5 (lead) + consommation bibliothèque agent 3.6.
//!
//! Architecture :
//!   - `InspecteurPoisoning::inspecter` parcourt chaque outil (description + input_schema récursif,
//!     profondeur ≤ 5) et applique tous les patterns compilés.
//!   - `inspecter_texte` est le noyau de détection : applique la bibliothèque de patterns (agent 3.6)
//!     avec fallback inline si la bibliothèque est vide.
//!   - `vers_constat` convertit un `ConstatPoisoning` en `Constat` formel pour le store.
//!
//! Contrat d'entrée/sortie :
//!   Entrée  : `&[Outil]` produits par agent 1.6, plus `ServeurId` pour la conversion en constat.
//!   Sortie  : `Vec<ConstatPoisoning>` (détails locaux) ou `Vec<Constat>` (store-ready).
//!
//! Références de conformité émises : SAFE-T1001, OWASP MCP03.

pub mod patterns;

use once_cell::sync::Lazy;
use regex::Regex;
use sentinel_protocol::{Constat, EtatConstat, Outil, Severite, ServeurId, TypeConstat};
use chrono::Utc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Patterns de secours (fallback si la bibliothèque de l'agent 3.6 est vide)
// ---------------------------------------------------------------------------

struct PatternFallback {
    nom: &'static str,
    categorie: &'static str,
    regex: &'static str,
}

const FALLBACKS: &[PatternFallback] = &[
    PatternFallback {
        nom: "injection-system",
        categorie: "injection-prompt",
        regex: r"(?i)\[SYSTEM\]",
    },
    PatternFallback {
        nom: "acces-env",
        categorie: "exfiltration-secrets",
        regex: r"(?i)\.env",
    },
    PatternFallback {
        nom: "acces-ssh",
        categorie: "exfiltration-secrets",
        regex: r"(?i)~/\.ssh",
    },
];

// ---------------------------------------------------------------------------
// Type interne compilé (regex déjà construite)
// ---------------------------------------------------------------------------

struct PatternCompile {
    nom: String,
    categorie: String,
    severite: Severite,
    re: Regex,
}

/// Cache des patterns compilés (bibliothèque 3.6 + fallbacks si vide).
static PATTERNS: Lazy<Vec<PatternCompile>> = Lazy::new(|| {
    let biblio = patterns::bibliotheque();
    if biblio.is_empty() {
        FALLBACKS
            .iter()
            .filter_map(|p| {
                Regex::new(p.regex).ok().map(|re| PatternCompile {
                    nom: p.nom.to_string(),
                    categorie: p.categorie.to_string(),
                    severite: Severite::Critique,
                    re,
                })
            })
            .collect()
    } else {
        biblio
            .into_iter()
            .filter_map(|p| {
                Regex::new(p.regex).ok().map(|re| PatternCompile {
                    nom: p.nom.to_string(),
                    categorie: p.categorie.to_string(),
                    severite: p.severite,
                    re,
                })
            })
            .collect()
    }
});

// ---------------------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------------------

/// Constat de poisoning local (avant conversion en `Constat` formel du store).
#[derive(Debug, Clone)]
pub struct ConstatPoisoning {
    /// Nom de l'outil concerné.
    pub outil: String,
    /// Nom du pattern déclenché.
    pub pattern: String,
    /// Catégorie du pattern (injection-prompt, exfiltration-secrets, …).
    pub categorie: String,
    /// Extrait du texte qui a déclenché la correspondance (≤ 120 caractères).
    pub extrait: String,
    /// Sévérité héritée du pattern (Critique par défaut).
    pub severite: Severite,
}

// ---------------------------------------------------------------------------
// Inspecteur
// ---------------------------------------------------------------------------

pub struct InspecteurPoisoning;

impl InspecteurPoisoning {
    /// Inspecte un ensemble d'outils et retourne tous les constats de poisoning détectés.
    ///
    /// Pour chaque outil :
    ///   1. Inspecte le champ `description`.
    ///   2. Inspecte récursivement les descriptions des propriétés de `input_schema` (profondeur ≤ 5).
    pub fn inspecter(outils: &[Outil]) -> Vec<ConstatPoisoning> {
        let mut constats = Vec::new();
        for outil in outils {
            // Inspecter la description de l'outil.
            if let Some(desc) = &outil.description {
                for (pattern, categorie, extrait, severite) in Self::inspecter_texte(desc) {
                    constats.push(ConstatPoisoning {
                        outil: outil.nom.clone(),
                        pattern,
                        categorie,
                        extrait,
                        severite,
                    });
                }
            }
            // Inspecter récursivement les descriptions dans input_schema.
            Self::inspecter_schema(&outil.nom, &outil.input_schema, 0, &mut constats);
        }
        constats
    }

    /// Convertit un `ConstatPoisoning` en `Constat` formel pour le store.
    pub fn vers_constat(c: &ConstatPoisoning, serveur_id: ServeurId) -> Constat {
        Constat {
            id: Uuid::new_v4(),
            serveur_id,
            outil_nom: Some(c.outil.clone()),
            type_constat: TypeConstat::Poisoning,
            severite: c.severite,
            titre: format!("Poisoning détecté — outil « {} » [{}]", c.outil, c.categorie),
            detail: format!(
                "Pattern « {} » (catégorie : {}) déclenché. Extrait : « {} »",
                c.pattern, c.categorie, c.extrait
            ),
            diff: None,
            references_conformite: vec![
                "SAFE-T1001".to_string(),
                "OWASP MCP03".to_string(),
            ],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        }
    }

    /// Inspection rapide d'un texte arbitraire.
    ///
    /// Retourne un vecteur de tuples `(nom_pattern, categorie, extrait, severite)`.
    pub fn inspecter_texte(texte: &str) -> Vec<(String, String, String, Severite)> {
        let mut resultats = Vec::new();
        for p in PATTERNS.iter() {
            if let Some(m) = p.re.find(texte) {
                // Extrait contextuel : 60 caractères autour de la correspondance, tronqué à 120.
                let debut = m.start().saturating_sub(30);
                let fin = (m.end() + 30).min(texte.len());
                let extrait = texte[debut..fin].replace('\n', " ");
                let extrait = if extrait.len() > 120 {
                    format!("{}…", &extrait[..119])
                } else {
                    extrait
                };
                resultats.push((p.nom.clone(), p.categorie.clone(), extrait, p.severite));
            }
        }
        resultats
    }

    // -----------------------------------------------------------------------
    // Privé — parcours récursif de l'input_schema
    // -----------------------------------------------------------------------

    fn inspecter_schema(
        nom_outil: &str,
        schema: &serde_json::Value,
        profondeur: u8,
        constats: &mut Vec<ConstatPoisoning>,
    ) {
        if profondeur >= 5 {
            return;
        }
        // Inspecter la description du nœud courant.
        if let Some(desc) = schema.get("description").and_then(|v| v.as_str()) {
            for (pattern, categorie, extrait, severite) in Self::inspecter_texte(desc) {
                constats.push(ConstatPoisoning {
                    outil: nom_outil.to_string(),
                    pattern,
                    categorie,
                    extrait,
                    severite,
                });
            }
        }
        // Descendre dans les propriétés.
        if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
            for prop_schema in props.values() {
                Self::inspecter_schema(nom_outil, prop_schema, profondeur + 1, constats);
            }
        }
        // Descendre dans les items (tableaux JSON Schema).
        if let Some(items) = schema.get("items") {
            Self::inspecter_schema(nom_outil, items, profondeur + 1, constats);
        }
        // Descendre dans allOf / anyOf / oneOf.
        for clef in &["allOf", "anyOf", "oneOf"] {
            if let Some(arr) = schema.get(clef).and_then(|v| v.as_array()) {
                for sous_schema in arr {
                    Self::inspecter_schema(nom_outil, sous_schema, profondeur + 1, constats);
                }
            }
        }
    }
}
