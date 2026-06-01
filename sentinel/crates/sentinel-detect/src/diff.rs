//! Moteur de diff lisible — agent 3.3.
//!
//! Calcule et rend la différence entre une baseline d'outils MCP et la version
//! courante. Utilisé par les alertes rug-pull (SAFE-T1201) et le rapport de
//! conformité.

use sentinel_protocol::Outil;
use similar::{ChangeTag, TextDiff};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Structures publiques
// ─────────────────────────────────────────────────────────────────────────────

/// Résultat complet d'une comparaison entre deux listes d'outils MCP.
#[derive(Debug, Default, Clone)]
pub struct RenduDiff {
    /// Rendu Markdown prêt pour les alertes critiques et le rapport.
    pub markdown: String,
    /// Rendu texte brut pour les canaux ne supportant pas le Markdown.
    pub texte_brut: String,
    /// `true` dès qu'au moins un ajout, une suppression ou une modification.
    pub a_change: bool,
    /// Noms des outils présents dans `apres` mais absents de `avant`.
    pub outils_ajoutes: Vec<String>,
    /// Noms des outils présents dans `avant` mais absents de `apres`.
    pub outils_supprimes: Vec<String>,
    /// Détail des outils dont la description ou l'inputSchema a changé.
    pub outils_modifies: Vec<DiffOutil>,
}

/// Détail d'un outil modifié entre baseline et version courante.
#[derive(Debug, Clone)]
pub struct DiffOutil {
    pub nom: String,
    pub description_avant: Option<String>,
    pub description_apres: Option<String>,
    pub input_schema_avant: serde_json::Value,
    pub input_schema_apres: serde_json::Value,
}

// ─────────────────────────────────────────────────────────────────────────────
// Calcul du diff
// ─────────────────────────────────────────────────────────────────────────────

/// Compare deux listes d'outils et retourne un [`RenduDiff`] complet.
///
/// L'indexation se fait par `nom` d'outil. La comparaison de l'`inputSchema`
/// est insensible à l'ordre des clés (sérialisation canonique JSON triée).
pub fn diff_outils(avant: &[Outil], apres: &[Outil]) -> RenduDiff {
    let index_avant: HashMap<&str, &Outil> =
        avant.iter().map(|o| (o.nom.as_str(), o)).collect();
    let index_apres: HashMap<&str, &Outil> =
        apres.iter().map(|o| (o.nom.as_str(), o)).collect();

    // Outils ajoutés
    let mut outils_ajoutes: Vec<String> = apres
        .iter()
        .filter(|o| !index_avant.contains_key(o.nom.as_str()))
        .map(|o| o.nom.clone())
        .collect();
    outils_ajoutes.sort();

    // Outils supprimés
    let mut outils_supprimes: Vec<String> = avant
        .iter()
        .filter(|o| !index_apres.contains_key(o.nom.as_str()))
        .map(|o| o.nom.clone())
        .collect();
    outils_supprimes.sort();

    // Outils modifiés (même nom, description ou schema différent)
    let mut outils_modifies: Vec<DiffOutil> = avant
        .iter()
        .filter_map(|o_avant| {
            index_apres.get(o_avant.nom.as_str()).and_then(|o_apres| {
                let description_changee = o_avant.description != o_apres.description;
                let schema_change =
                    schema_canonique(&o_avant.input_schema) != schema_canonique(&o_apres.input_schema);

                if description_changee || schema_change {
                    Some(DiffOutil {
                        nom: o_avant.nom.clone(),
                        description_avant: o_avant.description.clone(),
                        description_apres: o_apres.description.clone(),
                        input_schema_avant: o_avant.input_schema.clone(),
                        input_schema_apres: o_apres.input_schema.clone(),
                    })
                } else {
                    None
                }
            })
        })
        .collect();
    outils_modifies.sort_by(|a, b| a.nom.cmp(&b.nom));

    let a_change =
        !outils_ajoutes.is_empty() || !outils_supprimes.is_empty() || !outils_modifies.is_empty();

    let markdown = construire_markdown(a_change, &outils_ajoutes, &outils_supprimes, &outils_modifies);
    let texte_brut = construire_texte_brut(a_change, &outils_ajoutes, &outils_supprimes, &outils_modifies);

    RenduDiff {
        markdown,
        texte_brut,
        a_change,
        outils_ajoutes,
        outils_supprimes,
        outils_modifies,
    }
}

/// Retourne le rendu Markdown d'un [`RenduDiff`] déjà calculé.
///
/// Expose le rendu séparément pour permettre un re-rendu sans recalcul.
pub fn rendu_markdown(d: &RenduDiff) -> String {
    d.markdown.clone()
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction du rendu
// ─────────────────────────────────────────────────────────────────────────────

fn construire_markdown(
    a_change: bool,
    ajoutes: &[String],
    supprimes: &[String],
    modifies: &[DiffOutil],
) -> String {
    if !a_change {
        return "Aucun changement détecté.".to_string();
    }

    let mut out = String::new();
    out.push_str("## Diff outils MCP\n\n");

    if !ajoutes.is_empty() {
        out.push_str("### Ajouts\n\n");
        for nom in ajoutes {
            out.push_str(&format!("- `{nom}` — outil ajouté\n"));
        }
        out.push('\n');
    }

    if !supprimes.is_empty() {
        out.push_str("### Suppressions\n\n");
        for nom in supprimes {
            out.push_str(&format!("- `{nom}` — outil supprimé\n"));
        }
        out.push('\n');
    }

    if !modifies.is_empty() {
        out.push_str("### Modifications\n\n");
        for diff in modifies {
            out.push_str(&format!("#### `{}`\n\n", diff.nom));

            // Diff de description
            if diff.description_avant != diff.description_apres {
                out.push_str("**Description**\n\n");
                let avant_str = diff.description_avant.as_deref().unwrap_or("(vide)");
                let apres_str = diff.description_apres.as_deref().unwrap_or("(vide)");
                out.push_str(&diff_texte_inline(avant_str, apres_str));
                out.push('\n');
            }

            // Diff de schema
            let avant_json = schema_canonique_pretty(&diff.input_schema_avant);
            let apres_json = schema_canonique_pretty(&diff.input_schema_apres);
            if avant_json != apres_json {
                out.push_str("**inputSchema**\n\n```diff\n");
                out.push_str(&diff_texte_unified(&avant_json, &apres_json));
                out.push_str("```\n\n");
            }
        }
    }

    out
}

fn construire_texte_brut(
    a_change: bool,
    ajoutes: &[String],
    supprimes: &[String],
    modifies: &[DiffOutil],
) -> String {
    if !a_change {
        return "Aucun changement détecté.".to_string();
    }

    let mut out = String::new();
    out.push_str("DIFF OUTILS MCP\n");
    out.push_str(&"=".repeat(40));
    out.push('\n');

    if !ajoutes.is_empty() {
        out.push_str("\nAJOUTS\n");
        for nom in ajoutes {
            out.push_str(&format!("  + {nom}\n"));
        }
    }

    if !supprimes.is_empty() {
        out.push_str("\nSUPPRESSIONS\n");
        for nom in supprimes {
            out.push_str(&format!("  - {nom}\n"));
        }
    }

    if !modifies.is_empty() {
        out.push_str("\nMODIFICATIONS\n");
        for diff in modifies {
            out.push_str(&format!("  ~ {}\n", diff.nom));
            if diff.description_avant != diff.description_apres {
                let avant = diff.description_avant.as_deref().unwrap_or("(vide)");
                let apres = diff.description_apres.as_deref().unwrap_or("(vide)");
                out.push_str(&format!("    description: {avant:?} -> {apres:?}\n"));
            }
            let avant_json = schema_canonique_pretty(&diff.input_schema_avant);
            let apres_json = schema_canonique_pretty(&diff.input_schema_apres);
            if avant_json != apres_json {
                out.push_str("    inputSchema modifié\n");
            }
        }
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers diff texte (via crate `similar`)
// ─────────────────────────────────────────────────────────────────────────────

/// Diff inline ligne à ligne pour la description (Markdown).
fn diff_texte_inline(avant: &str, apres: &str) -> String {
    let mut out = String::new();
    let diff = TextDiff::from_lines(avant, apres);
    for change in diff.iter_all_changes() {
        match change.tag() {
            ChangeTag::Delete => out.push_str(&format!("~~{}~~", change.value().trim_end())),
            ChangeTag::Insert => out.push_str(&format!("**{}**", change.value().trim_end())),
            ChangeTag::Equal => out.push_str(change.value().trim_end()),
        }
        out.push(' ');
    }
    out.trim_end().to_string() + "\n"
}

/// Diff unifié pour l'inputSchema (intérieur d'un bloc ```diff```).
fn diff_texte_unified(avant: &str, apres: &str) -> String {
    let mut out = String::new();
    let diff = TextDiff::from_lines(avant, apres);
    for change in diff.iter_all_changes() {
        let signe = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        out.push_str(&format!("{}{}", signe, change.value()));
        // S'assurer qu'on termine par un saut de ligne
        if !change.value().ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Canonicalisation JSON (clés triées récursivement)
// ─────────────────────────────────────────────────────────────────────────────

/// Sérialise la valeur JSON avec les clés d'objet triées, sur une ligne.
/// Utilisée pour la comparaison (insensible à l'ordre des clés).
fn schema_canonique(val: &serde_json::Value) -> String {
    serde_json::to_string(&trier_valeur(val)).unwrap_or_default()
}

/// Idem mais indenté à 2 espaces, pour le rendu diff.
fn schema_canonique_pretty(val: &serde_json::Value) -> String {
    serde_json::to_string_pretty(&trier_valeur(val)).unwrap_or_default()
}

/// Trie récursivement les clés de tous les objets JSON.
fn trier_valeur(val: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match val {
        Value::Object(map) => {
            let mut btree: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
            for (k, v) in map {
                btree.insert(k.clone(), trier_valeur(v));
            }
            Value::Object(btree.into_iter().collect())
        }
        Value::Array(arr) => Value::Array(arr.iter().map(trier_valeur).collect()),
        other => other.clone(),
    }
}
