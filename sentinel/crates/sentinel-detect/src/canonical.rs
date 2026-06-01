//! Lead empreinte canonique — agent 3.1.
//!
//! Point technique le plus important du produit : toute empreinte passe
//! par la sérialisation JSON canonique (clés et tableaux ordonnés de
//! façon déterministe) avant tout hash.
//!
//! ## Règles de canonicalisation
//!
//! 1. **Objets** : clés triées lexicographiquement (ordre UTF-8 des points de code).
//!    Récursif à chaque niveau d'imbrication.
//! 2. **Tableaux** : ordre d'origine préservé (sémantique de tableau MCP).
//!    Exception : `canonicaliser_outils` trie les éléments par champ `name`.
//! 3. **Encodage** : UTF-8, sans espaces inutiles (compact), conforme RFC 8259.
//! 4. **Nombres** : type JSON préservé tel que transmis par `serde_json`
//!    (`1` reste `1`, `1.0` reste `1.0`). Aucune normalisation arithmétique.
//! 5. **Null / bool** : représentation canonique `null`, `true`, `false`.
//!
//! ## Coordination inter-agents
//!
//! - Agent 3.2 (empreinte outil/serveur) consomme `canonicaliser_json_bytes`.
//! - Agent 2.2 (baselines) utilise `canonicaliser_json` pour l'égalité stricte.
//! - Agents 3.3, 3.4, 3.10 se réfèrent à ce module comme référence d'empreinte.

use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Sérialise un `Value` JSON en chaîne canonique :
/// - clés d'objets triées lexicographiquement (ordre UTF-8),
/// - tableaux préservés dans l'ordre d'origine (sémantique de tableau),
/// - encodage UTF-8 stable, sans espaces inutiles,
/// - nombres formatés de façon stable (entiers sans décimal, flottants en notation standard).
pub fn canonicaliser_json(v: &Value) -> String {
    // SAFETY : serde_json::to_string sur un Value reconstruit ne peut pas échouer.
    serde_json::to_string(&normaliser(v)).expect("sérialisation canonique infaillible")
}

/// Variante qui retourne directement les bytes (pour SHA-256 direct).
pub fn canonicaliser_json_bytes(v: &Value) -> Vec<u8> {
    canonicaliser_json(v).into_bytes()
}

/// Canonicalisation d'un tableau d'objets en triant les éléments par clé `name` (cas `tools`).
/// Si certains éléments n'ont pas de `name`, ils sont laissés en fin dans leur ordre relatif.
///
/// Le tri est stable : les éléments sans `name` conservent leur ordre relatif entre eux.
/// À l'intérieur de chaque élément, les clés d'objet sont triées comme dans `canonicaliser_json`.
pub fn canonicaliser_outils(outils: &Value) -> String {
    match outils {
        Value::Array(arr) => {
            // Partition : éléments avec `name` d'abord, sans `name` en fin.
            let mut avec_nom: Vec<(String, Value)> = Vec::new();
            let mut sans_nom: Vec<Value> = Vec::new();

            for element in arr {
                match extraire_nom(element) {
                    Some(nom) => avec_nom.push((nom, element.clone())),
                    None => sans_nom.push(element.clone()),
                }
            }

            // Tri stable par nom (lexicographique UTF-8).
            avec_nom.sort_by(|(a, _), (b, _)| a.cmp(b));

            let mut resultat: Vec<Value> = avec_nom.into_iter().map(|(_, v)| v).collect();
            resultat.extend(sans_nom);

            let tableau_trie = Value::Array(resultat);
            canonicaliser_json(&tableau_trie)
        }
        // Si ce n'est pas un tableau, canonicalisation standard.
        autre => canonicaliser_json(autre),
    }
}

// ---------------------------------------------------------------------------
// Fonctions internes
// ---------------------------------------------------------------------------

/// Reconstruit récursivement un `Value` avec les objets dont les clés sont triées.
fn normaliser(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            // Collecte dans un BTreeMap pour tri lexicographique automatique.
            let trie: BTreeMap<&str, Value> =
                map.iter().map(|(k, val)| (k.as_str(), normaliser(val))).collect();

            // Reconstruit un Map serde_json dans l'ordre du BTreeMap.
            let mut map_ordonnee = Map::with_capacity(trie.len());
            for (k, val) in trie {
                map_ordonnee.insert(k.to_owned(), val);
            }
            Value::Object(map_ordonnee)
        }
        Value::Array(arr) => {
            // Ordre préservé, récursion sur les éléments.
            Value::Array(arr.iter().map(normaliser).collect())
        }
        // Scalaires : copie directe (nombres, chaînes, bool, null).
        scalaire => scalaire.clone(),
    }
}

/// Extrait la valeur du champ `name` d'un élément JSON (objet uniquement).
fn extraire_nom(element: &Value) -> Option<String> {
    element
        .as_object()
        .and_then(|obj| obj.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_owned())
}
