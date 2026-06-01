//! Empreinte par outil et par serveur — agent 3.2.
//!
//! SHA-256 (hex lowercase) calculé sur la sérialisation canonique produite
//! par l'agent 3.1. Si `canonicaliser_json` renvoie une chaîne vide
//! (placeholder), le fallback sérialise via `BTreeMap` pour garantir
//! le déterminisme.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use sentinel_protocol::{Empreinte, Outil};

use crate::canonical::canonicaliser_json;

// --------------------------------------------------------------------------
// Helpers internes
// --------------------------------------------------------------------------

/// Convertit un `Outil` en `Value` avec la même structure que sa sérialisation
/// Serde, de façon à inclure `inputSchema` et `meta` dans l'empreinte.
fn outil_en_valeur(o: &Outil) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("nom".into(), Value::String(o.nom.clone()));
    obj.insert(
        "description".into(),
        match &o.description {
            Some(d) => Value::String(d.clone()),
            None => Value::Null,
        },
    );
    obj.insert("input_schema".into(), o.input_schema.clone());

    // meta : BTreeMap déjà ordonné → tableau de paires pour canonicalité stable
    let meta_val: serde_json::Map<String, Value> = o
        .meta
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    obj.insert("meta".into(), Value::Object(meta_val));

    Value::Object(obj)
}

/// Produit la représentation canonique d'une `Value`.
///
/// Utilise `canonicaliser_json` de l'agent 3.1 ; si elle renvoie une chaîne
/// vide (placeholder), fallback sur une sérialisation BTreeMap récursive.
fn canonique(v: &Value) -> String {
    let s = canonicaliser_json(v);
    if !s.is_empty() {
        return s;
    }
    // Fallback déterministe : trier les clés récursivement via BTreeMap.
    canonique_fallback(v)
}

fn canonique_fallback(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let ordered: BTreeMap<&str, &Value> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            let mut s = String::from("{");
            let mut premier = true;
            for (k, val) in &ordered {
                if !premier {
                    s.push(',');
                }
                premier = false;
                s.push('"');
                s.push_str(k);
                s.push_str("\":");
                s.push_str(&canonique_fallback(val));
            }
            s.push('}');
            s
        }
        Value::Array(arr) => {
            let mut s = String::from("[");
            let mut premier = true;
            for val in arr {
                if !premier {
                    s.push(',');
                }
                premier = false;
                s.push_str(&canonique_fallback(val));
            }
            s.push(']');
            s
        }
        // Délègue le reste à serde_json (null, bool, number, string).
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

/// Calcule le SHA-256 hex d'une chaîne UTF-8.
fn sha256_hex(data: &str) -> Empreinte {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    Empreinte::new(hex::encode(hasher.finalize()))
}

// --------------------------------------------------------------------------
// API publique
// --------------------------------------------------------------------------

/// SHA-256 hex (lowercase, 64 chars) de la canonicalisation d'un seul outil.
/// L'`inputSchema` complet est inclus dans l'empreinte.
pub fn empreinte_outil(o: &Outil) -> Empreinte {
    let val = outil_en_valeur(o);
    let canon = canonique(&val);
    sha256_hex(&canon)
}

/// SHA-256 hex global, calculé sur le tableau d'outils trié par `nom`.
/// Deux tableaux avec les mêmes outils dans un ordre différent produisent
/// la même empreinte.
pub fn empreinte_serveur(outils: &[Outil]) -> Empreinte {
    let mut tries: Vec<&Outil> = outils.iter().collect();
    tries.sort_by(|a, b| a.nom.cmp(&b.nom));

    let tableau: Value = Value::Array(tries.iter().map(|o| outil_en_valeur(o)).collect());
    let canon = canonique(&tableau);
    sha256_hex(&canon)
}

/// Empreintes individuelles sous forme de `BTreeMap nom → empreinte`.
pub fn empreintes_par_outil(outils: &[Outil]) -> BTreeMap<String, Empreinte> {
    outils
        .iter()
        .map(|o| (o.nom.clone(), empreinte_outil(o)))
        .collect()
}
