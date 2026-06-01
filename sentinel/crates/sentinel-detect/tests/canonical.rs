//! Tests de la canonicalisation JSON — agent 3.1.
//!
//! Garantit l'absence de faux positifs liés à un réordonnancement de champs.

use sentinel_detect::canonical::{canonicaliser_json, canonicaliser_json_bytes, canonicaliser_outils};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// 1. Réordonnancement de clés au premier niveau → même canonical string
// ---------------------------------------------------------------------------
#[test]
fn test_reordonnancement_cles_premier_niveau() {
    let a = json!({"z": 1, "a": 2, "m": 3});
    let b = json!({"m": 3, "z": 1, "a": 2});
    assert_eq!(
        canonicaliser_json(&a),
        canonicaliser_json(&b),
        "deux objets avec les mêmes clés/valeurs mais dans un ordre différent doivent produire la même empreinte"
    );
    // Vérifie que l'ordre canonique est bien "a" < "m" < "z".
    assert_eq!(canonicaliser_json(&a), r#"{"a":2,"m":3,"z":1}"#);
}

// ---------------------------------------------------------------------------
// 2. Imbrication profonde (3 niveaux) → tri à chaque niveau
// ---------------------------------------------------------------------------
#[test]
fn test_imbrication_profonde_trois_niveaux() {
    let a = json!({
        "z": {"y": {"c": 1, "a": 2}, "b": 3},
        "a": {"x": {"z": 99, "a": 0}}
    });
    let b = json!({
        "a": {"x": {"a": 0, "z": 99}},
        "z": {"b": 3, "y": {"a": 2, "c": 1}}
    });
    assert_eq!(
        canonicaliser_json(&a),
        canonicaliser_json(&b),
        "le tri doit être récursif sur tous les niveaux d'imbrication"
    );
    // Forme attendue : clés triées à chaque niveau.
    let attendu = r#"{"a":{"x":{"a":0,"z":99}},"z":{"b":3,"y":{"a":2,"c":1}}}"#;
    assert_eq!(canonicaliser_json(&a), attendu);
}

// ---------------------------------------------------------------------------
// 3. Tableaux : ordre d'origine préservé
// ---------------------------------------------------------------------------
#[test]
fn test_tableaux_ordre_preserve() {
    let v = json!([3, 1, 2]);
    assert_eq!(
        canonicaliser_json(&v),
        "[3,1,2]",
        "les tableaux ne doivent pas être triés"
    );
}

#[test]
fn test_tableau_objets_ordre_preserve() {
    // Dans un tableau d'objets ordinaire (hors `canonicaliser_outils`),
    // l'ordre des éléments est préservé même si les clés internes sont triées.
    let v = json!([{"b": 2, "a": 1}, {"d": 4, "c": 3}]);
    assert_eq!(
        canonicaliser_json(&v),
        r#"[{"a":1,"b":2},{"c":3,"d":4}]"#
    );
}

// ---------------------------------------------------------------------------
// 4. canonicaliser_outils trie par champ `name`
// ---------------------------------------------------------------------------
#[test]
fn test_canonicaliser_outils_tri_par_name() {
    let outils = json!([
        {"name": "zap", "description": "outil z"},
        {"name": "alpha", "description": "outil a"},
        {"name": "beta", "description": "outil b"}
    ]);
    let canonique = canonicaliser_outils(&outils);
    // L'ordre canonique doit être alpha, beta, zap.
    let attendu = r#"[{"description":"outil a","name":"alpha"},{"description":"outil b","name":"beta"},{"description":"outil z","name":"zap"}]"#;
    assert_eq!(canonique, attendu);
}

#[test]
fn test_canonicaliser_outils_sans_name_en_fin() {
    let outils = json!([
        {"name": "z-outil"},
        {"description": "sans nom"},
        {"name": "a-outil"}
    ]);
    let canonique = canonicaliser_outils(&outils);
    // a-outil avant z-outil, sans-nom en fin.
    let attendu = r#"[{"name":"a-outil"},{"name":"z-outil"},{"description":"sans nom"}]"#;
    assert_eq!(canonique, attendu);
}

// ---------------------------------------------------------------------------
// 5. Nombres : politique de préservation du type JSON
// ---------------------------------------------------------------------------
#[test]
fn test_nombre_entier_sans_decimal() {
    let v = json!(1);
    assert_eq!(canonicaliser_json(&v), "1");
}

#[test]
fn test_nombre_flottant_avec_decimal() {
    // serde_json::json!(1.0) sérialise en "1.0" — on préserve ce comportement.
    let v: Value = serde_json::from_str("1.0").unwrap();
    assert_eq!(canonicaliser_json(&v), "1.0");
}

#[test]
fn test_entier_et_flottant_distincts() {
    // 1 (entier) et 1.0 (flottant) sont des représentations différentes :
    // la canonicalisation les préserve sans normalisation arithmétique.
    let entier: Value = serde_json::from_str("1").unwrap();
    let flottant: Value = serde_json::from_str("1.0").unwrap();
    assert_eq!(canonicaliser_json(&entier), "1");
    assert_eq!(canonicaliser_json(&flottant), "1.0");
}

// ---------------------------------------------------------------------------
// 6. Caractères Unicode dans les clés → tri lexico UTF-8
// ---------------------------------------------------------------------------
#[test]
fn test_cles_unicode_tri_lexico_utf8() {
    // Point de code : 'a' (U+0061) < 'é' (U+00E9) < '中' (U+4E2D)
    let a = json!({"中": 3, "é": 2, "a": 1});
    let b = json!({"a": 1, "中": 3, "é": 2});
    assert_eq!(canonicaliser_json(&a), canonicaliser_json(&b));
    assert_eq!(canonicaliser_json(&a), r#"{"a":1,"é":2,"中":3}"#);
}

// ---------------------------------------------------------------------------
// 7. Valeurs scalaires : null, true, false
// ---------------------------------------------------------------------------
#[test]
fn test_scalaires_null_bool() {
    assert_eq!(canonicaliser_json(&Value::Null), "null");
    assert_eq!(canonicaliser_json(&Value::Bool(true)), "true");
    assert_eq!(canonicaliser_json(&Value::Bool(false)), "false");
}

#[test]
fn test_objet_avec_scalaires_mixtes() {
    let v = json!({"actif": true, "valeur": null, "score": false});
    assert_eq!(
        canonicaliser_json(&v),
        r#"{"actif":true,"score":false,"valeur":null}"#
    );
}

// ---------------------------------------------------------------------------
// 8. SHA-256 sur la forme canonique d'une réorganisation → mêmes bytes
// ---------------------------------------------------------------------------
#[test]
fn test_sha256_invariant_par_reordonnancement() {
    let original = json!({
        "inputSchema": {"type": "object", "properties": {"z": {}, "a": {}}},
        "name": "mon_outil",
        "description": "fait quelque chose"
    });
    let reorganise = json!({
        "description": "fait quelque chose",
        "name": "mon_outil",
        "inputSchema": {"properties": {"a": {}, "z": {}}, "type": "object"}
    });

    let hash_original = {
        let mut hasher = Sha256::new();
        hasher.update(canonicaliser_json_bytes(&original));
        hasher.finalize()
    };
    let hash_reorganise = {
        let mut hasher = Sha256::new();
        hasher.update(canonicaliser_json_bytes(&reorganise));
        hasher.finalize()
    };

    assert_eq!(
        hash_original, hash_reorganise,
        "le SHA-256 doit être identique quel que soit l'ordre des champs JSON"
    );
}

// ---------------------------------------------------------------------------
// 9. Canonicaliser_json_bytes retourne les bytes UTF-8 de la forme canonique
// ---------------------------------------------------------------------------
#[test]
fn test_canonicaliser_json_bytes_coherence() {
    let v = json!({"b": 1, "a": 2});
    let chaine = canonicaliser_json(&v);
    let bytes = canonicaliser_json_bytes(&v);
    assert_eq!(chaine.as_bytes(), bytes.as_slice());
}

// ---------------------------------------------------------------------------
// 10. Chaîne vide et objet vide
// ---------------------------------------------------------------------------
#[test]
fn test_objet_vide() {
    let v = json!({});
    assert_eq!(canonicaliser_json(&v), "{}");
}

#[test]
fn test_tableau_vide() {
    let v = json!([]);
    assert_eq!(canonicaliser_json(&v), "[]");
}

// ---------------------------------------------------------------------------
// 11. Objet imbriqué dans un tableau (cas inputSchema réel)
// ---------------------------------------------------------------------------
#[test]
fn test_input_schema_reel() {
    // Simule un inputSchema typique d'un outil MCP.
    let schema_a = json!({
        "type": "object",
        "required": ["repo", "path"],
        "properties": {
            "repo": {"type": "string", "description": "dépôt git"},
            "path": {"type": "string", "description": "chemin"}
        }
    });
    let schema_b = json!({
        "required": ["repo", "path"],
        "properties": {
            "path": {"description": "chemin", "type": "string"},
            "repo": {"description": "dépôt git", "type": "string"}
        },
        "type": "object"
    });
    assert_eq!(
        canonicaliser_json(&schema_a),
        canonicaliser_json(&schema_b),
        "inputSchema réordonné doit produire la même empreinte"
    );
}
