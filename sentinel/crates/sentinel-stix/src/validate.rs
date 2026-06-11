//! Field-level STIX 2.1 conformance validation.
//!
//! Checks, for every object type Sentinel emits, the required fields
//! mandated by the OASIS STIX 2.1 specification:
//!
//! - `type` / `spec_version == "2.1"` / `id` au format `<type>--<uuid>`;
//! - horodatages RFC 3339 stricts (suffixe `Z` obligatoire — la spec
//!   interdit la forme `+00:00`);
//! - champs requis par type (`pattern`/`pattern_type`/`valid_from` pour
//!   `indicator`, `object_refs` non vide pour `observed-data`, etc.).
//!
//! [`validate_bundle_value`] retourne la liste complète des violations
//! (vide = conforme) plutôt que de s'arrêter à la première.

use serde_json::Value;
use uuid::Uuid;

/// True when `s` is a STIX 2.1 timestamp: strict RFC 3339, UTC, `Z` suffix.
pub fn is_stix_timestamp(s: &str) -> bool {
    if !s.ends_with('Z') {
        return false;
    }
    chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

/// True when `id` matches `<object_type>--<uuid>`.
pub fn is_stix_id(id: &str, object_type: &str) -> bool {
    match id.strip_prefix(&format!("{object_type}--")) {
        Some(rest) => Uuid::parse_str(rest).is_ok(),
        None => false,
    }
}

fn str_field<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    obj.get(key).and_then(Value::as_str)
}

fn check_required_str(obj: &Value, key: &str, errs: &mut Vec<String>, ctx: &str) {
    match str_field(obj, key) {
        Some(v) if !v.is_empty() => {}
        _ => errs.push(format!("{ctx}: champ requis manquant ou vide: {key}")),
    }
}

fn check_timestamp(obj: &Value, key: &str, required: bool, errs: &mut Vec<String>, ctx: &str) {
    match str_field(obj, key) {
        Some(v) => {
            if !is_stix_timestamp(v) {
                errs.push(format!(
                    "{ctx}: {key} n'est pas un horodatage STIX 2.1 (RFC 3339 strict, suffixe Z): {v}"
                ));
            }
        }
        None if required => errs.push(format!("{ctx}: horodatage requis manquant: {key}")),
        None => {}
    }
}

fn check_ref_list(obj: &Value, key: &str, min_items: usize, errs: &mut Vec<String>, ctx: &str) {
    match obj.get(key).and_then(Value::as_array) {
        Some(items) => {
            if items.len() < min_items {
                errs.push(format!(
                    "{ctx}: {key} doit contenir au moins {min_items} élément(s)"
                ));
            }
            for it in items {
                match it.as_str() {
                    Some(r) if r.split_once("--").map(|(_, u)| Uuid::parse_str(u).is_ok())
                        == Some(true) => {}
                    _ => errs.push(format!("{ctx}: {key} contient une référence invalide: {it}")),
                }
            }
        }
        None if min_items > 0 => errs.push(format!("{ctx}: liste requise manquante: {key}")),
        None => {}
    }
}

/// Validates a single STIX object (as JSON). Returns every violation found.
pub fn validate_object(obj: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    let t = match str_field(obj, "type") {
        Some(t) => t.to_string(),
        None => {
            errs.push("objet sans champ `type`".to_string());
            return errs;
        }
    };
    let id = str_field(obj, "id").unwrap_or("<sans id>");
    let ctx = format!("{t} ({id})");

    if !is_stix_id(id, &t) {
        errs.push(format!("{ctx}: id invalide (attendu `{t}--<uuid>`)"));
    }
    match str_field(obj, "spec_version") {
        Some("2.1") => {}
        Some(v) => errs.push(format!("{ctx}: spec_version doit être \"2.1\", trouvé \"{v}\"")),
        None => errs.push(format!("{ctx}: spec_version manquant")),
    }

    // SDO/SRO common timestamps (SCOs like `software` don't carry them).
    let has_common_ts = t != "software";
    if has_common_ts {
        check_timestamp(obj, "created", true, &mut errs, &ctx);
        check_timestamp(obj, "modified", true, &mut errs, &ctx);
    }

    match t.as_str() {
        "indicator" => {
            check_required_str(obj, "pattern", &mut errs, &ctx);
            check_required_str(obj, "pattern_type", &mut errs, &ctx);
            check_timestamp(obj, "valid_from", true, &mut errs, &ctx);
            check_timestamp(obj, "valid_until", false, &mut errs, &ctx);
        }
        "observed-data" => {
            check_timestamp(obj, "first_observed", true, &mut errs, &ctx);
            check_timestamp(obj, "last_observed", true, &mut errs, &ctx);
            match obj.get("number_observed").and_then(Value::as_u64) {
                Some(n) if (1..=999_999_999).contains(&n) => {}
                _ => errs.push(format!(
                    "{ctx}: number_observed requis et compris entre 1 et 999999999"
                )),
            }
            check_ref_list(obj, "object_refs", 1, &mut errs, &ctx);
        }
        "software" => {
            check_required_str(obj, "name", &mut errs, &ctx);
        }
        "infrastructure" => {
            check_required_str(obj, "name", &mut errs, &ctx);
        }
        "identity" => {
            check_required_str(obj, "name", &mut errs, &ctx);
        }
        "relationship" => {
            check_required_str(obj, "relationship_type", &mut errs, &ctx);
            check_required_str(obj, "source_ref", &mut errs, &ctx);
            check_required_str(obj, "target_ref", &mut errs, &ctx);
        }
        "sighting" => {
            check_required_str(obj, "sighting_of_ref", &mut errs, &ctx);
            check_timestamp(obj, "first_seen", false, &mut errs, &ctx);
            check_timestamp(obj, "last_seen", false, &mut errs, &ctx);
            check_ref_list(obj, "observed_data_refs", 0, &mut errs, &ctx);
            check_ref_list(obj, "where_sighted_refs", 0, &mut errs, &ctx);
        }
        other => errs.push(format!("{ctx}: type STIX non géré par Sentinel: {other}")),
    }

    errs
}

/// Validates a whole bundle (as JSON). Returns every violation found.
pub fn validate_bundle_value(bundle: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    match str_field(bundle, "type") {
        Some("bundle") => {}
        _ => errs.push("bundle: champ `type` doit valoir \"bundle\"".to_string()),
    }
    match str_field(bundle, "id") {
        Some(id) if is_stix_id(id, "bundle") => {}
        _ => errs.push("bundle: id invalide (attendu `bundle--<uuid>`)".to_string()),
    }
    match bundle.get("objects").and_then(Value::as_array) {
        Some(objects) => {
            for o in objects {
                errs.extend(validate_object(o));
            }
        }
        None => errs.push("bundle: tableau `objects` manquant".to_string()),
    }
    errs
}
