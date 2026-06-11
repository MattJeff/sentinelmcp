//! Integration test: validate every object inside a bundle produced by
//! `sentinel_stix::export_bundle` against an embedded subset of the official
//! OASIS STIX 2.1 JSON Schemas.
//!
//! The schemas live in `tests/data/stix-2.1-schemas/` (see
//! `LICENSE-STIX-SCHEMAS.md` in that folder for attribution). They are a
//! self-contained re-extraction of the OASIS schemas, simplified by inlining
//! all cross-file `$ref`s so the test stays fully offline.
//!
//! Three tests live here:
//!
//! 1. [`bundle_validates_against_stix_2_1_schemas`] — happy path: build a
//!    store with one server, one high-severity finding, one threat-intel
//!    indicator (pulled from the bundled feed), run `export_bundle`, walk
//!    every object and validate against its per-type schema. Fails with a
//!    pretty list of every violation across all objects.
//!
//! 2. [`negative_malformed_indicator_id_rejected`] — takes the same bundle
//!    and corrupts one indicator's `id` from `indicator--<uuid>` to
//!    `indicator-<uuid>` (single dash). Asserts validation fails and that
//!    the error message points at the `id` field.
//!
//! 3. [`negative_wrong_spec_version_rejected`] — flips one object's
//!    `spec_version` from `"2.1"` to `"2.0"` and asserts rejection.

use chrono::Utc;
use jsonschema::{Draft, JSONSchema};
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Portee, Serveur, Severite, StatutServeur, Transport, TypeConstat,
};
use sentinel_store::Store;
use serde_json::{json, Value};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn schemas_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("data");
    p.push("stix-2.1-schemas");
    p
}

fn load_schema(name: &str) -> Value {
    let path: PathBuf = schemas_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read schema {}: {e}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("schema {} is not valid JSON: {e}", path.display()))
}

fn compile(schema: &Value) -> JSONSchema {
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .expect("schema must compile")
}

/// Runs every object in `bundle.objects` against its per-type schema.
/// Collects (object_index, object_type, object_id, error_path, error_msg)
/// for every failure and returns them.
#[derive(Debug)]
struct Violation {
    index: usize,
    object_type: String,
    object_id: String,
    instance_path: String,
    schema_path: String,
    message: String,
}

fn validate_bundle_objects(bundle: &Value) -> Vec<Violation> {
    let mut violations = Vec::new();

    // Compile each per-type schema once.
    let indicator = compile(&load_schema("indicator.json"));
    let observed_data = compile(&load_schema("observed-data.json"));
    let software = compile(&load_schema("software.json"));
    let infrastructure = compile(&load_schema("infrastructure.json"));
    let relationship = compile(&load_schema("relationship.json"));

    let objects = bundle
        .get("objects")
        .and_then(Value::as_array)
        .expect("bundle must have an objects array");

    for (idx, obj) in objects.iter().enumerate() {
        let t = obj
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
            .to_string();
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("<missing>")
            .to_string();

        let compiled = match t.as_str() {
            "indicator" => &indicator,
            "observed-data" => &observed_data,
            "software" => &software,
            "infrastructure" => &infrastructure,
            "relationship" => &relationship,
            other => panic!(
                "bundle contains an object of unknown STIX type '{}' at index {}; \
                 either the test schemas need extending or `export_bundle` is producing unexpected types",
                other, idx
            ),
        };

        if let Err(errs) = compiled.validate(obj) {
            for e in errs {
                violations.push(Violation {
                    index: idx,
                    object_type: t.clone(),
                    object_id: id.clone(),
                    instance_path: e.instance_path.to_string(),
                    schema_path: e.schema_path.to_string(),
                    message: e.to_string(),
                });
            }
        }
    }

    violations
}

fn render_violations(violations: &[Violation]) -> String {
    let mut s = format!("{} schema violation(s):\n", violations.len());
    for v in violations {
        s.push_str(&format!(
            "  - object #{idx} ({ty}, id={id}): {msg}\n      \
             instance_path: {ipath}\n      schema_path:   {spath}\n",
            idx = v.index,
            ty = v.object_type,
            id = v.object_id,
            msg = v.message,
            ipath = v.instance_path,
            spath = v.schema_path,
        ));
    }
    s
}

/// Build an in-memory store seeded with:
///   - 1 MCP server (will produce 1 software SCO + 1 infrastructure SDO)
///   - 1 Haute-severity finding (will produce 1 observed-data SDO)
///
/// Indicators are added by `export_bundle` from the bundled threat-intel feed,
/// so we don't need to seed them here.
fn seed_store() -> Store {
    let store = Store::in_memory().expect("in-memory store must open");

    let serveur_id = Uuid::new_v4();
    let serveur = Serveur {
        id: serveur_id,
        endpoint: "@modelcontextprotocol/server-filesystem".to_string(),
        transport: Transport::Stdio,
        portees: vec![Portee::Filesystem, Portee::Lecture],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: Some("abc123".to_string()),
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    };
    store.upsert_serveur(&serveur).expect("upsert serveur");

    let constat = Constat {
        id: Uuid::new_v4(),
        serveur_id,
        outil_nom: Some("read_file".to_string()),
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Haute,
        titre: "Shadow MCP detected".to_string(),
        detail: "An unapproved MCP server was contacted during a session.".to_string(),
        diff: None,
        references_conformite: vec!["OWASP-MCP09".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    };
    store.enregistrer_constat(&constat).expect("enregistrer constat");

    store
}

fn build_bundle_value() -> Value {
    let store = seed_store();
    let bundle = sentinel_stix::export_bundle(&store).expect("export_bundle must succeed");
    serde_json::to_value(&bundle).expect("bundle must serialise to JSON")
}

// ---------------------------------------------------------------------------
// Positive test
// ---------------------------------------------------------------------------

#[test]
fn bundle_validates_against_stix_2_1_schemas() {
    let bundle = build_bundle_value();

    // 1) Envelope: bundle itself must validate against bundle.json.
    let bundle_schema = compile(&load_schema("bundle.json"));
    if let Err(errs) = bundle_schema.validate(&bundle) {
        let msgs: Vec<String> = errs
            .map(|e| format!("  - {} @ {}", e, e.instance_path))
            .collect();
        panic!(
            "bundle envelope does not validate against bundle.json:\n{}",
            msgs.join("\n")
        );
    }

    // 2) Per-object validation.
    let violations = validate_bundle_objects(&bundle);
    assert!(
        violations.is_empty(),
        "bundle objects failed STIX 2.1 schema validation:\n{}",
        render_violations(&violations)
    );

    // Sanity: ensure we actually got at least one object of each expected type.
    let objects = bundle["objects"].as_array().unwrap();
    let have_indicator = objects.iter().any(|o| o["type"] == "indicator");
    let have_observed = objects.iter().any(|o| o["type"] == "observed-data");
    let have_software = objects.iter().any(|o| o["type"] == "software");
    let have_infra = objects.iter().any(|o| o["type"] == "infrastructure");
    assert!(have_indicator, "expected at least one indicator in bundle");
    assert!(have_observed, "expected at least one observed-data in bundle");
    assert!(have_software, "expected at least one software in bundle");
    assert!(have_infra, "expected at least one infrastructure in bundle");
}

// ---------------------------------------------------------------------------
// Negative tests
// ---------------------------------------------------------------------------

#[test]
fn negative_malformed_indicator_id_rejected() {
    let mut bundle = build_bundle_value();

    // Find the first indicator and corrupt its id by removing one of the two dashes.
    let objects = bundle["objects"].as_array_mut().unwrap();
    let mut corrupted = false;
    for obj in objects.iter_mut() {
        if obj["type"] == "indicator" {
            let id = obj["id"].as_str().unwrap().to_string();
            // "indicator--<uuid>" → "indicator-<uuid>" (single dash instead of double)
            let bad = id.replacen("--", "-", 1);
            obj["id"] = json!(bad);
            corrupted = true;
            break;
        }
    }
    assert!(corrupted, "test fixture must contain at least one indicator");

    let violations = validate_bundle_objects(&bundle);
    assert!(
        !violations.is_empty(),
        "expected schema validation to reject malformed indicator id, but bundle validated cleanly"
    );

    // At least one violation must point at /id.
    let has_id_violation = violations.iter().any(|v| {
        v.object_type == "indicator"
            && (v.instance_path.contains("/id") || v.schema_path.contains("/id"))
    });
    assert!(
        has_id_violation,
        "expected at least one violation to point at indicator /id, got:\n{}",
        render_violations(&violations)
    );
}

#[test]
fn negative_wrong_spec_version_rejected() {
    let mut bundle = build_bundle_value();

    // Flip the first object's spec_version from "2.1" to "2.0".
    let objects = bundle["objects"].as_array_mut().unwrap();
    let mut target_type: Option<String> = None;
    for obj in objects.iter_mut() {
        if obj.get("spec_version").is_some() {
            obj["spec_version"] = json!("2.0");
            target_type = obj["type"].as_str().map(|s| s.to_string());
            break;
        }
    }
    assert!(
        target_type.is_some(),
        "test fixture must contain at least one object with a spec_version field"
    );

    let violations = validate_bundle_objects(&bundle);
    assert!(
        !violations.is_empty(),
        "expected schema validation to reject wrong spec_version, but bundle validated cleanly"
    );

    let has_spec_violation = violations
        .iter()
        .any(|v| v.instance_path.contains("spec_version") || v.schema_path.contains("spec_version"));
    assert!(
        has_spec_violation,
        "expected at least one violation to point at /spec_version, got:\n{}",
        render_violations(&violations)
    );
}

// ---------------------------------------------------------------------------
// Meta tests on the schema files themselves (cheap sanity check that the
// embedded data did not get truncated / corrupted in the repo).
// ---------------------------------------------------------------------------

#[test]
fn schemas_directory_is_well_formed() {
    let dir = schemas_dir();
    assert!(dir.is_dir(), "schemas directory missing: {}", dir.display());

    // LICENSE file is mandatory for redistribution.
    let lic = dir.join("LICENSE-STIX-SCHEMAS.md");
    assert!(lic.is_file(), "missing {}", lic.display());

    // Every schema must compile.
    for name in [
        "bundle.json",
        "indicator.json",
        "observed-data.json",
        "software.json",
        "infrastructure.json",
        "relationship.json",
        "common.json",
    ] {
        let s = load_schema(name);
        let _ = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&s)
            .unwrap_or_else(|e| panic!("schema {} fails to compile: {e}", name));

        // Each individual file must declare $schema and $id.
        assert!(
            s.get("$schema").is_some(),
            "{} missing $schema",
            name
        );
        assert!(s.get("$id").is_some(), "{} missing $id", name);
    }

}
