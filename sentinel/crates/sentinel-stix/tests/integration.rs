//! Integration tests for sentinel-stix.
//!
//! Covers: round-trip serialisation, deterministic ID stability, tag
//! mapping coverage, and JSON-schema validation of a freshly generated
//! bundle against an embedded minimal STIX 2.1 schema (focused on the
//! most critical constraints: object `type`, `id` format, `spec_version`,
//! required fields).

use sentinel_protocol::{
    Couleur, Portee, Serveur, StatutServeur, Transport,
};
use sentinel_stix::mapping::{tag_to_indicator_types, type_constat_to_indicator_types};
use sentinel_stix::types::{Indicator, StixBundle};
use sentinel_stix::{bundle, deterministic_id, ids, mapping};
use uuid::Uuid;

#[test]
fn round_trip_bundle_serialisation() {
    // Build a small bundle by hand.
    let ind = Indicator {
        type_: "indicator".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("indicator", "demo-package"),
        created: chrono::Utc::now().to_rfc3339(),
        modified: chrono::Utc::now().to_rfc3339(),
        pattern: "[software:name = 'demo-package']".to_string(),
        pattern_type: "stix".to_string(),
        indicator_types: vec!["malicious-activity".to_string()],
        name: "demo".to_string(),
        description: Some("demo".to_string()),
        valid_from: chrono::Utc::now().to_rfc3339(),
        labels: vec!["tool-poisoning".to_string()],
        external_references: vec![],
    };
    let b = bundle::new_bundle(vec![bundle::StixObject::Indicator(ind)]);

    let json = serde_json::to_string(&b).expect("serialise");
    let back: StixBundle = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(back.type_, "bundle");
    assert!(back.id.starts_with("bundle--"));
    assert_eq!(back.objects.len(), 1);

    // Re-serialise the round-tripped value to make sure it produces the
    // same shape (modulo map ordering).
    let json2 = serde_json::to_string(&back).unwrap();
    let v1: serde_json::Value = serde_json::from_str(&json).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&json2).unwrap();
    assert_eq!(v1, v2);
}

#[test]
fn deterministic_id_is_stable() {
    let a = deterministic_id("indicator", "foo");
    let b = deterministic_id("indicator", "foo");
    assert_eq!(a, b);
    assert!(a.starts_with("indicator--"));
    // Different keys produce different IDs.
    let c = deterministic_id("indicator", "bar");
    assert_ne!(a, c);
    // Different types with same key produce different IDs too.
    let d = deterministic_id("software", "foo");
    assert_ne!(a, d);
}

#[test]
fn random_id_is_random() {
    let a = ids::random_id("relationship");
    let b = ids::random_id("relationship");
    assert_ne!(a, b);
    assert!(a.starts_with("relationship--"));
}

#[test]
fn tag_mapping_covers_all_documented_cases() {
    assert_eq!(
        tag_to_indicator_types(&["tool-poisoning".into()]),
        vec!["malicious-activity", "compromised"]
    );
    assert_eq!(
        tag_to_indicator_types(&["rug-pull".into()]),
        vec!["malicious-activity", "compromised"]
    );
    assert_eq!(
        tag_to_indicator_types(&["data-exfil".into()]),
        vec!["malicious-activity"]
    );
    assert_eq!(
        tag_to_indicator_types(&["lookalike".into()]),
        vec!["impersonation"]
    );
    assert_eq!(
        tag_to_indicator_types(&["account-compromise".into()]),
        vec!["compromised"]
    );
    // Unknown tag → "unknown".
    assert_eq!(
        tag_to_indicator_types(&["something-random".into()]),
        vec!["unknown"]
    );
}

#[test]
fn type_constat_mapping_uses_tag_table() {
    assert_eq!(
        type_constat_to_indicator_types(&sentinel_protocol::TypeConstat::Poisoning),
        vec!["malicious-activity", "compromised"]
    );
    assert_eq!(
        type_constat_to_indicator_types(&sentinel_protocol::TypeConstat::Sosie),
        vec!["impersonation"]
    );
}

#[test]
fn bundle_validates_against_minimal_stix21_schema() {
    use jsonschema::JSONSchema;
    use serde_json::json;

    // Minimal schema focused on the most critical 2.1 invariants:
    //  - top-level "type" must be "bundle"
    //  - "id" must match `bundle--<uuid>`
    //  - every object MUST have a STIX 2.1 `type`, `id` (=type--uuid),
    //    and `spec_version` equal to "2.1".
    let schema = json!({
        "type": "object",
        "required": ["type", "id", "objects"],
        "properties": {
            "type": { "type": "string", "const": "bundle" },
            "id": {
                "type": "string",
                "pattern": "^bundle--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
            },
            "objects": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["type", "id", "spec_version"],
                    "properties": {
                        "type": { "type": "string" },
                        "spec_version": { "type": "string", "const": "2.1" },
                        "id": {
                            "type": "string",
                            "pattern": "^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
                        }
                    }
                }
            }
        }
    });
    let compiled = JSONSchema::compile(&schema).expect("schema compile");

    // Build a fixture bundle by hand from the public mapping helpers — we
    // do NOT spin up a real Store here to keep the test hermetic.
    let now = chrono::Utc::now();
    let s = Serveur {
        id: Uuid::new_v4(),
        endpoint: "stdio://npx@modelcontextprotocol/server-filesystem".into(),
        transport: Transport::Stdio,
        portees: vec![Portee::Filesystem],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: now,
        derniere_vue: now,
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    };
    let sw = mapping::server_to_software(&s);
    let infra = mapping::server_to_infrastructure(&s);

    let entry = sentinel_discovery::threat_intel::EntreeMenace {
        identifiant: "MCP-TEST-1".to_string(),
        package_name: "@evil/mcp-bad".to_string(),
        raison: "test fixture".to_string(),
        severite: "high".to_string(),
        references: vec!["SAFE-T1001".to_string(), "tool-poisoning".to_string()],
        publie_a: chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
    };
    let ind = mapping::intel_entry_to_indicator(&entry);
    let rel = mapping::relate(&ind.id, &infra.id, "indicates");

    let bndl = bundle::new_bundle(vec![
        bundle::StixObject::Software(sw),
        bundle::StixObject::Infrastructure(infra),
        bundle::StixObject::Indicator(ind),
        bundle::StixObject::Relationship(rel),
    ]);

    let value = serde_json::to_value(&bndl).expect("to_value");
    let result = compiled.validate(&value);
    if let Err(errors) = result {
        let msgs: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!("schema validation failed:\n{}", msgs.join("\n"));
    }
}

#[test]
fn export_bundle_runs_against_in_memory_store() {
    let store = sentinel_store::Store::in_memory().expect("store");
    let bndl = sentinel_stix::export_bundle(&store).expect("export_bundle");
    assert_eq!(bndl.type_, "bundle");
    assert!(bndl.id.starts_with("bundle--"));
    // With an empty store we still get the bundled threat-intel indicators.
    assert!(!bndl.objects.is_empty());
}
