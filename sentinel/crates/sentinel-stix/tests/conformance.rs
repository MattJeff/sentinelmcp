//! Conformité STIX 2.1 :
//!
//! 1. Idempotence — deux exports du même état produisent un bundle
//!    strictement identique (IDs UUID v5 + horodatages dérivés des données).
//! 2. Chaîne complète — identity, indicator par constat, observed-data,
//!    sighting, relationship indicator→infrastructure.
//! 3. Horodatages RFC 3339 stricts (suffixe `Z` obligatoire).
//! 4. Le validateur interne accepte les exemples officiels de la spec
//!    OASIS STIX 2.1 et rejette des objets invalides.

use chrono::{TimeZone, Utc};
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Portee, Serveur, Severite, StatutServeur, Transport,
    TypeConstat,
};
use sentinel_store::Store;
use serde_json::{json, Value};
use uuid::Uuid;

fn fixed_serveur_id() -> Uuid {
    Uuid::parse_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8").unwrap()
}

fn fixed_constat_id() -> Uuid {
    Uuid::parse_str("6ba7b811-9dad-11d1-80b4-00c04fd430c8").unwrap()
}

/// Store seedé avec des horodatages FIXES pour pouvoir comparer deux exports.
fn seed_store() -> Store {
    let store = Store::in_memory().expect("store");
    let t0 = Utc.with_ymd_and_hms(2026, 5, 1, 8, 0, 0).unwrap();
    let t1 = Utc.with_ymd_and_hms(2026, 5, 2, 9, 30, 0).unwrap();

    let serveur = Serveur {
        id: fixed_serveur_id(),
        endpoint: "@modelcontextprotocol/server-filesystem".to_string(),
        transport: Transport::Stdio,
        portees: vec![Portee::Filesystem, Portee::Lecture],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: t0,
        derniere_vue: t1,
        empreinte_courante: Some("abc123".to_string()),
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    };
    store.upsert_serveur(&serveur).expect("upsert serveur");

    let constat = Constat {
        id: fixed_constat_id(),
        serveur_id: fixed_serveur_id(),
        outil_nom: Some("read_file".to_string()),
        type_constat: TypeConstat::Poisoning,
        severite: Severite::Critique,
        titre: "Description d'outil empoisonnée".to_string(),
        detail: "L'outil read_file contient des instructions cachées.".to_string(),
        diff: None,
        references_conformite: vec!["SAFE-T1001".to_string()],
        horodatage: t1,
        etat: EtatConstat::Ouvert,
    };
    store.enregistrer_constat(&constat).expect("constat");
    store
}

#[test]
fn export_is_idempotent_across_runs() {
    let store = seed_store();
    let b1 = sentinel_stix::export_bundle(&store).expect("export 1");
    let b2 = sentinel_stix::export_bundle(&store).expect("export 2");

    let v1 = serde_json::to_value(&b1).unwrap();
    let v2 = serde_json::to_value(&b2).unwrap();
    assert_eq!(v1, v2, "deux exports du même état doivent être identiques");
    assert_eq!(b1.id, b2.id, "le bundle id doit être déterministe");
}

#[test]
fn bundle_contains_full_chain_for_a_finding() {
    let store = seed_store();
    let bundle = sentinel_stix::export_bundle(&store).expect("export");
    let v = serde_json::to_value(&bundle).unwrap();
    let objects = v["objects"].as_array().unwrap();

    let of_type = |t: &str| -> Vec<&Value> {
        objects.iter().filter(|o| o["type"] == t).collect()
    };

    // Identity Sentinel.
    let identities = of_type("identity");
    assert_eq!(identities.len(), 1, "exactement une identity Sentinel");
    let identity_id = identities[0]["id"].as_str().unwrap();
    assert_eq!(identities[0]["name"], "Sentinel MCP");

    // Indicator dérivé du constat (en plus de ceux du flux de menaces).
    let constat_ref = fixed_constat_id().to_string();
    let finding_indicators: Vec<&Value> = of_type("indicator")
        .into_iter()
        .filter(|o| {
            o["external_references"]
                .as_array()
                .map(|refs| refs.iter().any(|r| r["external_id"] == json!(constat_ref)))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(finding_indicators.len(), 1, "un indicator par constat");
    let ind = finding_indicators[0];
    assert_eq!(ind["pattern_type"], "stix");
    assert_eq!(
        ind["pattern"],
        "[software:name = '@modelcontextprotocol/server-filesystem']"
    );
    let ind_id = ind["id"].as_str().unwrap();

    // Observed-data.
    assert_eq!(of_type("observed-data").len(), 1);
    let od_id = of_type("observed-data")[0]["id"].as_str().unwrap();

    // Sighting reliant indicator + observed-data + identity.
    let sightings = of_type("sighting");
    assert_eq!(sightings.len(), 1, "un sighting par constat");
    let s = sightings[0];
    assert_eq!(s["sighting_of_ref"], json!(ind_id));
    assert_eq!(s["observed_data_refs"], json!([od_id]));
    assert_eq!(s["where_sighted_refs"], json!([identity_id]));

    // Relationship indicator (du constat) → infrastructure.
    let infra_id = of_type("infrastructure")[0]["id"].as_str().unwrap();
    let has_rel = of_type("relationship").iter().any(|r| {
        r["relationship_type"] == "indicates"
            && r["source_ref"] == json!(ind_id)
            && r["target_ref"] == json!(infra_id)
    });
    assert!(has_rel, "relationship indicator→infrastructure manquante");
}

#[test]
fn all_timestamps_are_strict_rfc3339_zulu() {
    let store = seed_store();
    let bundle = sentinel_stix::export_bundle(&store).expect("export");
    let v = serde_json::to_value(&bundle).unwrap();
    let ts_fields = [
        "created",
        "modified",
        "valid_from",
        "first_observed",
        "last_observed",
        "first_seen",
        "last_seen",
    ];
    for obj in v["objects"].as_array().unwrap() {
        for f in &ts_fields {
            if let Some(ts) = obj.get(*f).and_then(Value::as_str) {
                assert!(
                    sentinel_stix::validate::is_stix_timestamp(ts),
                    "{}#{} n'est pas un horodatage STIX strict: {}",
                    obj["type"],
                    f,
                    ts
                );
                assert!(ts.ends_with('Z'), "suffixe Z requis: {ts}");
            }
        }
    }
}

#[test]
fn deterministic_relationship_id() {
    let r1 = sentinel_stix::mapping::relate("indicator--aaa", "infrastructure--bbb", "indicates");
    let r2 = sentinel_stix::mapping::relate("indicator--aaa", "infrastructure--bbb", "indicates");
    assert_eq!(r1.id, r2.id);
    // Source/target inversés ⇒ ID différent.
    let r3 = sentinel_stix::mapping::relate("infrastructure--bbb", "indicator--aaa", "indicates");
    assert_ne!(r1.id, r3.id);
}

// ---------------------------------------------------------------------------
// Validateur interne vs exemples officiels de la spec OASIS STIX 2.1
// ---------------------------------------------------------------------------

/// Exemple `indicator` tiré de la spec OASIS STIX 2.1 (§4.7, exemple 1).
#[test]
fn oasis_spec_indicator_example_passes_validation() {
    let example = json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "indicator_types": ["malicious-activity"],
        "name": "Poison Ivy Malware",
        "description": "This file is part of Poison Ivy",
        "pattern": "[ file:hashes.'SHA-256' = '4bac27393bdd9777ce02453256c5577cd02275510b2227f473d03f533924f877' ]",
        "pattern_type": "stix",
        "valid_from": "2016-01-01T00:00:00Z"
    });
    let errs = sentinel_stix::validate_object(&example);
    assert!(errs.is_empty(), "exemple OASIS rejeté: {errs:?}");
}

/// Exemple `relationship` tiré de la spec OASIS STIX 2.1 (§5.2).
#[test]
fn oasis_spec_relationship_example_passes_validation() {
    let example = json!({
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--57b56a43-b8b0-4cba-9deb-34e3e1faed9e",
        "created": "2016-04-06T20:06:37.000Z",
        "modified": "2016-04-06T20:06:37.000Z",
        "relationship_type": "indicates",
        "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
    });
    let errs = sentinel_stix::validate_object(&example);
    assert!(errs.is_empty(), "exemple OASIS rejeté: {errs:?}");
}

/// Exemple `identity` tiré de la spec OASIS STIX 2.1 (§4.5).
#[test]
fn oasis_spec_identity_example_passes_validation() {
    let example = json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "ACME Widget, Inc.",
        "identity_class": "organization"
    });
    let errs = sentinel_stix::validate_object(&example);
    assert!(errs.is_empty(), "exemple OASIS rejeté: {errs:?}");
}

/// Exemple `sighting` tiré de la spec OASIS STIX 2.1 (§5.3).
#[test]
fn oasis_spec_sighting_example_passes_validation() {
    let example = json!({
        "type": "sighting",
        "spec_version": "2.1",
        "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
        "created": "2016-08-22T14:09:00.123Z",
        "modified": "2016-08-22T14:09:00.123Z",
        "first_seen": "2015-12-21T19:00:00Z",
        "last_seen": "2015-12-21T19:00:00Z",
        "count": 50,
        "sighting_of_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "observed_data_refs": ["observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"],
        "where_sighted_refs": ["identity--b67d30ff-02ac-498a-92f9-32f845f448ff"]
    });
    let errs = sentinel_stix::validate_object(&example);
    assert!(errs.is_empty(), "exemple OASIS rejeté: {errs:?}");
}

#[test]
fn validator_rejects_missing_required_fields_and_bad_timestamps() {
    // Indicator sans pattern.
    let no_pattern = json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "created": "2016-04-06T20:03:48.000Z",
        "modified": "2016-04-06T20:03:48.000Z",
        "pattern_type": "stix",
        "valid_from": "2016-01-01T00:00:00Z"
    });
    let errs = sentinel_stix::validate_object(&no_pattern);
    assert!(errs.iter().any(|e| e.contains("pattern")), "{errs:?}");

    // Horodatage avec offset +00:00 → refusé (la spec exige Z).
    let offset_ts = json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created": "2016-04-06T20:03:00.000+00:00",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "x"
    });
    let errs = sentinel_stix::validate_object(&offset_ts);
    assert!(errs.iter().any(|e| e.contains("created")), "{errs:?}");

    // Mauvaise spec_version.
    let bad_spec = json!({
        "type": "identity",
        "spec_version": "2.0",
        "id": "identity--023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "x"
    });
    let errs = sentinel_stix::validate_object(&bad_spec);
    assert!(errs.iter().any(|e| e.contains("spec_version")), "{errs:?}");

    // observed-data sans object_refs.
    let od = json!({
        "type": "observed-data",
        "spec_version": "2.1",
        "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "first_observed": "2016-04-06T20:03:00.000Z",
        "last_observed": "2016-04-06T20:03:00.000Z",
        "number_observed": 1
    });
    let errs = sentinel_stix::validate_object(&od);
    assert!(errs.iter().any(|e| e.contains("object_refs")), "{errs:?}");

    // ID malformé (simple tiret).
    let bad_id = json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity-023d105b-752e-4e3c-941c-7d3f3cb15e9e",
        "created": "2016-04-06T20:03:00.000Z",
        "modified": "2016-04-06T20:03:00.000Z",
        "name": "x"
    });
    let errs = sentinel_stix::validate_object(&bad_id);
    assert!(errs.iter().any(|e| e.contains("id invalide")), "{errs:?}");
}
