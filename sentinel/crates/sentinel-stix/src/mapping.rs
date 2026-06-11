//! Mappings from Sentinel domain objects to STIX 2.1 SDOs/SCOs/SROs.
//!
//! ## Type adaptation
//!
//! The brief named `ThreatIntelEntry`, `Finding`, `McpServer` but the real
//! workspace types are:
//!
//! - `sentinel_discovery::threat_intel::EntreeMenace`  (threat intel)
//! - `sentinel_protocol::Constat`                      (finding)
//! - `sentinel_protocol::Serveur`                      (MCP server)
//!
//! The function signatures below use the real names. Tag→indicator-type
//! mapping operates on `EntreeMenace.references` plus `severite`, since
//! the feed doesn't carry free-form tags. See
//! `sentinel-discovery/data/threat_feed.yaml` for the source data.

use crate::ids::deterministic_id;
use crate::types::{
    ExternalReference, Identity, Indicator, Infrastructure, ObservedData, Relationship, Sighting,
    Software,
};
use chrono::{DateTime, SecondsFormat, TimeZone, Utc};
use sentinel_discovery::threat_intel::EntreeMenace;
use sentinel_protocol::{Constat, Serveur, Severite, TypeConstat};

/// Fixed canonical timestamp used for objects that have no natural source
/// timestamp (the Sentinel identity, relationships). Keeping it constant
/// preserves the idempotence of repeated exports/pushes: a TAXII server
/// deduplicates on `(id, modified)`.
pub const SENTINEL_EPOCH: &str = "2024-01-01T00:00:00.000Z";

/// Serialises a timestamp the way STIX 2.1 mandates: strict RFC 3339,
/// millisecond precision, `Z` suffix (never a `+00:00` offset).
pub fn stix_timestamp(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The `identity` SDO describing Sentinel itself, with a fully
/// deterministic ID and timestamps.
pub fn sentinel_identity() -> Identity {
    Identity {
        type_: "identity".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("identity", "identity:sentinel-mcp"),
        created: SENTINEL_EPOCH.to_string(),
        modified: SENTINEL_EPOCH.to_string(),
        name: "Sentinel MCP".to_string(),
        description: Some(
            "Sentinel MCP — surveillance de sécurité des serveurs Model Context Protocol."
                .to_string(),
        ),
        identity_class: Some("system".to_string()),
    }
}

/// Maps a threat-intel feed entry to a STIX 2.1 `indicator` SDO.
///
/// - `id` is deterministic, derived from the package name.
/// - `pattern` is a STIX pattern `[software:name = '<package>']`.
/// - `indicator_types` is computed from the entry's references plus its
///   `type_constat`-like hints (see [`tag_to_indicator_types`]).
/// - `external_references` lifts any `SAFE-T*` token in `references` into
///   a STIX external-reference with `source_name = "SAFE-MCP"`.
pub fn intel_entry_to_indicator(entry: &EntreeMenace) -> Indicator {
    // `publie_a` is a NaiveDate; convert to RFC 3339 at UTC midnight. Using
    // the publication date (not `now`) keeps the object fully deterministic.
    let valid_from = entry
        .publie_a
        .and_hms_opt(0, 0, 0)
        .map(|naive| stix_timestamp(&Utc.from_utc_datetime(&naive)))
        .unwrap_or_else(|| SENTINEL_EPOCH.to_string());

    // Tags = references + severity-derived hint.
    let mut tags: Vec<String> = entry.references.clone();
    tags.push(entry.severite.clone());

    let mut external_references: Vec<ExternalReference> = Vec::new();
    // Always reference the Sentinel feed identifier.
    external_references.push(ExternalReference {
        source_name: "Sentinel".to_string(),
        external_id: Some(entry.identifiant.clone()),
        url: None,
    });
    for r in &entry.references {
        if let Some(safe_id) = r.strip_prefix("SAFE-").or_else(|| {
            if r.starts_with("SAFE-T") {
                Some(r.as_str())
            } else {
                None
            }
        }) {
            // Normalise to "SAFE-T<digits>"; tolerate both "SAFE-T1001" and "T1001".
            let id = if safe_id.starts_with('T') {
                safe_id.to_string()
            } else {
                format!("T{}", safe_id)
            };
            external_references.push(ExternalReference {
                source_name: "SAFE-MCP".to_string(),
                external_id: Some(id),
                url: None,
            });
        }
    }

    Indicator {
        type_: "indicator".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("indicator", &entry.package_name),
        created: valid_from.clone(),
        modified: valid_from.clone(),
        pattern: format!("[software:name = '{}']", escape_stix_string(&entry.package_name)),
        pattern_type: "stix".to_string(),
        indicator_types: tag_to_indicator_types(&tags),
        name: format!("Known-bad MCP package: {}", entry.package_name),
        description: Some(entry.raison.clone()),
        valid_from,
        labels: tags,
        external_references,
    }
}

/// Maps a list of Sentinel tags onto STIX 2.1 `indicator-type-ov` values.
///
/// `impersonation` is a custom value (not in the open vocab) — STIX 2.1
/// explicitly permits any string here as long as the producer documents
/// it, which Sentinel does via this function.
pub fn tag_to_indicator_types(tags: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: &str| {
        let v = s.to_string();
        if !out.contains(&v) {
            out.push(v);
        }
    };
    for t in tags {
        match t.as_str() {
            "tool-poisoning" | "poisoning" => {
                push("malicious-activity");
                push("compromised");
            }
            "rug-pull" | "rug_pull" => {
                push("malicious-activity");
                push("compromised");
            }
            "data-exfil" | "exfiltration" => {
                push("malicious-activity");
            }
            "lookalike" | "sosie" | "typosquat" => {
                push("impersonation");
            }
            "account-compromise" | "compromise" => {
                push("compromised");
            }
            _ => {}
        }
    }
    if out.is_empty() {
        out.push("unknown".to_string());
    }
    out
}

/// Maps a Sentinel `Constat` (finding) to a STIX 2.1 `observed-data` SDO.
///
/// Callers should pre-filter to `Severite::Haute | Severite::Critique`.
/// We always create an empty `object_refs` list when no referenced SCO is
/// in the bundle yet — the bundle pass can be extended later to populate
/// it. The presence of the SDO alone is sufficient for downstream
/// consumers that just want timeline / count data.
pub fn finding_to_observed_data(finding: &Constat) -> ObservedData {
    let ts = stix_timestamp(&finding.horodatage);
    ObservedData {
        type_: "observed-data".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id(
            "observed-data",
            &format!("constat:{}", finding.id),
        ),
        created: ts.clone(),
        modified: ts.clone(),
        first_observed: ts.clone(),
        last_observed: ts,
        number_observed: 1,
        // Built empty for now; relationship layer in `lib::export_bundle`
        // could attach a corresponding `software` SCO ref. Keeping this
        // empty does NOT violate STIX 2.1 since `object_refs` MUST contain
        // at least one element — we therefore add a placeholder ref to
        // the originating server's software SCO when we can derive one.
        object_refs: vec![deterministic_id(
            "software",
            &format!("server:{}", finding.serveur_id),
        )],
    }
}

/// Maps a Sentinel `Serveur` to a STIX 2.1 `software` SCO.
pub fn server_to_software(server: &Serveur) -> Software {
    Software {
        type_: "software".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("software", &format!("server:{}", server.id)),
        name: server.endpoint.clone(),
        version: None,
        vendor: None,
    }
}

/// Maps a Sentinel `Serveur` to a STIX 2.1 `infrastructure` SDO.
///
/// `created`/`modified` derive from the server's first/last sighting, so
/// the object only changes when the server actually changes.
pub fn server_to_infrastructure(server: &Serveur) -> Infrastructure {
    Infrastructure {
        type_: "infrastructure".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("infrastructure", &format!("server:{}", server.id)),
        created: stix_timestamp(&server.premiere_vue),
        modified: stix_timestamp(&server.derniere_vue),
        name: format!("MCP server {}", server.endpoint),
        infrastructure_types: vec!["unknown".to_string()],
        description: Some(format!("transport={:?} statut={:?}", server.transport, server.statut)),
    }
}

/// Builds a STIX 2.1 `relationship` SRO between two existing object IDs.
///
/// The ID is a UUID v5 over `(rel_type, source, target)` and the
/// timestamps are the fixed [`SENTINEL_EPOCH`], so the SRO is idempotent
/// across exports.
pub fn relate(source: &str, target: &str, rel_type: &str) -> Relationship {
    Relationship {
        type_: "relationship".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id(
            "relationship",
            &format!("relationship:{rel_type}:{source}:{target}"),
        ),
        created: SENTINEL_EPOCH.to_string(),
        modified: SENTINEL_EPOCH.to_string(),
        relationship_type: rel_type.to_string(),
        source_ref: source.to_string(),
        target_ref: target.to_string(),
    }
}

/// Maps a Sentinel `Constat` (finding) to a STIX 2.1 `indicator` SDO with
/// a valid STIX pattern.
///
/// The pattern targets the offending server's package/endpoint when known
/// (`[software:name = '<endpoint>']`), falling back to the tool name. ID
/// and timestamps derive entirely from the finding, so repeated exports of
/// the same store produce byte-identical objects.
pub fn finding_to_indicator(finding: &Constat, endpoint: Option<&str>) -> Indicator {
    let ts = stix_timestamp(&finding.horodatage);
    let subject = endpoint
        .map(|e| e.to_string())
        .or_else(|| finding.outil_nom.clone())
        .unwrap_or_else(|| format!("mcp-server-{}", finding.serveur_id));
    let pattern = format!("[software:name = '{}']", escape_stix_string(&subject));

    let mut external_references = vec![ExternalReference {
        source_name: "Sentinel".to_string(),
        external_id: Some(finding.id.to_string()),
        url: None,
    }];
    for r in &finding.references_conformite {
        external_references.push(ExternalReference {
            source_name: "Sentinel-Conformite".to_string(),
            external_id: Some(r.clone()),
            url: None,
        });
    }

    Indicator {
        type_: "indicator".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("indicator", &format!("constat:{}", finding.id)),
        created: ts.clone(),
        modified: ts.clone(),
        pattern,
        pattern_type: "stix".to_string(),
        indicator_types: type_constat_to_indicator_types(&finding.type_constat),
        name: finding.titre.clone(),
        description: Some(finding.detail.clone()),
        valid_from: ts,
        labels: vec![format!("sentinel:{:?}", finding.type_constat).to_lowercase()],
        external_references,
    }
}

/// Builds a STIX 2.1 `sighting` SRO for a finding: the indicator derived
/// from the finding was sighted (once) by the Sentinel identity, with the
/// matching `observed-data` attached.
pub fn finding_to_sighting(
    finding: &Constat,
    indicator_id: &str,
    observed_data_id: &str,
    identity_id: &str,
) -> Sighting {
    let ts = stix_timestamp(&finding.horodatage);
    Sighting {
        type_: "sighting".to_string(),
        spec_version: "2.1".to_string(),
        id: deterministic_id("sighting", &format!("constat:{}", finding.id)),
        created: ts.clone(),
        modified: ts.clone(),
        sighting_of_ref: indicator_id.to_string(),
        first_seen: Some(ts.clone()),
        last_seen: Some(ts),
        count: Some(1),
        observed_data_refs: vec![observed_data_id.to_string()],
        where_sighted_refs: vec![identity_id.to_string()],
    }
}

/// Returns a copy of `s` safe to embed inside a STIX single-quoted pattern
/// literal. The STIX 2.1 patterning grammar escapes with a backslash:
/// `\` becomes `\\` and `'` becomes `\'`.
fn escape_stix_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Helper kept for tests / completeness: classify a Sentinel finding's
/// `TypeConstat` into one or more STIX indicator-type strings. Unused by
/// the main `finding_to_observed_data` path but exported for callers that
/// build cross-references.
pub fn type_constat_to_indicator_types(t: &TypeConstat) -> Vec<String> {
    match t {
        TypeConstat::Poisoning => tag_to_indicator_types(&["tool-poisoning".to_string()]),
        TypeConstat::RugPull => tag_to_indicator_types(&["rug-pull".to_string()]),
        TypeConstat::Exfiltration => tag_to_indicator_types(&["data-exfil".to_string()]),
        TypeConstat::Sosie => tag_to_indicator_types(&["lookalike".to_string()]),
        TypeConstat::ShadowMcp => tag_to_indicator_types(&["account-compromise".to_string()]),
        _ => vec!["unknown".to_string()],
    }
}

/// True if a `Severite` is high or critical (exposed for callers).
pub fn is_high_or_critical(sev: Severite) -> bool {
    matches!(sev, Severite::Haute | Severite::Critique)
}
