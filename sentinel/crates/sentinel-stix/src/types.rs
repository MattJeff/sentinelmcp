//! STIX 2.1 wire types.
//!
//! Only the subset of STIX needed by Sentinel is modelled — indicator,
//! observed-data, software (SCO), infrastructure, relationship, and the
//! bundle wrapper. The `spec_version` field at the bundle level was
//! REMOVED by STIX 2.1; it is now mandatory on every object instead.

use serde::{Deserialize, Serialize};

/// STIX 2.1 `external-reference` data type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalReference {
    pub source_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// STIX 2.1 `indicator` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    #[serde(rename = "type")]
    pub type_: String, // always "indicator"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub created: String,
    pub modified: String,
    pub pattern: String,
    pub pattern_type: String, // always "stix"
    pub indicator_types: Vec<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub valid_from: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub external_references: Vec<ExternalReference>,
}

/// STIX 2.1 `observed-data` SDO (post-2.1 form: `object_refs`, no inline `objects`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedData {
    #[serde(rename = "type")]
    pub type_: String, // always "observed-data"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub created: String,
    pub modified: String,
    pub first_observed: String,
    pub last_observed: String,
    pub number_observed: u32,
    pub object_refs: Vec<String>,
}

/// STIX 2.1 `software` SCO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    #[serde(rename = "type")]
    pub type_: String, // always "software"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
}

/// STIX 2.1 `infrastructure` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Infrastructure {
    #[serde(rename = "type")]
    pub type_: String, // always "infrastructure"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub created: String,
    pub modified: String,
    pub name: String,
    pub infrastructure_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// STIX 2.1 `identity` SDO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    #[serde(rename = "type")]
    pub type_: String, // always "identity"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub created: String,
    pub modified: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_class: Option<String>,
}

/// STIX 2.1 `sighting` SRO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sighting {
    #[serde(rename = "type")]
    pub type_: String, // always "sighting"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub created: String,
    pub modified: String,
    pub sighting_of_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub observed_data_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub where_sighted_refs: Vec<String>,
}

/// STIX 2.1 `relationship` SRO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relationship {
    #[serde(rename = "type")]
    pub type_: String, // always "relationship"
    pub spec_version: String, // always "2.1"
    pub id: String,
    pub created: String,
    pub modified: String,
    pub relationship_type: String,
    pub source_ref: String,
    pub target_ref: String,
}

/// STIX 2.1 `bundle`.
///
/// Note: in 2.1 the `spec_version` field at the bundle level has been
/// removed. Every contained SDO/SCO/SRO carries its own `spec_version`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub type_: String, // always "bundle"
    pub id: String,
    pub objects: Vec<crate::bundle::StixObject>,
}
