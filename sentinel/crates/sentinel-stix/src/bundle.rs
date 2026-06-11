//! STIX bundle envelope and the [`StixObject`] enum that contains every
//! variant we emit.

use crate::ids::{deterministic_id, random_id};
use crate::types::{
    Identity, Indicator, Infrastructure, ObservedData, Relationship, Sighting, Software,
    StixBundle,
};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// Single bundle element. Each variant already carries its own `type`
/// field, so serialization is `#[serde(untagged)]`; deserialization
/// dispatches explicitly on the STIX `type` field (an untagged derive
/// would be ambiguous — e.g. an `indicator` also satisfies all the
/// required fields of `identity`).
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum StixObject {
    Identity(Identity),
    Indicator(Indicator),
    ObservedData(ObservedData),
    Software(Software),
    Infrastructure(Infrastructure),
    Relationship(Relationship),
    Sighting(Sighting),
}

impl<'de> Deserialize<'de> for StixObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let t = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| D::Error::missing_field("type"))?
            .to_string();
        let from = |e: serde_json::Error| D::Error::custom(e.to_string());
        match t.as_str() {
            "identity" => serde_json::from_value(value).map(StixObject::Identity).map_err(from),
            "indicator" => serde_json::from_value(value).map(StixObject::Indicator).map_err(from),
            "observed-data" => serde_json::from_value(value)
                .map(StixObject::ObservedData)
                .map_err(from),
            "software" => serde_json::from_value(value).map(StixObject::Software).map_err(from),
            "infrastructure" => serde_json::from_value(value)
                .map(StixObject::Infrastructure)
                .map_err(from),
            "relationship" => serde_json::from_value(value)
                .map(StixObject::Relationship)
                .map_err(from),
            "sighting" => serde_json::from_value(value).map(StixObject::Sighting).map_err(from),
            other => Err(D::Error::custom(format!("type STIX inconnu: {other}"))),
        }
    }
}

impl StixObject {
    /// STIX `id` of the wrapped object.
    pub fn id(&self) -> &str {
        match self {
            StixObject::Identity(o) => &o.id,
            StixObject::Indicator(o) => &o.id,
            StixObject::ObservedData(o) => &o.id,
            StixObject::Software(o) => &o.id,
            StixObject::Infrastructure(o) => &o.id,
            StixObject::Relationship(o) => &o.id,
            StixObject::Sighting(o) => &o.id,
        }
    }

    /// `modified` timestamp when the object type carries one (SCOs do not).
    pub fn modified(&self) -> Option<&str> {
        match self {
            StixObject::Identity(o) => Some(&o.modified),
            StixObject::Indicator(o) => Some(&o.modified),
            StixObject::ObservedData(o) => Some(&o.modified),
            StixObject::Software(_) => None,
            StixObject::Infrastructure(o) => Some(&o.modified),
            StixObject::Relationship(o) => Some(&o.modified),
            StixObject::Sighting(o) => Some(&o.modified),
        }
    }
}

/// Wraps a list of STIX objects into a fresh bundle with a random v4 ID.
pub fn new_bundle(objects: Vec<StixObject>) -> StixBundle {
    StixBundle {
        type_: "bundle".to_string(),
        id: random_id("bundle"),
        objects,
    }
}

/// Wraps a list of STIX objects into a bundle whose ID is a UUID v5 over
/// the canonical content `<id>|<modified>` of every object (sorted), so
/// re-exporting the same state yields the exact same bundle — required for
/// idempotent TAXII pushes.
pub fn deterministic_bundle(objects: Vec<StixObject>) -> StixBundle {
    let mut keys: Vec<String> = objects
        .iter()
        .map(|o| format!("{}|{}", o.id(), o.modified().unwrap_or("")))
        .collect();
    keys.sort();
    StixBundle {
        type_: "bundle".to_string(),
        id: deterministic_id("bundle", &keys.join("\n")),
        objects,
    }
}
