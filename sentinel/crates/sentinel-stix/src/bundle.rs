//! STIX bundle envelope and the [`StixObject`] enum that contains every
//! variant we emit.

use crate::ids::random_id;
use crate::types::{Indicator, Infrastructure, ObservedData, Relationship, Software, StixBundle};
use serde::{Deserialize, Serialize};

/// Single bundle element. Each variant already carries its own `type`
/// field, so we use `#[serde(untagged)]` to flatten them at the JSON level.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StixObject {
    Indicator(Indicator),
    ObservedData(ObservedData),
    Software(Software),
    Infrastructure(Infrastructure),
    Relationship(Relationship),
}

/// Wraps a list of STIX objects into a fresh bundle with a random v4 ID.
pub fn new_bundle(objects: Vec<StixObject>) -> StixBundle {
    StixBundle {
        type_: "bundle".to_string(),
        id: random_id("bundle"),
        objects,
    }
}
