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
pub fn deterministic_bundle(mut objects: Vec<StixObject>) -> StixBundle {
    // Tri déterministe des objets par contenu canonique `<id>|<modified>`
    // AVANT sérialisation. Sans ce tri, seul l'ID du bundle était stable :
    // l'ordre de lecture en amont (le store ne garantit pas d'`ORDER BY`) se
    // propageait dans le corps du bundle, si bien que deux exports des mêmes
    // données produisaient un JSON différent byte-à-byte — ce qu'un serveur
    // TAXII dédupliquant sur le hash du corps interprète comme des doublons.
    // `sort_by_cached_key` est stable et ne calcule la clé qu'une fois par
    // objet. Comme les `id` STIX sont uniques dans un bundle, l'ordre obtenu
    // est total et l'ID du bundle reste identique à l'implémentation passée.
    objects.sort_by_cached_key(|o| format!("{}|{}", o.id(), o.modified().unwrap_or("")));
    let keys: Vec<String> = objects
        .iter()
        .map(|o| format!("{}|{}", o.id(), o.modified().unwrap_or("")))
        .collect();
    StixBundle {
        type_: "bundle".to_string(),
        id: deterministic_id("bundle", &keys.join("\n")),
        objects,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Indicator, Software};

    fn indicateur(cle: &str) -> StixObject {
        StixObject::Indicator(Indicator {
            type_: "indicator".to_string(),
            spec_version: "2.1".to_string(),
            id: deterministic_id("indicator", cle),
            created: "2024-01-01T00:00:00.000Z".to_string(),
            modified: "2024-01-01T00:00:00.000Z".to_string(),
            pattern: "[software:name = 'x']".to_string(),
            pattern_type: "stix".to_string(),
            indicator_types: vec!["unknown".to_string()],
            name: format!("ind-{cle}"),
            description: None,
            valid_from: "2024-01-01T00:00:00.000Z".to_string(),
            labels: vec![],
            external_references: vec![],
        })
    }

    fn logiciel(cle: &str) -> StixObject {
        StixObject::Software(Software {
            type_: "software".to_string(),
            spec_version: "2.1".to_string(),
            id: deterministic_id("software", cle),
            name: format!("sw-{cle}"),
            version: None,
            vendor: None,
        })
    }

    /// Régression B15 : deux générations sur les mêmes objets, fournis dans
    /// des ordres d'entrée différents, doivent produire un bundle IDENTIQUE
    /// byte-à-byte. Sinon un serveur TAXII dédupliquant sur le hash du corps
    /// crée des doublons silencieux.
    #[test]
    fn bundle_deterministe_identique_quel_que_soit_l_ordre_d_entree() {
        let objets = vec![
            logiciel("server:zzz"),
            indicateur("pkg-alpha"),
            logiciel("server:aaa"),
            indicateur("pkg-omega"),
        ];
        let mut inverse = objets.clone();
        inverse.reverse();

        let b1 = deterministic_bundle(objets);
        let b2 = deterministic_bundle(inverse);

        // Même ID de bundle...
        assert_eq!(b1.id, b2.id);
        // ...et surtout même corps sérialisé byte-à-byte.
        let j1 = serde_json::to_string(&b1).expect("sérialisation b1");
        let j2 = serde_json::to_string(&b2).expect("sérialisation b2");
        assert_eq!(j1, j2);

        // L'ordre des objets est bien trié par `id` (donc stable et total).
        let ids: Vec<&str> = b1.objects.iter().map(StixObject::id).collect();
        let mut tries = ids.clone();
        tries.sort_unstable();
        assert_eq!(ids, tries);
    }
}
