//! STIX ID generation.
//!
//! STIX 2.1 IDs use the format `<object_type>--<UUID>`, with two dashes
//! between the type prefix and the UUID. We expose:
//!
//! - [`deterministic_id`] using UUID v5 for objects that must round-trip
//!   across runs (e.g. indicators derived from a stable feed key), and
//! - [`random_id`] using UUID v4 for transient objects (bundles,
//!   observed-data, relationships).

use uuid::Uuid;

/// Sentinel STIX namespace UUID (used as the v5 namespace).
///
/// This is a fixed v4 UUID generated once for this crate. Any change to
/// this constant invalidates every previously emitted deterministic ID.
pub const STIX_UUID_NAMESPACE: Uuid =
    Uuid::from_u128(0x3e2c_6f48_bb71_4e6d_9c2a_8e3d_71f0_b9a4);

/// Builds a deterministic STIX ID: `<object_type>--<uuidv5(NAMESPACE, key)>`.
pub fn deterministic_id(object_type: &str, key: &str) -> String {
    let u = Uuid::new_v5(&STIX_UUID_NAMESPACE, key.as_bytes());
    format!("{}--{}", object_type, u)
}

/// Builds a random STIX ID: `<object_type>--<uuidv4>`.
pub fn random_id(object_type: &str) -> String {
    format!("{}--{}", object_type, Uuid::new_v4())
}
