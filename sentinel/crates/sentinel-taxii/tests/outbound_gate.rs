//! Outbound-toggle gate semantics for TAXII pushes.
//!
//! The desktop layer adds **two** safeguards on top of `sentinel-taxii`:
//!
//! 1. A *global* "Outbound calls" toggle (`settings.privacy.outbound_lookups`)
//!    that gates every channel that performs an outbound HTTP call —
//!    email, webhook, SIEM, **and TAXII**. When OFF, the Tauri command
//!    `taxii_test_send` returns the exact string
//!    `"Outbound calls disabled in Settings — TAXII push blocked."`.
//!
//! 2. A *per-sink* `enabled` flag inside [`TaxiiConfig`]. When OFF, the
//!    `TaxiiClient` short-circuits every push method with
//!    [`TaxiiError::Disabled`] before the network is touched.
//!
//! The first gate is implemented in `sentinel-desktop/src/commands_taxii.rs`
//! (and unit-tested there with a temp directory + fake `settings.toml`).
//!
//! This test covers the second gate: even when the global toggle is ON, an
//! operator can still keep `TaxiiConfig::enabled = false`, and the crate
//! must refuse to send. This is the property `taxii_test_send` relies on.

use sentinel_taxii::{TaxiiClient, TaxiiConfig, TaxiiError};

#[tokio::test]
async fn test_send_short_circuits_when_per_sink_disabled() {
    let mut cfg = TaxiiConfig::new(
        "https://taxii.example.invalid/taxii2/",
        "00000000-0000-0000-0000-000000000000",
    );
    cfg.enabled = false;

    let client = TaxiiClient::new(cfg).expect("client builds");
    let result = client.test_send().await;
    assert!(
        matches!(result, Err(TaxiiError::Disabled)),
        "expected TaxiiError::Disabled, got {:?}",
        result
    );
}

#[tokio::test]
async fn push_bundle_short_circuits_when_per_sink_disabled() {
    let mut cfg = TaxiiConfig::new(
        "https://taxii.example.invalid/taxii2/",
        "00000000-0000-0000-0000-000000000000",
    );
    cfg.enabled = false;

    let client = TaxiiClient::new(cfg).expect("client builds");
    let bundle = serde_json::json!({ "type": "bundle", "objects": [] });
    let result = client.push_bundle(&bundle).await;
    assert!(
        matches!(result, Err(TaxiiError::Disabled)),
        "expected TaxiiError::Disabled, got {:?}",
        result
    );
}

#[tokio::test]
async fn push_objects_short_circuits_when_per_sink_disabled() {
    let mut cfg = TaxiiConfig::new(
        "https://taxii.example.invalid/taxii2/",
        "00000000-0000-0000-0000-000000000000",
    );
    cfg.enabled = false;

    let client = TaxiiClient::new(cfg).expect("client builds");
    let result = client.push_objects(&[]).await;
    assert!(
        matches!(result, Err(TaxiiError::Disabled)),
        "expected TaxiiError::Disabled, got {:?}",
        result
    );
}
