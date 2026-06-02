//! TAXII 2.1 client for pushing STIX bundles to a TAXII collection.
//!
//! This crate implements **only the client side**: it builds the proper
//! envelope, injects authentication, posts to
//! `<api_root>/collections/<collection_id>/objects/`, and parses the
//! resulting `Status` resource.
//!
//! Outbound calls are gated by [`TaxiiConfig::enabled`]. When `enabled` is
//! `false`, every push method short-circuits with [`TaxiiError::Disabled`].

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Crate version, used in the `User-Agent` header.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// TAXII 2.1 media type used for both `Accept` and `Content-Type`.
pub const TAXII_MEDIA_TYPE: &str = "application/taxii+json;version=2.1";

/// Authentication method for the TAXII endpoint.
///
/// `Debug` is implemented manually to redact secrets — derived `Debug`
/// would expose passwords and bearer tokens in tracing/log output.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TaxiiAuth {
    None,
    Basic { user: String, pass: String },
    Bearer { token: String },
}

impl fmt::Debug for TaxiiAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaxiiAuth::None => f.write_str("None"),
            TaxiiAuth::Basic { user, .. } => f
                .debug_struct("Basic")
                .field("user", user)
                .field("pass", &"***")
                .finish(),
            TaxiiAuth::Bearer { .. } => f
                .debug_struct("Bearer")
                .field("token", &"***")
                .finish(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Configuration for [`TaxiiClient`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaxiiConfig {
    /// Base URL of the TAXII API root, e.g. `https://taxii.example.com/taxii2/`.
    pub api_root_url: String,
    /// Target collection id (a UUID, typically).
    pub collection_id: String,
    /// Authentication strategy.
    pub auth: TaxiiAuth,
    /// Master switch: if `false`, all push methods return [`TaxiiError::Disabled`].
    pub enabled: bool,
    /// Verify TLS certificates. Defaults to `true`. Set to `false` only for
    /// POCs against self-signed servers.
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

impl TaxiiConfig {
    /// Build a minimal config with no authentication, enabled, TLS verified.
    pub fn new(api_root_url: impl Into<String>, collection_id: impl Into<String>) -> Self {
        Self {
            api_root_url: api_root_url.into(),
            collection_id: collection_id.into(),
            auth: TaxiiAuth::None,
            enabled: true,
            verify_tls: true,
        }
    }
}

/// TAXII 2.1 `status` resource returned by the server in response to a POST.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaxiiStatus {
    pub id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timestamp: Option<String>,
    #[serde(default)]
    pub total_count: u64,
    #[serde(default)]
    pub success_count: u64,
    #[serde(default)]
    pub failure_count: u64,
    #[serde(default)]
    pub pending_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successes: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pendings: Option<serde_json::Value>,
}

/// Errors returned by the TAXII client. Auth secrets are never embedded.
#[derive(Debug, Error)]
pub enum TaxiiError {
    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TAXII server returned status {status}: {body}")]
    Server { status: u16, body: String },
    #[error("TAXII client disabled by configuration")]
    Disabled,
    #[error("invalid TAXII configuration: {0}")]
    InvalidConfig(String),
}

/// HTTP client for a single TAXII collection.
#[derive(Debug, Clone)]
pub struct TaxiiClient {
    config: TaxiiConfig,
    http: reqwest::Client,
}

impl TaxiiClient {
    /// Build a client. Configures a 30 s timeout, the project user-agent,
    /// and honours [`TaxiiConfig::verify_tls`].
    pub fn new(config: TaxiiConfig) -> Result<Self, TaxiiError> {
        if config.api_root_url.is_empty() {
            return Err(TaxiiError::InvalidConfig(
                "api_root_url must not be empty".into(),
            ));
        }
        if config.collection_id.is_empty() {
            return Err(TaxiiError::InvalidConfig(
                "collection_id must not be empty".into(),
            ));
        }

        let user_agent = format!("Sentinel-MCP/{VERSION}");
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(user_agent)
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(TaxiiError::Http)?;

        Ok(Self { config, http })
    }

    /// Access the underlying config (auth is redacted in Debug).
    pub fn config(&self) -> &TaxiiConfig {
        &self.config
    }

    fn objects_url(&self) -> Result<String, TaxiiError> {
        // Normalize api_root: ensure a single trailing slash before appending.
        let root = self.config.api_root_url.trim_end_matches('/');
        let url = format!(
            "{}/collections/{}/objects/",
            root, self.config.collection_id
        );
        // Validate the produced URL.
        url::Url::parse(&url)
            .map_err(|e| TaxiiError::InvalidConfig(format!("bad api_root_url: {e}")))?;
        Ok(url)
    }

    /// Push raw STIX objects wrapped in a TAXII 2.1 envelope.
    ///
    /// Returns the parsed [`TaxiiStatus`] on HTTP 202. Any other 4xx/5xx
    /// becomes [`TaxiiError::Server`] with body truncated to 500 chars.
    pub async fn push_objects(
        &self,
        objects: &[serde_json::Value],
    ) -> Result<TaxiiStatus, TaxiiError> {
        if !self.config.enabled {
            return Err(TaxiiError::Disabled);
        }
        let url = self.objects_url()?;
        let envelope = serde_json::json!({ "objects": objects });

        let mut req = self
            .http
            .post(&url)
            .header("Accept", TAXII_MEDIA_TYPE)
            .header("Content-Type", TAXII_MEDIA_TYPE)
            .json(&envelope);

        req = match &self.config.auth {
            TaxiiAuth::None => req,
            TaxiiAuth::Basic { user, pass } => {
                let token = BASE64_STANDARD.encode(format!("{user}:{pass}"));
                req.header("Authorization", format!("Basic {token}"))
            }
            TaxiiAuth::Bearer { token } => {
                req.header("Authorization", format!("Bearer {token}"))
            }
        };

        let resp = req.send().await.map_err(TaxiiError::Http)?;
        let status = resp.status();

        if status.as_u16() == 202 || status.is_success() {
            let status_obj = resp
                .json::<TaxiiStatus>()
                .await
                .map_err(TaxiiError::Http)?;
            return Ok(status_obj);
        }

        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        let truncated = if body.len() > 500 { &body[..500] } else { &body[..] };
        Err(TaxiiError::Server {
            status: code,
            body: truncated.to_string(),
        })
    }

    /// Push a STIX bundle by extracting its `objects` array.
    pub async fn push_bundle(
        &self,
        bundle_json: &serde_json::Value,
    ) -> Result<TaxiiStatus, TaxiiError> {
        if !self.config.enabled {
            return Err(TaxiiError::Disabled);
        }
        let objects = bundle_json
            .get("objects")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                TaxiiError::InvalidConfig("bundle has no 'objects' array".into())
            })?;
        self.push_objects(objects).await
    }

    /// Push a minimal STIX 2.1 indicator to validate connectivity, auth, and
    /// the collection's write permissions.
    pub async fn test_send(&self) -> Result<TaxiiStatus, TaxiiError> {
        if !self.config.enabled {
            return Err(TaxiiError::Disabled);
        }
        let indicator = build_test_indicator();
        self.push_objects(&[indicator]).await
    }
}

/// Build the minimal STIX 2.1 indicator used by [`TaxiiClient::test_send`].
fn build_test_indicator() -> serde_json::Value {
    // ISO-8601 / RFC-3339 timestamp without milliseconds. We avoid pulling
    // chrono in this crate by formatting via std time helpers.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let timestamp = format_unix_as_rfc3339(now);

    serde_json::json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": format!("indicator--{}", deterministic_uuid_v4_for_test()),
        "created": timestamp,
        "modified": timestamp,
        "name": "Sentinel MCP TAXII test",
        "description": "Connectivity test from sentinel-taxii client; benign synthetic indicator.",
        "indicator_types": ["benign"],
        "pattern": "[software:name = 'sentinel-mcp-test']",
        "pattern_type": "stix",
        "valid_from": timestamp
    })
}

fn format_unix_as_rfc3339(secs: u64) -> String {
    // Minimal RFC-3339 formatter (UTC). STIX 2.1 requires this format.
    // Algorithm: convert seconds-since-epoch to date + time components.
    let days = (secs / 86_400) as i64;
    let time_of_day = secs % 86_400;
    let hour = (time_of_day / 3600) as u32;
    let minute = ((time_of_day / 60) % 60) as u32;
    let second = (time_of_day % 60) as u32;

    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Howard Hinnant's days_from_civil inverse — converts days since 1970-01-01
/// to (year, month, day). Used to keep this crate free of chrono.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m as u32, d as u32)
}

/// Generates an opaque pseudo-uuid for the test indicator without pulling
/// the `uuid` crate. Not cryptographically random, but adequate for a
/// connectivity probe (we suffix nanoseconds + a fixed prefix).
fn deterministic_uuid_v4_for_test() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // RFC 4122 v4 shape: 8-4-4-4-12 hex chars. We fill from `nanos` rotated.
    let a = (nanos & 0xFFFF_FFFF) as u32;
    let b = ((nanos >> 32) & 0xFFFF) as u16;
    let c: u16 = 0x4000 | ((nanos >> 48) as u16 & 0x0FFF); // version 4
    let d: u16 = 0x8000 | ((nanos >> 16) as u16 & 0x3FFF); // variant 1
    let e = ((nanos.wrapping_mul(2862933555777941757)) & 0xFFFF_FFFF_FFFF) as u64;
    format!("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}", a, b, c, d, e)
}
