//! TAXII 2.1 client for pushing STIX bundles to a TAXII collection.
//!
//! This crate implements **only the client side**:
//!
//! - discovery (`GET {root}/taxii2/` → api-roots → collections, sélection
//!   de collection par titre ou par id);
//! - auth Basic et Bearer;
//! - Content-Type `application/taxii+json;version=2.1` strict, à l'envoi
//!   **et** vérifié en réception;
//! - retries avec backoff exponentiel sur 5xx/erreurs réseau et respect de
//!   `Retry-After` sur 429;
//! - pagination des réponses (`more`/`next`);
//! - suivi du status resource après un POST d'envelope (`pending` →
//!   polling jusqu'à complétion).
//!
//! Outbound calls are gated by [`TaxiiConfig::enabled`]. When `enabled` is
//! `false`, every network method short-circuits with [`TaxiiError::Disabled`].

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

/// TAXII 2.1 server discovery resource (`GET {root}/taxii2/`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaxiiDiscovery {
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default)]
    pub api_roots: Vec<String>,
}

/// TAXII 2.1 collection resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaxiiCollection {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub can_read: bool,
    #[serde(default)]
    pub can_write: bool,
    #[serde(default)]
    pub media_types: Vec<String>,
}

#[derive(Deserialize)]
struct TaxiiCollections {
    #[serde(default)]
    collections: Vec<TaxiiCollection>,
}

/// One page of a TAXII 2.1 envelope response.
#[derive(Deserialize)]
struct TaxiiEnvelopePage {
    #[serde(default)]
    objects: Vec<serde_json::Value>,
    #[serde(default)]
    more: bool,
    #[serde(default)]
    next: Option<String>,
}

/// Retry behaviour for transient failures (réseau, 5xx, 429).
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// Number of *re*tries after the first attempt.
    pub max_retries: u32,
    /// Base delay; attempt `n` waits `base_delay * 2^n`.
    pub base_delay: Duration,
    /// Cap applied to any `Retry-After` value advertised by the server.
    pub max_retry_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(250),
            max_retry_after: Duration::from_secs(30),
        }
    }
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
    #[error("unexpected Content-Type from TAXII server (expected application/taxii+json;version=2.1): {0}")]
    BadContentType(String),
    #[error("TAXII collection not found: {0}")]
    CollectionNotFound(String),
    #[error("TAXII status still pending after {0} poll(s)")]
    StatusPending(u32),
    #[error("TAXII pagination exceeded {0} pages")]
    TooManyPages(u32),
}

/// HTTP client for a single TAXII collection.
#[derive(Debug, Clone)]
pub struct TaxiiClient {
    config: TaxiiConfig,
    http: reqwest::Client,
    retry: RetryPolicy,
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

        Ok(Self {
            config,
            http,
            retry: RetryPolicy::default(),
        })
    }

    /// Override the retry policy (builder style).
    pub fn with_retry_policy(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// Access the underlying config (auth is redacted in Debug).
    pub fn config(&self) -> &TaxiiConfig {
        &self.config
    }

    /// Mutable access — used after discovery to pin the resolved collection.
    pub fn config_mut(&mut self) -> &mut TaxiiConfig {
        &mut self.config
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

    fn status_url(&self, status_id: &str) -> Result<String, TaxiiError> {
        let root = self.config.api_root_url.trim_end_matches('/');
        let url = format!("{}/status/{}/", root, status_id);
        url::Url::parse(&url)
            .map_err(|e| TaxiiError::InvalidConfig(format!("bad api_root_url: {e}")))?;
        Ok(url)
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.auth {
            TaxiiAuth::None => req,
            TaxiiAuth::Basic { user, pass } => {
                let token = BASE64_STANDARD.encode(format!("{user}:{pass}"));
                req.header("Authorization", format!("Basic {token}"))
            }
            TaxiiAuth::Bearer { token } => req.header("Authorization", format!("Bearer {token}")),
        }
    }

    /// Sends a request built by `build`, retrying on network errors and
    /// 5xx with exponential backoff, and honouring `Retry-After` on 429.
    async fn send_with_retries<F>(&self, build: F) -> Result<reqwest::Response, TaxiiError>
    where
        F: Fn() -> reqwest::RequestBuilder,
    {
        let mut attempt: u32 = 0;
        loop {
            let backoff = self
                .retry
                .base_delay
                .checked_mul(1u32 << attempt.min(16))
                .unwrap_or(self.retry.max_retry_after);
            match build().send().await {
                Err(e) => {
                    if attempt >= self.retry.max_retries {
                        return Err(TaxiiError::Http(e));
                    }
                    tokio::time::sleep(backoff).await;
                }
                Ok(resp) => {
                    let code = resp.status().as_u16();
                    let retryable_5xx = (500..600).contains(&code);
                    if code == 429 && attempt < self.retry.max_retries {
                        let delay = parse_retry_after(&resp)
                            .unwrap_or(backoff)
                            .min(self.retry.max_retry_after);
                        tokio::time::sleep(delay).await;
                    } else if retryable_5xx && attempt < self.retry.max_retries {
                        tokio::time::sleep(backoff).await;
                    } else {
                        return Ok(resp);
                    }
                }
            }
            attempt += 1;
        }
    }

    /// Verifies the response Content-Type, then deserialises the body.
    async fn parse_taxii_body<T: serde::de::DeserializeOwned>(
        resp: reqwest::Response,
    ) -> Result<T, TaxiiError> {
        check_taxii_content_type(&resp)?;
        resp.json::<T>().await.map_err(TaxiiError::Http)
    }

    async fn server_error(resp: reqwest::Response) -> TaxiiError {
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        TaxiiError::Server {
            status: code,
            body: truncate_at_char_boundary(&body, 500).to_string(),
        }
    }

    /// Authenticated GET of a TAXII resource with retries and strict
    /// Content-Type verification.
    async fn get_taxii<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, TaxiiError> {
        if !self.config.enabled {
            return Err(TaxiiError::Disabled);
        }
        let resp = self
            .send_with_retries(|| {
                self.apply_auth(self.http.get(url).header("Accept", TAXII_MEDIA_TYPE))
            })
            .await?;
        if !resp.status().is_success() {
            return Err(Self::server_error(resp).await);
        }
        Self::parse_taxii_body(resp).await
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    /// TAXII 2.1 server discovery: `GET {base}/taxii2/`.
    ///
    /// `base_url` may or may not already end with `/taxii2`.
    pub async fn discover(&self, base_url: &str) -> Result<TaxiiDiscovery, TaxiiError> {
        self.get_taxii(&discovery_url(base_url)?).await
    }

    /// Lists the collections of an API root: `GET {api_root}/collections/`.
    pub async fn list_collections(
        &self,
        api_root_url: &str,
    ) -> Result<Vec<TaxiiCollection>, TaxiiError> {
        let root = api_root_url.trim_end_matches('/');
        let url = format!("{root}/collections/");
        url::Url::parse(&url)
            .map_err(|e| TaxiiError::InvalidConfig(format!("bad api root url: {e}")))?;
        let cols: TaxiiCollections = self.get_taxii(&url).await?;
        Ok(cols.collections)
    }

    /// Full discovery walk: `GET {base}/taxii2/`, then every advertised API
    /// root's `/collections/`, returning the first collection whose `id`
    /// equals `selector` or whose `title` matches it (case-insensitive),
    /// together with the resolved (absolute) API root URL.
    ///
    /// Un api root en erreur (401/403 sur un serveur multi-tenant, root mal
    /// formé…) n'interrompt pas la recherche : on continue avec les roots
    /// suivants et les erreurs rencontrées sont résumées dans le
    /// [`TaxiiError::CollectionNotFound`] final si rien n'est trouvé.
    pub async fn find_collection(
        &self,
        base_url: &str,
        selector: &str,
    ) -> Result<(String, TaxiiCollection), TaxiiError> {
        let discovery = self.discover(base_url).await?;
        let base = url::Url::parse(&discovery_url(base_url)?)
            .map_err(|e| TaxiiError::InvalidConfig(format!("bad base url: {e}")))?;
        let mut root_errors: Vec<String> = Vec::new();
        for root in &discovery.api_roots {
            // API roots may be absolute or relative to the base URL.
            let absolute = match url::Url::parse(root) {
                Ok(u) => u.to_string(),
                Err(_) => match base.join(root) {
                    Ok(u) => u.to_string(),
                    Err(e) => {
                        root_errors.push(format!("'{root}': {e}"));
                        continue;
                    }
                },
            };
            let collections = match self.list_collections(&absolute).await {
                Ok(cols) => cols,
                Err(e) => {
                    root_errors.push(format!("'{absolute}': {e}"));
                    continue;
                }
            };
            for c in collections {
                if c.id == selector || c.title.eq_ignore_ascii_case(selector) {
                    return Ok((absolute, c));
                }
            }
        }
        if root_errors.is_empty() {
            Err(TaxiiError::CollectionNotFound(selector.to_string()))
        } else {
            Err(TaxiiError::CollectionNotFound(format!(
                "{selector} (api roots en erreur: {})",
                root_errors.join("; ")
            )))
        }
    }

    // ------------------------------------------------------------------
    // Push + status resource
    // ------------------------------------------------------------------

    /// Push raw STIX objects wrapped in a TAXII 2.1 envelope.
    ///
    /// Returns the parsed [`TaxiiStatus`] on HTTP 202. Any other 4xx
    /// becomes [`TaxiiError::Server`] with body truncated to 500 chars;
    /// 5xx/réseau/429 are retried per the [`RetryPolicy`].
    pub async fn push_objects(
        &self,
        objects: &[serde_json::Value],
    ) -> Result<TaxiiStatus, TaxiiError> {
        if !self.config.enabled {
            return Err(TaxiiError::Disabled);
        }
        let url = self.objects_url()?;
        let envelope = serde_json::json!({ "objects": objects });

        let resp = self
            .send_with_retries(|| {
                self.apply_auth(
                    self.http
                        .post(&url)
                        .header("Accept", TAXII_MEDIA_TYPE)
                        .header("Content-Type", TAXII_MEDIA_TYPE)
                        .json(&envelope),
                )
            })
            .await?;

        let status = resp.status();
        if status.as_u16() == 202 || status.is_success() {
            return Self::parse_taxii_body(resp).await;
        }
        Err(Self::server_error(resp).await)
    }

    /// Fetches a status resource: `GET {api_root}/status/{id}/`.
    pub async fn get_status(&self, status_id: &str) -> Result<TaxiiStatus, TaxiiError> {
        let url = self.status_url(status_id)?;
        self.get_taxii(&url).await
    }

    /// Polls the status resource while it is `pending`, sleeping
    /// `poll_interval` between polls, up to `max_polls` times.
    pub async fn wait_for_status(
        &self,
        status: TaxiiStatus,
        poll_interval: Duration,
        max_polls: u32,
    ) -> Result<TaxiiStatus, TaxiiError> {
        let mut current = status;
        let mut polls: u32 = 0;
        while current.status == "pending" {
            if polls >= max_polls {
                return Err(TaxiiError::StatusPending(polls));
            }
            tokio::time::sleep(poll_interval).await;
            current = self.get_status(&current.id).await?;
            polls += 1;
        }
        Ok(current)
    }

    /// Push then follow the status resource until it leaves `pending`.
    pub async fn push_objects_and_wait(
        &self,
        objects: &[serde_json::Value],
        poll_interval: Duration,
        max_polls: u32,
    ) -> Result<TaxiiStatus, TaxiiError> {
        let status = self.push_objects(objects).await?;
        self.wait_for_status(status, poll_interval, max_polls).await
    }

    // ------------------------------------------------------------------
    // Read with pagination
    // ------------------------------------------------------------------

    /// Fetches every object of the collection, following `more`/`next`
    /// pagination until exhaustion (bounded at 100 pages).
    pub async fn get_objects(&self) -> Result<Vec<serde_json::Value>, TaxiiError> {
        if !self.config.enabled {
            return Err(TaxiiError::Disabled);
        }
        const MAX_PAGES: u32 = 100;
        let base = self.objects_url()?;
        let mut all: Vec<serde_json::Value> = Vec::new();
        let mut next: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let mut url = url::Url::parse(&base)
                .map_err(|e| TaxiiError::InvalidConfig(format!("bad objects url: {e}")))?;
            if let Some(n) = &next {
                url.query_pairs_mut().append_pair("next", n);
            }
            let page: TaxiiEnvelopePage = self.get_taxii(url.as_str()).await?;
            all.extend(page.objects);
            if !page.more {
                return Ok(all);
            }
            match page.next {
                Some(n) => next = Some(n),
                None => return Ok(all),
            }
        }
        Err(TaxiiError::TooManyPages(MAX_PAGES))
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

/// Tronque `s` à au plus `max_bytes` octets en respectant les frontières de
/// caractères UTF-8 — le corps vient d'un serveur externe et peut contenir
/// des caractères multi-octets exactement à la limite.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Builds the discovery endpoint URL from a base server URL, tolerating a
/// base that already ends with `/taxii2`.
fn discovery_url(base_url: &str) -> Result<String, TaxiiError> {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(TaxiiError::InvalidConfig("empty base url".into()));
    }
    let url = if trimmed.ends_with("/taxii2") {
        format!("{trimmed}/")
    } else {
        format!("{trimmed}/taxii2/")
    };
    url::Url::parse(&url).map_err(|e| TaxiiError::InvalidConfig(format!("bad base url: {e}")))?;
    Ok(url)
}

/// Strict verification of the TAXII 2.1 media type on a response:
/// `application/taxii+json` is mandatory, and when a `version` parameter is
/// present it must be `2.1`.
fn check_taxii_content_type(resp: &reqwest::Response) -> Result<(), TaxiiError> {
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let normalised: String = ct.to_ascii_lowercase().split_whitespace().collect();
    if !normalised.starts_with("application/taxii+json") {
        return Err(TaxiiError::BadContentType(ct));
    }
    if let Some(version) = normalised.split("version=").nth(1) {
        let version = version.split(';').next().unwrap_or("");
        if version != "2.1" {
            return Err(TaxiiError::BadContentType(ct));
        }
    }
    Ok(())
}

/// Parses a `Retry-After` header (delta-seconds form only).
fn parse_retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
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
