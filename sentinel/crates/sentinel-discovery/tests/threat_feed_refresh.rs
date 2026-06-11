//! Integration tests for the remote refresh + cache cascade of the threat
//! intel feed. Each test pins one branch of the [`charger_feed`] cascade so
//! a regression in the fallback order is caught loudly.

use std::path::PathBuf;
use std::time::Duration;

use sentinel_discovery::threat_intel::refresh::{
    self, CacheMeta, ThreatFeedConfig, ThreatFeedError, CACHE_FILENAME, META_FILENAME,
};
use sentinel_discovery::threat_intel::FluxMenaces;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const VALID_YAML: &str = r#"
version: "test-2026-01-01"
entries:
  - identifiant: MCP-TEST-001
    package_name: "@test/example"
    raison: "Synthetic test entry."
    severite: medium
    references: ["test"]
    publie_a: 2026-01-01
"#;

const INVALID_YAML: &str = "not: a: valid yaml ::: file";

fn tempdir_unique(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("sentinel-threat-feed-{}-{}", tag, nanos));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn write_cache(dir: &std::path::Path, yaml: &str, meta: &CacheMeta) {
    std::fs::write(dir.join(CACHE_FILENAME), yaml).unwrap();
    std::fs::write(
        dir.join(META_FILENAME),
        serde_json::to_string_pretty(meta).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn rafraichir_feed_writes_cache_when_remote_is_ok() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/threat_feed.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(VALID_YAML))
        .mount(&server)
        .await;

    let cache = tempdir_unique("rafraichir-ok");
    let url = format!("{}/threat_feed.yaml", server.uri());
    let flux = refresh::rafraichir_feed(&url, &cache)
        .await
        .expect("remote OK must succeed");

    assert!(!flux.entrees.is_empty(), "remote feed should have entries");
    assert_eq!(flux.version_feed, "test-2026-01-01");

    let yaml = cache.join(CACHE_FILENAME);
    let meta = cache.join(META_FILENAME);
    assert!(yaml.exists(), "cache YAML must be written");
    assert!(meta.exists(), "cache meta must be written");

    let meta_raw = std::fs::read_to_string(meta).unwrap();
    let parsed: CacheMeta = serde_json::from_str(&meta_raw).unwrap();
    assert_eq!(parsed.source, "remote");
    assert!(!parsed.sha256.is_empty(), "sha256 must be populated");

    std::fs::remove_dir_all(&cache).ok();
}

#[tokio::test]
async fn charger_feed_falls_back_to_disk_cache_when_server_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/threat_feed.yaml"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    // Pre-seed a valid cache so the cascade has something to fall back to.
    let cache = tempdir_unique("fallback-cache");
    let meta = CacheMeta {
        sha256: "deadbeef".to_string(),
        fetched_at: chrono::Utc::now(),
        source: "remote".to_string(),
    };
    write_cache(&cache, VALID_YAML, &meta);

    // Force the cache to look stale so the cascade tries the remote first.
    // We do this by setting an old mtime — `set_modified` is the easiest
    // portable way in tests, but we can also just rely on `auto_refresh`
    // gating: the cache is "stale" if older than 24h, but our fixture is
    // brand-new. Instead, we trigger the remote path by deleting the YAML
    // mtime cache via filetime. The simplest, portable trick: pass the
    // freshly-fetched-at meta but a stale `mtime`. We rely on
    // `est_cache_perime` returning `true` for a missing file, so we
    // touch the YAML and then `set_modified` to far in the past.
    let yaml_path = cache.join(CACHE_FILENAME);
    let two_days_ago = std::time::SystemTime::now() - Duration::from_secs(48 * 3600);
    filetime::set_file_mtime(&yaml_path, filetime::FileTime::from_system_time(two_days_ago))
        .ok();

    let cfg = ThreatFeedConfig {
        url: format!("{}/threat_feed.yaml", server.uri()),
        auto_refresh_enabled: true,
        last_refresh_at: None,
    };
    let (flux, status) = refresh::charger_feed(&cfg, &cache, true).await;
    assert_eq!(
        status.source, "cache",
        "remote 500 should fall back to cache, got source={}",
        status.source
    );
    assert!(!flux.entrees.is_empty(), "cache must rehydrate entries");

    std::fs::remove_dir_all(&cache).ok();
}

#[tokio::test]
async fn charger_feed_falls_back_to_bundled_when_no_cache() {
    // No mock server URL is reachable; cache is empty → bundled fallback.
    let cache = tempdir_unique("fallback-bundled");
    let cfg = ThreatFeedConfig {
        url: "http://127.0.0.1:1/does-not-exist".to_string(),
        auto_refresh_enabled: true,
        last_refresh_at: None,
    };
    let (flux, status) = refresh::charger_feed(&cfg, &cache, true).await;
    assert_eq!(status.source, "bundled");
    assert!(
        !flux.entrees.is_empty(),
        "bundled feed must always have entries"
    );

    std::fs::remove_dir_all(&cache).ok();
}

#[tokio::test]
async fn charger_feed_skips_remote_when_outbound_disabled() {
    // A mock server is online but the outbound toggle is OFF — we MUST
    // never call it. To verify, we expect 0 hits on the mock.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/threat_feed.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(VALID_YAML))
        .expect(0)
        .mount(&server)
        .await;

    let cache = tempdir_unique("outbound-off");
    // Pre-seed cache so the fallback returns "cache".
    let meta = CacheMeta {
        sha256: "deadbeef".to_string(),
        fetched_at: chrono::Utc::now(),
        source: "remote".to_string(),
    };
    write_cache(&cache, VALID_YAML, &meta);

    let cfg = ThreatFeedConfig {
        url: format!("{}/threat_feed.yaml", server.uri()),
        auto_refresh_enabled: true,
        last_refresh_at: None,
    };
    let (flux, status) = refresh::charger_feed(&cfg, &cache, /* outbound */ false).await;
    assert_eq!(
        status.source, "cache",
        "outbound OFF must skip remote and read cache"
    );
    assert!(!flux.entrees.is_empty());

    std::fs::remove_dir_all(&cache).ok();
}

#[tokio::test]
async fn rafraichir_feed_rejects_invalid_yaml() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/threat_feed.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(INVALID_YAML))
        .mount(&server)
        .await;

    let cache = tempdir_unique("invalid-yaml");
    let url = format!("{}/threat_feed.yaml", server.uri());
    let err = refresh::rafraichir_feed(&url, &cache)
        .await
        .expect_err("invalid YAML must return Err");
    assert!(matches!(err, ThreatFeedError::Parse(_)));

    // Cache MUST NOT be overwritten when the remote payload is malformed.
    assert!(
        !cache.join(CACHE_FILENAME).exists(),
        "cache YAML must not be written on parse failure"
    );

    std::fs::remove_dir_all(&cache).ok();
}

#[tokio::test]
async fn charger_feed_falls_back_to_cache_when_invalid_yaml() {
    // Remote returns invalid YAML; cache exists and is valid. The
    // cascade must keep the cache intact and return it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/threat_feed.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(INVALID_YAML))
        .mount(&server)
        .await;

    let cache = tempdir_unique("invalid-yaml-cascade");
    let meta = CacheMeta {
        sha256: "deadbeef".to_string(),
        fetched_at: chrono::Utc::now(),
        source: "remote".to_string(),
    };
    write_cache(&cache, VALID_YAML, &meta);
    // Force the cache to look stale.
    let two_days_ago = std::time::SystemTime::now() - Duration::from_secs(48 * 3600);
    filetime::set_file_mtime(
        cache.join(CACHE_FILENAME),
        filetime::FileTime::from_system_time(two_days_ago),
    )
    .ok();

    let cfg = ThreatFeedConfig {
        url: format!("{}/threat_feed.yaml", server.uri()),
        auto_refresh_enabled: true,
        last_refresh_at: None,
    };
    let (flux, status) = refresh::charger_feed(&cfg, &cache, true).await;
    assert_eq!(status.source, "cache");
    assert_eq!(flux.version_feed, "test-2026-01-01");

    std::fs::remove_dir_all(&cache).ok();
}

#[tokio::test]
async fn depuis_yaml_parses_bundled_feed_shape() {
    // The crate-level helper is exercised in detail by the bundled-feed
    // tests; here we just pin the public re-export path used by the
    // refresh pipeline.
    let flux = FluxMenaces::depuis_yaml(VALID_YAML).unwrap();
    assert_eq!(flux.entrees.len(), 1);
    assert_eq!(flux.version_feed, "test-2026-01-01");
}
