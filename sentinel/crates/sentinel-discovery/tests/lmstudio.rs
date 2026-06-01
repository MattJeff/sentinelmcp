//! Integration tests for the LM Studio discovery source (agent D12).
//!
//! Run with: `cargo test -p sentinel-discovery --test lmstudio`.

use sentinel_discovery::sources::lmstudio::{detecter_aux, SourceLmstudio};
use sentinel_discovery::sources::SourceClient;
use sentinel_discovery::ClientKind;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Tempdir helper — keeps us off of `tempfile` (matches the D1 pattern).
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("sentinel_d12_{prefix}_{pid}_{now}_{n}"));
        fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }
    fn p(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Returns 5 paths: (primary_cfg, legacy_cfg, models_cache, app_bundle, app_binary, info_plist).
/// None of these exist on disk by default — tests create what they need.
fn unused_paths(td: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let primary = td.p().join(".lmstudio/mcp.json");
    let legacy = td.p().join(".cache/lm-studio/mcp.json");
    let models = td.p().join(".lmstudio/models");
    let app = td.p().join("nope_app");
    let bin = app.join("Contents/MacOS/LM Studio");
    let plist = app.join("Contents/Info.plist");
    (primary, legacy, models, app, bin, plist)
}

// ---------------------------------------------------------------------------
// Test 1: nothing on disk → empty Vec.
// ---------------------------------------------------------------------------

#[test]
fn absent_si_rien_installe() {
    let td = TempDir::new("absent");
    let (primary, legacy, models, app, bin, plist) = unused_paths(&td);
    let out = detecter_aux(&[primary, legacy], &models, &app, &bin, &plist);
    assert!(
        out.is_empty(),
        "no config + no app + no models cache should yield empty, got {} entries",
        out.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2: synthetic mcp.json with 2 servers parsed.
// ---------------------------------------------------------------------------

#[test]
fn parse_config_synthetique_deux_serveurs() {
    let td = TempDir::new("ok");
    let (primary, legacy, models, app, bin, plist) = unused_paths(&td);
    fs::create_dir_all(primary.parent().unwrap()).unwrap();
    let json = r#"
    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"],
          "env": { "ZZZ": "1", "AAA": "2" }
        },
        "weather": {
          "url": "https://example.com/weather/mcp"
        }
      }
    }
    "#;
    fs::write(&primary, json).unwrap();

    let out = detecter_aux(&[primary.clone(), legacy], &models, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert_eq!(c.kind, ClientKind::LmStudio);
    assert_eq!(c.configs.len(), 1, "config file must be recorded");
    assert_eq!(c.configs[0].source_id, "lmstudio");
    assert_eq!(c.configs[0].config_path, primary);
    assert_eq!(c.serveurs.len(), 2);

    let fs_srv = c.serveurs.iter().find(|s| s.nom == "filesystem").unwrap();
    assert_eq!(fs_srv.transport, "stdio");
    assert_eq!(fs_srv.commande.as_deref(), Some("npx"));
    assert_eq!(
        fs_srv.env_keys,
        vec!["AAA".to_string(), "ZZZ".to_string()],
        "env keys must be sorted alphabetically"
    );
    assert!(!fs_srv.disabled);

    let w = c.serveurs.iter().find(|s| s.nom == "weather").unwrap();
    assert_eq!(w.transport, "http");
    assert_eq!(w.url.as_deref(), Some("https://example.com/weather/mcp"));
    assert!(w.commande.is_none());
}

// ---------------------------------------------------------------------------
// Test 3: app bundle present, no MCP config → "no MCP block" note.
// ---------------------------------------------------------------------------

#[test]
fn app_present_pas_de_config_donne_note() {
    let td = TempDir::new("app");
    let (primary, legacy, models, _, bin, plist) = unused_paths(&td);
    // Fabricate an "app bundle" the detector can see.
    let fake_app = td.p().join("LM Studio.app");
    fs::create_dir_all(&fake_app).unwrap();

    let out = detecter_aux(&[primary, legacy], &models, &fake_app, &bin, &plist);
    assert_eq!(out.len(), 1, "app present is enough to surface a client");
    let c = &out[0];
    assert_eq!(c.kind, ClientKind::LmStudio);
    assert!(c.serveurs.is_empty(), "no config → no servers");
    assert_eq!(c.binary_path.as_deref(), Some(fake_app.as_path()));
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected a 'no MCP block' note, got {:?}",
        c.notes
    );
}

// ---------------------------------------------------------------------------
// Test 4: models cache exists but no MCP config → "no MCP block" note.
// ---------------------------------------------------------------------------

#[test]
fn models_cache_seul_donne_note_no_mcp() {
    let td = TempDir::new("models");
    let (primary, legacy, models, app, bin, plist) = unused_paths(&td);
    fs::create_dir_all(&models).unwrap();

    let out = detecter_aux(&[primary, legacy], &models, &app, &bin, &plist);
    assert_eq!(out.len(), 1, "models cache alone is enough to surface client");
    let c = &out[0];
    assert_eq!(c.kind, ClientKind::LmStudio);
    assert!(c.serveurs.is_empty());
    assert!(
        c.meta.get("models_cache").is_some(),
        "models cache path should be reported in meta"
    );
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected 'no MCP block' note, got {:?}",
        c.notes
    );
}

// ---------------------------------------------------------------------------
// Test 5: legacy ~/.cache/lm-studio/mcp.json path is honoured.
// ---------------------------------------------------------------------------

#[test]
fn config_legacy_est_lu() {
    let td = TempDir::new("legacy");
    let (primary, legacy, models, app, bin, plist) = unused_paths(&td);
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(
        &legacy,
        r#"{ "mcpServers": { "only": { "command": "echo", "args": ["hi"] } } }"#,
    )
    .unwrap();

    let out = detecter_aux(&[primary, legacy.clone()], &models, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert_eq!(c.configs.len(), 1);
    assert_eq!(c.configs[0].config_path, legacy);
    assert_eq!(c.serveurs.len(), 1);
    assert_eq!(c.serveurs[0].nom, "only");
}

// ---------------------------------------------------------------------------
// Test 6: empty mcpServers object → "no MCP block" note.
// ---------------------------------------------------------------------------

#[test]
fn bloc_mcp_vide_note_no_mcp() {
    let td = TempDir::new("empty");
    let (primary, legacy, models, app, bin, plist) = unused_paths(&td);
    fs::create_dir_all(primary.parent().unwrap()).unwrap();
    fs::write(&primary, r#"{ "mcpServers": {} }"#).unwrap();

    let out = detecter_aux(&[primary, legacy], &models, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert!(c.serveurs.is_empty());
    assert!(c.notes.iter().any(|n| n.contains("no MCP block")));
}

// ---------------------------------------------------------------------------
// Test 7: smoke-test the real-host detection (never panics, prints summary).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smoke_host_reel() {
    let src = SourceLmstudio;
    let found = src.detecter().await;
    if found.is_empty() {
        eprintln!("[D12 host probe] LM Studio not detected on this Mac.");
    } else {
        let c = &found[0];
        eprintln!(
            "[D12 host probe] LM Studio detected: version={:?}, binary={:?}, servers={}, notes={:?}, meta={:?}",
            c.version,
            c.binary_path,
            c.serveurs.len(),
            c.notes,
            c.meta,
        );
        for s in &c.serveurs {
            eprintln!(
                "  - {} (transport={}, cmd={:?}, args={:?}, env_keys={:?}, disabled={})",
                s.nom, s.transport, s.commande, s.args, s.env_keys, s.disabled
            );
        }
    }
    assert!(found.len() <= 1);
}
