//! Integration tests for the Claude Desktop discovery source (agent D1).
//!
//! Run with: `cargo test -p sentinel-discovery --test claude_desktop`.

use sentinel_discovery::sources::claude_desktop::{detecter_aux, SourceClaudeDesktop};
use sentinel_discovery::sources::SourceClient;
use sentinel_discovery::ClientKind;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Tempdir helper — keeps us off of `tempfile` (not in the workspace deps).
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
        let path = std::env::temp_dir().join(format!("sentinel_d1_{prefix}_{pid}_{now}_{n}"));
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

// Returns 4 paths: (config, app_bundle, app_binary, info_plist).
// `app_bundle` and friends point under the tempdir but do NOT exist on disk.
fn unused_app_paths(td: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let app = td.p().join("nope_app");
    let bin = app.join("Contents/MacOS/Claude");
    let plist = app.join("Contents/Info.plist");
    (td.p().join("claude_desktop_config.json"), app, bin, plist)
}

// ---------------------------------------------------------------------------
// Test 1: skip cleanly when Claude Desktop is not installed.
// ---------------------------------------------------------------------------

#[test]
fn absent_si_rien_installe() {
    let td = TempDir::new("absent");
    let (cfg, app, bin, plist) = unused_app_paths(&td);
    let out = detecter_aux(&cfg, &app, &bin, &plist);
    assert!(
        out.is_empty(),
        "no config + no app should yield an empty Vec, got {} entries",
        out.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2: synthetic config — full field extraction including env_keys order.
// ---------------------------------------------------------------------------

#[test]
fn parse_config_synthetique_complet() {
    let td = TempDir::new("ok");
    let (cfg, app, bin, plist) = unused_app_paths(&td);
    let json = r#"
    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"],
          "env": { "ZZZ": "1", "AAA": "2", "MMM": "3" }
        },
        "github": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-github"],
          "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xxx" },
          "disabled": true
        },
        "remote": {
          "url": "https://example.com/mcp"
        }
      }
    }
    "#;
    fs::write(&cfg, json).unwrap();

    let out = detecter_aux(&cfg, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert_eq!(c.kind, ClientKind::ClaudeDesktop);
    assert_eq!(c.configs.len(), 1, "config file must be recorded");
    assert_eq!(c.configs[0].source_id, "claude-desktop");
    assert_eq!(c.configs[0].config_path, cfg);
    assert_eq!(c.serveurs.len(), 3, "three servers declared");

    // filesystem
    let fs_srv = c.serveurs.iter().find(|s| s.nom == "filesystem").unwrap();
    assert_eq!(fs_srv.transport, "stdio");
    assert_eq!(fs_srv.commande.as_deref(), Some("npx"));
    assert_eq!(
        fs_srv.args,
        vec![
            "-y".to_string(),
            "@modelcontextprotocol/server-filesystem".to_string(),
            "/Users/me".to_string(),
        ]
    );
    assert_eq!(
        fs_srv.env_keys,
        vec!["AAA".to_string(), "MMM".to_string(), "ZZZ".to_string()],
        "env keys must be sorted alphabetically"
    );
    assert!(!fs_srv.disabled);
    assert!(fs_srv.url.is_none());

    // github (disabled)
    let gh = c.serveurs.iter().find(|s| s.nom == "github").unwrap();
    assert_eq!(gh.transport, "stdio");
    assert!(gh.disabled, "explicit disabled:true must be honoured");
    assert_eq!(
        gh.env_keys,
        vec!["GITHUB_PERSONAL_ACCESS_TOKEN".to_string()]
    );

    // remote (no command → http)
    let r = c.serveurs.iter().find(|s| s.nom == "remote").unwrap();
    assert_eq!(r.transport, "http");
    assert_eq!(r.url.as_deref(), Some("https://example.com/mcp"));
    assert!(r.commande.is_none());
}

// ---------------------------------------------------------------------------
// Test 3: malformed JSON still produces a ClientDecouvert with a "parse" note.
// ---------------------------------------------------------------------------

#[test]
fn json_malforme_donne_note_parse() {
    let td = TempDir::new("bad");
    let (cfg, app, bin, plist) = unused_app_paths(&td);
    fs::write(&cfg, "{ this is not valid json :::").unwrap();

    let out = detecter_aux(&cfg, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert!(c.serveurs.is_empty(), "broken config → no servers");
    assert!(
        c.notes.iter().any(|n| n.to_lowercase().contains("parse")),
        "notes should mention parse error, got {:?}",
        c.notes
    );
}

// ---------------------------------------------------------------------------
// Test 4: empty mcpServers ⇒ empty servers and a "no MCP block" note.
// ---------------------------------------------------------------------------

#[test]
fn bloc_mcp_vide_note_no_mcp() {
    let td = TempDir::new("empty");
    let (cfg, app, bin, plist) = unused_app_paths(&td);
    fs::write(&cfg, r#"{ "mcpServers": {} }"#).unwrap();

    let out = detecter_aux(&cfg, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert!(c.serveurs.is_empty());
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected a 'no MCP block' note, got {:?}",
        c.notes
    );
}

// ---------------------------------------------------------------------------
// Test 5: a config with no mcpServers key at all also yields "no MCP block".
// ---------------------------------------------------------------------------

#[test]
fn config_sans_mcpservers_donne_note_no_mcp() {
    let td = TempDir::new("nomcp");
    let (cfg, app, bin, plist) = unused_app_paths(&td);
    fs::write(&cfg, r#"{ "preferences": { "foo": "bar" } }"#).unwrap();

    let out = detecter_aux(&cfg, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    assert!(c.serveurs.is_empty());
    assert!(c.notes.iter().any(|n| n.contains("no MCP block")));
}

// ---------------------------------------------------------------------------
// Test 6: smoke-test the real-host detection (never panics, prints summary).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn smoke_host_reel() {
    let src = SourceClaudeDesktop;
    let found = src.detecter().await;
    if found.is_empty() {
        eprintln!("[D1 host probe] Claude Desktop not detected on this Mac.");
    } else {
        let c = &found[0];
        eprintln!(
            "[D1 host probe] Claude Desktop detected: version={:?}, binary={:?}, servers={}, notes={:?}",
            c.version,
            c.binary_path,
            c.serveurs.len(),
            c.notes,
        );
        for s in &c.serveurs {
            eprintln!(
                "  - {} (transport={}, cmd={:?}, args={:?}, env_keys={:?}, disabled={})",
                s.nom, s.transport, s.commande, s.args, s.env_keys, s.disabled
            );
        }
    }
    // Test must never panic; that's the contract.
    assert!(found.len() <= 1);
}
