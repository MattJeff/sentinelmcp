//! Integration tests for the Google Antigravity MCP discovery source.

use sentinel_discovery::sources::antigravity::detecter_avec_chemins;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Build `<home>/Library/Application Support/Antigravity/User/` and write
/// `settings.json` with the given contents.
fn ecrire_settings(home: &Path, contenu: &str) -> PathBuf {
    let dir = home
        .join("Library")
        .join("Application Support")
        .join("Antigravity")
        .join("User");
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join("settings.json");
    fs::write(&p, contenu).unwrap();
    p
}

/// Build `<home>/.antigravity/` and write `mcp.json`.
fn ecrire_mcp_json(home: &Path, contenu: &str) -> PathBuf {
    let dir = home.join(".antigravity");
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join("mcp.json");
    fs::write(&p, contenu).unwrap();
    p
}

/// Fake an `Antigravity.app` bundle under `<root>/Applications/Antigravity.app`.
fn ecrire_app(root: &Path) -> PathBuf {
    let app = root.join("Applications").join("Antigravity.app");
    fs::create_dir_all(app.join("Contents").join("MacOS")).unwrap();
    // Minimal Info.plist with a recognisable CFBundleShortVersionString.
    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>CFBundleShortVersionString</key>
    <string>0.1.2</string>
</dict>
</plist>"#;
    fs::write(app.join("Contents").join("Info.plist"), plist).unwrap();
    app
}

#[test]
fn parses_mcp_servers_block_anthropic_shape_from_mcp_json() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let contenu = r#"{
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"FS_TOKEN": "xxx"}
            },
            "remote": {
                "url": "https://mcp.example.com/sse",
                "type": "sse"
            }
        }
    }"#;
    ecrire_mcp_json(&home, contenu);

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1, "should detect antigravity from mcp.json");
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 2);

    let fs_srv = c.serveurs.iter().find(|s| s.nom == "fs").expect("fs entry");
    assert_eq!(fs_srv.commande.as_deref(), Some("npx"));
    assert_eq!(fs_srv.transport, "stdio");
    assert!(fs_srv.env_keys.contains(&"FS_TOKEN".to_string()));

    let remote = c
        .serveurs
        .iter()
        .find(|s| s.nom == "remote")
        .expect("remote entry");
    assert_eq!(remote.transport, "sse");
    assert_eq!(remote.url.as_deref(), Some("https://mcp.example.com/sse"));

    assert_eq!(c.configs.len(), 1);
    assert_eq!(c.configs[0].source_id, "antigravity");
}

#[test]
fn parses_mcp_dot_servers_block_vscode_shape_from_settings_json() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let settings = r#"{
        // VS-Code-fork JSONC
        "editor.fontSize": 14,
        "mcp.servers": {
            "git": {
                "command": "uvx",
                "args": ["mcp-server-git"]
            }
        }
    }"#;
    ecrire_settings(&home, settings);

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1, "should detect antigravity from settings alone");
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 1);
    let git = &c.serveurs[0];
    assert_eq!(git.nom, "git");
    assert_eq!(git.commande.as_deref(), Some("uvx"));
    assert_eq!(git.transport, "stdio");
    assert!(
        c.notes.iter().all(|n| !n.contains("failed to parse")),
        "expected clean JSONC parse, got notes {:?}",
        c.notes
    );
}

#[test]
fn app_present_but_no_config_yields_no_mcp_block_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let app = ecrire_app(tmp.path());

    let res = detecter_avec_chemins(&home, Some(&app));
    assert_eq!(res.len(), 1, "app alone should still yield a detection");
    let c = &res[0];
    assert!(c.serveurs.is_empty());
    assert_eq!(c.version.as_deref(), Some("0.1.2"));
    assert!(c.binary_path.is_some());
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected 'no MCP block' note, got {:?}",
        c.notes
    );
}

#[test]
fn missing_settings_and_no_app_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-empty");
    fs::create_dir_all(&home).unwrap();
    let res = detecter_avec_chemins(&home, None);
    assert!(res.is_empty(), "no signals at all should yield nothing");
}

#[test]
fn merges_both_keys_when_both_present() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    // settings.json: VS Code shape
    ecrire_settings(
        &home,
        r#"{
            "mcp.servers": {
                "alpha": { "command": "alpha-bin" }
            }
        }"#,
    );
    // ~/.antigravity/mcp.json: Anthropic shape
    ecrire_mcp_json(
        &home,
        r#"{
            "mcpServers": {
                "beta": { "command": "beta-bin", "args": ["--port", "42"] }
            }
        }"#,
    );

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 2);
    assert!(c.serveurs.iter().any(|s| s.nom == "alpha"));
    assert!(c.serveurs.iter().any(|s| s.nom == "beta"));
    assert_eq!(c.configs.len(), 2, "both configs should be recorded");
}

#[tokio::test]
#[ignore]
async fn host_probe_for_manual_verify() {
    use sentinel_discovery::sources::SourceClient;
    let s = sentinel_discovery::sources::antigravity::SourceAntigravity;
    let r = s.detecter().await;
    eprintln!("HOST detected: {} antigravity client(s)", r.len());
    for c in &r {
        eprintln!(
            "  binary={:?} version={:?} servers={} notes={:?} meta={:?}",
            c.binary_path,
            c.version,
            c.serveurs.len(),
            c.notes,
            c.meta
        );
        for srv in &c.serveurs {
            eprintln!(
                "    - {} transport={} cmd={:?} url={:?}",
                srv.nom, srv.transport, srv.commande, srv.url
            );
        }
    }
}
