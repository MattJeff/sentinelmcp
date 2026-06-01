//! Integration tests for the Cursor MCP discovery source.

use sentinel_discovery::sources::cursor::detecter_avec_chemins;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Build a fake `Cursor.app` bundle under `root` with the given short version.
fn faux_cursor_app(root: &std::path::Path, version: &str) -> PathBuf {
    let app = root.join("Cursor.app");
    let macos = app.join("Contents").join("MacOS");
    fs::create_dir_all(&macos).unwrap();
    fs::write(macos.join("Cursor"), b"#!/bin/sh\nexit 0\n").unwrap();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Cursor</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundleVersion</key><string>{version}</string>
</dict></plist>
"#
    );
    fs::write(app.join("Contents").join("Info.plist"), plist).unwrap();
    app
}

#[test]
fn parses_two_stdio_and_one_sse_server() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let cursor_dir = home.join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    let config = r#"{
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"FOO_TOKEN": "secret", "BAR": "value"}
            },
            "git": {
                "command": "uvx",
                "args": ["mcp-server-git"]
            },
            "remote": {
                "url": "https://example.com/mcp",
                "type": "sse"
            }
        }
    }"#;
    fs::write(cursor_dir.join("mcp.json"), config).unwrap();

    // App path that does not exist on disk.
    let app = tmp.path().join("nope/Cursor.app");

    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1, "should detect cursor from config alone");
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 3);

    let fs_srv = c.serveurs.iter().find(|s| s.nom == "fs").expect("fs server");
    assert_eq!(fs_srv.transport, "stdio");
    assert_eq!(fs_srv.commande.as_deref(), Some("npx"));
    assert_eq!(fs_srv.args.len(), 3);
    assert!(fs_srv.env_keys.contains(&"FOO_TOKEN".to_string()));
    assert!(fs_srv.env_keys.contains(&"BAR".to_string()));
    assert!(fs_srv.url.is_none());

    let git_srv = c.serveurs.iter().find(|s| s.nom == "git").expect("git server");
    assert_eq!(git_srv.transport, "stdio");
    assert_eq!(git_srv.commande.as_deref(), Some("uvx"));

    let remote = c
        .serveurs
        .iter()
        .find(|s| s.nom == "remote")
        .expect("remote server");
    assert_eq!(remote.transport, "sse");
    assert_eq!(remote.url.as_deref(), Some("https://example.com/mcp"));
    assert!(remote.commande.is_none());

    assert_eq!(c.configs.len(), 1);
    assert_eq!(c.configs[0].source_id, "cursor");
}

#[test]
fn missing_config_and_missing_app_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-empty");
    fs::create_dir_all(&home).unwrap();
    let app = tmp.path().join("nowhere/Cursor.app");

    let res = detecter_avec_chemins(&home, &app);
    assert!(res.is_empty(), "no config and no app should yield nothing");
}

#[test]
fn app_detected_without_config_returns_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home2");
    fs::create_dir_all(&home).unwrap();
    let app = faux_cursor_app(tmp.path(), "0.42.3");

    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert!(c.binary_path.is_some(), "binary_path must be set");
    let bp = c.binary_path.as_ref().unwrap();
    assert!(bp.ends_with("Contents/MacOS/Cursor"), "got {:?}", bp);
    assert!(c.serveurs.is_empty(), "no servers when config absent");
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected 'no MCP block' note, got {:?}",
        c.notes
    );
    assert_eq!(c.version.as_deref(), Some("0.42.3"));
}

#[test]
fn garbage_json_produces_parse_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home3");
    let cursor_dir = home.join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    fs::write(cursor_dir.join("mcp.json"), "{ this is not json ::::").unwrap();

    let app = tmp.path().join("missing/Cursor.app");
    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert!(
        c.notes.iter().any(|n| n.to_lowercase().contains("parse")),
        "expected a parse note, got {:?}",
        c.notes
    );
    assert!(c.serveurs.is_empty());
}

#[test]
fn no_mcp_servers_key_produces_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home4");
    let cursor_dir = home.join(".cursor");
    fs::create_dir_all(&cursor_dir).unwrap();
    fs::write(cursor_dir.join("mcp.json"), r#"{"other":"thing"}"#).unwrap();

    let app = tmp.path().join("missing/Cursor.app");
    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    assert!(res[0]
        .notes
        .iter()
        .any(|n| n.contains("no MCP block")));
    assert!(res[0].serveurs.is_empty());
}

#[tokio::test]
#[ignore]
async fn host_probe_for_manual_verify() {
    use sentinel_discovery::sources::SourceClient;
    let s = sentinel_discovery::sources::cursor::SourceCursor;
    let r = s.detecter().await;
    eprintln!("HOST detected: {} client(s)", r.len());
    for c in &r {
        eprintln!("  binary={:?} version={:?} servers={} notes={:?}",
            c.binary_path, c.version, c.serveurs.len(), c.notes);
        for srv in &c.serveurs {
            eprintln!("    - {} transport={} cmd={:?} url={:?}",
                srv.nom, srv.transport, srv.commande, srv.url);
        }
    }
}
