//! Integration tests for the Windsurf discovery source.
//!
//! Each test stands up a synthetic on-disk layout (fake `$HOME`, fake
//! `/Applications`) so we can exercise the parser without touching the real
//! user environment.

use sentinel_discovery::model::ClientKind;
use sentinel_discovery::sources::windsurf::SourceWindsurf;
use sentinel_discovery::sources::SourceClient;

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

fn write_config(home: &Path, body: &str) -> PathBuf {
    let dir = home.join(".codeium/windsurf");
    fs::create_dir_all(&dir).expect("create windsurf config dir");
    let path = dir.join("mcp_config.json");
    fs::write(&path, body).expect("write mcp_config.json");
    path
}

fn write_fake_app(apps: &Path, version: Option<&str>) -> PathBuf {
    let app = apps.join("Windsurf.app");
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    // Fake the Electron binary so we can prove the source picked it up.
    fs::write(app.join("Contents/MacOS/Electron"), b"#!/bin/sh\n").unwrap();
    if let Some(v) = version {
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Windsurf</string>
    <key>CFBundleShortVersionString</key>
    <string>{v}</string>
</dict>
</plist>
"#
        );
        fs::write(app.join("Contents/Info.plist"), plist).unwrap();
    }
    app
}

#[tokio::test]
async fn synthetic_config_with_two_servers_is_parsed() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    let config_body = r#"
    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
          "env": { "MCP_DEBUG": "1" }
        },
        "remote": {
          "transport": "http",
          "url": "https://example.com/mcp",
          "disabled": true
        }
      }
    }
    "#;
    write_config(home.path(), config_body);
    write_fake_app(apps.path(), Some("1.2.3"));

    let source = SourceWindsurf::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1, "expected one Windsurf client");
    let client = &result[0];

    assert_eq!(client.kind, ClientKind::Windsurf);
    assert_eq!(client.version.as_deref(), Some("1.2.3"));
    assert_eq!(client.serveurs.len(), 2);

    let by_name: std::collections::BTreeMap<_, _> = client
        .serveurs
        .iter()
        .map(|s| (s.nom.as_str(), s))
        .collect();

    let fs_entry = by_name.get("filesystem").expect("filesystem server");
    assert_eq!(fs_entry.transport, "stdio");
    assert_eq!(fs_entry.commande.as_deref(), Some("npx"));
    assert_eq!(fs_entry.args.len(), 3);
    assert_eq!(fs_entry.env_keys, vec!["MCP_DEBUG".to_string()]);
    assert!(!fs_entry.disabled);

    let remote = by_name.get("remote").expect("remote server");
    assert_eq!(remote.transport, "http");
    assert_eq!(remote.url.as_deref(), Some("https://example.com/mcp"));
    assert!(remote.disabled);

    assert_eq!(client.configs.len(), 1);
    assert!(client.configs[0]
        .config_path
        .ends_with(".codeium/windsurf/mcp_config.json"));
}

#[tokio::test]
async fn missing_config_and_missing_app_returns_empty() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    let source = SourceWindsurf::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert!(
        result.is_empty(),
        "expected no client when neither app nor config exist, got: {result:?}"
    );
}

#[tokio::test]
async fn app_present_but_no_config_sets_binary_path_and_notes() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();
    write_fake_app(apps.path(), Some("2.0.0"));

    let source = SourceWindsurf::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1);
    let client = &result[0];

    let binary = client.binary_path.as_ref().expect("binary_path set");
    assert!(
        binary.ends_with("Windsurf.app/Contents/MacOS/Electron"),
        "unexpected binary path: {}",
        binary.display()
    );

    assert!(client.serveurs.is_empty());
    assert!(client.configs.is_empty());

    let has_missing_config_note = client
        .notes
        .iter()
        .any(|n| n.contains("no mcp config at"));
    assert!(
        has_missing_config_note,
        "expected a 'no mcp config' note, got {:?}",
        client.notes
    );
    assert_eq!(client.version.as_deref(), Some("2.0.0"));
}

#[tokio::test]
async fn bad_json_emits_parse_note() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();
    write_config(home.path(), "{ this is not valid json ");

    let source = SourceWindsurf::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1);
    let client = &result[0];

    assert!(client.serveurs.is_empty());
    let has_parse_note = client
        .notes
        .iter()
        .any(|n| n.to_lowercase().contains("parse"));
    assert!(
        has_parse_note,
        "expected a 'parse' note, got {:?}",
        client.notes
    );
}

/// Probe this actual host. Marked `#[ignore]` so it doesn't add noise to
/// normal CI runs; invoke with `cargo test -p sentinel-discovery --test
/// windsurf -- --ignored probe_live_host --nocapture` to see what's there.
#[tokio::test]
#[ignore]
async fn probe_live_host() {
    let result = SourceWindsurf::new().detecter().await;
    if result.is_empty() {
        eprintln!("[windsurf-probe] no Windsurf install detected on this host");
        return;
    }
    for c in &result {
        eprintln!(
            "[windsurf-probe] kind={:?} version={:?} binary={:?}",
            c.kind, c.version, c.binary_path
        );
        for s in &c.serveurs {
            eprintln!(
                "[windsurf-probe]   server name={} transport={} command={:?} args={:?} disabled={}",
                s.nom, s.transport, s.commande, s.args, s.disabled
            );
        }
        for n in &c.notes {
            eprintln!("[windsurf-probe]   note: {n}");
        }
    }
}

#[tokio::test]
async fn cli_dir_only_still_produces_a_client() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();
    fs::create_dir_all(home.path().join(".codeium/windsurf-cli")).unwrap();

    let source = SourceWindsurf::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1);
    let client = &result[0];
    assert!(client.meta.contains_key("cli_dir"));
}
