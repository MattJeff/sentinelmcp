//! Integration tests for the Zed editor discovery source.
//!
//! Each test stands up a synthetic on-disk layout (fake `$HOME`, fake
//! `/Applications`) so we can exercise the JSONC parser, the
//! `context_servers` block, and the `extensions` block without touching the
//! real user environment.

use sentinel_discovery::model::ClientKind;
use sentinel_discovery::sources::zed::SourceZed;
use sentinel_discovery::sources::SourceClient;

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

fn write_settings(home: &Path, body: &str) -> PathBuf {
    let dir = home.join(".config/zed");
    fs::create_dir_all(&dir).expect("create zed config dir");
    let path = dir.join("settings.json");
    fs::write(&path, body).expect("write zed settings.json");
    path
}

fn write_fake_app(apps: &Path, version: Option<&str>) -> PathBuf {
    let app = apps.join("Zed.app");
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    fs::write(app.join("Contents/MacOS/zed"), b"#!/bin/sh\n").unwrap();
    if let Some(v) = version {
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Zed</string>
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
async fn synthetic_settings_with_two_context_servers_is_parsed() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    let body = r#"
    {
      "context_servers": {
        "github": {
          "source": "custom",
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-github"],
          "env": { "GITHUB_TOKEN": "ghp_xxx" }
        },
        "remote-thing": {
          "source": "custom",
          "transport": "http",
          "url": "https://example.com/mcp",
          "enabled": false
        }
      }
    }
    "#;
    write_settings(home.path(), body);
    write_fake_app(apps.path(), Some("0.150.0"));

    let source = SourceZed::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1, "expected one Zed client");
    let client = &result[0];

    assert_eq!(client.kind, ClientKind::Zed);
    assert_eq!(client.version.as_deref(), Some("0.150.0"));
    assert_eq!(client.serveurs.len(), 2);

    let by_name: std::collections::BTreeMap<_, _> = client
        .serveurs
        .iter()
        .map(|s| (s.nom.as_str(), s))
        .collect();

    let gh = by_name.get("github").expect("github server");
    assert_eq!(gh.transport, "stdio");
    assert_eq!(gh.commande.as_deref(), Some("npx"));
    assert_eq!(gh.args.len(), 2);
    assert_eq!(gh.env_keys, vec!["GITHUB_TOKEN".to_string()]);
    assert!(!gh.disabled);

    let remote = by_name.get("remote-thing").expect("remote-thing server");
    assert_eq!(remote.transport, "http");
    assert_eq!(remote.url.as_deref(), Some("https://example.com/mcp"));
    assert!(remote.disabled, "enabled:false should map to disabled:true");

    assert_eq!(client.configs.len(), 1);
    assert!(client.configs[0]
        .config_path
        .ends_with(".config/zed/settings.json"));
}

#[tokio::test]
async fn jsonc_with_line_and_block_comments_is_parsed() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    // Note the `//` line comments, `/* … */` block comments, and a `//`
    // sequence that appears *inside* a string (https://…) which must NOT
    // be treated as a comment.
    let body = r#"
    // Top-level Zed config
    {
      /* user-tuned MCP servers */
      "context_servers": {
        // GitHub MCP
        "github": {
          "source": "custom",
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-github"], // inline
          "env": { "GITHUB_TOKEN": "ghp_xxx" }
        },
        "remote": {
          "transport": "http",
          /* multi
             line
             comment */
          "url": "https://example.com/mcp"
        }
      }
    }
    "#;
    write_settings(home.path(), body);
    write_fake_app(apps.path(), Some("0.151.0"));

    let source = SourceZed::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1);
    let client = &result[0];

    assert_eq!(client.serveurs.len(), 2);
    let by_name: std::collections::BTreeMap<_, _> = client
        .serveurs
        .iter()
        .map(|s| (s.nom.as_str(), s))
        .collect();

    let remote = by_name.get("remote").expect("remote server");
    assert_eq!(
        remote.url.as_deref(),
        Some("https://example.com/mcp"),
        "the // inside the URL must not be treated as a comment"
    );

    let parse_failed = client
        .notes
        .iter()
        .any(|n| n.contains("failed to parse"));
    assert!(
        !parse_failed,
        "expected JSONC parse to succeed, notes: {:?}",
        client.notes
    );
}

#[tokio::test]
async fn missing_settings_and_missing_app_returns_empty() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    let source = SourceZed::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert!(
        result.is_empty(),
        "expected no Zed client when neither app nor settings exist, got: {result:?}"
    );
}

#[tokio::test]
async fn extensions_only_block_marks_as_extension_declared() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    let body = r#"
    {
      "extensions": {
        "mcp-server-github": { "enabled": true },
        "mcp-server-jira":  true,
        "some-unrelated-theme": { "enabled": true },
        "mcp-server-disabled": { "enabled": false }
      }
    }
    "#;
    write_settings(home.path(), body);
    write_fake_app(apps.path(), Some("0.152.0"));

    let source = SourceZed::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1);
    let client = &result[0];

    // Only the two enabled, MCP-looking extensions should surface.
    let names: std::collections::BTreeSet<_> = client
        .serveurs
        .iter()
        .map(|s| s.nom.clone())
        .collect();
    assert!(names.contains("mcp-server-github"), "got names {names:?}");
    assert!(names.contains("mcp-server-jira"), "got names {names:?}");
    assert!(
        !names.contains("some-unrelated-theme"),
        "themes must not be reported as MCP servers, got {names:?}"
    );
    assert!(
        !names.contains("mcp-server-disabled"),
        "disabled extensions must not be reported, got {names:?}"
    );

    // Notes should explain that these are extension-declared.
    let has_extension_declared_note = client
        .notes
        .iter()
        .any(|n| n.contains("extension-declared"));
    assert!(
        has_extension_declared_note,
        "expected an 'extension-declared' note, got {:?}",
        client.notes
    );

    // Extension-declared entries have no concrete command.
    let gh = client
        .serveurs
        .iter()
        .find(|s| s.nom == "mcp-server-github")
        .expect("mcp-server-github entry");
    assert!(gh.commande.is_none());
    assert!(gh.args.is_empty());
}

#[tokio::test]
async fn legacy_application_support_path_is_picked_up() {
    let home = TempDir::new().unwrap();
    let apps = TempDir::new().unwrap();

    let dir = home.path().join("Library/Application Support/Zed");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("settings.json");
    fs::write(
        &path,
        r#"{ "context_servers": { "fs": { "command": "npx", "args": ["-y", "fs"] } } }"#,
    )
    .unwrap();
    write_fake_app(apps.path(), Some("0.153.0"));

    let source = SourceZed::new()
        .with_home(home.path())
        .with_applications(apps.path());

    let result = source.detecter().await;
    assert_eq!(result.len(), 1);
    let client = &result[0];

    assert_eq!(client.serveurs.len(), 1);
    assert_eq!(client.serveurs[0].nom, "fs");
    assert!(client.configs[0]
        .config_path
        .ends_with("Library/Application Support/Zed/settings.json"));
}

/// Probe this actual host. Marked `#[ignore]` so it doesn't add noise to
/// normal CI runs; invoke with:
///   cargo test -p sentinel-discovery --test zed -- --ignored probe_live_host --nocapture
#[tokio::test]
#[ignore]
async fn probe_live_host() {
    let result = SourceZed::new().detecter().await;
    if result.is_empty() {
        eprintln!("[zed-probe] no Zed install detected on this host");
        return;
    }
    for c in &result {
        eprintln!(
            "[zed-probe] kind={:?} version={:?} binary={:?}",
            c.kind, c.version, c.binary_path
        );
        for s in &c.serveurs {
            eprintln!(
                "[zed-probe]   server name={} transport={} command={:?} args={:?} disabled={}",
                s.nom, s.transport, s.commande, s.args, s.disabled
            );
        }
        for n in &c.notes {
            eprintln!("[zed-probe]   note: {n}");
        }
    }
}
