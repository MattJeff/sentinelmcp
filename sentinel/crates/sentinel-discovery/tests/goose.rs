//! Integration tests for the Goose MCP discovery source.

use sentinel_discovery::sources::goose::detecter_avec_chemins;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Build a fake `Goose.app` bundle under `root` with the given short version.
fn faux_goose_app(root: &std::path::Path, version: &str) -> PathBuf {
    let app = root.join("Goose.app");
    let macos = app.join("Contents").join("MacOS");
    fs::create_dir_all(&macos).unwrap();
    fs::write(macos.join("Goose"), b"#!/bin/sh\nexit 0\n").unwrap();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Goose</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundleVersion</key><string>{version}</string>
</dict></plist>
"#
    );
    fs::write(app.join("Contents").join("Info.plist"), plist).unwrap();
    app
}

fn ecrire_config(home: &std::path::Path, contenu: &str) -> PathBuf {
    let goose_dir = home.join(".config").join("goose");
    fs::create_dir_all(&goose_dir).unwrap();
    let p = goose_dir.join("config.yaml");
    fs::write(&p, contenu).unwrap();
    p
}

#[test]
fn parses_two_stdio_extensions() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let yaml = r#"
extensions:
  github:
    type: stdio
    cmd: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    envs:
      GITHUB_TOKEN: secret
      OTHER: value
  filesystem:
    type: stdio
    cmd: uvx
    args: ["mcp-server-filesystem", "/tmp"]
"#;
    ecrire_config(&home, yaml);

    let app = tmp.path().join("nope/Goose.app");
    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1, "should detect goose from config alone");
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 2, "expected two stdio extensions");

    let gh = c.serveurs.iter().find(|s| s.nom == "github").expect("github");
    assert_eq!(gh.transport, "stdio");
    assert_eq!(gh.commande.as_deref(), Some("npx"));
    assert_eq!(gh.args.len(), 2);
    assert!(gh.env_keys.contains(&"GITHUB_TOKEN".to_string()));
    assert!(gh.env_keys.contains(&"OTHER".to_string()));
    assert!(gh.url.is_none());

    let fs_srv = c
        .serveurs
        .iter()
        .find(|s| s.nom == "filesystem")
        .expect("filesystem");
    assert_eq!(fs_srv.transport, "stdio");
    assert_eq!(fs_srv.commande.as_deref(), Some("uvx"));
    assert_eq!(fs_srv.args, vec!["mcp-server-filesystem", "/tmp"]);

    assert_eq!(c.configs.len(), 1);
    assert_eq!(c.configs[0].source_id, "goose");
}

#[test]
fn builtin_extension_is_skipped() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let yaml = r#"
extensions:
  brave:
    type: builtin
    name: brave
  github:
    type: stdio
    cmd: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
"#;
    ecrire_config(&home, yaml);

    let app = tmp.path().join("nope/Goose.app");
    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 1, "only stdio should remain");
    assert_eq!(c.serveurs[0].nom, "github");
    assert!(
        c.serveurs.iter().all(|s| s.nom != "brave"),
        "builtin must not appear in serveurs, got {:?}",
        c.serveurs.iter().map(|s| &s.nom).collect::<Vec<_>>()
    );
}

#[test]
fn sse_entry_uses_http_transport() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();
    let yaml = r#"
extensions:
  remote:
    type: sse
    url: https://example.com/mcp
"#;
    ecrire_config(&home, yaml);

    let app = tmp.path().join("nope/Goose.app");
    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 1);
    let r = &c.serveurs[0];
    assert_eq!(r.nom, "remote");
    assert_eq!(r.transport, "http");
    assert_eq!(r.url.as_deref(), Some("https://example.com/mcp"));
    assert!(r.commande.is_none());
}

#[test]
fn missing_config_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-empty");
    fs::create_dir_all(&home).unwrap();
    let app = tmp.path().join("nowhere/Goose.app");

    let res = detecter_avec_chemins(&home, &app);
    assert!(
        res.is_empty(),
        "no config, no app, no local bin should yield nothing, got {:?}",
        res
    );
}

#[test]
fn app_detected_without_config_returns_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home2");
    fs::create_dir_all(&home).unwrap();
    let app = faux_goose_app(tmp.path(), "1.2.3");

    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert!(c.binary_path.is_some(), "binary_path must be set");
    let bp = c.binary_path.as_ref().unwrap();
    assert!(bp.ends_with("Contents/MacOS/Goose"), "got {:?}", bp);
    assert_eq!(c.version.as_deref(), Some("1.2.3"));
    assert!(c.serveurs.is_empty());
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected 'no MCP block' note, got {:?}",
        c.notes
    );
}

#[test]
fn profiles_yaml_extensions_are_parsed() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home3");
    let goose_dir = home.join(".config").join("goose");
    fs::create_dir_all(&goose_dir).unwrap();
    let yaml = r#"
default:
  extensions:
    git:
      type: stdio
      cmd: uvx
      args: ["mcp-server-git"]
"#;
    fs::write(goose_dir.join("profiles.yaml"), yaml).unwrap();

    let app = tmp.path().join("missing/Goose.app");
    let res = detecter_avec_chemins(&home, &app);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert!(
        c.serveurs.iter().any(|s| s.nom == "git" && s.transport == "stdio"),
        "expected git stdio from profile, got {:?}",
        c.serveurs
    );
    assert!(c.configs.iter().any(|cfg| cfg.config_path.ends_with("profiles.yaml")));
}

#[tokio::test]
#[ignore]
async fn host_probe_for_manual_verify() {
    use sentinel_discovery::sources::SourceClient;
    let s = sentinel_discovery::sources::goose::SourceGoose;
    let r = s.detecter().await;
    eprintln!("HOST detected: {} client(s)", r.len());
    for c in &r {
        eprintln!(
            "  binary={:?} version={:?} servers={} notes={:?}",
            c.binary_path,
            c.version,
            c.serveurs.len(),
            c.notes
        );
        for srv in &c.serveurs {
            eprintln!(
                "    - {} transport={} cmd={:?} url={:?} envs={:?}",
                srv.nom, srv.transport, srv.commande, srv.url, srv.env_keys
            );
        }
    }
}
