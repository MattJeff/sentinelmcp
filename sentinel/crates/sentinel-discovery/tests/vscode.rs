//! Integration tests for the VS Code MCP discovery source.

use sentinel_discovery::sources::vscode::detecter_avec_chemins;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Build the full chain `<home>/Library/Application Support/Code/User/` and
/// write `settings.json` with the given contents.
fn ecrire_settings(home: &std::path::Path, contenu: &str) -> PathBuf {
    let dir = home
        .join("Library")
        .join("Application Support")
        .join("Code")
        .join("User");
    fs::create_dir_all(&dir).unwrap();
    let p = dir.join("settings.json");
    fs::write(&p, contenu).unwrap();
    p
}

/// Create an extension folder under `<home>/.vscode/extensions/<name>/`.
fn ecrire_extension(home: &std::path::Path, nom: &str) -> PathBuf {
    let dir = home.join(".vscode").join("extensions").join(nom);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("package.json"), "{}").unwrap();
    dir
}

#[test]
fn parses_mcp_servers_block_from_settings_json() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let settings = r#"{
        "editor.fontSize": 14,
        "mcp.servers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"FOO_TOKEN": "secret"}
            },
            "git": {
                "command": "uvx",
                "args": ["mcp-server-git"]
            }
        }
    }"#;
    ecrire_settings(&home, settings);

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1, "should detect vscode from settings alone");
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 2);
    let fs_srv = c.serveurs.iter().find(|s| s.nom == "fs").expect("fs");
    assert_eq!(fs_srv.commande.as_deref(), Some("npx"));
    assert_eq!(fs_srv.transport, "stdio");
    assert!(fs_srv.env_keys.contains(&"FOO_TOKEN".to_string()));
    let git_srv = c.serveurs.iter().find(|s| s.nom == "git").expect("git");
    assert_eq!(git_srv.commande.as_deref(), Some("uvx"));
    assert_eq!(c.configs.len(), 1);
    assert_eq!(c.configs[0].source_id, "vscode");
}

#[test]
fn parses_jsonc_with_line_and_block_comments() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let settings = r#"{
        // user-level VS Code config (JSONC)
        "editor.fontSize": 14, /* size in px */
        /* block comment with " quotes // inside */
        "mcp.servers": {
            // primary stdio server
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                // end of fs
            }
        }
        // trailing comment
    }"#;
    ecrire_settings(&home, settings);

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1, "should parse JSONC with comments");
    let c = &res[0];
    assert!(
        c.notes.iter().all(|n| !n.contains("failed to parse")),
        "expected clean parse, got notes {:?}",
        c.notes
    );
    assert_eq!(c.serveurs.len(), 1);
    assert_eq!(c.serveurs[0].nom, "fs");
    assert_eq!(c.serveurs[0].commande.as_deref(), Some("npx"));
}

#[test]
fn detects_known_mcp_extension_in_extensions_dir() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    ecrire_extension(&home, "saoudrizwan.claude-dev-2.0.0");
    // Add an unrelated extension to ensure we don't pick it up.
    ecrire_extension(&home, "ms-python.python-2024.0.0");

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1, "should detect vscode via extensions dir");
    let c = &res[0];
    let meta = c
        .meta
        .get("vscode_mcp_extensions")
        .cloned()
        .unwrap_or_default();
    assert!(
        meta.contains("saoudrizwan.claude-dev"),
        "expected saoudrizwan.claude-dev in meta, got {:?}",
        meta
    );
    assert!(
        !meta.contains("ms-python.python"),
        "unrelated extension leaked into meta: {:?}",
        meta
    );
    assert!(
        c.notes
            .iter()
            .any(|n| n.contains("saoudrizwan.claude-dev")),
        "expected note about the extension, got {:?}",
        c.notes
    );
}

#[test]
fn missing_settings_and_no_extensions_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-empty");
    fs::create_dir_all(&home).unwrap();
    // No settings.json, no ~/.vscode/extensions, no app.
    let res = detecter_avec_chemins(&home, None);
    assert!(res.is_empty(), "no signals at all should yield nothing");
}

#[test]
fn settings_without_mcp_block_produces_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    ecrire_settings(&home, r#"{"editor.fontSize": 14}"#);

    let res = detecter_avec_chemins(&home, None);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert!(c.serveurs.is_empty());
    assert!(
        c.notes.iter().any(|n| n.contains("no MCP block")),
        "expected 'no MCP block' note, got {:?}",
        c.notes
    );
}

#[tokio::test]
#[ignore]
async fn host_probe_for_manual_verify() {
    use sentinel_discovery::sources::SourceClient;
    let s = sentinel_discovery::sources::vscode::SourceVscode;
    let r = s.detecter().await;
    eprintln!("HOST detected: {} client(s)", r.len());
    for c in &r {
        eprintln!(
            "  binary={:?} version={:?} servers={} notes={:?} meta={:?}",
            c.binary_path, c.version, c.serveurs.len(), c.notes, c.meta
        );
        for srv in &c.serveurs {
            eprintln!(
                "    - {} transport={} cmd={:?} url={:?}",
                srv.nom, srv.transport, srv.commande, srv.url
            );
        }
    }
}
