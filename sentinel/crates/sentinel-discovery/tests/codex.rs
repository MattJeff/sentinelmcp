//! Integration tests for the OpenAI Codex CLI discovery source.
//!
//! Each test builds a synthetic `$HOME` in a tempdir, writes the appropriate
//! `config.toml`, then calls `detecter_avec_home` directly so we exercise the
//! parsing logic without depending on the real user's machine.

use sentinel_discovery::sources::codex::detecter_avec_home;
use std::fs;
use std::path::PathBuf;

/// Build a unique throwaway `$HOME` under the OS temp dir.
fn fake_home(tag: &str) -> PathBuf {
    let nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!(
        "sentinel-codex-{}-{}-{}",
        tag,
        std::process::id(),
        nano
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create fake home");
    p
}

fn write_primary_config(home: &PathBuf, contents: &str) {
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir).unwrap();
    fs::write(codex_dir.join("config.toml"), contents).unwrap();
}

#[tokio::test]
async fn parses_two_table_style_servers() {
    let home = fake_home("table");
    let cfg = r#"
model = "gpt-5"

[mcp.servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = { GITHUB_TOKEN = "x" }

[mcp.servers.filesystem]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"]
"#;
    write_primary_config(&home, cfg);

    let results = detecter_avec_home(&home).await;
    assert_eq!(results.len(), 1, "expected one ClientDecouvert");
    let c = &results[0];
    assert_eq!(c.serveurs.len(), 2, "expected 2 stdio servers");

    let names: Vec<&str> = c.serveurs.iter().map(|s| s.nom.as_str()).collect();
    assert!(names.contains(&"github"));
    assert!(names.contains(&"filesystem"));

    let gh = c.serveurs.iter().find(|s| s.nom == "github").unwrap();
    assert_eq!(gh.transport, "stdio");
    assert_eq!(gh.commande.as_deref(), Some("npx"));
    assert_eq!(gh.args.len(), 2);
    assert_eq!(gh.env_keys, vec!["GITHUB_TOKEN".to_string()]);
    assert!(gh.url.is_none());

    let fs_srv = c.serveurs.iter().find(|s| s.nom == "filesystem").unwrap();
    assert_eq!(fs_srv.args.len(), 3);

    assert_eq!(c.configs.len(), 1);
    assert!(c.configs[0].config_path.ends_with(".codex/config.toml"));
}

#[tokio::test]
async fn parses_array_of_tables_shape() {
    let home = fake_home("aot");
    let cfg = r#"
[[mcp.servers]]
name = "github"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[[mcp.servers]]
name = "remote-tools"
type = "sse"
url = "https://x.example/mcp"
"#;
    write_primary_config(&home, cfg);

    let results = detecter_avec_home(&home).await;
    assert_eq!(results.len(), 1);
    let c = &results[0];
    assert_eq!(c.serveurs.len(), 2);

    let gh = c.serveurs.iter().find(|s| s.nom == "github").unwrap();
    assert_eq!(gh.transport, "stdio");
    assert_eq!(gh.commande.as_deref(), Some("npx"));

    let rem = c.serveurs.iter().find(|s| s.nom == "remote-tools").unwrap();
    assert_eq!(rem.transport, "http");
    assert_eq!(rem.url.as_deref(), Some("https://x.example/mcp"));
    assert!(rem.commande.is_none());
    assert!(rem.args.is_empty());
}

#[tokio::test]
async fn missing_config_returns_empty_vec() {
    let home = fake_home("missing");
    // Nothing written. The test host may or may not have a real `codex`
    // binary installed; if it does the source returns a client with no
    // configs and a note. If it doesn't, the source returns an empty Vec.
    let results = detecter_avec_home(&home).await;
    if results.is_empty() {
        return;
    }
    assert_eq!(results.len(), 1);
    let c = &results[0];
    assert!(
        c.serveurs.is_empty(),
        "no servers should be discovered from an empty fake home"
    );
    assert!(
        c.configs.is_empty(),
        "no configs should be discovered from an empty fake home"
    );
}

#[tokio::test]
async fn bad_toml_records_parse_note() {
    let home = fake_home("bad");
    // Intentionally invalid TOML (unterminated string).
    let cfg = "model = \"gpt-5\nthis is not valid toml [[[";
    write_primary_config(&home, cfg);

    let results = detecter_avec_home(&home).await;
    assert_eq!(results.len(), 1, "broken config should still surface a client");
    let c = &results[0];
    assert!(c.serveurs.is_empty(), "no servers expected from invalid toml");
    assert!(
        c.notes.iter().any(|n| n.contains("parse")),
        "expected a note mentioning 'parse', got: {:?}",
        c.notes
    );
}
