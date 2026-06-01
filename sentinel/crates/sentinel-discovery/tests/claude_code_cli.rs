//! Integration tests for the Claude Code CLI discovery source.
//!
//! Each test builds a synthetic `$HOME` in a tempdir, writes the appropriate
//! config files, then calls `detecter_avec_home` directly so we can exercise
//! the parsing logic without depending on the real user's machine.

use sentinel_discovery::sources::claude_code_cli::detecter_avec_home;
use std::fs;
use std::path::PathBuf;

/// Build a unique throwaway `$HOME` under the OS temp dir.
fn fake_home(tag: &str) -> PathBuf {
    let nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!(
        "sentinel-claude-code-cli-{}-{}-{}",
        tag,
        std::process::id(),
        nano
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("create fake home");
    p
}

#[tokio::test]
async fn parses_three_stdio_servers_from_claude_json() {
    let home = fake_home("stdio");
    let cfg = r#"{
      "numStartups": 1,
      "mcpServers": {
        "filesystem": {
          "type": "stdio",
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
          "env": {"FOO": "bar"}
        },
        "github": {
          "command": "node",
          "args": ["/opt/github-mcp/index.js"],
          "env": {"GITHUB_TOKEN": "x"}
        },
        "chrome-devtools": {
          "type": "stdio",
          "command": "npx",
          "args": ["chrome-devtools-mcp@latest"]
        }
      }
    }"#;
    fs::write(home.join(".claude.json"), cfg).unwrap();

    let results = detecter_avec_home(&home).await;
    assert_eq!(results.len(), 1, "expected one ClientDecouvert");
    let c = &results[0];
    assert_eq!(c.serveurs.len(), 3, "expected 3 stdio servers");

    let names: Vec<&str> = c.serveurs.iter().map(|s| s.nom.as_str()).collect();
    assert!(names.contains(&"filesystem"));
    assert!(names.contains(&"github"));
    assert!(names.contains(&"chrome-devtools"));

    for s in &c.serveurs {
        assert_eq!(s.transport, "stdio");
        assert!(s.commande.is_some());
        assert!(s.url.is_none());
    }

    let fs_srv = c.serveurs.iter().find(|s| s.nom == "filesystem").unwrap();
    assert_eq!(fs_srv.commande.as_deref(), Some("npx"));
    assert_eq!(fs_srv.args.len(), 3);
    assert_eq!(fs_srv.env_keys, vec!["FOO".to_string()]);

    assert_eq!(c.configs.len(), 1);
    assert!(c.configs[0].config_path.ends_with(".claude.json"));
}

#[tokio::test]
async fn parses_sse_server_as_http_transport() {
    let home = fake_home("sse");
    let cfg = r#"{
      "mcpServers": {
        "remote-tools": {
          "type": "sse",
          "url": "https://x.example/mcp"
        }
      }
    }"#;
    fs::write(home.join(".claude.json"), cfg).unwrap();

    let results = detecter_avec_home(&home).await;
    assert_eq!(results.len(), 1);
    let c = &results[0];
    assert_eq!(c.serveurs.len(), 1);
    let s = &c.serveurs[0];
    assert_eq!(s.nom, "remote-tools");
    assert_eq!(s.transport, "http");
    assert_eq!(s.url.as_deref(), Some("https://x.example/mcp"));
    assert!(s.commande.is_none());
    assert!(s.args.is_empty());
}

#[tokio::test]
async fn missing_config_returns_empty_vec() {
    let home = fake_home("missing");
    // Nothing written.
    let results = detecter_avec_home(&home).await;
    // The host running this test may or may not have `claude` installed.
    // If it does, the source returns a client with no configs and a note.
    // If it doesn't, the source returns an empty Vec.
    if results.is_empty() {
        // Good: clean machine, no binary, no configs.
        return;
    }
    // Otherwise: a real binary was located. In that case at least no MCP
    // servers should have been parsed from the (non-existent) synthetic home.
    assert_eq!(results.len(), 1);
    let c = &results[0];
    assert!(c.serveurs.is_empty(), "no servers should be discovered from an empty fake home");
    assert!(c.configs.is_empty(), "no configs should be discovered from an empty fake home");
}

#[tokio::test]
async fn discovers_project_level_mcp_json_in_subdir() {
    let home = fake_home("project");
    let proj = home.join("myproj");
    fs::create_dir_all(&proj).unwrap();
    let cfg = r#"{
      "mcpServers": {
        "proj-server": {
          "command": "python",
          "args": ["-m", "my_mcp_server"],
          "env": {"API_KEY": "x"}
        }
      }
    }"#;
    fs::write(proj.join(".mcp.json"), cfg).unwrap();

    let results = detecter_avec_home(&home).await;
    assert_eq!(results.len(), 1, "should detect via project .mcp.json");
    let c = &results[0];
    assert!(c.configs.iter().any(|cs| cs.config_path.ends_with("myproj/.mcp.json")));
    assert_eq!(c.serveurs.len(), 1);
    let s = &c.serveurs[0];
    assert_eq!(s.nom, "proj-server");
    assert_eq!(s.transport, "stdio");
    assert_eq!(s.commande.as_deref(), Some("python"));
    assert_eq!(s.env_keys, vec!["API_KEY".to_string()]);
}
