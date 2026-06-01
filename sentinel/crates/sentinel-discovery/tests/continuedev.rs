//! Integration tests for the Continue.dev MCP discovery source.

use sentinel_discovery::sources::continuedev::detecter_avec_home;
use std::fs;
use tempfile::TempDir;

#[test]
fn parses_yaml_with_two_servers() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let dir = home.join(".continue");
    fs::create_dir_all(&dir).unwrap();
    let yaml = r#"
mcpServers:
  - name: github
    command: npx
    args: ["-y", "@modelcontextprotocol/server-github"]
    env:
      GITHUB_TOKEN: "redacted"
  - name: filesystem
    command: npx
    args:
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/tmp"
"#;
    fs::write(dir.join("config.yaml"), yaml).unwrap();

    let res = detecter_avec_home(&home);
    assert_eq!(res.len(), 1, "should detect continue from yaml config");
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 2, "expected 2 servers, got {:?}", c.serveurs);

    let gh = c.serveurs.iter().find(|s| s.nom == "github").expect("github");
    assert_eq!(gh.transport, "stdio");
    assert_eq!(gh.commande.as_deref(), Some("npx"));
    assert_eq!(gh.args, vec!["-y", "@modelcontextprotocol/server-github"]);
    assert!(gh.env_keys.contains(&"GITHUB_TOKEN".to_string()));
    assert!(gh.url.is_none());

    let fs_srv = c
        .serveurs
        .iter()
        .find(|s| s.nom == "filesystem")
        .expect("filesystem");
    assert_eq!(fs_srv.transport, "stdio");
    assert_eq!(fs_srv.args.len(), 3);
    assert_eq!(fs_srv.args[2], "/tmp");

    assert_eq!(c.configs.len(), 1);
    assert_eq!(c.configs[0].source_id, "continuedev");
    assert!(c.configs[0].config_path.ends_with("config.yaml"));
}

#[test]
fn parses_json_variant() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-json");
    let dir = home.join(".continue");
    fs::create_dir_all(&dir).unwrap();
    let json = r#"{
        "mcpServers": [
            {
                "name": "github",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "xxx"}
            },
            {
                "name": "remote",
                "url": "https://example.com/mcp",
                "type": "http"
            }
        ]
    }"#;
    fs::write(dir.join("config.json"), json).unwrap();

    let res = detecter_avec_home(&home);
    assert_eq!(res.len(), 1);
    let c = &res[0];
    assert_eq!(c.serveurs.len(), 2, "expected 2 servers, got {:?}", c.serveurs);

    let gh = c.serveurs.iter().find(|s| s.nom == "github").expect("github");
    assert_eq!(gh.commande.as_deref(), Some("npx"));
    assert!(gh.env_keys.contains(&"GITHUB_TOKEN".to_string()));

    let remote = c.serveurs.iter().find(|s| s.nom == "remote").expect("remote");
    assert_eq!(remote.transport, "http");
    assert_eq!(remote.url.as_deref(), Some("https://example.com/mcp"));
    assert!(remote.commande.is_none());

    assert!(c.configs.iter().any(|cfg| cfg.config_path.ends_with("config.json")));
}

#[test]
fn missing_config_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-empty");
    fs::create_dir_all(&home).unwrap();

    let res = detecter_avec_home(&home);
    assert!(res.is_empty(), "no .continue dir should yield no client");
}

#[test]
fn bad_yaml_produces_parse_note() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home-bad");
    let dir = home.join(".continue");
    fs::create_dir_all(&dir).unwrap();
    // Deliberately broken YAML: unbalanced brackets / bad indentation.
    fs::write(
        dir.join("config.yaml"),
        "mcpServers:\n  - name: oops\n    args: [unterminated,\n",
    )
    .unwrap();

    let res = detecter_avec_home(&home);
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
    let home = tmp.path().join("home-no-mcp");
    let dir = home.join(".continue");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.yaml"), "models:\n  - name: gpt-4\n").unwrap();

    let res = detecter_avec_home(&home);
    assert_eq!(res.len(), 1);
    assert!(
        res[0].notes.iter().any(|n| n.contains("no MCP block")),
        "expected 'no MCP block' note, got {:?}",
        res[0].notes
    );
    assert!(res[0].serveurs.is_empty());
}

#[tokio::test]
#[ignore]
async fn host_probe_for_manual_verify() {
    use sentinel_discovery::sources::SourceClient;
    let s = sentinel_discovery::sources::continuedev::SourceContinuedev;
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
                "    - {} transport={} cmd={:?} url={:?}",
                srv.nom, srv.transport, srv.commande, srv.url
            );
        }
    }
}
