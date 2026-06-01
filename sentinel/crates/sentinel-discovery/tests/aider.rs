//! Integration tests for the Aider discovery source.
//!
//! We stand up a synthetic `$HOME`, a synthetic bin directory, and write
//! representative YAML/JSON configs so we can exercise the parser without
//! touching the live user environment.

use sentinel_discovery::model::ClientKind;
use sentinel_discovery::sources::aider::{detecter_avec_options, AiderOptions, SourceAider};
use sentinel_discovery::sources::SourceClient;

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

fn write_global_conf(home: &Path, body: &str) -> PathBuf {
    let path = home.join(".aider.conf.yml");
    fs::write(&path, body).expect("write .aider.conf.yml");
    path
}

fn write_fake_bin(bin_dir: &Path) -> PathBuf {
    fs::create_dir_all(bin_dir).unwrap();
    let bin = bin_dir.join("aider");
    fs::write(&bin, b"#!/bin/sh\necho aider 0.0.0-test\n").unwrap();
    bin
}

#[tokio::test]
async fn inline_mcp_servers_list_is_parsed() {
    let home = TempDir::new().unwrap();

    let yaml = r#"
model: gpt-4o
mcp-servers:
  - name: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    env:
      MCP_DEBUG: "1"
      OPENAI_API_KEY: "redacted"
  - name: remote
    transport: sse
    url: https://example.com/mcp
    disabled: true
"#;
    write_global_conf(home.path(), yaml);

    let opts = AiderOptions::default()
        .with_home(home.path())
        .with_bin_dirs(vec![])
        .without_version_probe();
    let result = detecter_avec_options(&opts);
    assert_eq!(result.len(), 1, "expected one Aider client, got {result:?}");
    let client = &result[0];

    assert_eq!(client.kind, ClientKind::Aider);
    assert_eq!(client.serveurs.len(), 2, "two servers expected");

    let by_name: std::collections::BTreeMap<_, _> = client
        .serveurs
        .iter()
        .map(|s| (s.nom.as_str(), s))
        .collect();

    let fs_entry = by_name.get("filesystem").expect("filesystem server");
    assert_eq!(fs_entry.transport, "stdio");
    assert_eq!(fs_entry.commande.as_deref(), Some("npx"));
    assert_eq!(fs_entry.args.len(), 3);
    assert!(fs_entry.env_keys.contains(&"MCP_DEBUG".to_string()));
    assert!(fs_entry.env_keys.contains(&"OPENAI_API_KEY".to_string()));
    assert!(!fs_entry.disabled);

    let remote = by_name.get("remote").expect("remote server");
    assert_eq!(remote.transport, "sse");
    assert_eq!(remote.url.as_deref(), Some("https://example.com/mcp"));
    assert!(remote.disabled);

    assert_eq!(client.configs.len(), 1);
    assert!(client.configs[0]
        .config_path
        .ends_with(".aider.conf.yml"));
}

#[tokio::test]
async fn external_mcp_config_is_followed() {
    let home = TempDir::new().unwrap();
    let external_dir = TempDir::new().unwrap();

    let external_path = external_dir.path().join("mcp.json");
    let external_json = r#"
    {
      "mcpServers": {
        "github": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-github"],
          "env": { "GITHUB_TOKEN": "x" }
        },
        "fetch": {
          "command": "uvx",
          "args": ["mcp-server-fetch"]
        }
      }
    }
    "#;
    fs::write(&external_path, external_json).unwrap();

    let yaml = format!(
        "model: gpt-4o\nmcp-config: {}\n",
        external_path.display()
    );
    write_global_conf(home.path(), &yaml);

    let opts = AiderOptions::default()
        .with_home(home.path())
        .with_bin_dirs(vec![])
        .without_version_probe();
    let result = detecter_avec_options(&opts);
    assert_eq!(result.len(), 1);
    let client = &result[0];

    // Both the yaml *and* the external json should appear as configs.
    assert_eq!(
        client.configs.len(),
        2,
        "expected both yaml and external json in configs: {:?}",
        client.configs
    );
    assert!(client
        .configs
        .iter()
        .any(|c| c.config_path.ends_with(".aider.conf.yml")));
    assert!(client
        .configs
        .iter()
        .any(|c| c.config_path == external_path));

    let names: Vec<&str> = client.serveurs.iter().map(|s| s.nom.as_str()).collect();
    assert!(names.contains(&"github"), "missing github in {names:?}");
    assert!(names.contains(&"fetch"), "missing fetch in {names:?}");
    assert_eq!(client.serveurs.len(), 2);
}

#[tokio::test]
async fn missing_config_and_missing_binary_returns_empty() {
    let home = TempDir::new().unwrap();

    let opts = AiderOptions::default()
        .with_home(home.path())
        .with_bin_dirs(vec![])
        .without_version_probe();
    let result = detecter_avec_options(&opts);
    assert!(
        result.is_empty(),
        "expected no Aider when neither binary nor config exist, got {result:?}"
    );
}

#[tokio::test]
async fn binary_present_but_no_config_yields_client_with_notes() {
    let home = TempDir::new().unwrap();
    let bin_dir = TempDir::new().unwrap();
    let bin = write_fake_bin(bin_dir.path());

    let opts = AiderOptions::default()
        .with_home(home.path())
        .with_bin_dirs(vec![bin_dir.path().to_path_buf()])
        .without_version_probe();
    let result = detecter_avec_options(&opts);
    assert_eq!(result.len(), 1, "expected one client (binary-only)");
    let client = &result[0];

    assert_eq!(client.kind, ClientKind::Aider);
    assert_eq!(client.binary_path.as_deref(), Some(bin.as_path()));
    assert!(client.serveurs.is_empty());
    assert!(client.configs.is_empty());

    let has_missing_cfg_note = client
        .notes
        .iter()
        .any(|n| n.contains("no global config file"));
    assert!(
        has_missing_cfg_note,
        "expected a 'no global config' note, got {:?}",
        client.notes
    );
}

#[tokio::test]
async fn alt_global_config_dir_is_also_scanned() {
    let home = TempDir::new().unwrap();
    let cfg_dir = home.path().join(".aider");
    fs::create_dir_all(&cfg_dir).unwrap();
    fs::write(
        cfg_dir.join("config.yml"),
        "mcp-servers:\n  - name: only-here\n    command: echo\n    args: [\"hi\"]\n",
    )
    .unwrap();

    let opts = AiderOptions::default()
        .with_home(home.path())
        .with_bin_dirs(vec![])
        .without_version_probe();
    let result = detecter_avec_options(&opts);
    assert_eq!(result.len(), 1);
    let client = &result[0];
    assert_eq!(client.serveurs.len(), 1);
    assert_eq!(client.serveurs[0].nom, "only-here");
    assert_eq!(client.serveurs[0].commande.as_deref(), Some("echo"));
    assert_eq!(client.configs.len(), 1);
    assert!(client.configs[0].config_path.ends_with(".aider/config.yml"));
}

/// Probe THIS host. Marked `#[ignore]` so it doesn't add noise to normal CI
/// runs; invoke with
/// `cargo test -p sentinel-discovery --test aider -- --ignored probe_live_host --nocapture`.
#[tokio::test]
#[ignore]
async fn probe_live_host() {
    let result = SourceAider.detecter().await;
    if result.is_empty() {
        eprintln!("[aider-probe] no Aider install detected on this host");
        return;
    }
    for c in &result {
        eprintln!(
            "[aider-probe] kind={:?} version={:?} binary={:?}",
            c.kind, c.version, c.binary_path
        );
        for cfg in &c.configs {
            eprintln!("[aider-probe]   config: {}", cfg.config_path.display());
        }
        for s in &c.serveurs {
            eprintln!(
                "[aider-probe]   server name={} transport={} command={:?} args={:?} disabled={}",
                s.nom, s.transport, s.commande, s.args, s.disabled
            );
        }
        for n in &c.notes {
            eprintln!("[aider-probe]   note: {n}");
        }
    }
}
