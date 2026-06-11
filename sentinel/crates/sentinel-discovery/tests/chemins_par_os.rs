//! Tests d'intégration multi-OS : on fabrique des homes synthétiques avec
//! les layouts Windows / Linux / macOS et on vérifie que la détection
//! paramétrée par [`ContexteOs`] trouve bien les configs — sans dépendre de
//! l'OS de la machine qui exécute les tests.

use sentinel_discovery::sources::os_paths::{ContexteOs, OsCible};
use sentinel_discovery::sources::{antigravity, claude_desktop, codex, goose, vscode};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn ecrire(path: &Path, contenu: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contenu).unwrap();
}

// ── Claude Desktop ─────────────────────────────────────────────────────────

#[test]
fn claude_desktop_layout_windows_detecte() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Windows, home.path());

    let cfg = ctx
        .dossier_appdata()
        .join("Claude")
        .join("claude_desktop_config.json");
    ecrire(
        &cfg,
        r#"{ "mcpServers": { "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] } } }"#,
    );

    let candidats = claude_desktop::chemins_config_candidats(&ctx);
    let trouve = candidats.iter().find(|p| p.exists()).expect("config absente");
    assert!(trouve.ends_with("Claude/claude_desktop_config.json"));

    let app_absente = home.path().join("nope.app");
    let out = claude_desktop::detecter_aux(trouve, &app_absente, &app_absente, &app_absente);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].serveurs.len(), 1);
    assert_eq!(out[0].serveurs[0].nom, "github");
}

#[test]
fn claude_desktop_layout_linux_xdg_detecte() {
    let home = TempDir::new().unwrap();
    let xdg = home.path().join("xdg-custom");
    let ctx = ContexteOs::nouveau(OsCible::Linux, home.path()).avec_xdg_config_home(&xdg);

    ecrire(
        &xdg.join("Claude").join("claude_desktop_config.json"),
        r#"{ "mcpServers": {} }"#,
    );

    let candidats = claude_desktop::chemins_config_candidats(&ctx);
    assert_eq!(candidats.len(), 2, "XDG + ~/.config attendus");
    assert!(candidats[0].exists());
    assert!(!candidats[1].exists());
}

// ── VS Code ────────────────────────────────────────────────────────────────

#[test]
fn vscode_layout_linux_detecte_settings() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Linux, home.path());

    ecrire(
        &home
            .path()
            .join(".config")
            .join("Code")
            .join("User")
            .join("settings.json"),
        r#"{ "mcp.servers": { "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"] } } }"#,
    );

    let res = vscode::detecter_avec_contexte(&ctx, None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "fs");
}

#[test]
fn vscode_layout_windows_detecte_settings() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Windows, home.path());

    ecrire(
        &ctx.dossier_appdata()
            .join("Code")
            .join("User")
            .join("settings.json"),
        r#"{ "mcp.servers": { "github": { "command": "npx" } } }"#,
    );

    let res = vscode::detecter_avec_contexte(&ctx, None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "github");
}

#[test]
fn vscode_layout_macos_detecte_settings() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::MacOs, home.path());

    ecrire(
        &home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("settings.json"),
        r#"{ "mcp.servers": { "memo": { "command": "npx" } } }"#,
    );

    let res = vscode::detecter_avec_contexte(&ctx, None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "memo");
}

// ── Antigravity ────────────────────────────────────────────────────────────

#[test]
fn antigravity_layout_windows_detecte_settings() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Windows, home.path());

    ecrire(
        &ctx.dossier_appdata()
            .join("Antigravity")
            .join("User")
            .join("settings.json"),
        r#"{ "mcpServers": { "search": { "url": "https://mcp.example.com/sse", "type": "sse" } } }"#,
    );

    let res = antigravity::detecter_avec_contexte(&ctx, None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "search");
    assert_eq!(res[0].serveurs[0].transport, "sse");
}

#[test]
fn antigravity_layout_linux_detecte_settings() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Linux, home.path());

    ecrire(
        &home
            .path()
            .join(".config")
            .join("Antigravity")
            .join("User")
            .join("settings.json"),
        r#"{ "mcp.servers": { "fs": { "command": "npx" } } }"#,
    );

    let res = antigravity::detecter_avec_contexte(&ctx, None);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "fs");
}

// ── Goose ──────────────────────────────────────────────────────────────────

#[test]
fn goose_layout_windows_block_appdata_detecte() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Windows, home.path());

    ecrire(
        &ctx.dossier_appdata()
            .join("Block")
            .join("goose")
            .join("config")
            .join("config.yaml"),
        "extensions:\n  github:\n    type: stdio\n    cmd: npx\n    args: [\"-y\", \"@modelcontextprotocol/server-github\"]\n",
    );

    let app_absente = home.path().join("nope.app");
    let res = goose::detecter_avec_contexte(&ctx, &app_absente);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "github");
}

#[test]
fn goose_layout_linux_xdg_detecte() {
    let home = TempDir::new().unwrap();
    let xdg = home.path().join("xdg");
    let ctx = ContexteOs::nouveau(OsCible::Linux, home.path()).avec_xdg_config_home(&xdg);

    ecrire(
        &xdg.join("goose").join("config.yaml"),
        "extensions:\n  fetch:\n    type: stdio\n    cmd: uvx\n    args: [\"mcp-server-fetch\"]\n",
    );

    let app_absente = home.path().join("nope.app");
    let res = goose::detecter_avec_contexte(&ctx, &app_absente);
    assert_eq!(res.len(), 1);
    assert_eq!(res[0].serveurs[0].nom, "fetch");
}

// ── Codex ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn codex_layout_linux_xdg_alt_config_detecte() {
    let home = TempDir::new().unwrap();
    let xdg = home.path().join("xdg");
    let ctx = ContexteOs::nouveau(OsCible::Linux, home.path()).avec_xdg_config_home(&xdg);

    ecrire(
        &xdg.join("openai-codex").join("config.toml"),
        "[mcp.servers.github]\ncommand = \"npx\"\nargs = [\"-y\", \"@modelcontextprotocol/server-github\"]\n",
    );

    let res = codex::detecter_avec_contexte(&ctx).await;
    assert_eq!(res.len(), 1);
    assert!(res[0].serveurs.iter().any(|s| s.nom == "github"));
}

#[tokio::test]
async fn codex_layout_windows_primaire_detecte() {
    let home = TempDir::new().unwrap();
    let ctx = ContexteOs::nouveau(OsCible::Windows, home.path());

    ecrire(
        &home.path().join(".codex").join("config.toml"),
        "[mcp.servers.fs]\ncommand = \"npx\"\n",
    );

    let res = codex::detecter_avec_contexte(&ctx).await;
    assert_eq!(res.len(), 1);
    assert!(res[0].serveurs.iter().any(|s| s.nom == "fs"));
}
