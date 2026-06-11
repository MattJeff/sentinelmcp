//! Tests d'intégration — découverte du scope projet pour `.claude.json`.
//!
//! Couvre :
//!   * lecture du bloc `projects.<chemin>.mcpServers` en plus du
//!     `mcpServers` top-level (Claude Desktop / Claude Code CLI) ;
//!   * rétrocompat des fichiers qui n'ont qu'un `mcpServers` top-level
//!     (tous leurs serveurs doivent rester en scope `User`) ;
//!   * dédup user/project : un nom partagé top-level + projet ne doit
//!     produire qu'une seule entrée, en scope `Project`.

use sentinel_discovery::sources::claude_desktop::detecter_aux;
use sentinel_protocol::ScopeServeur;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

// ─── Tempdir helper (aligné sur `claude_desktop.rs` test) ────────────────

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("sentinel_scope_{prefix}_{pid}_{now}_{n}"));
        fs::create_dir_all(&path).expect("create tempdir");
        Self { path }
    }
    fn p(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn paths(td: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let app = td.p().join("nope_app");
    let bin = app.join("Contents/MacOS/Claude");
    let plist = app.join("Contents/Info.plist");
    (td.p().join("claude_desktop_config.json"), app, bin, plist)
}

// ─── 1) Mix top-level + plusieurs projets ────────────────────────────────

#[test]
fn extraire_mix_user_et_projects() {
    let td = TempDir::new("mix");
    let (cfg, app, bin, plist) = paths(&td);
    let json = r#"
    {
      "mcpServers": {
        "global-fs": { "command": "npx", "args": ["-y", "@mcp/fs"] }
      },
      "projects": {
        "/Users/alice/repo-foo": {
          "mcpServers": {
            "foo-db": { "command": "node", "args": ["foo-db.js"] }
          }
        },
        "/Users/alice/repo-bar": {
          "mcpServers": {
            "bar-vector": { "command": "node", "args": ["bar.js"] },
            "bar-http":   { "url": "https://bar.local/mcp" }
          }
        }
      }
    }
    "#;
    fs::write(&cfg, json).unwrap();

    let out = detecter_aux(&cfg, &app, &bin, &plist);
    assert_eq!(out.len(), 1);
    let c = &out[0];
    // 1 user + 1 foo + 2 bar = 4 serveurs.
    assert_eq!(c.serveurs.len(), 4, "got: {:?}", c.serveurs);

    let by_name = |n: &str| c.serveurs.iter().find(|s| s.nom == n).expect(n);
    assert_eq!(by_name("global-fs").scope, ScopeServeur::User);
    assert_eq!(
        by_name("foo-db").scope,
        ScopeServeur::Project {
            path: "/Users/alice/repo-foo".to_string()
        }
    );
    assert_eq!(
        by_name("bar-vector").scope,
        ScopeServeur::Project {
            path: "/Users/alice/repo-bar".to_string()
        }
    );
    assert_eq!(by_name("bar-http").transport, "http");
}

// ─── 2) Rétrocompat : top-level uniquement → tous en User ────────────────

#[test]
fn rétrocompat_top_level_uniquement() {
    let td = TempDir::new("legacy");
    let (cfg, app, bin, plist) = paths(&td);
    let json = r#"
    {
      "mcpServers": {
        "a": { "command": "cmd-a" },
        "b": { "command": "cmd-b" }
      }
    }
    "#;
    fs::write(&cfg, json).unwrap();
    let out = detecter_aux(&cfg, &app, &bin, &plist);
    let c = &out[0];
    assert_eq!(c.serveurs.len(), 2);
    assert!(c.serveurs.iter().all(|s| s.scope == ScopeServeur::User));
}

// ─── 3) Collision User + Project → Project gagne ─────────────────────────

#[test]
fn collision_user_project_garde_project() {
    let td = TempDir::new("clash");
    let (cfg, app, bin, plist) = paths(&td);
    // "github" est déclaré dans les deux scopes : top-level (avec token A)
    // ET projet `/work/repo-x` (avec token B). Le projet doit gagner.
    let json = r#"
    {
      "mcpServers": {
        "github": {
          "command": "npx",
          "args": ["-y", "@mcp/github"],
          "env": { "GITHUB_TOKEN": "ghp_user_level" }
        }
      },
      "projects": {
        "/work/repo-x": {
          "mcpServers": {
            "github": {
              "command": "npx",
              "args": ["-y", "@mcp/github-fork"],
              "env": { "GITHUB_TOKEN": "ghp_project_level" }
            }
          }
        }
      }
    }
    "#;
    fs::write(&cfg, json).unwrap();
    let out = detecter_aux(&cfg, &app, &bin, &plist);
    let c = &out[0];

    let github = c.serveurs.iter().filter(|s| s.nom == "github").collect::<Vec<_>>();
    assert_eq!(
        github.len(),
        1,
        "dédup : un seul `github` doit survivre, vu {:?}",
        c.serveurs
    );
    assert_eq!(
        github[0].scope,
        ScopeServeur::Project {
            path: "/work/repo-x".to_string()
        },
        "le scope projet doit l'emporter sur le scope user"
    );
    // L'args/env doit être ceux du projet, pas du user.
    assert_eq!(github[0].args, vec!["-y".to_string(), "@mcp/github-fork".to_string()]);
}

// ─── 4) Projet présent, top-level absent → pas de note "no MCP block" ───

#[test]
fn projets_seuls_sans_top_level_pas_de_note_no_mcp() {
    let td = TempDir::new("project_only");
    let (cfg, app, bin, plist) = paths(&td);
    let json = r#"
    {
      "projects": {
        "/p": {
          "mcpServers": {
            "only-here": { "command": "x" }
          }
        }
      }
    }
    "#;
    fs::write(&cfg, json).unwrap();
    let out = detecter_aux(&cfg, &app, &bin, &plist);
    let c = &out[0];
    assert_eq!(c.serveurs.len(), 1);
    assert_eq!(
        c.serveurs[0].scope,
        ScopeServeur::Project { path: "/p".to_string() }
    );
    assert!(
        !c.notes.iter().any(|n| n.contains("no MCP block")),
        "trouvé au moins un serveur projet → pas de 'no MCP block', notes={:?}",
        c.notes
    );
}
