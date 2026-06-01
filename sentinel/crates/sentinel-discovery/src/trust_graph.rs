//! Trust graph + blast radius scoring (agent X4).
//!
//! Builds a typed graph **AI clients → MCP servers → scopes (portées)** from
//! a discovery report, then computes a "blast radius" score per AI client.
//!
//! The blast radius answers a simple question:
//! > *If this AI client is compromised, how much can it touch transitively
//! >  through the MCP servers it has wired up?*
//!
//! Each MCP server is mapped to a set of [`sentinel_protocol::Portee`]-like
//! scope tags inferred from its declared package / command / args. Each scope
//! has a static risk weight. The blast radius of a client is the sum of risk
//! across every scope it can reach through any of its servers (a scope is
//! only counted once per client).
//!
//! The graph is intentionally serialisable so the desktop UI can render it as
//! a force-directed graph and a 0–1 "blast radius" bar (normalised by
//! `indice_max`).

use crate::model::{ClientDecouvert, ServeurMcpDeclare};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

// ---------------------------------------------------------------------------
// Public graph types
// ---------------------------------------------------------------------------

/// A node representing one AI client (Claude Desktop, Cursor, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoeudClient {
    /// Stable client node id (e.g. `client:claude_desktop:0`).
    pub id: String,
    /// Human label (`ClientKind::libelle`).
    pub libelle: String,
    /// Computed blast-radius score for this client (sum of scope weights
    /// reachable through any of its servers, each scope counted once).
    pub blast_radius: f64,
}

/// A node representing one declared MCP server, deduplicated across clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoeudServeur {
    /// Stable server node id (e.g. `server:0`).
    pub id: String,
    /// Human name of the server as written in the config (the JSON key).
    pub nom: String,
    /// Inferred npm/pip/binary package, if we could pull one out of the args.
    pub package: Option<String>,
    /// Inferred functional scopes for this server (kebab/snake names of
    /// [`sentinel_protocol::Portee`] plus the synthetic `navigateur`, `read`,
    /// `write` tags used by the scoring table — these are stored as strings
    /// so the UI never has to grow the enum to render new categories).
    pub portees: Vec<String>,
}

/// A directed edge in the trust graph. Currently only `client → server`
/// edges are emitted; servers' scopes are stored inline on `NoeudServeur`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Arete {
    pub source: String,
    pub cible: String,
}

/// Full trust-graph payload returned by [`ConstructeurGraphe::construire`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrapheConfiance {
    pub clients: Vec<NoeudClient>,
    pub serveurs: Vec<NoeudServeur>,
    pub aretes: Vec<Arete>,
    /// Largest blast radius observed in this graph. The UI normalises every
    /// client score by this value to produce a 0..=1 bar. `0.0` if no client
    /// has any risk-bearing scope.
    pub indice_max: f64,
}

/// Graph builder. Stateless, lives in its own struct so future versions can
/// hang configuration (scope weights, allow-lists, …) off of it without
/// breaking the call site.
pub struct ConstructeurGraphe;

impl ConstructeurGraphe {
    /// Build the trust graph from a slice of discovered clients.
    ///
    /// Servers are deduplicated by the canonical key
    /// `(package, command, args)`. Two clients pointing at the exact same
    /// MCP server share the same `NoeudServeur` and each emit their own
    /// edge to it.
    pub fn construire(clients: &[ClientDecouvert]) -> GrapheConfiance {
        // ---- 1. Materialise dedup'd server nodes -------------------------
        // Map from canonical key → server index in `serveurs`.
        let mut serveurs: Vec<NoeudServeur> = Vec::new();
        let mut idx_par_cle: HashMap<String, usize> = HashMap::new();

        // We also need, per client, the set of server ids it touches.
        let mut aretes: Vec<Arete> = Vec::new();
        let mut clients_nodes: Vec<NoeudClient> = Vec::with_capacity(clients.len());

        for (i_cli, client) in clients.iter().enumerate() {
            let client_id = format!("client:{}:{}", client_kind_slug(client), i_cli);
            // Track scopes reachable from this specific client (dedup).
            let mut scopes_atteints: BTreeSet<String> = BTreeSet::new();

            for serveur in &client.serveurs {
                if serveur.disabled {
                    // Disabled entries don't contribute to blast radius.
                    continue;
                }
                let package = inferer_package(serveur);
                let cle = cle_serveur(&package, &serveur.commande, &serveur.args);

                let s_idx = if let Some(&idx) = idx_par_cle.get(&cle) {
                    idx
                } else {
                    let idx = serveurs.len();
                    let portees = inferer_portees(&package, &serveur.args, &serveur.commande);
                    serveurs.push(NoeudServeur {
                        id: format!("server:{}", idx),
                        nom: serveur.nom.clone(),
                        package: package.clone(),
                        portees,
                    });
                    idx_par_cle.insert(cle, idx);
                    idx
                };

                // Edge client → server.
                aretes.push(Arete {
                    source: client_id.clone(),
                    cible: serveurs[s_idx].id.clone(),
                });
                for p in &serveurs[s_idx].portees {
                    scopes_atteints.insert(p.clone());
                }
            }

            let blast = score_blast_radius(&scopes_atteints);
            clients_nodes.push(NoeudClient {
                id: client_id,
                libelle: client.libelle.clone(),
                blast_radius: blast,
            });
        }

        let indice_max = clients_nodes
            .iter()
            .map(|c| c.blast_radius)
            .fold(0.0_f64, f64::max);

        GrapheConfiance {
            clients: clients_nodes,
            serveurs,
            aretes,
            indice_max,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn client_kind_slug(c: &ClientDecouvert) -> String {
    // We can't depend on `serde_json` round-trip here cheaply — just pick a
    // stable lowercased label.
    c.libelle
        .to_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

/// Build a canonical key used to dedupe servers across clients.
fn cle_serveur(
    package: &Option<String>,
    commande: &Option<String>,
    args: &[String],
) -> String {
    let pkg = package.as_deref().unwrap_or("");
    let cmd = commande.as_deref().unwrap_or("");
    format!("{pkg}\u{0001}{cmd}\u{0001}{}", args.join("\u{0002}"))
}

/// Try to extract a meaningful "package" identifier from a server config.
///
/// For `npx -y @modelcontextprotocol/server-filesystem /tmp` we want
/// `@modelcontextprotocol/server-filesystem`. For `uvx mcp-server-git` we
/// want `mcp-server-git`. Falls back to the raw command otherwise.
fn inferer_package(s: &ServeurMcpDeclare) -> Option<String> {
    // Look through args for the first token that looks like a package name
    // (skipping the npm/uvx flags).
    let skip_flags = ["-y", "--yes", "-q", "--quiet", "--silent"];
    for a in &s.args {
        if a.starts_with('-') && skip_flags.contains(&a.as_str()) {
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        // Looks like a path? Skip — these are typically positional args.
        if a.starts_with('/') || a.starts_with("./") || a.starts_with("../") {
            continue;
        }
        return Some(a.clone());
    }
    s.commande.clone()
}

/// Map a server (by package / args / command) to its functional scopes.
///
/// Scope tags are stored as plain strings on the graph so we can grow the
/// taxonomy without touching `sentinel_protocol::Portee`. The names mirror
/// `Portee` variants where possible (`filesystem`, `base_donnees`,
/// `api_externe`, `secrets`, `reseau`, plus the synthetic `navigateur`,
/// `read`, `write`).
fn inferer_portees(
    package: &Option<String>,
    args: &[String],
    commande: &Option<String>,
) -> Vec<String> {
    let mut portees: BTreeSet<String> = BTreeSet::new();
    let pkg_lower = package.as_deref().unwrap_or("").to_lowercase();
    let cmd_lower = commande.as_deref().unwrap_or("").to_lowercase();
    let haystack = format!("{pkg_lower} {cmd_lower}");

    // --- Mapping table --------------------------------------------------
    // Order matters only for clarity; portees is a set so dupes are ignored.

    // Filesystem servers.
    if haystack.contains("server-filesystem")
        || haystack.contains("mcp-filesystem")
        || haystack.contains("filesystem")
    {
        portees.insert("filesystem".into());
        portees.insert("read".into());
        // Writable iff a path arg was supplied (the official server treats
        // every positional path as r/w). Conservative default: assume write
        // when there is at least one path-like argument.
        if args.iter().any(|a| a.starts_with('/') || a.contains('~')) {
            portees.insert("write".into());
        }
    }

    // GitHub / GitLab / Bitbucket / Linear / Jira / Notion / Slack — all
    // talk to an external API and almost always carry a token.
    if haystack.contains("server-github")
        || haystack.contains("mcp-server-github")
        || haystack.contains("github")
        || haystack.contains("gitlab")
        || haystack.contains("bitbucket")
        || haystack.contains("linear")
        || haystack.contains("slack")
        || haystack.contains("notion")
    {
        portees.insert("external_api".into());
        portees.insert("secrets".into());
    }

    // Database servers.
    if haystack.contains("server-postgres")
        || haystack.contains("server-sqlite")
        || haystack.contains("mcp-server-postgres")
        || haystack.contains("mcp-server-sqlite")
        || haystack.contains("postgres")
        || haystack.contains("sqlite")
        || haystack.contains("mysql")
    {
        portees.insert("database".into());
        portees.insert("read".into());
    }

    // Web search — external API + network.
    if haystack.contains("server-brave-search")
        || haystack.contains("brave-search")
        || haystack.contains("server-search")
    {
        portees.insert("external_api".into());
        portees.insert("network".into());
    }

    // Puppeteer / Playwright — network + automated writes.
    if haystack.contains("puppeteer") || haystack.contains("playwright") {
        portees.insert("network".into());
        portees.insert("write".into());
    }

    // Chrome DevTools — browser scope + network + read.
    if haystack.contains("chrome-devtools") || haystack.contains("chrome_devtools") {
        portees.insert("browser".into());
        portees.insert("network".into());
        portees.insert("read".into());
    }

    // Generic fetch/http servers.
    if haystack.contains("server-fetch") || haystack.contains("mcp-fetch") {
        portees.insert("network".into());
        portees.insert("external_api".into());
    }

    // Secrets / credential stores.
    if haystack.contains("vault") || haystack.contains("1password") || haystack.contains("bitwarden")
    {
        portees.insert("secrets".into());
    }

    if portees.is_empty() {
        portees.insert("unknown".into());
    }

    portees.into_iter().collect()
}

/// Translate a set of scope tags into a blast-radius score.
///
/// Weights (per spec):
/// - `secrets`               → 10
/// - `filesystem` + `write`  →  8 (combo, replaces the bare-filesystem 4)
/// - `filesystem` alone      →  4
/// - `base_donnees`          →  6
/// - `api_externe`           →  3
/// - `reseau`                →  2
///
/// Read-only scopes (`read`) and `navigateur` are tracked on the graph for
/// the UI but do not directly add to the score (they almost always come
/// alongside one of the weighted scopes).
fn score_blast_radius(scopes: &BTreeSet<String>) -> f64 {
    let mut score = 0.0_f64;

    let has = |s: &str| scopes.contains(s);

    if has("secrets") {
        score += 10.0;
    }
    if has("filesystem") {
        if has("write") || has("ecriture") {
            score += 8.0;
        } else {
            score += 4.0;
        }
    }
    if has("database") {
        score += 6.0;
    }
    if has("external_api") {
        score += 3.0;
    }
    if has("network") {
        score += 2.0;
    }

    score
}
