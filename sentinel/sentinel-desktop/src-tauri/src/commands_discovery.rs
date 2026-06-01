//! Tauri commands wrapping the `sentinel-discovery` crate.
//!
//! Exposes [`discover_system`] to the React frontend. The command runs the
//! default discovery orchestrator (which scans every known AI client config
//! on this Mac in parallel) and maps the result into the stable DTO shape
//! defined in `src/api/contract.ts`.

use std::time::Duration;

use sentinel_discovery::{
    threat_intel::FluxMenaces,
    trust_graph::ConstructeurGraphe,
    ClientDecouvert, ClientKind, EtatProbe, OrchestrateurDecouverte, ProbeurActif,
    ServeurMcpDeclare,
};
use sentinel_protocol::Severite;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

/// One MCP server declared by a client config, normalised for the UI.
#[derive(Serialize)]
pub struct DeclaredServer {
    pub name: String,
    pub transport: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
    pub url: Option<String>,
    pub package: Option<String>,
    pub scopes: Vec<String>,
    pub disabled: bool,
}

/// One AI client found on this Mac, normalised for the UI.
#[derive(Serialize)]
pub struct DiscoveredClient {
    pub kind: String,
    pub label: String,
    pub installed: bool,
    pub version: Option<String>,
    pub binary_path: Option<String>,
    pub configs: Vec<String>,
    pub servers: Vec<DeclaredServer>,
    pub notes: Vec<String>,
}

/// Aggregated discovery report mirroring `DiscoveryReport` in the TS contract.
#[derive(Serialize)]
pub struct DiscoveryReport {
    pub clients: Vec<DiscoveredClient>,
    pub started_at: String,
    pub finished_at: String,
}

/// Map a [`ClientKind`] to the kebab-case identifier used by the TS contract.
fn kind_to_string(kind: ClientKind) -> &'static str {
    match kind {
        ClientKind::ClaudeDesktop => "claude-desktop",
        ClientKind::ClaudeCodeCli => "claude-code-cli",
        ClientKind::Cursor => "cursor",
        ClientKind::Windsurf => "windsurf",
        ClientKind::Continue => "continue",
        ClientKind::Zed => "zed",
        ClientKind::VsCode => "vscode",
        ClientKind::Aider => "aider",
        ClientKind::Goose => "goose",
        ClientKind::Codex => "codex",
        ClientKind::Antigravity => "antigravity",
        ClientKind::LmStudio => "lm-studio",
        ClientKind::OpenWebUi => "open-webui",
        ClientKind::Sketch => "sketch",
        ClientKind::Autre => "other",
    }
}

/// Derive the npm package / binary identifier from a stdio command + args.
///
/// For `npx`, this is the first argument that doesn't look like a flag
/// (i.e. doesn't start with `-`). Otherwise we fall back to the command
/// itself if it looks like a package-ish identifier.
fn derive_package(command: Option<&str>, args: &[String]) -> Option<String> {
    let cmd = command?;
    if cmd == "npx" || cmd.ends_with("/npx") {
        return args
            .iter()
            .find(|a| !a.starts_with('-'))
            .cloned();
    }
    None
}

/// Infer high-level capability scopes from a package name using a small
/// keyword heuristic. Keeps in sync with the `Scope` union in
/// `src/api/contract.ts`.
fn infer_scopes(package: Option<&str>, args: &[String]) -> Vec<String> {
    // Build a single haystack from the package name and stringified args so we
    // can match against either source.
    let mut haystack = String::new();
    if let Some(p) = package {
        haystack.push_str(&p.to_lowercase());
    }
    haystack.push(' ');
    for a in args {
        haystack.push_str(&a.to_lowercase());
        haystack.push(' ');
    }

    // (keyword, scope) heuristic table — first hit wins per scope.
    let table: &[(&[&str], &str)] = &[
        (&["filesystem", "fs", "file-system", "files"], "filesystem"),
        (&["secret", "vault", "1password", "keychain", "credential"], "secrets"),
        (&["http", "fetch", "network", "web", "url", "curl"], "network"),
        (&["db", "database", "postgres", "mysql", "sqlite", "mongo", "redis"], "database"),
        (&["browser", "puppeteer", "playwright", "chrome", "chromium", "selenium"], "browser"),
    ];

    let mut scopes: Vec<String> = Vec::new();
    for (keywords, scope) in table {
        if keywords.iter().any(|kw| haystack.contains(kw)) {
            scopes.push((*scope).to_string());
        }
    }

    if scopes.is_empty() {
        scopes.push("unknown".to_string());
    }
    scopes
}

/// Map a single declared server into the UI DTO.
fn map_server(s: &ServeurMcpDeclare) -> DeclaredServer {
    let package = derive_package(s.commande.as_deref(), &s.args);
    let scopes = infer_scopes(package.as_deref(), &s.args);
    DeclaredServer {
        name: s.nom.clone(),
        transport: s.transport.clone(),
        command: s.commande.clone(),
        args: s.args.clone(),
        env_keys: s.env_keys.clone(),
        url: s.url.clone(),
        package,
        scopes,
        disabled: s.disabled,
    }
}

/// Map a discovered client into the UI DTO.
fn map_client(c: &ClientDecouvert) -> DiscoveredClient {
    let binary_path = c
        .binary_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());
    let configs: Vec<String> = c
        .configs
        .iter()
        .map(|cs| cs.config_path.to_string_lossy().to_string())
        .collect();
    let installed = binary_path.is_some() || !configs.is_empty();
    DiscoveredClient {
        kind: kind_to_string(c.kind).to_string(),
        label: c.libelle.clone(),
        installed,
        version: c.version.clone(),
        binary_path,
        configs,
        servers: c.serveurs.iter().map(map_server).collect(),
        notes: c.notes.clone(),
    }
}

// ─── Live probe DTOs ──────────────────────────────────────────────────────
// Inputs/outputs of the [`probe_server`] command: the UI passes a single
// declared server (mirroring `DeclaredServer` in the TS contract) and gets
// back the result of an actual MCP `initialize` + `tools/list` round-trip.

/// Subset of [`DeclaredServer`] the frontend needs to send to launch a probe.
#[derive(Deserialize)]
pub struct DeclaredServerInput {
    pub name: String,
    pub transport: String,
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

/// One tool returned by the live `tools/list` response, trimmed for the UI.
#[derive(Serialize)]
pub struct ToolBrief {
    pub name: String,
    pub description: Option<String>,
}

/// One poisoning finding surfaced by `InspecteurPoisoning` on the live tools.
#[derive(Serialize)]
pub struct PoisoningBrief {
    pub pattern: String,
    pub category: String,
    pub excerpt: String,
    pub severity: String,
}

/// Full result of probing a single declared MCP server.
#[derive(Serialize)]
pub struct ProbeResult {
    pub server_name: String,
    /// "success" / "launch_failed" / "handshake_failed" / "parse_failed"
    pub state: String,
    pub tool_count: u64,
    pub fingerprint: Option<String>,
    pub tools: Vec<ToolBrief>,
    pub poisoning_findings: Vec<PoisoningBrief>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

fn etat_to_string(e: &EtatProbe) -> &'static str {
    match e {
        EtatProbe::Reussi => "success",
        EtatProbe::EchecLancement => "launch_failed",
        EtatProbe::EchecHandshake => "handshake_failed",
        EtatProbe::EchecParseur => "parse_failed",
    }
}

fn severite_to_string(s: &Severite) -> &'static str {
    match s {
        Severite::Info => "info",
        Severite::Moyenne => "medium",
        Severite::Haute => "high",
        Severite::Critique => "critical",
    }
}

/// Probe one MCP server live: spawn it, run the MCP handshake, list its tools,
/// fingerprint them, and run poisoning detection on the response.
///
/// Wraps [`ProbeurActif::probe_serveur`]; the probe itself enforces an 8 s
/// budget per server, so we don't add an outer timeout here.
#[tauri::command]
pub async fn probe_server(server: DeclaredServerInput) -> Result<ProbeResult, String> {
    let serveur = ServeurMcpDeclare {
        nom: server.name.clone(),
        transport: server.transport,
        commande: server.command,
        args: server.args,
        env_keys: vec![],
        url: None,
        disabled: false,
    };

    let probeur = ProbeurActif::par_defaut();
    let rapport = probeur.probe_serveur(&serveur).await;

    let tools: Vec<ToolBrief> = rapport
        .outils
        .iter()
        .map(|o| ToolBrief {
            name: o.nom.clone(),
            description: o.description.clone(),
        })
        .collect();
    let tool_count = tools.len() as u64;

    let poisoning_findings: Vec<PoisoningBrief> = rapport
        .constats_poisoning
        .iter()
        .map(|c| PoisoningBrief {
            pattern: c.pattern.clone(),
            category: c.categorie.clone(),
            excerpt: c.extrait.clone(),
            severity: severite_to_string(&c.severite).to_string(),
        })
        .collect();

    Ok(ProbeResult {
        server_name: rapport.serveur_nom,
        state: etat_to_string(&rapport.etat).to_string(),
        tool_count,
        fingerprint: rapport.empreinte_serveur.map(|e| e.0),
        tools,
        poisoning_findings,
        duration_ms: rapport.duree_ms,
        error: rapport.erreur,
    })
}

/// Sweep the system for AI clients and the MCP servers they declare.
///
/// Wraps the underlying orchestrator in a 15s safety timeout — discovery is
/// pure filesystem reads, but we never want the UI to hang forever.
#[tauri::command]
pub async fn discover_system() -> Result<DiscoveryReport, String> {
    let orchestrator = OrchestrateurDecouverte::default();
    let report = timeout(Duration::from_secs(15), orchestrator.balayer())
        .await
        .map_err(|_| "discovery timed out after 15s".to_string())?;

    let clients = report.clients.iter().map(map_client).collect();
    Ok(DiscoveryReport {
        clients,
        started_at: report.demarre_a.to_rfc3339(),
        finished_at: report.termine_a.to_rfc3339(),
    })
}

// ─── Trust graph DTOs ─────────────────────────────────────────────────────
// Returned by [`compute_trust_graph`]: the *real* trust graph computed by
// `sentinel_discovery::trust_graph::ConstructeurGraphe`. The frontend used to
// derive this client-side from `discover_system()`; this command moves the
// computation to Rust so the UI gets authoritative blast-radius scores.

/// One graph node — either an AI client or an MCP server.
#[derive(Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    /// "client" or "server".
    pub kind: String,
    /// Computed blast-radius score; present only on `kind == "client"`.
    pub blast_radius: Option<f64>,
    /// Inferred functional scopes for this server; empty on client nodes.
    pub scopes: Vec<String>,
}

/// One directed edge `client → server` in the trust graph.
#[derive(Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
}

/// Full trust-graph payload returned to the UI.
#[derive(Serialize)]
pub struct TrustGraphResponse {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Largest blast-radius observed; UI normalises each client by this.
    pub max_blast_radius: f64,
}

/// Build the trust graph from a fresh discovery sweep.
///
/// Runs the discovery orchestrator (same as [`discover_system`]) then feeds
/// the discovered clients into [`ConstructeurGraphe::construire`] so the UI
/// never has to redo blast-radius scoring client-side.
#[tauri::command]
pub async fn compute_trust_graph() -> Result<TrustGraphResponse, String> {
    let orchestrator = OrchestrateurDecouverte::default();
    let report = timeout(Duration::from_secs(15), orchestrator.balayer())
        .await
        .map_err(|_| "discovery timed out after 15s".to_string())?;

    let graphe = ConstructeurGraphe::construire(&report.clients);

    let mut nodes: Vec<GraphNode> = Vec::with_capacity(graphe.clients.len() + graphe.serveurs.len());
    for c in &graphe.clients {
        nodes.push(GraphNode {
            id: c.id.clone(),
            label: c.libelle.clone(),
            kind: "client".to_string(),
            blast_radius: Some(c.blast_radius),
            scopes: Vec::new(),
        });
    }
    for s in &graphe.serveurs {
        nodes.push(GraphNode {
            id: s.id.clone(),
            label: s.nom.clone(),
            kind: "server".to_string(),
            blast_radius: None,
            scopes: s.portees.clone(),
        });
    }

    let edges: Vec<GraphEdge> = graphe
        .aretes
        .iter()
        .map(|a| GraphEdge {
            from: a.source.clone(),
            to: a.cible.clone(),
        })
        .collect();

    Ok(TrustGraphResponse {
        nodes,
        edges,
        max_blast_radius: graphe.indice_max,
    })
}

// ─── Threat intelligence DTOs ─────────────────────────────────────────────
// Returned by [`list_threats`]: the curated `FluxMenaces` feed, enriched
// per-entry with a count of how many MCP servers currently declared on
// this Mac match the threat. UI surfaces this in the Discovery page so
// operators can spot known-bad packages in their own configs at a glance.

/// One threat-feed entry plus a live `matches_count` against this Mac.
#[derive(Serialize)]
pub struct ThreatEntry {
    pub identifier: String,
    pub package_name: String,
    pub reason: String,
    pub severity: String,
    pub references: Vec<String>,
    pub published_at: String,
    /// Number of declared MCP servers currently matching this threat.
    pub matches_count: u64,
}

/// Map severity string to a sortable rank (higher = more severe).
fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 3,
        "high" => 2,
        "medium" => 1,
        _ => 0,
    }
}

/// List every entry in the bundled threat-intel feed, annotated with the
/// number of currently-declared MCP servers that match it.
///
/// Sorting:
///   1. entries with `matches_count > 0` first, descending by match count
///   2. then by severity (critical > high > medium)
///   3. then by `published_at` descending (most recent first)
#[tauri::command]
pub async fn list_threats() -> Result<Vec<ThreatEntry>, String> {
    let flux = FluxMenaces::par_defaut();

    // Best-effort discovery — if the sweep fails or times out, we still
    // return the feed with `matches_count = 0` so the UI works offline.
    let orchestrator = OrchestrateurDecouverte::default();
    let servers: Vec<ServeurMcpDeclare> = match timeout(
        Duration::from_secs(15),
        orchestrator.balayer(),
    )
    .await
    {
        Ok(report) => report
            .clients
            .iter()
            .flat_map(|c| c.serveurs.clone())
            .collect(),
        Err(_) => Vec::new(),
    };

    // For each threat, count how many declared servers match it.
    let mut entries: Vec<ThreatEntry> = flux
        .entrees
        .iter()
        .map(|e| {
            let matches_count = servers
                .iter()
                .filter(|s| !flux.correspondances(s).is_empty()
                    && flux
                        .correspondances(s)
                        .iter()
                        .any(|m| m.identifiant == e.identifiant))
                .count() as u64;
            ThreatEntry {
                identifier: e.identifiant.clone(),
                package_name: e.package_name.clone(),
                reason: e.raison.clone(),
                severity: e.severite.clone(),
                references: e.references.clone(),
                published_at: e.publie_a.to_string(),
                matches_count,
            }
        })
        .collect();

    entries.sort_by(|a, b| {
        // 1. matches > 0 first, then by descending match count
        let a_has = (a.matches_count > 0) as u8;
        let b_has = (b.matches_count > 0) as u8;
        b_has
            .cmp(&a_has)
            .then_with(|| b.matches_count.cmp(&a.matches_count))
            // 2. by severity rank descending
            .then_with(|| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)))
            // 3. by published_at descending (lexicographic works for YYYY-MM-DD)
            .then_with(|| b.published_at.cmp(&a.published_at))
    });

    Ok(entries)
}
