//! Active MCP probe — launch each declared MCP server in a sandbox, request
//! its `tools/list`, fingerprint every tool, and run poisoning detection on
//! the live response.
//!
//! This is Sentinel's killer differentiator: instead of statically grepping
//! the client config, we actually *talk* to the declared server via the
//! standard MCP handshake and capture what it exposes at runtime.
//!
//! Flow per server:
//!   1. Spawn the declared command + args with piped stdin/stdout/stderr.
//!   2. Send `initialize` → wait for response → send `notifications/initialized`.
//!   3. Send `tools/list` → wait up to `timeout` for the JSON-RPC response.
//!   4. Parse the response (`sentinel_scan::tools_list::parser_reponse_tools_list`).
//!   5. Compute `empreinte_serveur(outils)` and run `InspecteurPoisoning::inspecter`.
//!   6. Kill the child cleanly.
//!
//! Failures are reported via `EtatProbe` + `erreur`; this module never panics.

use std::process::Stdio;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sentinel_detect::{empreinte_serveur, ConstatPoisoning, InspecteurPoisoning};
use sentinel_protocol::{Empreinte, Outil};
use sentinel_scan::tools_list::parser_reponse_tools_list;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use crate::model::{ClientDecouvert, ServeurMcpDeclare};

/// Outcome state of a single active probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtatProbe {
    /// `tools/list` returned successfully; fingerprint + poisoning available.
    Reussi,
    /// The declared command could not be spawned (binary not found, etc.).
    EchecLancement,
    /// The handshake or `tools/list` timed out / the process died early.
    EchecHandshake,
    /// `tools/list` response was received but could not be parsed.
    EchecParseur,
}

/// Enriched per-server report produced by an active probe.
#[derive(Debug, Clone)]
pub struct RapportProbe {
    pub serveur_nom: String,
    pub serveur_commande: String,
    pub demarre_a: DateTime<Utc>,
    pub duree_ms: u64,
    pub etat: EtatProbe,
    pub outils: Vec<Outil>,
    pub empreinte_serveur: Option<Empreinte>,
    pub constats_poisoning: Vec<ConstatPoisoning>,
    pub erreur: Option<String>,
}

/// Active MCP probe driver.
pub struct ProbeurActif {
    pub timeout: Duration,
}

impl Default for ProbeurActif {
    fn default() -> Self {
        Self::par_defaut()
    }
}

impl ProbeurActif {
    /// Construct a probe driver with the default 8 s budget per server.
    pub fn par_defaut() -> Self {
        Self {
            timeout: Duration::from_secs(8),
        }
    }

    /// Probe one declared MCP server end-to-end.
    ///
    /// HTTP transports are skipped with `EchecLancement` in v1.
    pub async fn probe_serveur(&self, s: &ServeurMcpDeclare) -> RapportProbe {
        let demarre_a = Utc::now();
        let debut = std::time::Instant::now();

        let commande_libelle = match &s.commande {
            Some(c) => {
                if s.args.is_empty() {
                    c.clone()
                } else {
                    format!("{} {}", c, s.args.join(" "))
                }
            }
            None => s.url.clone().unwrap_or_default(),
        };

        // Fast path: HTTP transport is not yet implemented in v1.
        if s.transport.eq_ignore_ascii_case("http")
            || s.transport.eq_ignore_ascii_case("sse")
        {
            return RapportProbe {
                serveur_nom: s.nom.clone(),
                serveur_commande: commande_libelle,
                demarre_a,
                duree_ms: debut.elapsed().as_millis() as u64,
                etat: EtatProbe::EchecLancement,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some("http probe not implemented in v1".into()),
            };
        }

        let commande = match &s.commande {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                return RapportProbe {
                    serveur_nom: s.nom.clone(),
                    serveur_commande: commande_libelle,
                    demarre_a,
                    duree_ms: debut.elapsed().as_millis() as u64,
                    etat: EtatProbe::EchecLancement,
                    outils: vec![],
                    empreinte_serveur: None,
                    constats_poisoning: vec![],
                    erreur: Some("no command declared for stdio server".into()),
                };
            }
        };

        let resultat = timeout(self.timeout, executer_probe(&commande, &s.args)).await;

        let duree_ms = debut.elapsed().as_millis() as u64;

        match resultat {
            // Timeout firing on the whole probe.
            Err(_) => RapportProbe {
                serveur_nom: s.nom.clone(),
                serveur_commande: commande_libelle,
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecHandshake,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(format!(
                    "probe timed out after {} ms",
                    self.timeout.as_millis()
                )),
            },
            Ok(Err(SortieProbe::Lancement(e))) => RapportProbe {
                serveur_nom: s.nom.clone(),
                serveur_commande: commande_libelle,
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecLancement,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(e),
            },
            Ok(Err(SortieProbe::Handshake(e))) => RapportProbe {
                serveur_nom: s.nom.clone(),
                serveur_commande: commande_libelle,
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecHandshake,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(e),
            },
            Ok(Err(SortieProbe::Parseur(e))) => RapportProbe {
                serveur_nom: s.nom.clone(),
                serveur_commande: commande_libelle,
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecParseur,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(e),
            },
            Ok(Ok(outils)) => {
                let empreinte = empreinte_serveur(&outils);
                let constats = InspecteurPoisoning::inspecter(&outils);
                RapportProbe {
                    serveur_nom: s.nom.clone(),
                    serveur_commande: commande_libelle,
                    demarre_a,
                    duree_ms,
                    etat: EtatProbe::Reussi,
                    outils,
                    empreinte_serveur: Some(empreinte),
                    constats_poisoning: constats,
                    erreur: None,
                }
            }
        }
    }

    /// Probe every server declared across a discovery sweep.
    ///
    /// Servers explicitly marked `disabled` are skipped. Each remaining server
    /// is probed sequentially (so the global wall time stays predictable).
    pub async fn probe_clients(&self, clients: &[ClientDecouvert]) -> Vec<RapportProbe> {
        let mut rapports = Vec::new();
        for client in clients {
            for serveur in &client.serveurs {
                if serveur.disabled {
                    continue;
                }
                rapports.push(self.probe_serveur(serveur).await);
            }
        }
        rapports
    }
}

/// Internal probe failure mode (kept private; we map to `EtatProbe` outside).
enum SortieProbe {
    Lancement(String),
    Handshake(String),
    Parseur(String),
}

/// Core stdio dance: spawn → initialize → initialized → tools/list → parse.
async fn executer_probe(
    commande: &str,
    args: &[String],
) -> Result<Vec<Outil>, SortieProbe> {
    // 1. Spawn the child with piped stdio.
    //
    // When Sentinel runs as a .app bundle launched via Finder/launchd, the
    // inherited PATH is the minimal launchd one (`/usr/bin:/bin:/usr/sbin:/sbin`)
    // — Homebrew binaries like `npx` aren't visible. We augment PATH with the
    // standard Mac developer locations so commands like `npx`/`uvx` resolve.
    let path_existing = std::env::var("PATH").unwrap_or_default();
    let path_augmented = format!(
        "/opt/homebrew/bin:/usr/local/bin:/opt/homebrew/opt/node/bin:/Users/{}/.cargo/bin:/Users/{}/.local/bin:{}",
        std::env::var("USER").unwrap_or_default(),
        std::env::var("USER").unwrap_or_default(),
        path_existing,
    );

    // Defensive resolution: if `commande` is a bare name (no `/`), try to
    // resolve it to an absolute path BEFORE spawning. This is a belt-and-
    // suspenders complement to the augmented PATH env: in some launch
    // contexts (Finder/launchd, sandboxed apps) the augmented PATH may not
    // be honored for binary lookup, so we pre-resolve.
    let commande_a_lancer: String = if commande.contains('/') {
        commande.to_string()
    } else {
        resoudre_chemin_absolu(commande, &path_augmented)
            .unwrap_or_else(|| commande.to_string())
    };

    let mut child: Child = Command::new(&commande_a_lancer)
        .args(args)
        .env("PATH", &path_augmented)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            SortieProbe::Lancement(format!("spawn `{}` failed: {}", commande, e))
        })?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SortieProbe::Lancement("child stdin unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SortieProbe::Lancement("child stdout unavailable".into()))?;

    // Run the actual protocol exchange; ensure we kill the child afterwards.
    let resultat = dialogue_mcp(stdin, stdout).await;

    // Always reap the child — kill_on_drop makes this safe even on early return.
    let _ = child.start_kill();
    let _ = child.wait().await;

    resultat
}

/// Best-effort resolution of a bare command name to an absolute path.
///
/// Tries entries from the augmented PATH first, then a hard-coded list of
/// well-known install locations on macOS (Homebrew, system, user-local,
/// bun, deno). Returns `None` if nothing resolves; callers should fall
/// back to spawning the bare name and letting the OS search PATH.
fn resoudre_chemin_absolu(cmd: &str, path_env: &str) -> Option<String> {
    // 1) Walk the augmented PATH.
    for dir in path_env.split(':').filter(|s| !s.is_empty()) {
        let candidat = std::path::Path::new(dir).join(cmd);
        if candidat.is_file() {
            return candidat.to_str().map(|s| s.to_string());
        }
    }

    // 2) Standard fallback locations (some may overlap with PATH; that's fine).
    let home = std::env::var("HOME").unwrap_or_default();
    let emplacements: [String; 5] = [
        format!("/opt/homebrew/bin/{}", cmd),
        format!("/usr/local/bin/{}", cmd),
        format!("{}/.local/bin/{}", home, cmd),
        format!("{}/.bun/bin/{}", home, cmd),
        format!("{}/.deno/bin/{}", home, cmd),
    ];
    for chemin in &emplacements {
        if std::path::Path::new(chemin).is_file() {
            return Some(chemin.clone());
        }
    }

    None
}

/// Performs the JSON-RPC handshake and returns the parsed tool list.
async fn dialogue_mcp(
    mut stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
) -> Result<Vec<Outil>, SortieProbe> {
    let mut lecteur = BufReader::new(stdout);

    // 2. initialize
    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "sentinel-active-probe",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    });
    envoyer(&mut stdin, &init_req).await?;

    // Wait for the matching response (id == 1). Other lines (notifications,
    // logs, non-JSON) are skipped.
    let _init_resp = lire_reponse(&mut lecteur, &json!(1)).await?;

    // 3. notifications/initialized
    let initd = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    envoyer(&mut stdin, &initd).await?;

    // 4. tools/list
    let tools_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    envoyer(&mut stdin, &tools_req).await?;

    let tools_resp = lire_reponse(&mut lecteur, &json!(2)).await?;

    // 5. parse via the shared sentinel-scan parser.
    let parsed = parser_reponse_tools_list(&tools_resp).map_err(|e| {
        SortieProbe::Parseur(format!("tools/list response unparsable: {}", e))
    })?;

    Ok(parsed.outils)
}

/// Writes one JSON-RPC message terminated by a newline.
async fn envoyer(
    stdin: &mut tokio::process::ChildStdin,
    msg: &Value,
) -> Result<(), SortieProbe> {
    let mut ligne = serde_json::to_string(msg)
        .map_err(|e| SortieProbe::Handshake(format!("encode request: {}", e)))?;
    ligne.push('\n');
    stdin
        .write_all(ligne.as_bytes())
        .await
        .map_err(|e| SortieProbe::Handshake(format!("write to child stdin: {}", e)))?;
    stdin
        .flush()
        .await
        .map_err(|e| SortieProbe::Handshake(format!("flush child stdin: {}", e)))?;
    Ok(())
}

/// Reads lines until one decodes as a JSON-RPC response whose `id` matches
/// the expected value. Returns the full parsed JSON value.
async fn lire_reponse<R>(
    lecteur: &mut BufReader<R>,
    id_attendu: &Value,
) -> Result<Value, SortieProbe>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut ligne = String::new();
    loop {
        ligne.clear();
        let n = lecteur
            .read_line(&mut ligne)
            .await
            .map_err(|e| SortieProbe::Handshake(format!("read from child stdout: {}", e)))?;
        if n == 0 {
            return Err(SortieProbe::Handshake(
                "child closed stdout before response".into(),
            ));
        }
        let trimmed = ligne.trim();
        if trimmed.is_empty() {
            continue;
        }
        let valeur: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue, // non-JSON noise line, skip
        };
        // Notifications (no `id`) are not what we wait for.
        match valeur.get("id") {
            Some(v) if v == id_attendu => return Ok(valeur),
            _ => continue,
        }
    }
}
