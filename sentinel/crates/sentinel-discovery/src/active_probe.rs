//! Active MCP probe — launch each declared MCP server in a sandbox, request
//! its `tools/list`, fingerprint every tool, and run poisoning detection on
//! the live response.
//!
//! This is Sentinel's killer differentiator: instead of statically grepping
//! the client config, we actually *talk* to the declared server via the
//! standard MCP handshake and capture what it exposes at runtime.
//!
//! Flow per server:
//!   1. Spawn the declared command + args with piped stdin/stdout/stderr and
//!      a *minimal* environment (PATH + HOME only — never the parent's full
//!      env, to avoid leaking secrets to a potentially malicious server).
//!   2. Send `initialize` → wait for response → send `notifications/initialized`.
//!   3. Send `tools/list` → wait for the JSON-RPC response.
//!   4. Parse the response (`sentinel_scan::tools_list::parser_reponse_tools_list`).
//!   5. Compute `empreinte_serveur(outils)` and run `InspecteurPoisoning::inspecter`.
//!   6. Kill + reap the child unconditionally (no zombies).
//!
//! Robustness:
//!   - three configurable timeouts (connexion / réponse / total) — see
//!     [`ConfigProbe`];
//!   - retries with exponential backoff (1 retry by default), skipped when
//!     the failure cannot heal (binary absent);
//!   - fine-grained failure classification ([`ClassificationEchec`]) persisted
//!     in the report, exploitable by the scoring layer;
//!   - parallel probing bounded by `concurrence_max` (default 4); dropping the
//!     returned future cancels every in-flight probe and `kill_on_drop` kills
//!     the spawned children.
//!
//! Failures are reported via `EtatProbe` + `classification_echec` + `erreur`;
//! this module never panics.

use std::process::Stdio;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use sentinel_detect::{empreinte_serveur, ConstatPoisoning, InspecteurPoisoning};
use sentinel_protocol::{Empreinte, Outil};
use sentinel_scan::tools_list::parser_reponse_tools_list;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::timeout;

use crate::model::{ClientDecouvert, ServeurMcpDeclare};

/// Outcome state of a single active probe.
///
/// Kept intentionally coarse (and stable — consumers match exhaustively);
/// the fine-grained cause lives in [`ClassificationEchec`].
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

/// Fine-grained failure classification, persisted in the probe report and
/// exploitable by the scoring layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClassificationEchec {
    /// The declared binary does not exist / could not be spawned.
    BinaireAbsent,
    /// A timeout fired (connexion, réponse, ou budget total).
    Timeout,
    /// The transport refused the connection (spawn refused, TCP refused, HTTP
    /// status error, DNS failure).
    ConnexionRefusee,
    /// A response was received but is not valid MCP (unparsable tools/list,
    /// non-JSON body, empty SSE stream).
    ReponseMalformee,
    /// The process died before completing the handshake.
    CrashImmediat { code_sortie: Option<i32> },
}

/// Tunable knobs of the active probe (stdio + HTTP).
#[derive(Debug, Clone)]
pub struct ConfigProbe {
    /// Budget to establish the dialogue: stdio waits this long for the
    /// `initialize` response; HTTP uses it as the TCP connect timeout.
    pub timeout_connexion: Duration,
    /// Budget for each subsequent response (`tools/list`).
    pub timeout_reponse: Duration,
    /// Hard budget for one whole probe attempt. The child is killed when it
    /// fires.
    pub timeout_total: Duration,
    /// Number of *additional* attempts after the first failure.
    pub retries: u32,
    /// Initial backoff between attempts; doubled after each retry.
    pub backoff_initial: Duration,
    /// Max number of servers probed concurrently by `probe_clients`.
    pub concurrence_max: usize,
}

impl Default for ConfigProbe {
    fn default() -> Self {
        Self {
            timeout_connexion: Duration::from_secs(3),
            timeout_reponse: Duration::from_secs(5),
            timeout_total: Duration::from_secs(10),
            retries: 1,
            backoff_initial: Duration::from_millis(250),
            concurrence_max: 4,
        }
    }
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
    /// Fine-grained cause when `etat != Reussi`.
    pub classification_echec: Option<ClassificationEchec>,
    /// How many attempts were made (1 = first try succeeded/failed for good).
    pub tentatives: u32,
}

/// Active MCP probe driver.
pub struct ProbeurActif {
    pub config: ConfigProbe,
}

impl Default for ProbeurActif {
    fn default() -> Self {
        Self::par_defaut()
    }
}

impl ProbeurActif {
    /// Construct a probe driver with sane defaults (see [`ConfigProbe`]).
    pub fn par_defaut() -> Self {
        Self {
            config: ConfigProbe::default(),
        }
    }

    /// Construct a probe driver with a custom configuration.
    pub fn avec_config(config: ConfigProbe) -> Self {
        Self { config }
    }

    /// Probe one declared MCP server end-to-end, with retries.
    ///
    /// HTTP transports are skipped here — use
    /// [`ProbeurHttp`](crate::active_probe_http::ProbeurHttp).
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

        // Fast path: HTTP transport is handled by `ProbeurHttp`, not here.
        if s.transport.eq_ignore_ascii_case("http")
            || s.transport.eq_ignore_ascii_case("sse")
        {
            return rapport_echec(
                &s.nom,
                commande_libelle,
                demarre_a,
                debut.elapsed().as_millis() as u64,
                EchecProbe {
                    etat: EtatProbe::EchecLancement,
                    classification: ClassificationEchec::ConnexionRefusee,
                    message: "http probe not implemented in v1".into(),
                },
                1,
            );
        }

        let commande = match &s.commande {
            Some(c) if !c.is_empty() => c.clone(),
            _ => {
                return rapport_echec(
                    &s.nom,
                    commande_libelle,
                    demarre_a,
                    debut.elapsed().as_millis() as u64,
                    EchecProbe {
                        etat: EtatProbe::EchecLancement,
                        classification: ClassificationEchec::BinaireAbsent,
                        message: "no command declared for stdio server".into(),
                    },
                    1,
                );
            }
        };

        let mut tentative: u32 = 0;
        loop {
            tentative += 1;
            match executer_probe(&commande, &s.args, &self.config).await {
                Ok(outils) => {
                    let empreinte = empreinte_serveur(&outils);
                    let constats = InspecteurPoisoning::inspecter(&outils);
                    return RapportProbe {
                        serveur_nom: s.nom.clone(),
                        serveur_commande: commande_libelle,
                        demarre_a,
                        duree_ms: debut.elapsed().as_millis() as u64,
                        etat: EtatProbe::Reussi,
                        outils,
                        empreinte_serveur: Some(empreinte),
                        constats_poisoning: constats,
                        erreur: None,
                        classification_echec: None,
                        tentatives: tentative,
                    };
                }
                Err(echec) => {
                    let irrecuperable = matches!(
                        echec.classification,
                        ClassificationEchec::BinaireAbsent
                    );
                    if irrecuperable || tentative > self.config.retries {
                        return rapport_echec(
                            &s.nom,
                            commande_libelle,
                            demarre_a,
                            debut.elapsed().as_millis() as u64,
                            echec,
                            tentative,
                        );
                    }
                    let backoff =
                        self.config.backoff_initial * 2u32.saturating_pow(tentative - 1);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// Probe every server declared across a discovery sweep, in parallel.
    ///
    /// Servers explicitly marked `disabled` are skipped. Probing is bounded
    /// by `config.concurrence_max` concurrent servers; report order follows
    /// declaration order. Dropping the returned future cancels all in-flight
    /// probes cleanly (children are killed via `kill_on_drop`).
    pub async fn probe_clients(&self, clients: &[ClientDecouvert]) -> Vec<RapportProbe> {
        let serveurs: Vec<&ServeurMcpDeclare> = clients
            .iter()
            .flat_map(|c| c.serveurs.iter())
            .filter(|s| !s.disabled)
            .collect();

        futures::stream::iter(serveurs)
            .map(|s| self.probe_serveur(s))
            .buffered(self.config.concurrence_max.max(1))
            .collect()
            .await
    }
}

/// Internal probe failure (mapped into the public report at the boundary).
#[derive(Debug)]
pub(crate) struct EchecProbe {
    pub(crate) etat: EtatProbe,
    pub(crate) classification: ClassificationEchec,
    pub(crate) message: String,
}

/// Build a failure report from an `EchecProbe`.
fn rapport_echec(
    nom: &str,
    commande_libelle: String,
    demarre_a: DateTime<Utc>,
    duree_ms: u64,
    echec: EchecProbe,
    tentatives: u32,
) -> RapportProbe {
    RapportProbe {
        serveur_nom: nom.to_string(),
        serveur_commande: commande_libelle,
        demarre_a,
        duree_ms,
        etat: echec.etat,
        outils: vec![],
        empreinte_serveur: None,
        constats_poisoning: vec![],
        erreur: Some(echec.message),
        classification_echec: Some(echec.classification),
        tentatives,
    }
}

/// Dialogue-level failure modes, classified by the caller which owns the child.
enum ErreurDialogue {
    /// I/O error talking to the child (broken pipe, read error) — the child
    /// most likely died.
    Io(String),
    /// The child closed stdout before answering.
    FluxFerme,
    /// `initialize` response did not arrive within `timeout_connexion`.
    TimeoutConnexion,
    /// `tools/list` response did not arrive within `timeout_reponse`.
    TimeoutReponse,
    /// The `tools/list` payload could not be parsed.
    Parse(String),
}

/// Core stdio dance: spawn → initialize → initialized → tools/list → parse.
///
/// One *attempt*: bounded by `config.timeout_total`; the child is always
/// killed and reaped before returning.
async fn executer_probe(
    commande: &str,
    args: &[String],
    config: &ConfigProbe,
) -> Result<Vec<Outil>, EchecProbe> {
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

    // Environment hygiene: the probed process gets a *minimal* env (PATH +
    // HOME). Never the parent's full env — a malicious server would happily
    // exfiltrate API keys and tokens found there.
    let home = std::env::var("HOME").unwrap_or_default();

    let mut child: Child = Command::new(&commande_a_lancer)
        .args(args)
        .env_clear()
        .env("PATH", &path_augmented)
        .env("HOME", &home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            let classification = if e.kind() == std::io::ErrorKind::NotFound {
                ClassificationEchec::BinaireAbsent
            } else {
                ClassificationEchec::ConnexionRefusee
            };
            EchecProbe {
                etat: EtatProbe::EchecLancement,
                classification,
                message: format!("spawn `{}` failed: {}", commande, e),
            }
        })?;

    let stdin = match child.stdin.take() {
        Some(s) => s,
        None => {
            terminer_enfant(&mut child).await;
            return Err(EchecProbe {
                etat: EtatProbe::EchecLancement,
                classification: ClassificationEchec::ConnexionRefusee,
                message: "child stdin unavailable".into(),
            });
        }
    };
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            terminer_enfant(&mut child).await;
            return Err(EchecProbe {
                etat: EtatProbe::EchecLancement,
                classification: ClassificationEchec::ConnexionRefusee,
                message: "child stdout unavailable".into(),
            });
        }
    };

    // Run the protocol exchange under the *total* budget.
    let resultat = timeout(config.timeout_total, dialogue_mcp(stdin, stdout, config)).await;

    let echec = match resultat {
        Ok(Ok(outils)) => {
            terminer_enfant(&mut child).await;
            return Ok(outils);
        }
        Err(_) => {
            // Total budget exhausted: kill, reap, report.
            terminer_enfant(&mut child).await;
            EchecProbe {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::Timeout,
                message: format!(
                    "probe timed out after {} ms (total budget)",
                    config.timeout_total.as_millis()
                ),
            }
        }
        Ok(Err(ErreurDialogue::TimeoutConnexion)) => {
            terminer_enfant(&mut child).await;
            EchecProbe {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::Timeout,
                message: format!(
                    "initialize response not received within {} ms",
                    config.timeout_connexion.as_millis()
                ),
            }
        }
        Ok(Err(ErreurDialogue::TimeoutReponse)) => {
            terminer_enfant(&mut child).await;
            EchecProbe {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::Timeout,
                message: format!(
                    "tools/list response not received within {} ms",
                    config.timeout_reponse.as_millis()
                ),
            }
        }
        Ok(Err(ErreurDialogue::Parse(e))) => {
            terminer_enfant(&mut child).await;
            EchecProbe {
                etat: EtatProbe::EchecParseur,
                classification: ClassificationEchec::ReponseMalformee,
                message: e,
            }
        }
        Ok(Err(err @ (ErreurDialogue::FluxFerme | ErreurDialogue::Io(_)))) => {
            // The child most likely died — grab its exit code before reaping.
            let detail = match err {
                ErreurDialogue::Io(m) => format!(" ({})", m),
                _ => String::new(),
            };
            let code_sortie = attendre_code_sortie(&mut child).await;
            terminer_enfant(&mut child).await;
            EchecProbe {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::CrashImmediat { code_sortie },
                message: match code_sortie {
                    Some(code) => format!(
                        "child exited with code {} before completing the handshake{}",
                        code, detail
                    ),
                    None => format!(
                        "child died before completing the handshake{}",
                        detail
                    ),
                },
            }
        }
    };

    Err(echec)
}

/// Best-effort capture of the child's exit code (short wait, no kill).
async fn attendre_code_sortie(child: &mut Child) -> Option<i32> {
    match timeout(Duration::from_millis(500), child.wait()).await {
        Ok(Ok(status)) => status.code(),
        _ => None,
    }
}

/// Kill + reap the child unconditionally — no zombies left behind.
///
/// `kill_on_drop(true)` remains as a backup if this future is itself dropped.
async fn terminer_enfant(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
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
    config: &ConfigProbe,
) -> Result<Vec<Outil>, ErreurDialogue> {
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

    // Wait for the matching response (id == 1) under the connexion budget.
    // Other lines (notifications, logs, non-JSON) are skipped.
    let _init_resp = timeout(config.timeout_connexion, lire_reponse(&mut lecteur, &json!(1)))
        .await
        .map_err(|_| ErreurDialogue::TimeoutConnexion)??;

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

    let tools_resp = timeout(config.timeout_reponse, lire_reponse(&mut lecteur, &json!(2)))
        .await
        .map_err(|_| ErreurDialogue::TimeoutReponse)??;

    // 5. parse via the shared sentinel-scan parser.
    let parsed = parser_reponse_tools_list(&tools_resp).map_err(|e| {
        ErreurDialogue::Parse(format!("tools/list response unparsable: {}", e))
    })?;

    Ok(parsed.outils)
}

/// Writes one JSON-RPC message terminated by a newline.
async fn envoyer(
    stdin: &mut tokio::process::ChildStdin,
    msg: &Value,
) -> Result<(), ErreurDialogue> {
    let mut ligne = serde_json::to_string(msg)
        .map_err(|e| ErreurDialogue::Io(format!("encode request: {}", e)))?;
    ligne.push('\n');
    stdin
        .write_all(ligne.as_bytes())
        .await
        .map_err(|e| ErreurDialogue::Io(format!("write to child stdin: {}", e)))?;
    stdin
        .flush()
        .await
        .map_err(|e| ErreurDialogue::Io(format!("flush child stdin: {}", e)))?;
    Ok(())
}

/// Reads lines until one decodes as a JSON-RPC response whose `id` matches
/// the expected value. Returns the full parsed JSON value.
async fn lire_reponse<R>(
    lecteur: &mut BufReader<R>,
    id_attendu: &Value,
) -> Result<Value, ErreurDialogue>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut ligne = String::new();
    loop {
        ligne.clear();
        let n = lecteur
            .read_line(&mut ligne)
            .await
            .map_err(|e| ErreurDialogue::Io(format!("read from child stdout: {}", e)))?;
        if n == 0 {
            return Err(ErreurDialogue::FluxFerme);
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
