//! Active MCP probe over Streamable HTTP — counterpart to the stdio
//! [`ProbeurActif`](crate::active_probe::ProbeurActif).
//!
//! Speaks the MCP "Streamable HTTP" transport: POST JSON-RPC messages to a
//! single URL, capture the `Mcp-Session-Id` header echoed back by the server
//! on `initialize`, and replay it on subsequent calls. Responses may be either
//! `application/json` (single envelope) or `text/event-stream` (SSE; we read
//! the first `data:` line and treat its payload as JSON).
//!
//! Flow per URL:
//!   1. POST `initialize`             → capture `Mcp-Session-Id`.
//!   2. POST `notifications/initialized` (with session id).
//!   3. POST `tools/list`             (with session id) → parse outils.
//!   4. Compute `empreinte_serveur` + run `InspecteurPoisoning::inspecter`.
//!
//! Each individual HTTP request is bounded by an 8 s timeout. The whole
//! probe never panics: every failure is folded into a `RapportProbe` with
//! the relevant `EtatProbe` and a human-readable `erreur`.

use std::time::Duration;

use chrono::Utc;
use sentinel_detect::{empreinte_serveur, InspecteurPoisoning};
use sentinel_scan::tools_list::parser_reponse_tools_list;
use serde_json::{json, Value};

use crate::active_probe::{EtatProbe, RapportProbe};

/// HTTP MCP probe driver.
pub struct ProbeurHttp {
    /// Per-request budget. Defaults to 8 s.
    pub timeout: Duration,
    /// Shared HTTP client (cheap to clone; backed by an internal `Arc`).
    pub client: reqwest::Client,
}

impl Default for ProbeurHttp {
    fn default() -> Self {
        Self::par_defaut()
    }
}

impl ProbeurHttp {
    /// Construct an HTTP probe driver with sensible defaults.
    pub fn par_defaut() -> Self {
        let timeout = Duration::from_secs(8);
        let client = reqwest::Client::builder()
            .user_agent("sentinel-mcp-active-probe-http/0.1")
            .timeout(timeout)
            .build()
            .expect("reqwest client build");
        Self { timeout, client }
    }

    /// Probe a single Streamable HTTP MCP endpoint.
    ///
    /// `nom` is the logical server name used to label the report;
    /// `url` is the single POST endpoint declared by the client config.
    pub async fn probe_url(&self, nom: &str, url: &str) -> RapportProbe {
        let demarre_a = Utc::now();
        let debut = std::time::Instant::now();

        let resultat = self.executer(url).await;

        let duree_ms = debut.elapsed().as_millis() as u64;

        match resultat {
            Ok(outils) => {
                let empreinte = empreinte_serveur(&outils);
                let constats = InspecteurPoisoning::inspecter(&outils);
                RapportProbe {
                    serveur_nom: nom.to_string(),
                    serveur_commande: url.to_string(),
                    demarre_a,
                    duree_ms,
                    etat: EtatProbe::Reussi,
                    outils,
                    empreinte_serveur: Some(empreinte),
                    constats_poisoning: constats,
                    erreur: None,
                }
            }
            Err(SortieHttp::Lancement(e)) => RapportProbe {
                serveur_nom: nom.to_string(),
                serveur_commande: url.to_string(),
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecLancement,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(e),
            },
            Err(SortieHttp::Handshake(e)) => RapportProbe {
                serveur_nom: nom.to_string(),
                serveur_commande: url.to_string(),
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecHandshake,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(e),
            },
            Err(SortieHttp::Parseur(e)) => RapportProbe {
                serveur_nom: nom.to_string(),
                serveur_commande: url.to_string(),
                demarre_a,
                duree_ms,
                etat: EtatProbe::EchecParseur,
                outils: vec![],
                empreinte_serveur: None,
                constats_poisoning: vec![],
                erreur: Some(e),
            },
        }
    }

    /// Drive the three POSTs end-to-end.
    async fn executer(
        &self,
        url: &str,
    ) -> Result<Vec<sentinel_protocol::Outil>, SortieHttp> {
        // 1. initialize
        let init_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "sentinel-mcp",
                    "version": "0.1.0"
                }
            }
        });

        let resp_init = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
            .json(&init_body)
            .send()
            .await
            .map_err(|e| classer_erreur_envoi(e, "initialize"))?;

        if !resp_init.status().is_success() {
            return Err(SortieHttp::Lancement(format!(
                "initialize returned HTTP {}",
                resp_init.status().as_u16()
            )));
        }

        // 2. capture Mcp-Session-Id (may be absent on stateless servers — that's fine).
        let session_id = resp_init
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Drain the initialize body so the connection can be reused; we don't
        // actually need to interpret it beyond having received a 2xx.
        let _ = lire_corps_json(resp_init).await;

        // 3. notifications/initialized
        let initd = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let mut req_initd = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream");
        if let Some(sid) = session_id.as_deref() {
            req_initd = req_initd.header("Mcp-Session-Id", sid);
        }
        let resp_initd = req_initd
            .json(&initd)
            .send()
            .await
            .map_err(|e| classer_erreur_envoi(e, "notifications/initialized"))?;

        // Notifications need only be accepted (2xx / 202). A 4xx here means
        // the server rejected the session and the rest of the probe would fail.
        if !resp_initd.status().is_success() {
            return Err(SortieHttp::Handshake(format!(
                "notifications/initialized returned HTTP {}",
                resp_initd.status().as_u16()
            )));
        }
        let _ = resp_initd.bytes().await;

        // 4. tools/list
        let tools_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });

        let mut req_tools = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream");
        if let Some(sid) = session_id.as_deref() {
            req_tools = req_tools.header("Mcp-Session-Id", sid);
        }
        let resp_tools = req_tools
            .json(&tools_req)
            .send()
            .await
            .map_err(|e| classer_erreur_envoi(e, "tools/list"))?;

        if !resp_tools.status().is_success() {
            return Err(SortieHttp::Handshake(format!(
                "tools/list returned HTTP {}",
                resp_tools.status().as_u16()
            )));
        }

        let payload = lire_corps_json(resp_tools)
            .await
            .map_err(SortieHttp::Handshake)?;

        // 5. parse via the shared sentinel-scan parser.
        let parsed = parser_reponse_tools_list(&payload).map_err(|e| {
            SortieHttp::Parseur(format!("tools/list response unparsable: {}", e))
        })?;

        Ok(parsed.outils)
    }
}

/// Internal failure modes — mapped to `EtatProbe` at the public boundary.
enum SortieHttp {
    Lancement(String),
    Handshake(String),
    Parseur(String),
}

/// Map a reqwest send error to the right failure mode.
///
/// Timeouts (which reqwest tags via `Error::is_timeout`) are reported as a
/// handshake failure — the server was reachable but did not answer in time;
/// other transport errors (DNS, connection refused, TLS) are launch failures.
fn classer_erreur_envoi(e: reqwest::Error, etape: &str) -> SortieHttp {
    if e.is_timeout() {
        SortieHttp::Handshake(format!("{} timed out: {}", etape, e))
    } else if e.is_connect() || e.is_request() {
        SortieHttp::Lancement(format!("{} transport error: {}", etape, e))
    } else {
        SortieHttp::Handshake(format!("{} failed: {}", etape, e))
    }
}

/// Read a response body and parse it as JSON.
///
/// Supports both `application/json` (single envelope) and `text/event-stream`
/// (in which case we extract the payload of the first `data:` line).
async fn lire_corps_json(resp: reqwest::Response) -> Result<Value, String> {
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    let texte = resp
        .text()
        .await
        .map_err(|e| format!("read response body: {}", e))?;

    if content_type.contains("text/event-stream") {
        // Walk SSE lines, return the first `data: …` payload as JSON.
        for ligne in texte.lines() {
            let t = ligne.trim_start();
            if let Some(rest) = t.strip_prefix("data:") {
                let data = rest.trim();
                if data.is_empty() {
                    continue;
                }
                return serde_json::from_str(data)
                    .map_err(|e| format!("SSE data line is not JSON: {}", e));
            }
        }
        Err("SSE response contained no `data:` line".into())
    } else {
        // Best-effort: even if the server forgot the content-type, try JSON.
        serde_json::from_str(texte.trim())
            .map_err(|e| format!("response is not JSON: {}", e))
    }
}
