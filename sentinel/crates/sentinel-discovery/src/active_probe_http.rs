//! Active MCP probe over Streamable HTTP — counterpart to the stdio
//! [`ProbeurActif`](crate::active_probe::ProbeurActif).
//!
//! Speaks the MCP "Streamable HTTP" transport: POST JSON-RPC messages to a
//! single URL, capture the `Mcp-Session-Id` header echoed back by the server
//! on `initialize`, and replay it on subsequent calls. Responses may be either
//! `application/json` (single envelope) or `text/event-stream` (SSE; events
//! are parsed properly — multi-line `data:` fields, multiple events — and the
//! response whose JSON-RPC `id` matches the request is selected).
//!
//! Flow per URL:
//!   1. POST `initialize`             → capture `Mcp-Session-Id`.
//!   2. POST `notifications/initialized` (with session id).
//!   3. POST `tools/list`             (with session id) → parse outils.
//!   4. Compute `empreinte_serveur` + run `InspecteurPoisoning::inspecter`.
//!
//! Robustness mirrors the stdio probe ([`ConfigProbe`]):
//!   - `timeout_connexion` bounds the TCP connect, `timeout_reponse` each
//!     HTTP request, `timeout_total` the whole attempt;
//!   - transient failures (timeout, connexion refusée) are retried with
//!     exponential backoff;
//!   - failures carry a fine-grained [`ClassificationEchec`];
//!   - per-server Bearer auth via [`ProbeurHttp::probe_url_auth`].
//!
//! The probe never panics: every failure is folded into a `RapportProbe`.

use chrono::Utc;
use sentinel_detect::{empreinte_serveur, InspecteurPoisoning};
use sentinel_scan::tools_list::parser_reponse_tools_list;
use serde_json::{json, Value};
use tokio::time::timeout;

use crate::active_probe::{ClassificationEchec, ConfigProbe, EtatProbe, RapportProbe};

/// HTTP MCP probe driver.
pub struct ProbeurHttp {
    /// Timeouts / retries / concurrency knobs, shared with the stdio probe.
    pub config: ConfigProbe,
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
        Self::avec_config(ConfigProbe::default())
    }

    /// Construct an HTTP probe driver with a custom configuration.
    pub fn avec_config(config: ConfigProbe) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("sentinel-mcp-active-probe-http/0.1")
            .connect_timeout(config.timeout_connexion)
            .timeout(config.timeout_reponse)
            .build()
            .expect("reqwest client build");
        Self { config, client }
    }

    /// Probe a single Streamable HTTP MCP endpoint (no auth).
    pub async fn probe_url(&self, nom: &str, url: &str) -> RapportProbe {
        self.probe_url_auth(nom, url, None).await
    }

    /// Probe a single Streamable HTTP MCP endpoint, optionally sending a
    /// per-server `Authorization: Bearer <token>` header on every request.
    ///
    /// `nom` is the logical server name used to label the report;
    /// `url` is the single POST endpoint declared by the client config.
    pub async fn probe_url_auth(
        &self,
        nom: &str,
        url: &str,
        bearer: Option<&str>,
    ) -> RapportProbe {
        let demarre_a = Utc::now();
        let debut = std::time::Instant::now();

        let mut tentative: u32 = 0;
        loop {
            tentative += 1;

            let resultat = match timeout(
                self.config.timeout_total,
                self.executer(url, bearer),
            )
            .await
            {
                Ok(r) => r,
                Err(_) => Err(EchecHttp {
                    etat: EtatProbe::EchecHandshake,
                    classification: ClassificationEchec::Timeout,
                    message: format!(
                        "probe timed out after {} ms (total budget)",
                        self.config.timeout_total.as_millis()
                    ),
                }),
            };

            match resultat {
                Ok(outils) => {
                    let empreinte = empreinte_serveur(&outils);
                    let constats = InspecteurPoisoning::inspecter(&outils);
                    return RapportProbe {
                        serveur_nom: nom.to_string(),
                        serveur_commande: url.to_string(),
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
                    let transitoire = matches!(
                        echec.classification,
                        ClassificationEchec::Timeout
                            | ClassificationEchec::ConnexionRefusee
                    );
                    if !transitoire || tentative > self.config.retries {
                        return RapportProbe {
                            serveur_nom: nom.to_string(),
                            serveur_commande: url.to_string(),
                            demarre_a,
                            duree_ms: debut.elapsed().as_millis() as u64,
                            etat: echec.etat,
                            outils: vec![],
                            empreinte_serveur: None,
                            constats_poisoning: vec![],
                            erreur: Some(echec.message),
                            classification_echec: Some(echec.classification),
                            tentatives: tentative,
                        };
                    }
                    let backoff = self.config.backoff_initial
                        * 2u32.saturating_pow(tentative - 1);
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    /// Build one POST request with the standard headers (+ session, + bearer).
    fn requete(
        &self,
        url: &str,
        session_id: Option<&str>,
        bearer: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream");
        if let Some(sid) = session_id {
            req = req.header("Mcp-Session-Id", sid);
        }
        if let Some(token) = bearer {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {}", token));
        }
        req
    }

    /// Drive the three POSTs end-to-end (one attempt).
    async fn executer(
        &self,
        url: &str,
        bearer: Option<&str>,
    ) -> Result<Vec<sentinel_protocol::Outil>, EchecHttp> {
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
            .requete(url, None, bearer)
            .json(&init_body)
            .send()
            .await
            .map_err(|e| classer_erreur_envoi(e, "initialize"))?;

        if !resp_init.status().is_success() {
            return Err(EchecHttp {
                etat: EtatProbe::EchecLancement,
                classification: ClassificationEchec::ConnexionRefusee,
                message: format!(
                    "initialize returned HTTP {}",
                    resp_init.status().as_u16()
                ),
            });
        }

        // 2. capture Mcp-Session-Id (may be absent on stateless servers — that's fine).
        let session_id = resp_init
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Drain the initialize body so the connection can be reused; we don't
        // actually need to interpret it beyond having received a 2xx.
        let _ = lire_corps_json(resp_init, Some(&json!(1))).await;

        // 3. notifications/initialized
        let initd = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let resp_initd = self
            .requete(url, session_id.as_deref(), bearer)
            .json(&initd)
            .send()
            .await
            .map_err(|e| classer_erreur_envoi(e, "notifications/initialized"))?;

        // Notifications need only be accepted (2xx / 202). A 4xx here means
        // the server rejected the session and the rest of the probe would fail.
        if !resp_initd.status().is_success() {
            return Err(EchecHttp {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::ConnexionRefusee,
                message: format!(
                    "notifications/initialized returned HTTP {}",
                    resp_initd.status().as_u16()
                ),
            });
        }
        let _ = resp_initd.bytes().await;

        // 4. tools/list
        let tools_req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });

        let resp_tools = self
            .requete(url, session_id.as_deref(), bearer)
            .json(&tools_req)
            .send()
            .await
            .map_err(|e| classer_erreur_envoi(e, "tools/list"))?;

        if !resp_tools.status().is_success() {
            return Err(EchecHttp {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::ConnexionRefusee,
                message: format!(
                    "tools/list returned HTTP {}",
                    resp_tools.status().as_u16()
                ),
            });
        }

        let payload = lire_corps_json(resp_tools, Some(&json!(2)))
            .await
            .map_err(|message| EchecHttp {
                etat: EtatProbe::EchecHandshake,
                classification: ClassificationEchec::ReponseMalformee,
                message,
            })?;

        // 5. parse via the shared sentinel-scan parser.
        let parsed = parser_reponse_tools_list(&payload).map_err(|e| EchecHttp {
            etat: EtatProbe::EchecParseur,
            classification: ClassificationEchec::ReponseMalformee,
            message: format!("tools/list response unparsable: {}", e),
        })?;

        Ok(parsed.outils)
    }
}

/// Internal failure modes — mapped onto the public report at the boundary.
struct EchecHttp {
    etat: EtatProbe,
    classification: ClassificationEchec,
    message: String,
}

/// Map a reqwest send error to the right failure mode.
///
/// Timeouts (which reqwest tags via `Error::is_timeout`) are reported as a
/// handshake failure — the server was reachable but did not answer in time;
/// other transport errors (DNS, connection refused, TLS) are launch failures.
fn classer_erreur_envoi(e: reqwest::Error, etape: &str) -> EchecHttp {
    if e.is_timeout() {
        EchecHttp {
            etat: EtatProbe::EchecHandshake,
            classification: ClassificationEchec::Timeout,
            message: format!("{} timed out: {}", etape, e),
        }
    } else if e.is_connect() || e.is_request() {
        EchecHttp {
            etat: EtatProbe::EchecLancement,
            classification: ClassificationEchec::ConnexionRefusee,
            message: format!("{} transport error: {}", etape, e),
        }
    } else {
        EchecHttp {
            etat: EtatProbe::EchecHandshake,
            classification: ClassificationEchec::ConnexionRefusee,
            message: format!("{} failed: {}", etape, e),
        }
    }
}

/// Read a response body and parse it as JSON.
///
/// Supports both `application/json` (single envelope) and `text/event-stream`
/// (proper SSE event parsing — see [`extraire_json_sse`]).
async fn lire_corps_json(
    resp: reqwest::Response,
    id_attendu: Option<&Value>,
) -> Result<Value, String> {
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
        extraire_json_sse(&texte, id_attendu)
    } else {
        // Best-effort: even if the server forgot the content-type, try JSON.
        serde_json::from_str(texte.trim())
            .map_err(|e| format!("response is not JSON: {}", e))
    }
}

/// Parse an SSE body into the JSON-RPC response we are waiting for.
///
/// Events are separated by blank lines; an event's payload is the
/// concatenation of its `data:` lines (multi-line data supported, per the
/// SSE spec). If `id_attendu` is given, the first event whose JSON carries
/// that `id` wins; otherwise (or as a fallback) the first JSON event is
/// returned.
fn extraire_json_sse(texte: &str, id_attendu: Option<&Value>) -> Result<Value, String> {
    let mut premier_json: Option<Value> = None;

    for evenement in texte.replace("\r\n", "\n").split("\n\n") {
        let lignes_data: Vec<&str> = evenement
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|d| d.strip_prefix(' ').unwrap_or(d))
            .collect();
        if lignes_data.is_empty() {
            continue;
        }
        let data = lignes_data.join("\n");
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        let valeur: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match id_attendu {
            Some(id) if valeur.get("id") == Some(id) => return Ok(valeur),
            _ => {
                if premier_json.is_none() {
                    premier_json = Some(valeur);
                }
            }
        }
    }

    premier_json.ok_or_else(|| "SSE response contained no JSON `data:` event".into())
}

#[cfg(test)]
mod tests {
    use super::extraire_json_sse;
    use serde_json::json;

    #[test]
    fn sse_selectionne_l_evenement_au_bon_id() {
        let corps = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[]}}\n\n";
        let v = extraire_json_sse(corps, Some(&json!(2))).expect("json");
        assert_eq!(v["id"], json!(2));
    }

    #[test]
    fn sse_concatene_les_data_multilignes() {
        let corps = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":2,\"result\":{\"tools\":[]}}\n\n";
        let v = extraire_json_sse(corps, Some(&json!(2))).expect("json");
        assert_eq!(v["id"], json!(2));
    }

    #[test]
    fn sse_sans_data_est_une_erreur() {
        let corps = "event: ping\n\n";
        assert!(extraire_json_sse(corps, None).is_err());
    }

    #[test]
    fn sse_fallback_premier_json_sans_id_correspondant() {
        let corps = "data: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{\"tools\":[]}}\n\n";
        let v = extraire_json_sse(corps, Some(&json!(2))).expect("json");
        assert_eq!(v["id"], json!(99));
    }
}
