//! Proxy HTTP **actif** (mode B) — interception locale MCP via normaliseur.
//!
//! Contrairement à [`crate::http::CaptureHttp`] (proxy passif d'observation,
//! mode A) qui se concentre sur la capture de trafic existant entre client et
//! serveur, `ProxyMcp` est un proxy **local explicite** : l'utilisateur
//! configure son client MCP pour pointer sur `http://127.0.0.1:<port>/mcp`,
//! et ce proxy relaie ensuite chaque requête vers un upstream choisi.
//!
//! Pipeline :
//!   1. POST /mcp : on lit le corps complet sans le modifier, on normalise le
//!      corps via [`Normaliseur::depuis_corps_http`], on émet chaque événement
//!      (batch JSON-RPC déplié), puis on relaie le corps **bit-exact** à
//!      l'upstream. La réponse upstream est renvoyée telle quelle ; si elle est
//!      en `text/event-stream`, elle est streamée et chaque `data:` est
//!      analysé via [`Normaliseur::depuis_event_sse`].
//!   2. GET /mcp : on relaie au serveur upstream (long-poll SSE). Les chunks
//!      sont streamés au client appelant et observés en parallèle.
//!   3. L'en-tête `Mcp-Session-Id` est préservé dans les deux sens. Si le
//!      client n'en fournit pas, un UUID est synthétisé pour rattacher les
//!      événements à une session unique.
//!
//! Invariants :
//! - Le corps de la requête envoyé à l'upstream est *bit-exact* (les bytes
//!   normalisés et les bytes transmis proviennent du même `Bytes`).
//! - Le corps de la réponse upstream relayé au client est *bit-exact* (pour
//!   les réponses non-SSE) ou *streamé tel quel* (pour les réponses SSE).
//! - Les erreurs upstream produisent un `502 Bad Gateway` côté client.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use futures::StreamExt;
use reqwest::Client;
use sentinel_protocol::{Direction, EvenementBrut};
use tokio::sync::mpsc::Sender;

use crate::event::Normaliseur;

/// En-tête de session MCP (insensible à la casse côté HTTP).
const EN_TETE_SESSION: &str = "mcp-session-id";

/// État interne partagé entre les handlers axum.
#[derive(Clone)]
struct EtatProxy {
    emetteur: Sender<EvenementBrut>,
    client_http: Client,
    upstream: String,
}

/// Proxy HTTP MCP **actif** (mode B).
///
/// Voir la documentation au sommet du module.
pub struct ProxyMcp {
    /// Canal d'émission des événements normalisés vers le pipeline aval.
    pub emetteur: Sender<EvenementBrut>,
    /// URL complète de l'endpoint MCP upstream (p.ex. `http://localhost:3000/mcp`).
    pub upstream: String,
}

impl ProxyMcp {
    /// Construit un nouveau proxy actif.
    pub fn nouveau(emetteur: Sender<EvenementBrut>, upstream: String) -> Self {
        Self { emetteur, upstream }
    }

    /// Lance le serveur de proxy sur un `TcpListener` déjà lié.
    ///
    /// Pratique pour les tests : permet de pré-binder le port `0` et de
    /// récupérer l'adresse réelle avant de spawn la tâche.
    pub async fn servir_sur(self, ecouteur: tokio::net::TcpListener) -> anyhow::Result<()> {
        let etat = Arc::new(EtatProxy {
            emetteur: self.emetteur,
            client_http: Client::builder()
                .build()
                .expect("client reqwest invalide"),
            upstream: self.upstream,
        });

        let app = Router::new()
            .route("/mcp", post(handler_post))
            .route("/mcp", get(handler_get))
            .with_state(etat);

        let addr = ecouteur.local_addr()?;
        tracing::info!(%addr, "ProxyMcp (mode B) démarré");
        axum::serve(ecouteur, app).await?;
        Ok(())
    }

    /// Lance le serveur de proxy en bindant l'adresse fournie.
    pub async fn servir(self, addr: SocketAddr) -> anyhow::Result<()> {
        let ecouteur = tokio::net::TcpListener::bind(addr).await?;
        self.servir_sur(ecouteur).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extrait le `Mcp-Session-Id` des en-têtes, ou en synthétise un UUID.
fn session_id_ou_uuid(headers: &HeaderMap) -> String {
    headers
        .get(EN_TETE_SESSION)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Émet un lot d'événements normalisés via le canal mpsc.
async fn emettre_lot(emetteur: &Sender<EvenementBrut>, lot: Vec<EvenementBrut>) {
    for evt in lot {
        let _ = emetteur.send(evt).await;
    }
}

/// Copie les en-têtes pertinents d'une requête entrante vers la requête sortante.
///
/// Les en-têtes de connexion bas-niveau (`host`, `content-length`,
/// `transfer-encoding`) sont volontairement omis : ils seront recalculés par
/// `reqwest` pour la requête sortante.
fn recopier_entetes(
    mut req: reqwest::RequestBuilder,
    headers: &HeaderMap,
) -> reqwest::RequestBuilder {
    for (nom, valeur) in headers {
        let nom_str = nom.as_str();
        if matches!(nom_str, "host" | "content-length" | "transfer-encoding") {
            continue;
        }
        if let Ok(valeur_str) = valeur.to_str() {
            req = req.header(nom_str, valeur_str);
        }
    }
    req
}

/// Détecte si un `content-type` annonce du SSE.
fn est_content_type_sse(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("text/event-stream"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Handler POST /mcp
// ---------------------------------------------------------------------------

async fn handler_post(
    State(etat): State<Arc<EtatProxy>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Body>, StatusCode> {
    let session_id = session_id_ou_uuid(&headers);

    // 1. Normalisation du corps entrant — le `Bytes` n'est pas consommé,
    //    on lit seulement ses octets.
    let evenements = Normaliseur::depuis_corps_http(
        body.as_ref(),
        &session_id,
        &etat.upstream,
        Direction::ClientVersServeur,
    );
    emettre_lot(&etat.emetteur, evenements).await;

    // 2. Forward au serveur upstream avec le corps bit-exact.
    let req = etat
        .client_http
        .post(&etat.upstream)
        .body(body.clone());
    let req = recopier_entetes(req, &headers);

    let reponse_upstream = req.send().await.map_err(|e| {
        tracing::error!(err = %e, "erreur upstream POST proxy");
        StatusCode::BAD_GATEWAY
    })?;

    relayer_reponse(reponse_upstream, &etat, &session_id).await
}

// ---------------------------------------------------------------------------
// Handler GET /mcp
// ---------------------------------------------------------------------------

async fn handler_get(
    State(etat): State<Arc<EtatProxy>>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    let session_id = session_id_ou_uuid(&headers);

    let req = etat.client_http.get(&etat.upstream);
    let req = recopier_entetes(req, &headers);

    let reponse_upstream = req.send().await.map_err(|e| {
        tracing::error!(err = %e, "erreur upstream GET proxy");
        StatusCode::BAD_GATEWAY
    })?;

    relayer_reponse(reponse_upstream, &etat, &session_id).await
}

// ---------------------------------------------------------------------------
// Relais de la réponse upstream
// ---------------------------------------------------------------------------

/// Construit la réponse axum à partir de la réponse upstream, en observant
/// le contenu et en préservant le `Mcp-Session-Id`.
async fn relayer_reponse(
    reponse: reqwest::Response,
    etat: &Arc<EtatProxy>,
    session_id: &str,
) -> Result<Response<Body>, StatusCode> {
    let status = reponse.status();
    let headers_resp = reponse.headers().clone();
    let est_sse = est_content_type_sse(&headers_resp);

    let mut constructeur = Response::builder().status(status.as_u16());

    // Copie tous les en-têtes upstream tels quels (y compris Mcp-Session-Id
    // potentiellement émis par l'upstream).
    let mut session_id_vu_dans_reponse = false;
    for (nom, valeur) in &headers_resp {
        if nom.as_str().eq_ignore_ascii_case(EN_TETE_SESSION) {
            session_id_vu_dans_reponse = true;
        }
        constructeur = constructeur.header(nom.as_str(), valeur.as_bytes());
    }

    // Si l'upstream n'a pas réémis l'en-tête, on le rajoute nous-même pour
    // garantir la propagation bidirectionnelle.
    if !session_id_vu_dans_reponse {
        constructeur = constructeur.header(EN_TETE_SESSION, session_id);
    }

    if est_sse {
        // ---------------- SSE : on streame et on observe en parallèle. ----------------
        let emetteur = etat.emetteur.clone();
        let upstream = etat.upstream.clone();
        let session_id = session_id.to_string();

        // Tampon résiduel persistant entre chunks pour reconstruire les
        // lignes coupées en deux livraisons.
        let reste = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));

        let stream_upstream = reponse.bytes_stream();
        let stream_observe = stream_upstream.then(move |chunk_result| {
            let emetteur = emetteur.clone();
            let upstream = upstream.clone();
            let session_id = session_id.clone();
            let reste = reste.clone();

            async move {
                match chunk_result {
                    Ok(chunk) => {
                        let mut tampon = reste.lock().await;
                        tampon.extend_from_slice(&chunk);

                        // Extraction ligne par ligne (terminées par \n).
                        while let Some(pos) = tampon.iter().position(|&b| b == b'\n') {
                            let ligne_bytes: Vec<u8> = tampon.drain(..=pos).collect();
                            let ligne = String::from_utf8_lossy(&ligne_bytes);
                            let ligne = ligne.trim_end_matches(['\n', '\r']);
                            if let Some(data) = ligne.strip_prefix("data:") {
                                if let Some(evt) = Normaliseur::depuis_event_sse(
                                    data,
                                    &session_id,
                                    &upstream,
                                ) {
                                    let _ = emetteur.send(evt).await;
                                }
                            }
                        }

                        Ok::<Bytes, std::io::Error>(chunk)
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "erreur chunk SSE upstream proxy");
                        Err(std::io::Error::other(e))
                    }
                }
            }
        });

        let body = Body::from_stream(stream_observe);
        constructeur
            .body(body)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        // ---------------- Non-SSE : on lit le corps complet, on normalise. ----------------
        let corps = reponse.bytes().await.map_err(|e| {
            tracing::error!(err = %e, "lecture corps réponse upstream proxy");
            StatusCode::BAD_GATEWAY
        })?;

        let evenements = Normaliseur::depuis_corps_http(
            corps.as_ref(),
            session_id,
            &etat.upstream,
            Direction::ServeurVersClient,
        );
        emettre_lot(&etat.emetteur, evenements).await;

        constructeur
            .body(Body::from(corps))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}
