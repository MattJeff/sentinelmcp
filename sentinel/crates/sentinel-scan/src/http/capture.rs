//! Proxy HTTP passif — capture du trafic MCP HTTP Streamable.
//!
//! `CaptureHttp` lance un serveur axum sur l'adresse d'écoute fournie.
//! Pour chaque requête POST ou GET vers `/mcp`, il :
//!   1. Lit le corps de la requête entrante (sans le modifier).
//!   2. Émet un `EvenementBrut` (direction `ClientVersServeur`).
//!   3. Transmet la requête à l'upstream configuré.
//!   4. Si la réponse est en SSE (`text/event-stream`), parse le flux et émet
//!      un `EvenementBrut` par message JSON-RPC (direction `ServeurVersClient`).
//!   5. Sinon, émet un seul `EvenementBrut` pour le corps de la réponse.
//!   6. Retourne la réponse bit-exacte au client appelant.
//!
//! Le contenu des arguments d'appel `tools/call` n'est jamais stocké en dehors
//! du `EvenementBrut` dont la durée de vie est contrôlée par le récepteur mpsc.

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
use sentinel_protocol::{Direction, EvenementBrut, Transport};
use tokio::sync::mpsc::Sender;
use chrono::Utc;

use crate::http::sessions::SuiviSessionsHttp;
use crate::http::sse::{est_sse, parser_flux_sse};

/// Constante : nom de l'en-tête de session MCP.
const EN_TETE_SESSION: &str = "mcp-session-id";

/// État partagé entre les handlers axum.
#[derive(Clone)]
struct EtatProxy {
    emetteur: Sender<EvenementBrut>,
    client_http: Client,
    suivi: SuiviSessionsHttp,
}

/// Proxy HTTP passif local pour le transport Streamable HTTP MCP.
pub struct CaptureHttp {
    emetteur: Sender<EvenementBrut>,
    cible_upstream: String,
}

impl CaptureHttp {
    /// Crée un nouveau proxy passif.
    ///
    /// - `emetteur` : canal vers le normaliseur (agent 1.3).
    /// - `cible_upstream` : URL de base du serveur MCP cible, p.ex. `http://localhost:3000`.
    pub fn nouvelle(emetteur: Sender<EvenementBrut>, cible_upstream: String) -> Self {
        Self { emetteur, cible_upstream }
    }

    /// Lance le serveur de proxy sur un `TcpListener` déjà lié.
    ///
    /// Permet aux tests de récupérer l'adresse réelle (port 0) avant de lancer
    /// le serveur, sans risquer un double-bind.
    pub async fn servir_sur(self, ecouteur: tokio::net::TcpListener) -> anyhow::Result<()> {
        let etat = Arc::new(EtatProxy {
            emetteur: self.emetteur,
            client_http: Client::builder()
                .build()
                .expect("client reqwest invalide"),
            suivi: SuiviSessionsHttp::nouveau(self.cible_upstream),
        });

        let app = Router::new()
            .route("/mcp", post(handler_post))
            .route("/mcp", get(handler_get))
            .with_state(etat);

        let addr = ecouteur.local_addr()?;
        tracing::info!(%addr, "CaptureHttp démarrée");
        axum::serve(ecouteur, app).await?;
        Ok(())
    }

    /// Lance le serveur de proxy sur une adresse d'écoute (bind interne).
    pub async fn servir(self, ecoute: SocketAddr) -> anyhow::Result<()> {
        let ecouteur = tokio::net::TcpListener::bind(ecoute).await?;
        self.servir_sur(ecouteur).await
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extrait le `Mcp-Session-Id` des en-têtes (insensible à la casse via hyper).
fn extraire_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(EN_TETE_SESSION)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Émet un `EvenementBrut` pour un corps JSON-RPC donné.
async fn emettre_evenement(
    emetteur: &Sender<EvenementBrut>,
    corps: &Bytes,
    session_id: &str,
    serveur: &str,
    direction: Direction,
) {
    match serde_json::from_slice::<serde_json::Value>(corps) {
        Ok(payload) => {
            let methode = payload
                .get("method")
                .and_then(|v| v.as_str())
                .map(String::from);

            let evt = EvenementBrut {
                session_id: session_id.to_string(),
                transport: Transport::Http,
                serveur: serveur.to_string(),
                direction,
                methode,
                payload,
                horodatage: Utc::now(),
            };
            let _ = emetteur.send(evt).await;
        }
        Err(_) => {
            // Corps non-JSON (p.ex. corps vide sur GET) : on ignore silencieusement.
            tracing::trace!("corps non-JSON ignoré");
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Handler pour POST /mcp.
async fn handler_post(
    State(etat): State<Arc<EtatProxy>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response<Body>, StatusCode> {
    let session_id = extraire_session_id(&headers)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let upstream = etat.suivi.enregistrer(&session_id);

    // Émet l'événement client → serveur.
    emettre_evenement(
        &etat.emetteur,
        &body,
        &session_id,
        &upstream,
        Direction::ClientVersServeur,
    )
    .await;

    // Transmet la requête à l'upstream.
    let url_upstream = format!("{}/mcp", upstream);
    let mut req_builder = etat.client_http.post(&url_upstream).body(body);

    // Copie les en-têtes pertinents.
    for (nom, valeur) in &headers {
        let nom_str = nom.as_str();
        // On ne copie pas les en-têtes de connexion de bas niveau.
        if matches!(nom_str, "host" | "content-length" | "transfer-encoding") {
            continue;
        }
        if let Ok(valeur_str) = valeur.to_str() {
            req_builder = req_builder.header(nom_str, valeur_str);
        }
    }

    let reponse_upstream = req_builder.send().await.map_err(|e| {
        tracing::error!(err = %e, "erreur upstream POST");
        StatusCode::BAD_GATEWAY
    })?;

    construire_reponse(reponse_upstream, &etat, &session_id, &upstream).await
}

/// Handler pour GET /mcp (SSE entrant depuis le serveur).
async fn handler_get(
    State(etat): State<Arc<EtatProxy>>,
    headers: HeaderMap,
) -> Result<Response<Body>, StatusCode> {
    let session_id = extraire_session_id(&headers)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let upstream = etat.suivi.enregistrer(&session_id);

    let url_upstream = format!("{}/mcp", upstream);
    let mut req_builder = etat.client_http.get(&url_upstream);

    for (nom, valeur) in &headers {
        let nom_str = nom.as_str();
        if matches!(nom_str, "host" | "content-length" | "transfer-encoding") {
            continue;
        }
        if let Ok(valeur_str) = valeur.to_str() {
            req_builder = req_builder.header(nom_str, valeur_str);
        }
    }

    let reponse_upstream = req_builder.send().await.map_err(|e| {
        tracing::error!(err = %e, "erreur upstream GET");
        StatusCode::BAD_GATEWAY
    })?;

    construire_reponse(reponse_upstream, &etat, &session_id, &upstream).await
}

/// Construit la réponse axum à partir de la réponse upstream, en observant
/// le contenu au passage.
async fn construire_reponse(
    reponse: reqwest::Response,
    etat: &Arc<EtatProxy>,
    session_id: &str,
    upstream: &str,
) -> Result<Response<Body>, StatusCode> {
    let status = reponse.status();
    let headers_resp = reponse.headers().clone();

    // Détermine si la réponse est un flux SSE.
    let est_flux_sse = headers_resp
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(est_sse)
        .unwrap_or(false);

    // Copie les en-têtes de réponse.
    let mut constructeur = Response::builder()
        .status(status.as_u16());

    for (nom, valeur) in &headers_resp {
        constructeur = constructeur.header(nom.as_str(), valeur.as_bytes());
    }

    if est_flux_sse {
        // Cas SSE : on streame la réponse et on émet un événement par message.
        let emetteur = etat.emetteur.clone();
        let session_id = session_id.to_string();
        let upstream = upstream.to_string();

        let stream_upstream = reponse.bytes_stream();

        let stream_observe = stream_upstream.then(move |chunk_result| {
            let emetteur = emetteur.clone();
            let session_id = session_id.clone();
            let upstream = upstream.clone();

            async move {
                match chunk_result {
                    Ok(chunk) => {
                        // Tampon de reste SSE : doit être persisté entre chunks.
                        // Pour la v1 démo on parse chaque chunk indépendamment ;
                        // un chunk coupé au milieu d'une ligne sera ignoré.
                        // Un reste global nécessiterait un Arc<Mutex<Vec<u8>>> par session.
                        let mut reste: Vec<u8> = Vec::new();
                        parser_flux_sse(&chunk, &mut reste, &session_id, &upstream, &emetteur)
                            .await;
                        Ok::<Bytes, std::io::Error>(chunk)
                    }
                    Err(e) => {
                        tracing::warn!(err = %e, "erreur chunk SSE upstream");
                        Err(std::io::Error::other(e))
                    }
                }
            }
        });

        let body = Body::from_stream(stream_observe);
        constructeur.body(body).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        // Cas non-SSE : lit le corps entier, observe, retourne.
        let corps = reponse.bytes().await.map_err(|e| {
            tracing::error!(err = %e, "lecture corps réponse upstream");
            StatusCode::BAD_GATEWAY
        })?;

        emettre_evenement(
            &etat.emetteur,
            &corps,
            session_id,
            upstream,
            Direction::ServeurVersClient,
        )
        .await;

        let corps_clone = corps.clone();
        constructeur
            .body(Body::from(corps_clone))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    }
}
