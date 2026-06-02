//! Tests d'intégration pour `ProxyMcp` (mode B — proxy HTTP actif).
//!
//! Ces tests démarrent un faux upstream MCP en axum, puis spawn `ProxyMcp` sur
//! un port libre. Les requêtes du « client » MCP sont envoyées au proxy ; on
//! vérifie ensuite (1) que les événements normalisés portent le bon
//! `session_id`, (2) que le corps est relayé bit-exact.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use reqwest::Client;
use sentinel_protocol::{Direction, EvenementBrut, Transport};
use sentinel_scan::http::ProxyMcp;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

/// Démarre un upstream factice et retourne son adresse réelle.
async fn demarrer_upstream(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Démarre `ProxyMcp` et retourne `(adresse_proxy, récepteur_événements)`.
async fn demarrer_proxy(upstream_url: String) -> (SocketAddr, mpsc::Receiver<EvenementBrut>) {
    let (tx, rx) = mpsc::channel(64);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let addr = listener.local_addr().unwrap();

    let proxy = ProxyMcp::nouveau(tx, upstream_url);
    tokio::spawn(async move {
        proxy.servir_sur(listener).await.unwrap();
    });

    // Laisse le temps au serveur de démarrer.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, rx)
}

// ---------------------------------------------------------------------------
// Test 1 : fake upstream renvoie tools/list → événements emis avec bon session_id
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_list_emet_evenements_avec_session_id() {
    // Upstream factice : sur POST /mcp, retourne une réponse JSON-RPC
    // simulant le résultat d'un `tools/list`.
    let upstream_app = Router::new().route(
        "/mcp",
        post(|| async {
            let corps = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"},{"name":"sum"}]}}"#;
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(corps))
                .unwrap()
        }),
    );

    let upstream_addr = demarrer_upstream(upstream_app).await;
    let upstream_url = format!("http://{}/mcp", upstream_addr);
    let (proxy_addr, mut rx) = demarrer_proxy(upstream_url).await;

    let client = Client::new();
    let payload = r#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;

    let session_id_attendu = "sess-tools-list-001";

    let reponse = client
        .post(format!("http://{}/mcp", proxy_addr))
        .header("content-type", "application/json")
        .header("mcp-session-id", session_id_attendu)
        .body(payload)
        .send()
        .await
        .expect("requête POST tools/list");

    assert_eq!(reponse.status(), StatusCode::OK);

    // L'en-tête Mcp-Session-Id doit être préservé dans la réponse retournée
    // au client (réinjecté par le proxy puisque le faux upstream ne l'émet pas).
    assert_eq!(
        reponse
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok()),
        Some(session_id_attendu),
        "le proxy doit propager Mcp-Session-Id vers le client"
    );

    // Événement 1 : requête tools/list (client → serveur).
    let evt_req = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout requete")
        .expect("evenement requete");
    assert_eq!(evt_req.session_id, session_id_attendu);
    assert_eq!(evt_req.transport, Transport::Http);
    assert_eq!(evt_req.direction, Direction::ClientVersServeur);
    assert_eq!(evt_req.methode.as_deref(), Some("tools/list"));

    // Événement 2 : réponse tools/list (serveur → client).
    let evt_resp = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout reponse")
        .expect("evenement reponse");
    assert_eq!(evt_resp.session_id, session_id_attendu);
    assert_eq!(evt_resp.transport, Transport::Http);
    assert_eq!(evt_resp.direction, Direction::ServeurVersClient);
    // Une réponse JSON-RPC n'a pas de champ `method` — c'est attendu.
    assert!(evt_resp.methode.is_none());
    // On vérifie qu'on a bien le résultat de tools/list dans le payload.
    let tools = evt_resp
        .payload
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .expect("tableau tools dans la réponse normalisée");
    assert_eq!(tools.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 2 : round-trip bit-exact du corps de la requête et de la réponse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn round_trip_corps_bit_exact() {
    // L'upstream enregistre le corps reçu et le renvoie tel quel.
    // On compare ensuite (a) ce que l'upstream a vu vs ce que le client a
    // envoyé, et (b) ce que le client reçoit vs ce que l'upstream a envoyé.
    let corps_capture_upstream: Arc<Mutex<Option<Bytes>>> = Arc::new(Mutex::new(None));
    let capture_clone = corps_capture_upstream.clone();

    let upstream_app = Router::new().route(
        "/mcp",
        post(
            move |State(capture): State<Arc<Mutex<Option<Bytes>>>>, body: Bytes| async move {
                // Enregistre le corps reçu côté upstream.
                {
                    let mut g = capture.lock().await;
                    *g = Some(body.clone());
                }
                // Renvoie un corps déterministe (différent du request body) pour
                // tester aussi le round-trip de la réponse.
                let reponse = r#"{"jsonrpc":"2.0","id":42,"result":{"ok":true}}"#;
                Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(Body::from(reponse))
                    .unwrap()
            },
        )
        .with_state(capture_clone),
    );

    let upstream_addr = demarrer_upstream(upstream_app).await;
    let upstream_url = format!("http://{}/mcp", upstream_addr);
    let (proxy_addr, _rx) = demarrer_proxy(upstream_url).await;

    // Payload arbitraire contenant des espaces, des caractères non-ASCII et
    // des guillemets imbriqués — tout doit transiter sans la moindre
    // modification d'octet.
    let payload = "{\"jsonrpc\":\"2.0\",\"method\":\"ping\",\"params\":{\"msg\":\"héllo  world\\nÆ\"},\"id\":42}";
    let payload_bytes = payload.as_bytes().to_vec();

    let client = Client::new();
    let reponse = client
        .post(format!("http://{}/mcp", proxy_addr))
        .header("content-type", "application/json")
        .header("mcp-session-id", "sess-roundtrip")
        .body(payload_bytes.clone())
        .send()
        .await
        .expect("requête round-trip");

    assert_eq!(reponse.status(), StatusCode::OK);

    let corps_recu_par_client = reponse.bytes().await.expect("lecture corps réponse");

    // (a) Le corps que l'upstream a reçu doit être bit-exact à celui envoyé.
    let corps_vu_par_upstream = corps_capture_upstream
        .lock()
        .await
        .clone()
        .expect("l'upstream doit avoir reçu un corps");
    assert_eq!(
        corps_vu_par_upstream.as_ref(),
        payload_bytes.as_slice(),
        "le corps relayé à l'upstream doit être bit-exact au corps émis par le client"
    );

    // (b) Le corps que le client reçoit doit être bit-exact à celui que
    //     l'upstream a renvoyé.
    let reponse_upstream_attendue = r#"{"jsonrpc":"2.0","id":42,"result":{"ok":true}}"#;
    assert_eq!(
        corps_recu_par_client.as_ref(),
        reponse_upstream_attendue.as_bytes(),
        "le corps relayé au client doit être bit-exact à la réponse upstream"
    );
}

// ---------------------------------------------------------------------------
// Test 3 (bonus, < 100 LoC) : la réponse SSE est observée + streamée intacte
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sse_relaye_chunks_et_emet_evenements() {
    let upstream_app = Router::new().route(
        "/mcp",
        get(|| async {
            let corps = concat!(
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"p\":1}}\n",
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"p\":2}}\n",
            );
            Response::builder()
                .status(200)
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .body(Body::from(corps))
                .unwrap()
        }),
    );

    let upstream_addr = demarrer_upstream(upstream_app).await;
    let upstream_url = format!("http://{}/mcp", upstream_addr);
    let (proxy_addr, mut rx) = demarrer_proxy(upstream_url).await;

    let client = Client::new();
    let reponse = client
        .get(format!("http://{}/mcp", proxy_addr))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", "sess-sse-proxy")
        .send()
        .await
        .expect("requête GET SSE");

    // Force la consommation complète du flux côté client.
    let _ = reponse.bytes().await.expect("lecture flux SSE");

    let mut nb = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while nb < 2 {
        match timeout(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            rx.recv(),
        )
        .await
        {
            Ok(Some(evt)) => {
                assert_eq!(evt.session_id, "sess-sse-proxy");
                assert_eq!(evt.direction, Direction::ServeurVersClient);
                assert_eq!(evt.methode.as_deref(), Some("notifications/progress"));
                nb += 1;
            }
            _ => break,
        }
    }
    assert_eq!(nb, 2, "deux événements SSE attendus");
}
