//! Tauri commands exposing the active MCP HTTP proxy (mode B) to the UI.
//!
//! These commands wrap [`sentinel_scan::http::proxy::ProxyMcp`] — a local HTTP
//! interceptor that an AI client can be pointed at instead of its real MCP
//! server. The proxy forwards each request bit-exact to the configured upstream
//! while emitting normalised `EvenementBrut`s on an mpsc channel; a consumer
//! task spawned alongside the proxy persists `tools/list` responses into the
//! same SQLite store the manual scan uses (`AdaptateurStore`), so the UI's
//! inventory page picks up proxy traffic transparently.
//!
//! Three commands are exposed:
//!   * [`start_proxy`] — spawn the proxy + consumer pair on `127.0.0.1:<port>`.
//!     If a proxy is already running, returns its current status (idempotent).
//!   * [`stop_proxy`]  — abort the proxy task and clear the state.
//!   * [`proxy_status`] — return a snapshot of whether the proxy is running,
//!     on which port, against which upstream, and how many events it has seen.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use sentinel_protocol::EvenementBrut;
use sentinel_scan::http::proxy::ProxyMcp;
use sentinel_scan::store_contract::{AdaptateurStore, ContratScanStore, EvenementInventaire};
use serde::Serialize;
use tauri::State;
use tokio::sync::mpsc;

use crate::state::AppState;

/// Snapshot of the proxy task, returned by [`start_proxy`] and [`proxy_status`].
///
/// `port` and `upstream` are `None` when the proxy is not running; `events_seen`
/// is monotonically increasing across the lifetime of the current proxy task
/// and is reset to 0 each time a new proxy is started.
#[derive(Serialize, Clone)]
pub struct ProxyStatus {
    pub running: bool,
    pub port: Option<u16>,
    pub upstream: Option<String>,
    pub events_seen: u64,
}

/// Build a [`ProxyStatus`] snapshot from the shared [`AppState`].
async fn snapshot(state: &AppState) -> ProxyStatus {
    let running = state.proxy_handle.read().await.is_some();
    let port = *state.proxy_port.read().await;
    let upstream = state.proxy_upstream.read().await.clone();
    let events_seen = state.proxy_events_seen.load(Ordering::Relaxed);
    ProxyStatus {
        running,
        port,
        upstream,
        events_seen,
    }
}

/// Start the active MCP proxy on `127.0.0.1:<port>` forwarding to `upstream`.
///
/// If a proxy is already running, this is a no-op and returns its current
/// status — the UI does not need to call `stop_proxy` first.
#[tauri::command]
pub async fn start_proxy(
    state: State<'_, AppState>,
    port: u16,
    upstream: String,
) -> Result<ProxyStatus, String> {
    // Idempotent: if already running, just return the current status.
    if state.proxy_handle.read().await.is_some() {
        return Ok(snapshot(&state).await);
    }

    // Reset counters and record the new (port, upstream) pair *before* we
    // spawn the proxy so a racing `proxy_status` call always sees coherent
    // metadata.
    state.proxy_events_seen.store(0, Ordering::Relaxed);
    *state.proxy_port.write().await = Some(port);
    *state.proxy_upstream.write().await = Some(upstream.clone());

    // Channel between the proxy server (producer) and the consumer task that
    // persists into the SQLite store. Buffer size mirrors `demo.rs` (512).
    let (tx, mut rx) = mpsc::channel::<EvenementBrut>(512);

    // Consumer task: reads `EvenementBrut`s, persists `tools/list` responses
    // through `AdaptateurStore`, and bumps the events_seen counter for the UI.
    let adaptateur = Arc::new(AdaptateurStore::nouveau(state.store.clone()));
    let events_seen = state.proxy_events_seen.clone();
    let consumer = tauri::async_runtime::spawn(async move {
        while let Some(evt) = rx.recv().await {
            events_seen.fetch_add(1, Ordering::Relaxed);

            // Persist `tools/list` responses (the only event kind that
            // materialises a server in the inventory). All other JSON-RPC
            // traffic is observed but not currently persisted by this proxy
            // pipeline.
            let est_reponse_tools_list = evt
                .payload
                .get("result")
                .and_then(|r| r.get("tools"))
                .is_some()
                && evt.payload.get("method").is_none();

            if !est_reponse_tools_list {
                continue;
            }

            let outils: Vec<sentinel_protocol::Outil> = evt
                .payload
                .get("result")
                .and_then(|r| r.get("tools"))
                .and_then(|t| serde_json::from_value(t.clone()).ok())
                .unwrap_or_default();

            if outils.is_empty() {
                continue;
            }

            let portees = sentinel_scan::scope::inferer_portee(&outils);
            let evenement = EvenementInventaire {
                endpoint: evt.serveur.clone(),
                transport: evt.transport,
                outils,
                portees,
            };

            if let Err(e) = adaptateur.enregistrer_inventaire(evenement).await {
                log::warn!("proxy: could not persist inventory: {}", e);
            }
        }
    });

    // Producer task: spawn the proxy itself. When it returns (or panics) we
    // detach the consumer so it can drain the channel and exit cleanly.
    let upstream_for_task = upstream.clone();
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let proxy_task = tauri::async_runtime::spawn(async move {
        let proxy = ProxyMcp::nouveau(tx, upstream_for_task);
        if let Err(e) = proxy.servir(addr).await {
            log::warn!("proxy: serve loop ended with error: {}", e);
        }
        // Once the proxy returns, dropping `tx` (held inside `proxy.emetteur`,
        // moved into `servir`) lets `rx.recv()` return `None` in the consumer.
        let _ = consumer.await;
    });

    *state.proxy_handle.write().await = Some(proxy_task);

    Ok(snapshot(&state).await)
}

/// Stop the running active proxy, if any. No-op if it isn't running.
#[tauri::command]
pub async fn stop_proxy(state: State<'_, AppState>) -> Result<(), String> {
    let handle = state.proxy_handle.write().await.take();
    if let Some(h) = handle {
        h.abort();
        // We don't `await` the handle after abort — `JoinHandle::abort` is
        // best-effort and the task may still be in flight. Clearing the
        // metadata immediately is enough for `proxy_status` to report idle.
    }
    *state.proxy_port.write().await = None;
    *state.proxy_upstream.write().await = None;
    Ok(())
}

/// Return the current proxy status snapshot.
#[tauri::command]
pub async fn proxy_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    Ok(snapshot(&state).await)
}
