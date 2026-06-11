//! Shared application state for Tauri commands.

use chrono::{DateTime, Utc};
use sentinel_discovery::EtatProbe;
use sentinel_store::Store;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tauri::async_runtime::JoinHandle;
use tauri::{App, Manager};
use tokio::sync::RwLock;

/// Default tick for the background live-monitoring loop (seconds).
pub const DEFAULT_LIVE_INTERVAL_SECS: u64 = 30;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    pub scan_running: Arc<RwLock<bool>>,
    /// Interval (seconds) between two automatic discovery+probe sweeps.
    /// Mutated atomically from the `set_live_interval` Tauri command so the
    /// background task picks up changes on its next iteration.
    pub live_interval_secs: Arc<AtomicU64>,
    /// Timestamp of the most recent background scan, surfaced to the UI via
    /// `get_live_status` so the sidebar can render "Last refresh HH:MM:SS".
    pub last_refresh_at: Arc<RwLock<DateTime<Utc>>>,
    /// Handle to the running active proxy (mode B) task — `Some` while the
    /// proxy is serving, `None` otherwise. Wrapped in an `RwLock` so the
    /// `start_proxy` / `stop_proxy` Tauri commands can mutate it safely.
    pub proxy_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Current proxy listening port (set when proxy starts, cleared on stop).
    pub proxy_port: Arc<RwLock<Option<u16>>>,
    /// Current proxy upstream URL (set when proxy starts, cleared on stop).
    pub proxy_upstream: Arc<RwLock<Option<String>>>,
    /// Number of MCP events seen by the proxy since it started.
    pub proxy_events_seen: Arc<AtomicU64>,
    /// Last observed probe outcome per server (keyed by `DeclaredServer.name`).
    /// Used by `probe_server` to detect a "failed → succeeded" transition and
    /// trigger an automatic lookalike rescan on first successful contact.
    /// In-memory only — purposely not persisted, since the goal is to react to
    /// a per-session transition, not to remember failures across app reboots.
    pub last_probe_states: Arc<RwLock<HashMap<String, EtatProbe>>>,
}

impl AppState {
    /// Legacy/fallback constructor: in-memory store.
    /// Kept so tests and harness boots can still spin up without an `App`.
    pub fn nouveau() -> Self {
        let store = Store::in_memory().expect("opening in-memory store failed");
        Self {
            store,
            scan_running: Arc::new(RwLock::new(false)),
            live_interval_secs: Arc::new(AtomicU64::new(DEFAULT_LIVE_INTERVAL_SECS)),
            last_refresh_at: Arc::new(RwLock::new(Utc::now())),
            proxy_handle: Arc::new(RwLock::new(None)),
            proxy_port: Arc::new(RwLock::new(None)),
            proxy_upstream: Arc::new(RwLock::new(None)),
            proxy_events_seen: Arc::new(AtomicU64::new(0)),
            last_probe_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Builds the application state with a persistent SQLite store located in
    /// the macOS Application Support directory
    /// (`~/Library/Application Support/com.sentinel-mcp.desktop/sentinel.db`).
    ///
    /// If the path cannot be resolved or the store fails to open at that
    /// location, we transparently fall back to an in-memory store so the app
    /// still boots.
    pub fn nouveau_avec_app(app: &App) -> Self {
        let store = match app.path().app_data_dir() {
            Ok(dir) => {
                if let Err(err) = std::fs::create_dir_all(&dir) {
                    log::warn!(
                        "could not create app data dir {:?}: {} — falling back to in-memory store",
                        dir,
                        err
                    );
                    Store::in_memory().expect("opening in-memory store failed")
                } else {
                    let db_path = dir.join("sentinel.db");
                    match Store::open(&db_path) {
                        Ok(s) => {
                            log::info!("Sentinel store opened at {:?}", db_path);
                            s
                        }
                        Err(err) => {
                            log::warn!(
                                "failed to open persistent store at {:?}: {} — falling back to in-memory",
                                db_path,
                                err
                            );
                            Store::in_memory().expect("opening in-memory store failed")
                        }
                    }
                }
            }
            Err(err) => {
                log::warn!(
                    "could not resolve app data dir: {} — falling back to in-memory store",
                    err
                );
                Store::in_memory().expect("opening in-memory store failed")
            }
        };

        Self {
            store,
            scan_running: Arc::new(RwLock::new(false)),
            live_interval_secs: Arc::new(AtomicU64::new(DEFAULT_LIVE_INTERVAL_SECS)),
            last_refresh_at: Arc::new(RwLock::new(Utc::now())),
            proxy_handle: Arc::new(RwLock::new(None)),
            proxy_port: Arc::new(RwLock::new(None)),
            proxy_upstream: Arc::new(RwLock::new(None)),
            proxy_events_seen: Arc::new(AtomicU64::new(0)),
            last_probe_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
