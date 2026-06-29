//! Shared application state for Tauri commands.

use chrono::{DateTime, Utc};
use sentinel_discovery::EtatProbe;
use sentinel_store::Store;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tauri::async_runtime::JoinHandle;
use tauri::{App, Manager};
use tokio::sync::RwLock;

/// Default tick for the background live-monitoring loop (seconds).
pub const DEFAULT_LIVE_INTERVAL_SECS: u64 = 30;

/// Politique « approve-before-run » exposée à l'UI.
///
/// Cache mémoire de la configuration persistée sur disque par les commandes
/// `get_gate_config` / `set_gate_config`. Le gate temps réel (proxy) la
/// consulte pour décider s'il faut **retenir** un appel à risque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    /// `false` (défaut) : détection seule, relais bit-exact. `true` : mode
    /// enforce — un appel franchissant le seuil est retenu pour approbation.
    pub enforce: bool,
    /// Seuil de risque déclenchant la rétention : `"low"` | `"medium"` |
    /// `"high"` (défaut). Mappé sur `sentinel_scan::proxy::NiveauRisque` côté
    /// gate.
    pub seuil: String,
}

impl Default for GateConfig {
    fn default() -> Self {
        // Détection seule + seuil le plus strict : aucun blocage tant que
        // l'opérateur n'a pas explicitement opté pour l'enforce.
        Self {
            enforce: false,
            seuil: "high".to_string(),
        }
    }
}

/// Une demande d'approbation « approve-before-run » présentée à l'opérateur.
///
/// Alimentée soit EN DIRECT par le gate (couplage temps réel, champ
/// `source = "live"`), soit dérivée des constats « retenu pour approbation »
/// persistés dans le store (`source = "store"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    /// Identifiant : l'UUID du constat store quand `source = "store"`.
    pub id: String,
    /// Identifiant du serveur concerné (UUID).
    pub server_id: String,
    /// Nom de l'outil appelé, si connu.
    pub tool: Option<String>,
    /// Niveau de risque : `"info"` | `"medium"` | `"high"` | `"critical"`.
    pub risk_level: String,
    /// Explication lisible (sans contenu brut des arguments).
    pub reason: String,
    /// Titre du constat sous-jacent.
    pub title: String,
    /// Horodatage ISO-8601 de la demande.
    pub requested_at: String,
    /// `true` si l'appel a été effectivement RETENU (bloqué) ; `false` pour un
    /// simple advisory relayé en mode détection.
    pub held: bool,
    /// `"store"` (dérivé d'un constat persisté) ou `"live"` (poussé par le gate).
    pub source: String,
    /// `"pending"` | `"approved"` | `"denied"`.
    pub state: String,
}

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
    /// Politique « approve-before-run » (cache mémoire). Persistée sur disque
    /// (`gate.json`) par les commandes `get_gate_config` / `set_gate_config` ;
    /// consultable par le gate temps réel pour décider d'une rétention.
    pub gate_config: Arc<RwLock<GateConfig>>,
    /// Registre des demandes d'approbation alimentées EN DIRECT par le gate
    /// (couplage temps réel optionnel). `list_pending_approvals` fusionne ces
    /// demandes avec les constats « retenu pour approbation » du store, de
    /// sorte que l'UI voit la file complète même sans coupleur temps réel.
    pub pending_approvals: Arc<RwLock<Vec<PendingApproval>>>,
}

impl AppState {
    /// Legacy/fallback constructor: in-memory store.
    /// Kept so tests and harness boots can still spin up without an `App`.
    #[allow(dead_code)]
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
            gate_config: Arc::new(RwLock::new(GateConfig::default())),
            pending_approvals: Arc::new(RwLock::new(Vec::new())),
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
            gate_config: Arc::new(RwLock::new(GateConfig::default())),
            pending_approvals: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Hook temps réel : le gate (proxy) peut pousser une demande d'approbation
    /// dans le registre. Déduplique par `id`. Actuellement non câblé au proxy
    /// HTTP du desktop (voir `commands_runtime`) — fourni pour le couplage
    /// temps réel à venir.
    #[allow(dead_code)]
    pub async fn pousser_demande_approbation(&self, demande: PendingApproval) {
        let mut file = self.pending_approvals.write().await;
        if !file.iter().any(|d| d.id == demande.id) {
            file.push(demande);
        }
    }
}
