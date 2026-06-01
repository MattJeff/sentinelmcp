//! Live background monitoring loop.
//!
//! Spawned once at app start from `lib.rs::setup()`. Runs two tokio tasks:
//!
//! 1. A periodic tick (`live_interval_secs`, default 30 s) that re-runs the
//!    full discovery + active-probe sweep and persists the result through
//!    the same `AdaptateurStore` the manual scan uses.
//! 2. A filesystem watcher (`notify`) on every known AI-client config path.
//!    When any of those files (or their parent directories) changes, we
//!    trigger an immediate rescan with a 300 ms debounce so a single
//!    `claude mcp add foo` only produces one refresh.
//!
//! Both tasks call the same [`executer_scan`] helper, which emits a
//! `sentinel://live-tick` Tauri event after the sweep so the React UI can
//! `mutate()` its SWR keys without polling.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use notify::{recommended_watcher, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};

use crate::state::AppState;

/// Payload emitted to the frontend on `sentinel://live-tick`.
///
/// Mirrors the `LiveTick` TS DTO in `src/api/contract.ts`.
#[derive(Serialize, Clone)]
struct LiveTickPayload {
    last_refresh_iso: String,
    servers_total: u64,
    findings_total: u64,
}

/// Public entry point: spawn the two background tasks.
///
/// Fire-and-forget — both tasks live for the lifetime of the app. They never
/// panic; any unexpected error (notify failure, scan timeout) is logged and
/// swallowed so the UI keeps working.
pub fn lancer_boucle_live(app: AppHandle, state: AppState) {
    // Use Tauri's own async runtime so we don't depend on an outer tokio
    // context being present in the `setup()` synchronous callback. Plain
    // `tokio::spawn` from inside `did_finish_launching` panics non-unwindably
    // across the Objective-C boundary on macOS.
    let app_tick = app.clone();
    let state_tick = state.clone();
    tauri::async_runtime::spawn(async move {
        boucle_periodique(app_tick, state_tick).await;
    });

    let app_watch = app.clone();
    let state_watch = state.clone();
    tauri::async_runtime::spawn(async move {
        boucle_watcher(app_watch, state_watch).await;
    });
}

/// Periodic loop: read the current interval, sleep, scan, repeat.
async fn boucle_periodique(app: AppHandle, state: AppState) {
    loop {
        let secs = state.live_interval_secs.load(Ordering::Relaxed).max(1);
        sleep(Duration::from_secs(secs)).await;
        executer_scan(&app, &state).await;
    }
}

/// File watcher loop. Sets up `notify::recommended_watcher` on every known
/// AI-client config path *and* its parent directory (so notify fires when
/// the config file is created after Sentinel boots).
///
/// On any change we forward a single message to a tokio channel that
/// debounces back-to-back events into one scan.
async fn boucle_watcher(app: AppHandle, state: AppState) {
    let (tx, mut rx) = mpsc::unbounded_channel::<()>();

    // The `notify` callback runs on its own native thread, so we hop into
    // the tokio runtime via `tx.send()`.
    let tx_cb = tx.clone();
    let watcher_result: notify::Result<RecommendedWatcher> = recommended_watcher(
        move |res: notify::Result<Event>| {
            if res.is_ok() {
                let _ = tx_cb.send(());
            }
        },
    );

    let mut watcher = match watcher_result {
        Ok(w) => w,
        Err(e) => {
            log::warn!("live watcher: could not build notify watcher: {}", e);
            return;
        }
    };

    // Resolve every path we care about. Each path is watched at file level
    // when it exists, and at directory level so notify fires when the file
    // is created later (e.g. first time the user runs `claude mcp add`).
    let mut watched_count = 0usize;
    for path in chemins_a_surveiller() {
        // Watch the file itself, if present.
        if path.exists() {
            match watcher.watch(&path, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    watched_count += 1;
                    log::info!("live watcher: watching {:?}", path);
                }
                Err(e) => {
                    log::debug!("live watcher: could not watch {:?}: {}", path, e);
                }
            }
        }
        // Also watch the parent directory so we catch file creation later.
        if let Some(parent) = path.parent() {
            if parent.exists() {
                match watcher.watch(parent, RecursiveMode::NonRecursive) {
                    Ok(()) => {
                        watched_count += 1;
                    }
                    Err(e) => {
                        log::debug!(
                            "live watcher: could not watch dir {:?}: {}",
                            parent,
                            e
                        );
                    }
                }
            }
        }
    }
    log::info!(
        "live watcher: armed on {} file/dir entries",
        watched_count
    );

    // Keep the watcher alive — dropping it tears down the OS-level callbacks.
    // We `Arc` it so the closure can be moved around if needed.
    let _keep_alive: Arc<RecommendedWatcher> = Arc::new(watcher);

    // Debounce loop: collect a burst of events into a single scan.
    while let Some(()) = rx.recv().await {
        // Coalesce: drain any additional events that arrive in the 300 ms
        // window so back-to-back writes from e.g. `claude mcp add` only
        // produce one rescan.
        let deadline = Instant::now() + Duration::from_millis(300);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(())) => continue,
                _ => break,
            }
        }
        log::info!("live watcher: config change detected — triggering rescan");
        executer_scan(&app, &state).await;
    }
}

/// Run one full sweep:
///   1. Discovery (every AI client config on this Mac).
///   2. Probe each declared stdio server.
///   3. Persist results through `AdaptateurStore`.
///   4. Update `last_refresh_at` and emit `sentinel://live-tick`.
///
/// Wrapped in a 60-second outer timeout so a hung probe can never freeze
/// the loop. Errors are logged and never propagated.
async fn executer_scan(app: &AppHandle, state: &AppState) {
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        executer_scan_interne(state),
    )
    .await;

    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(e)) => log::warn!("live scan: error during sweep: {}", e),
        Err(_) => log::warn!("live scan: sweep timed out after 60 s"),
    }

    // Always advance the refresh clock and broadcast, even on partial failure.
    let now = Utc::now();
    {
        let mut last = state.last_refresh_at.write().await;
        *last = now;
    }

    // Build the payload using whatever the store has right now.
    let store = state.store.clone();
    let (servers_total, findings_total) = tokio::task::spawn_blocking(move || {
        let s = store.lister_serveurs().map(|v| v.len() as u64).unwrap_or(0);
        let f = store
            .lister_constats_ouverts()
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        (s, f)
    })
    .await
    .unwrap_or((0, 0));

    let payload = LiveTickPayload {
        last_refresh_iso: now.to_rfc3339(),
        servers_total,
        findings_total,
    };
    if let Err(e) = app.emit("sentinel://live-tick", payload) {
        log::warn!("live scan: could not emit live-tick: {}", e);
    }
}

/// Core sweep logic, factored out so [`executer_scan`] can wrap it in a
/// timeout + error log.
async fn executer_scan_interne(state: &AppState) -> anyhow::Result<()> {
    use sentinel_detect::InspecteurPoisoning;
    use sentinel_discovery::{
        active_probe::{EtatProbe, ProbeurActif},
        OrchestrateurDecouverte,
    };
    use sentinel_protocol::Transport;
    use sentinel_scan::scope::inferer_portee;
    use sentinel_scan::store_contract::{
        AdaptateurStore, ContratScanStore, EvenementInventaire,
    };

    let rapport = OrchestrateurDecouverte::default().balayer().await;
    let adaptateur = Arc::new(AdaptateurStore::nouveau(state.store.clone()));
    let probeur = ProbeurActif::par_defaut();

    for client in &rapport.clients {
        for serv in &client.serveurs {
            if serv.disabled {
                continue;
            }
            if !serv.transport.eq_ignore_ascii_case("stdio") {
                continue;
            }

            let rapport_probe = probeur.probe_serveur(serv).await;
            if rapport_probe.etat != EtatProbe::Reussi {
                continue;
            }

            let portees = inferer_portee(&rapport_probe.outils);
            let endpoint = if rapport_probe.serveur_commande.is_empty() {
                serv.nom.clone()
            } else {
                rapport_probe.serveur_commande.clone()
            };

            let evenement = EvenementInventaire {
                endpoint,
                transport: Transport::Stdio,
                outils: rapport_probe.outils.clone(),
                portees: portees.clone(),
            };

            let serveur_id = match adaptateur.enregistrer_inventaire(evenement).await {
                Ok(id) => id,
                Err(e) => {
                    log::warn!(
                        "live scan: could not persist inventory for {}: {}",
                        serv.nom,
                        e
                    );
                    continue;
                }
            };

            // Persist poisoning findings (re-using the probe's own list when
            // populated, else running the inspector ourselves).
            let constats = if rapport_probe.constats_poisoning.is_empty() {
                InspecteurPoisoning::inspecter(&rapport_probe.outils)
            } else {
                rapport_probe.constats_poisoning.clone()
            };
            for cp in &constats {
                let constat = InspecteurPoisoning::vers_constat(cp, serveur_id);
                if let Err(e) = state.store.enregistrer_constat(&constat) {
                    log::warn!("live scan: could not store poisoning finding: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Public list of files the watcher arms itself on. Re-exported so the
/// `get_live_status` Tauri command can surface it to the UI.
pub fn chemins_a_surveiller() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return out,
    };

    let candidates: &[&[&str]] = &[
        // macOS Claude Desktop
        &["Library", "Application Support", "Claude", "claude_desktop_config.json"],
        // Claude Code CLI (~/.claude.json)
        &[".claude.json"],
        // Cursor (~/.cursor/mcp.json)
        &[".cursor", "mcp.json"],
        // Windsurf (~/.codeium/windsurf/mcp_config.json)
        &[".codeium", "windsurf", "mcp_config.json"],
        // Continue (~/.continue/config.yaml)
        &[".continue", "config.yaml"],
        // Zed (~/.config/zed/settings.json)
        &[".config", "zed", "settings.json"],
        // VS Code (~/Library/Application Support/Code/User/settings.json)
        &["Library", "Application Support", "Code", "User", "settings.json"],
        // Aider (~/.aider.conf.yml)
        &[".aider.conf.yml"],
        // Goose (~/.config/goose/config.yaml)
        &[".config", "goose", "config.yaml"],
        // Codex (~/.codex/config.toml)
        &[".codex", "config.toml"],
        // Antigravity (~/Library/Application Support/Antigravity/User/settings.json)
        &[
            "Library",
            "Application Support",
            "Antigravity",
            "User",
            "settings.json",
        ],
        // LM Studio (~/.lmstudio/mcp.json)
        &[".lmstudio", "mcp.json"],
    ];

    for parts in candidates {
        let mut p = home.clone();
        for seg in *parts {
            p.push(seg);
        }
        out.push(p);
    }
    out
}
