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
    // Build the hybrid-detection configuration from the operator's settings
    // once per sweep (YARA on by default; optional local LLM judge only when
    // explicitly enabled). Passed into the inner sweep so every persisted
    // poisoning finding goes through the full pipeline.
    let config = crate::commands_settings::config_detection(app);

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        executer_scan_interne(state, &config),
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
async fn executer_scan_interne(
    state: &AppState,
    config: &sentinel_detect::ConfigDetection,
) -> anyhow::Result<()> {
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

            // Persist poisoning findings through the HYBRID pipeline:
            // patterns + Unicode anti-smuggling + line-jumping + embedded YARA
            // (and the optional local LLM judge when enabled in settings).
            // `inspecter_complet` already returns store-ready `Constat`s.
            let constats =
                InspecteurPoisoning::inspecter_complet(&rapport_probe.outils, serveur_id, config)
                    .await;
            for constat in &constats {
                if let Err(e) = state.store.enregistrer_constat(constat) {
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

// --- L17 registry refresh ---
//
// Daily refresh of the four lookalike registries (pulsemcp, smithery, mcpso,
// mcp_registry). Each tick fetches the entry list from the source, serializes
// it as JSON bytes and persists it via `CacheRegistres::ecrire`. The cache is
// stored alongside the main `sentinel.db` so it survives across launches.
//
// The task is fire-and-forget: any error (network, serialization, SQLite) is
// logged at `warn` level and swallowed — the app must never crash because a
// registry is down. On startup we run one immediate refresh if the entry is
// stale (`est_frais` returned false), then settle into the 24h cadence.

use sentinel_detect::lookalikes::{
    SourceMcpRegistry, SourceMcpSo, SourcePulseMCP, SourceRegistre, SourceSmithery,
};
use sentinel_store::registry_cache::CacheRegistres;
use tauri::Manager;
use tokio::time::interval;

/// TTL for a cache entry, in seconds (24h). An entry older than this is
/// considered stale and gets refetched on the next tick (or immediately at
/// startup).
#[allow(dead_code)]
const REGISTRY_CACHE_TTL_SECS: i64 = 24 * 3600;

/// Public entry point: spawn the daily registry refresh task.
///
/// Fire-and-forget — never panics, never crashes the app. The cache DB lives
/// next to the main store in the platform-specific app-data directory.
///
/// Currently not wired into `setup()`: the lookalike registries are refreshed
/// on-demand by the probe-driven rescan path instead. Kept here, ready to be
/// armed, behind `#[allow(dead_code)]` so the unused-helper warning stays off.
#[allow(dead_code)]
pub fn lancer_refresh_registres(app: AppHandle, _state: AppState) {
    tauri::async_runtime::spawn(async move {
        boucle_refresh_registres(app).await;
    });
}

/// Periodic refresh loop. Resolves the cache DB path once, runs an initial
/// refresh for any stale registry, then ticks every 24h.
#[allow(dead_code)]
async fn boucle_refresh_registres(app: AppHandle) {
    let cache = match ouvrir_cache_registres(&app) {
        Some(c) => c,
        None => return, // already logged
    };

    // Build the four source connectors. Names used as cache keys mirror the
    // task spec (pulsemcp, smithery, mcpso, mcp_registry) — they do not have
    // to match `SourceRegistre::nom()` since the cache is internal.
    let sources: Vec<(&'static str, Arc<dyn SourceRegistre>)> = vec![
        ("pulsemcp", SourcePulseMCP::nouveau()),
        ("smithery", SourceSmithery::nouveau()),
        ("mcpso", SourceMcpSo::nouveau()),
        ("mcp_registry", SourceMcpRegistry::nouveau()),
    ];

    // Startup pass: only refresh registries whose entries are missing or
    // older than the TTL. Avoids hammering the network on every cold boot.
    for (cle, source) in &sources {
        let frais = cache
            .est_frais(cle, REGISTRY_CACHE_TTL_SECS)
            .unwrap_or(false);
        if !frais {
            refresh_un_registre(&cache, cle, source.as_ref()).await;
        }
    }

    // Steady state: every 24h, refresh all four registries unconditionally.
    // `interval` ticks immediately on its first call — we consume that tick
    // (the startup pass above already handled the initial fetch) so the
    // first real network call happens after the full 24h delay.
    let mut tick = interval(Duration::from_secs(24 * 3600));
    tick.tick().await; // immediate first tick — discarded
    loop {
        tick.tick().await;
        for (cle, source) in &sources {
            refresh_un_registre(&cache, cle, source.as_ref()).await;
        }
    }
}

/// Resolve `<app-data>/sentinel.db` and open the `CacheRegistres` against it.
/// Returns `None` on any failure (logged), so the caller can early-exit
/// without crashing.
#[allow(dead_code)]
fn ouvrir_cache_registres(app: &AppHandle) -> Option<CacheRegistres> {
    let dir = match app.path().app_data_dir() {
        Ok(d) => d,
        Err(e) => {
            log::warn!(
                "registry refresh: could not resolve app data dir: {} — skipping",
                e
            );
            return None;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        log::warn!(
            "registry refresh: could not create app data dir {:?}: {} — skipping",
            dir,
            e
        );
        return None;
    }
    let db_path = dir.join("sentinel.db");
    match CacheRegistres::nouveau(db_path.clone()) {
        Ok(c) => Some(c),
        Err(e) => {
            log::warn!(
                "registry refresh: could not open cache at {:?}: {} — skipping",
                db_path,
                e
            );
            None
        }
    }
}

/// Fetch one registry, JSON-encode the result and persist it via
/// `CacheRegistres::ecrire`. All failure modes are logged at `warn` level
/// and swallowed.
#[allow(dead_code)]
async fn refresh_un_registre(cache: &CacheRegistres, cle: &str, source: &dyn SourceRegistre) {
    let entrees = match source.lister().await {
        Ok(v) => v,
        Err(e) => {
            log::warn!("registry refresh: {} fetch failed: {}", cle, e);
            return;
        }
    };
    let payload = match serde_json::to_vec(&entrees) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("registry refresh: {} serialize failed: {}", cle, e);
            return;
        }
    };
    if let Err(e) = cache.ecrire(cle, &payload) {
        log::warn!("registry refresh: {} write failed: {}", cle, e);
        return;
    }
    log::info!(
        "registry refresh: {} cached ({} entries, {} bytes)",
        cle,
        entrees.len(),
        payload.len()
    );
}

// --- V0.3 threat-intel feed refresh ---
//
// Periodic refresh of the threat intel feed cache from a remote URL,
// gated by:
//   * `settings.threat_feed.auto_refresh_enabled` — operator opt-in;
//   * `settings.privacy.outbound_lookups` — global outbound toggle
//     enforced by every network-bound command in this crate.
//
// The loop ticks every 4 hours so a flaky network has multiple chances
// to recover before the cache hits the 24h TTL the cascade considers
// "stale". Each successful refresh emits `sentinel://threat-feed-refreshed`
// so the Settings page can re-read the status without polling.

use sentinel_discovery::threat_intel::refresh as threat_feed_refresh;

use crate::commands_settings::Settings as DesktopSettings;
use crate::commands_threat_feed::ThreatFeedStatusDto;
use crate::outbound::is_outbound_enabled;

/// Tick cadence of the threat-feed refresh loop. The cache TTL itself is
/// 24h (see `threat_feed_refresh::CACHE_TTL_SECS`); we tick more
/// frequently so a transient network outage at the 24h boundary does not
/// leave the cache stale for another full day.
const THREAT_FEED_TICK_SECS: u64 = 4 * 3600;

/// Public entry point: spawn the threat-feed refresh task. Fire-and-forget
/// like the other background loops.
pub fn lancer_refresh_threat_feed(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        boucle_refresh_threat_feed(app).await;
    });
}

/// Periodic loop: every [`THREAT_FEED_TICK_SECS`], re-read the operator's
/// settings, decide whether to fetch, and either refresh + emit, or skip.
async fn boucle_refresh_threat_feed(app: AppHandle) {
    let mut tick = interval(Duration::from_secs(THREAT_FEED_TICK_SECS));
    // Consume the immediate tick — we want the first network call to
    // happen after the first full window, not on startup. Cold-boot
    // loads always come from the cache/bundled fallback via the
    // `threat_feed_status` command.
    tick.tick().await;
    loop {
        tick.tick().await;
        if let Err(e) = tick_refresh_threat_feed(&app).await {
            log::warn!("threat feed refresh: tick failed: {}", e);
        }
    }
}

/// One iteration of the loop: respect the two toggles, then either
/// refresh + emit, or fall through. Returns an error string so the
/// caller can decide whether to log; never propagates a panic.
async fn tick_refresh_threat_feed(app: &AppHandle) -> Result<(), String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create app data dir {:?}: {}", dir, e))?;
    let settings_path = dir.join("settings.toml");
    let settings: DesktopSettings = if settings_path.exists() {
        let raw = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("could not read settings: {}", e))?;
        toml::from_str::<DesktopSettings>(&raw).unwrap_or_default()
    } else {
        DesktopSettings::default()
    };

    if !settings.threat_feed.auto_refresh_enabled {
        log::debug!("threat feed refresh: auto-refresh disabled, skipping");
        return Ok(());
    }
    if !is_outbound_enabled(app) {
        log::debug!("threat feed refresh: outbound disabled, skipping");
        return Ok(());
    }

    let cache_dir = threat_feed_refresh::cache_dir_for(&dir);
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("could not create cache dir: {}", e))?;

    // Only fetch when the cache is stale; otherwise we would hit the
    // remote every tick even though the data has not changed.
    let cache_yaml = cache_dir.join(threat_feed_refresh::CACHE_FILENAME);
    if !threat_feed_refresh::est_cache_perime(&cache_yaml) {
        log::debug!("threat feed refresh: cache fresh, skipping");
        return Ok(());
    }

    let flux = threat_feed_refresh::rafraichir_feed(&settings.threat_feed.url, &cache_dir)
        .await
        .map_err(|e| e.to_string())?;

    let now = chrono::Utc::now();
    // Update `last_refresh_at` in settings.toml so the UI surfaces a
    // fresh timestamp without an extra round-trip.
    let mut new_settings = settings.clone();
    new_settings.threat_feed.last_refresh_at = Some(now.to_rfc3339());
    if let Ok(serialized) = toml::to_string_pretty(&new_settings) {
        let _ = std::fs::write(&settings_path, serialized);
    }

    let status = threat_feed_refresh::construire_statut(&flux, "remote", Some(now));
    let dto = ThreatFeedStatusDto {
        source: status.source,
        last_refresh: status.last_refresh,
        age_seconds: status.age_seconds,
        entries_count: status.entries_count,
        version: status.version,
        url: settings.threat_feed.url.clone(),
        auto_refresh_enabled: settings.threat_feed.auto_refresh_enabled,
    };
    if let Err(e) = app.emit("sentinel://threat-feed-refreshed", dto) {
        log::debug!("threat feed refresh: emit failed: {}", e);
    }
    log::info!(
        "threat feed refresh: ok ({} entries cached)",
        flux.entrees.len()
    );
    Ok(())
}
