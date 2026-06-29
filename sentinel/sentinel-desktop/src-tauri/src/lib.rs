//! Sentinel MCP desktop — Tauri entry point.
//!
//! The frontend (`src/`) is a React + Vite + Tailwind app. This module wires
//! the Tauri commands and events to the existing `sentinel-*` Rust crates.

mod background;
mod commands;
mod commands_discovery;
mod commands_enforcement;
mod commands_lookalikes;
mod commands_proxy;
mod commands_runtime;
mod commands_settings;
mod commands_siem;
mod commands_stix;
mod commands_tags;
mod commands_taxii;
mod commands_threat_feed;
mod outbound;
mod state;

use std::time::Duration;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Emitter, Manager};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::list_servers,
            commands::get_server_detail,
            commands::start_scan,
            commands::stop_scan,
            commands::scan_progress,
            commands::list_findings,
            commands::resolve_finding,
            commands::list_alerts,
            commands::apply_approval,
            commands::list_baselines,
            commands::generate_report,
            commands::open_report_file,
            commands::executive_summary,
            commands::compliance_references,
            commands::compliance_coverage,
            commands::app_version,
            commands::list_observed_events,
            commands::test_email_channel,
            commands::test_webhook_channel,
            commands::get_live_status,
            commands::set_live_interval,
            commands::create_investigation,
            commands::list_investigations,
            commands_discovery::discover_system,
            commands_discovery::probe_server,
            commands_discovery::compute_trust_graph,
            commands_discovery::list_threats,
            commands_discovery::scan_skills,
            commands_discovery::list_yara_rules,
            commands_lookalikes::scan_lookalikes,
            commands_enforcement::enforcement_remove_server,
            commands_enforcement::enforcement_restore,
            commands_proxy::start_proxy,
            commands_proxy::stop_proxy,
            commands_proxy::proxy_status,
            commands_runtime::get_gate_config,
            commands_runtime::set_gate_config,
            commands_runtime::list_pending_approvals,
            commands_runtime::approve_call,
            commands_runtime::deny_call,
            commands_runtime::list_rogue_sockets,
            commands_runtime::list_cve_findings,
            commands_settings::get_settings,
            commands_settings::save_settings,
            commands_siem::siem_test_send,
            commands_siem::siem_save_config,
            commands_siem::siem_get_config,
            commands_siem::siem_pick_ca_pem,
            commands_taxii::taxii_test_send,
            commands_taxii::taxii_save_config,
            commands_taxii::taxii_get_config,
            commands_stix::stix_export_bundle,
            commands_tags::server_set_tags,
            commands_tags::server_list_tags,
            commands_threat_feed::threat_feed_refresh,
            commands_threat_feed::threat_feed_status,
        ])
        .setup(|app| {
            log::info!("Sentinel MCP desktop launched");
            // Build the persistent app state once we have an `App` handle so we
            // can resolve the platform-specific data directory.
            let state = state::AppState::nouveau_avec_app(app);
            app.manage(state.clone());
            // Best-effort: hide the legacy traffic-light overlay flicker.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title("Sentinel MCP");
            }
            // Start the live background monitoring loop (periodic scan +
            // config-file watcher). Both tasks are fire-and-forget and live
            // for the lifetime of the app. Any panic during spawn is caught
            // so we never crash the app delegate's didFinishLaunching.
            let app_handle = app.handle().clone();
            let state_for_bg = state.clone();
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                background::lancer_boucle_live(app_handle, state_for_bg);
            })) {
                log::warn!("background loop spawn panicked: {:?}", e);
            }

            // Threat-intel feed refresh loop. Fires every 4h and respects
            // both `settings.threat_feed.auto_refresh_enabled` and the
            // global `privacy.outbound_lookups` toggle. Skipped silently
            // whenever either gate is OFF.
            let app_threat_feed = app.handle().clone();
            if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                background::lancer_refresh_threat_feed(app_threat_feed);
            })) {
                log::warn!("threat feed refresh spawn panicked: {:?}", e);
            }

            // ── Tray icon + menu ────────────────────────────────────────────
            //
            // Sentinel runs as a menu-bar resident on macOS. The icon stays
            // alive even after the main window is closed (see the
            // `on_window_event` handler below + the "keep running in
            // background" toggle in Settings → General).
            //
            // Menu actions:
            //   • Open Sentinel  — show/focus the main window
            //   • Run scan now   — emit a tray-scan event the frontend
            //                      forwards to `start_scan` via App.tsx
            //   • Quit Sentinel  — terminate the process unconditionally
            //
            // We `unwrap()` the `default_window_icon` because the bundle
            // declares an icon set in `tauri.conf.json`; if it were ever
            // missing the build itself would fail far earlier.
            let menu = Menu::with_items(
                app,
                &[
                    &MenuItem::with_id(app, "open", "Open Sentinel", true, None::<&str>)?,
                    &MenuItem::with_id(app, "scan", "Run scan now", true, None::<&str>)?,
                    &PredefinedMenuItem::separator(app)?,
                    &MenuItem::with_id(app, "quit", "Quit Sentinel", true, None::<&str>)?,
                ],
            )?;

            let tray_icon = app
                .default_window_icon()
                .expect("bundle must declare a default window icon")
                .clone();

            let _tray = TrayIconBuilder::with_id("sentinel-tray")
                .icon(tray_icon)
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.unminimize();
                            let _ = w.set_focus();
                        }
                    }
                    "scan" => {
                        // The actual scan is owned by the frontend (which
                        // already wraps `start_scan` with the right
                        // `ScanParams`); we just nudge it.
                        if let Err(e) = app.emit("sentinel://tray-scan-requested", ()) {
                            log::warn!("tray: could not emit scan-requested event: {}", e);
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            // ── Alerts counter on the tray title ───────────────────────────
            //
            // Poll the store every 30 s for open findings and reflect the
            // count next to the tray icon. The menu-bar title only renders
            // when count > 0 so the icon stays clean during steady state.
            // We also push the value to the frontend (`sentinel://alerts-
            // count-changed`) so the window UI can mirror it without an
            // extra round-trip.
            let store_for_count = state.store.clone();
            let app_for_count = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut last_count: Option<u64> = None;
                let mut tick = tokio::time::interval(Duration::from_secs(30));
                loop {
                    tick.tick().await;
                    let store_snapshot = store_for_count.clone();
                    let count: u64 = tokio::task::spawn_blocking(move || {
                        store_snapshot
                            .lister_constats_ouverts()
                            .map(|v| v.len() as u64)
                            .unwrap_or(0)
                    })
                    .await
                    .unwrap_or(0);

                    if last_count == Some(count) {
                        continue;
                    }
                    last_count = Some(count);

                    if let Some(tray) = app_for_count.tray_by_id("sentinel-tray") {
                        let title = if count > 0 {
                            Some(format!("●{}", count))
                        } else {
                            None
                        };
                        if let Err(e) = tray.set_title(title.as_deref()) {
                            log::debug!("tray: set_title failed: {}", e);
                        }
                    }
                    if let Err(e) = app_for_count
                        .emit("sentinel://alerts-count-changed", serde_json::json!({ "count": count }))
                    {
                        log::debug!("tray: emit alerts-count-changed failed: {}", e);
                    }
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Intercept the main window's close button. When the operator
            // has opted into "Keep running in background" (default), we
            // hide the window instead of quitting — the menu-bar icon
            // stays as the surviving entry point. Disable the toggle in
            // Settings → General to restore the legacy "close = quit"
            // behaviour.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() != "main" {
                    return;
                }
                let app = window.app_handle();
                let keep = commands_settings::lire_keep_running(app).unwrap_or(true);
                if keep {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            // macOS: when the user clicks the Dock icon while the main window
            // is hidden (via the "keep running in background" flow), reopen it.
            if let tauri::RunEvent::Reopen { has_visible_windows, .. } = event {
                if !has_visible_windows {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                }
            }
        });
}
