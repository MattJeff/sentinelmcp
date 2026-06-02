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
mod commands_settings;
mod commands_siem;
mod commands_stix;
mod commands_taxii;
mod state;

use tauri::Manager;

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
            commands_lookalikes::scan_lookalikes,
            commands_enforcement::enforcement_remove_server,
            commands_enforcement::enforcement_restore,
            commands_proxy::start_proxy,
            commands_proxy::stop_proxy,
            commands_proxy::proxy_status,
            commands_settings::get_settings,
            commands_settings::save_settings,
            commands_siem::siem_test_send,
            commands_siem::siem_save_config,
            commands_siem::siem_get_config,
            commands_taxii::taxii_test_send,
            commands_taxii::taxii_save_config,
            commands_taxii::taxii_get_config,
            commands_stix::stix_export_bundle,
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
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
