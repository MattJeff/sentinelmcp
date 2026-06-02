//! Tauri command exposing the STIX 2.1 bundle export to the UI.
//!
//! Companion to `commands_taxii.rs`. While TAXII deals with the outbound
//! push, this module is purely **local**: it builds a STIX 2.1 bundle from
//! the current Sentinel store via [`sentinel_stix::export_bundle`],
//! serialises it as pretty JSON with `serde_json::to_writer_pretty`, and
//! writes it to:
//!
//!     <app_data_dir>/reports/sentinel-<UTC-timestamp>.stix.json
//!
//! The absolute path of the written file is returned to the frontend so a
//! follow-up "Reveal in Finder" action can open it. Because this command
//! never makes an outbound network call, it is **not** gated by the global
//! `privacy.outbound_lookups` toggle — same trust model as the existing
//! `generate_report` PDF/JSON export.

use std::path::PathBuf;

use chrono::Utc;
use tauri::{AppHandle, Manager, State};

use crate::state::AppState;

const REPORTS_SUBDIR: &str = "reports";

/// Resolve `<app_data_dir>/reports/`, creating the directory tree if needed.
fn reports_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("could not resolve app data dir: {}", e))?;
    let dir = base.join(REPORTS_SUBDIR);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("could not create reports dir {:?}: {}", dir, e))?;
    Ok(dir)
}

/// Build a STIX 2.1 bundle from the current store and write it to disk.
///
/// Returns the absolute path of the resulting `.stix.json` file. Errors
/// (store I/O, serialisation, file write) are converted to a descriptive
/// `String` per Tauri convention.
#[tauri::command]
pub async fn stix_export_bundle(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let store = state.store.clone();

    // Build the bundle off the async runtime — `export_bundle` performs
    // synchronous store reads under the hood.
    let bundle = tokio::task::spawn_blocking(move || sentinel_stix::export_bundle(&store))
        .await
        .map_err(|e| format!("STIX export task panicked: {}", e))?
        .map_err(|e| format!("STIX export failed: {}", e))?;

    let dir = reports_dir(&app)?;
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let path = dir.join(format!("sentinel-{}.stix.json", timestamp));

    let file = std::fs::File::create(&path)
        .map_err(|e| format!("could not create {:?}: {}", path, e))?;
    serde_json::to_writer_pretty(file, &bundle)
        .map_err(|e| format!("could not serialise STIX bundle: {}", e))?;

    log::info!(
        "STIX bundle exported to {:?} ({} objects)",
        path,
        bundle.objects.len()
    );
    Ok(path.to_string_lossy().to_string())
}
