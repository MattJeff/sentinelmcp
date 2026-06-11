//! Résolution du chemin de la base SQLite et ouverture du store.
//!
//! Par défaut le CLI partage la base de l'app desktop
//! (`<app-data>/com.sentinel-mcp.desktop/sentinel.db`, soit
//! `~/Library/Application Support/com.sentinel-mcp.desktop/sentinel.db`
//! sur macOS). `--db` permet d'en cibler une autre.

use anyhow::{Context, Result};
use sentinel_store::Store;
use std::path::{Path, PathBuf};

/// Identifiant de l'app desktop Tauri — détermine le dossier app-data.
const IDENTIFIANT_APP: &str = "com.sentinel-mcp.desktop";

/// Chemin par défaut de la base : celui qu'utilise l'app desktop.
pub fn chemin_db_par_defaut() -> PathBuf {
    match dirs::data_dir() {
        Some(dir) => dir.join(IDENTIFIANT_APP).join("sentinel.db"),
        None => PathBuf::from("sentinel.db"),
    }
}

/// Ouvre le store au chemin donné (ou au chemin par défaut), en créant
/// les répertoires parents si nécessaire. Les migrations V1→V4 sont
/// appliquées par `Store::open`.
pub fn ouvrir_store(db: Option<&Path>) -> Result<Store> {
    let chemin = db
        .map(Path::to_path_buf)
        .unwrap_or_else(chemin_db_par_defaut);
    if let Some(parent) = chemin.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création du répertoire {parent:?}"))?;
        }
    }
    Store::open(&chemin).with_context(|| format!("ouverture du store {chemin:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemin_par_defaut_pointe_vers_la_base_desktop() {
        let chemin = chemin_db_par_defaut();
        assert!(chemin.ends_with("com.sentinel-mcp.desktop/sentinel.db") || chemin.ends_with("sentinel.db"));
    }

    #[test]
    fn ouvrir_store_cree_les_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let chemin = tmp.path().join("sous/dossier/sentinel.db");
        let store = ouvrir_store(Some(&chemin)).unwrap();
        assert!(chemin.exists());
        assert!(store.lister_serveurs().unwrap().is_empty());
    }
}
