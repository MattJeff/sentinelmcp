//! `sentinel metrics` — exposition Prometheus des compteurs du store.
//!
//! Imprime sur stdout le format texte d'exposition Prometheus
//! (`text/plain; version=0.0.4`), directement scrappable par un *textfile
//! collector* (node_exporter) ou un `curl | promtool`. Les compteurs
//! proviennent du store SQLite en lecture seule (serveurs, outils, constats,
//! alertes, répartitions par couleur/type/sévérité) via le module
//! `sentinel_alerts::metrics`. Aucune dépendance réseau, sortie déterministe.

use anyhow::Result;
use std::path::PathBuf;

use sentinel_alerts::{rendre_prometheus, Metriques};
use sentinel_store::Store;

use crate::db::ouvrir_store;
use crate::sortie::{imprimer, CodeSortie};

/// Construit le texte d'exposition Prometheus à partir des compteurs lus
/// dans le store. Lecture seule : sûr à interroger en continu par un scraper.
///
/// Les champs runtime (latence des canaux d'alerte, taille de déduplication)
/// ne sont pas disponibles depuis un processus CLI éphémère et restent donc
/// à zéro — seuls les compteurs persistés sont exportés.
pub fn construire_export(store: &Store) -> Result<String> {
    let stats = store.stats_metriques()?;
    let metriques = Metriques::depuis_stats_store(&stats);
    Ok(rendre_prometheus(&metriques))
}

pub fn executer(db: Option<PathBuf>, quiet: bool) -> Result<CodeSortie> {
    let store = ouvrir_store(db.as_deref())?;
    let export = construire_export(&store)?;
    imprimer(quiet, &export);
    // L'export de métriques est purement informatif : il ne signale aucun
    // constat de sévérité et termine donc toujours en code 0 (sauf erreur).
    Ok(CodeSortie::Aucun)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_store::Store;

    #[test]
    fn export_prometheus_valide_sur_un_store_vierge() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path().join("sentinel.db")).unwrap();
        let texte = construire_export(&store).unwrap();

        // En-têtes HELP/TYPE attendus du format d'exposition Prometheus.
        assert!(texte.contains("# HELP sentinel_db_servers_total"));
        assert!(texte.contains("# TYPE sentinel_db_servers_total gauge"));
        assert!(texte.contains("# TYPE sentinel_alerts_total counter"));

        // Store vierge : les compteurs persistés sont à zéro mais présents.
        assert!(texte.contains("sentinel_db_servers_total 0"));
        assert!(texte.contains("sentinel_db_tools_total 0"));
        assert!(texte.contains("sentinel_db_findings_total 0"));
        assert!(texte.contains("sentinel_db_alerts_total 0"));
    }

    #[test]
    fn export_est_deterministe() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path().join("sentinel.db")).unwrap();
        let a = construire_export(&store).unwrap();
        let b = construire_export(&store).unwrap();
        assert_eq!(a, b, "l'export doit être reproductible");
    }
}
