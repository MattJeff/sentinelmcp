//! Tests d'intégration de la démo — Agent 1.10.
//!
//! Valide :
//! 1. Que le mode `Fichier` avec la fixture remplit le store (1 serveur, 2 outils).
//! 2. Que le time-to-first-red est inférieur à 5 000 ms sur ce scénario.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use sentinel_scan::demo::{executer_demo, ModeDemo};
use sentinel_scan::store_contract::MockStore;

/// Chemin vers la fixture JSONL.
fn chemin_fixture() -> PathBuf {
    // En contexte `cargo test`, le cwd est la racine du crate.
    let candidats = [
        PathBuf::from("tests/fixtures/trafic_demo.jsonl"),
        PathBuf::from("crates/sentinel-scan/tests/fixtures/trafic_demo.jsonl"),
    ];
    for c in &candidats {
        if c.exists() {
            return c.clone();
        }
    }
    candidats[0].clone()
}

/// Test 1 : mode Fichier → 1 serveur découvert, 2 outils dans le store.
#[tokio::test]
async fn test_mode_fichier_inventaire_complet() {
    let store = Arc::new(MockStore::nouveau());
    let store_clone = store.clone();

    let metriques = executer_demo(ModeDemo::Fichier(chemin_fixture()), store)
        .await
        .expect("la démo doit se terminer sans erreur");

    assert_eq!(
        metriques.serveurs_decouverts, 1,
        "exactement 1 serveur doit être découvert"
    );
    assert_eq!(
        metriques.outils_decouverts, 2,
        "exactement 2 outils doivent être découverts"
    );

    // Vérification dans le store.
    let inventaires = store_clone.inventaires.lock().unwrap();
    assert_eq!(
        inventaires.len(),
        1,
        "le store doit contenir exactement 1 événement d'inventaire"
    );
    assert_eq!(
        inventaires[0].outils.len(),
        2,
        "l'événement d'inventaire doit contenir 2 outils"
    );
    assert_eq!(
        inventaires[0].outils[0].nom, "read_file",
        "premier outil attendu : read_file"
    );
    assert_eq!(
        inventaires[0].outils[1].nom, "write_file",
        "deuxième outil attendu : write_file"
    );
}

/// Test 2 : time-to-first-red < 5 000 ms sur la fixture (portée Filesystem
/// déclenchée par `read_file` et `write_file`).
#[tokio::test]
async fn test_time_to_first_red_sous_5000ms() {
    let store = Arc::new(MockStore::nouveau());
    let debut = Instant::now();

    let metriques = executer_demo(ModeDemo::Fichier(chemin_fixture()), store)
        .await
        .expect("la démo doit se terminer sans erreur");

    let elapsed_ms = debut.elapsed().as_millis() as u64;

    // Le time-to-first-red doit être renseigné (portée Filesystem présente).
    let ttfr = metriques
        .time_to_first_red_ms
        .expect("time_to_first_red_ms doit être renseigné (outils Filesystem présents)");

    assert!(
        ttfr < 5_000,
        "time-to-first-red {ttfr} ms doit être < 5 000 ms"
    );

    assert!(
        elapsed_ms < 5_000,
        "durée totale {elapsed_ms} ms doit être < 5 000 ms"
    );
}
