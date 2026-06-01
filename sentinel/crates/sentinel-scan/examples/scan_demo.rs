//! Exemple de démo « scan qui se remplit » — Agent 1.10.
//!
//! Lance un scan en mode Fichier (fixture JSONL) et affiche les métriques.
//!
//! Usage :
//!   cargo run -p sentinel-scan --example scan_demo
//!
//! Pour surcharger le fichier de trafic :
//!   TRAFIC_JSONL=/chemin/vers/trafic.jsonl cargo run -p sentinel-scan --example scan_demo
//!
//! Pour scanner un serveur HTTP réel :
//!   MODE=http CIBLE=http://localhost:3000 ECOUTE=127.0.0.1:9090 \
//!     cargo run -p sentinel-scan --example scan_demo

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use sentinel_scan::demo::{executer_demo, ModeDemo};
use sentinel_scan::store_contract::MockStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise un logger minimal via la macro tracing (pas de dépendance
    // supplémentaire : les spans sont émises sur stderr par le collecteur no-op
    // par défaut, les lignes info! apparaissent si RUST_LOG est configuré).
    // Pour un affichage complet : RUST_LOG=info cargo run --example scan_demo

    let debut = Instant::now();

    let mode = construire_mode_depuis_env();

    tracing::info!("[DÉMO] démarrage du scan…");

    let store = Arc::new(MockStore::nouveau());
    let metriques = executer_demo(mode, store).await?;

    let duree_totale_ms = debut.elapsed().as_millis();

    // Rapport de démo.
    println!();
    println!("=== Rapport de démo Sentinel MCP ===");
    println!("  Serveurs découverts : {}", metriques.serveurs_decouverts);
    println!("  Outils découverts   : {}", metriques.outils_decouverts);
    match metriques.time_to_first_red_ms {
        Some(ms) => {
            println!("  Time-to-first-red   : {ms} ms");
            if ms < 5_000 {
                println!("  Objectif (<5 000 ms): ATTEINT");
            } else {
                println!("  Objectif (<5 000 ms): DEPASSE");
            }
        }
        None => {
            println!("  Time-to-first-red   : (aucun serveur à risque détecté)");
        }
    }
    println!("  Durée totale        : {duree_totale_ms} ms");
    println!("=====================================");

    Ok(())
}

fn construire_mode_depuis_env() -> ModeDemo {
    let mode_env = std::env::var("MODE").unwrap_or_else(|_| "fichier".to_string());

    match mode_env.to_lowercase().as_str() {
        "http" => {
            let cible = std::env::var("CIBLE").unwrap_or_else(|_| "http://localhost:3000".to_string());
            let ecoute: SocketAddr = std::env::var("ECOUTE")
                .unwrap_or_else(|_| "127.0.0.1:9090".to_string())
                .parse()
                .expect("ECOUTE doit être une adresse valide (ex. 127.0.0.1:9090)");
            tracing::info!(%ecoute, %cible, "mode HTTP — proxy passif");
            ModeDemo::Http(ecoute, cible)
        }
        "stdio" => {
            let programme = std::env::var("PROGRAMME")
                .expect("PROGRAMME requis en mode stdio (ex. node serveur-mcp.js)");
            let args: Vec<String> = std::env::var("ARGS")
                .unwrap_or_default()
                .split_whitespace()
                .map(String::from)
                .collect();
            tracing::info!(%programme, "mode stdio — wrapper");
            ModeDemo::Stdio(programme, args)
        }
        _ => {
            // Mode par défaut : lecture de la fixture.
            let chemin = std::env::var("TRAFIC_JSONL")
                .map(PathBuf::from)
                .unwrap_or_else(|_| fixture_defaut());
            tracing::info!(chemin = ?chemin, "mode fichier — lecture fixture JSONL");
            ModeDemo::Fichier(chemin)
        }
    }
}

fn fixture_defaut() -> PathBuf {
    let candidats = [
        PathBuf::from("crates/sentinel-scan/tests/fixtures/trafic_demo.jsonl"),
        PathBuf::from("tests/fixtures/trafic_demo.jsonl"),
    ];
    for c in &candidats {
        if c.exists() {
            return c.clone();
        }
    }
    candidats[0].clone()
}
