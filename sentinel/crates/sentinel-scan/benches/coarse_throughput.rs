//! Bench de débit du filtre grossier (agent 1.4).
//!
//! Exécution : `cargo bench -p sentinel-scan --bench coarse_throughput`
//!
//! Ce bench n'utilise pas Criterion (absent des dépendances workspace) ;
//! il mesure directement le temps écoulé via `std::time::Instant` et
//! affiche le débit en messages par seconde. Il échoue si le débit
//! mesuré tombe sous 1 M msg/s, seuil fixé par l'agent 1.8.

use sentinel_scan::signature::coarse::filtre_grossier_bytes;
use std::time::Instant;

/// Corpus synthétique représentant un trafic mixte réaliste.
/// Ratio 1:1 MCP valide / trafic non pertinent.
fn construire_corpus() -> Vec<Vec<u8>> {
    let messages_mcp = vec![
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{"cmd":"ls"}}}"#.to_vec(),
        br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#.to_vec(),
        br#"{"jsonrpc":"2.0","id":4,"result":{"tools":[{"name":"read_file","description":"Read a file","inputSchema":{"type":"object"}}]}}"#.to_vec(),
    ];

    let messages_non_mcp = vec![
        b"GET /health HTTP/1.1\r\nHost: mcp.internal\r\n\r\n".to_vec(),
        br#"{"event":"metric","source":"agent","value":42,"ts":1700000000}"#.to_vec(),
        br#"{"type":"heartbeat","version":"1.0","uptime":3600}"#.to_vec(),
        b"POST /api/v2/deploy HTTP/1.1\r\nContent-Type: application/json\r\n".to_vec(),
        br#"{"status":"ok","code":200,"data":{"servers":["a","b"]}}"#.to_vec(),
    ];

    let mut corpus = Vec::with_capacity(messages_mcp.len() + messages_non_mcp.len());
    corpus.extend(messages_mcp);
    corpus.extend(messages_non_mcp);
    corpus
}

fn main() {
    let corpus = construire_corpus();
    let nombre_messages = corpus.len();

    // Chauffe : 100 000 itérations pour remplir les caches CPU.
    for _ in 0..100_000 {
        for msg in &corpus {
            std::hint::black_box(filtre_grossier_bytes(msg));
        }
    }

    // Mesure : 5 M appels au total (500 000 × 10 messages).
    let iterations: u64 = 500_000;
    let total_appels = iterations * nombre_messages as u64;

    let debut = Instant::now();
    let mut acceptes: u64 = 0;
    for _ in 0..iterations {
        for msg in &corpus {
            if filtre_grossier_bytes(std::hint::black_box(msg)) {
                acceptes += 1;
            }
        }
    }
    let duree = debut.elapsed();

    let msgs_par_seconde = total_appels as f64 / duree.as_secs_f64();
    let ns_par_msg = duree.as_nanos() as f64 / total_appels as f64;

    println!("╔══════════════════════════════════════════╗");
    println!("║  Bench filtre_grossier_bytes             ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║  Messages totaux  : {:>18} ║", total_appels);
    println!("║  Acceptés         : {:>18} ║", acceptes);
    println!("║  Durée            : {:>15.2?}    ║", duree);
    println!("║  Débit            : {:>12.0} msg/s ║", msgs_par_seconde);
    println!("║  Latence          : {:>13.1} ns/msg ║", ns_par_msg);
    println!("╚══════════════════════════════════════════╝");

    // Seuil de performance non négociable (agent 1.8).
    let seuil = 1_000_000.0_f64;
    if msgs_par_seconde < seuil {
        eprintln!(
            "ECHEC : débit {:.0} msg/s < seuil {:.0} msg/s",
            msgs_par_seconde, seuil
        );
        std::process::exit(1);
    } else {
        println!("OK : seuil 1 M msg/s respecté.");
    }
}
