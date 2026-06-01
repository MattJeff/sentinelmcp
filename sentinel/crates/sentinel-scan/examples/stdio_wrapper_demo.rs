//! Démonstration du wrapper stdio de Sentinel MCP.
//!
//! Lance un faux serveur MCP (script sh) qui émet quelques messages JSON-RPC,
//! puis affiche les `EvenementBrut` captés sur la console.
//!
//! Utilisation :
//!   cargo run -p sentinel-scan --example stdio_wrapper_demo

use sentinel_protocol::EvenementBrut;
use sentinel_scan::stdio::WrapperStdio;
use tokio::sync::mpsc;

/// Script sh simulant un serveur MCP minimaliste.
/// Il émet :
///   1. Une notification d'initialisation.
///   2. Une réponse à tools/list avec deux outils fictifs.
///   3. Une ligne non-JSON (comme un log applicatif).
///   4. Une réponse à un tools/call.
const FAUX_SERVEUR_SCRIPT: &str = r#"
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"lire_fichier","description":"Lit le contenu d un fichier","inputSchema":{"type":"object","properties":{"chemin":{"type":"string"}}}},{"name":"ecrire_fichier","description":"Ecrit dans un fichier","inputSchema":{"type":"object","properties":{"chemin":{"type":"string"},"contenu":{"type":"string"}}}}]}}'
printf '%s\n' '[INFO] serveur mcp pret'
printf '%s\n' '{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Contenu du fichier demo.txt"}]}}'
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Sentinel MCP — Démonstration du wrapper stdio ===");
    println!();

    // Création du channel qui recevra les événements.
    let (tx, mut rx) = mpsc::channel::<EvenementBrut>(64);

    // Création du wrapper avec le faux serveur.
    let wrapper = WrapperStdio::nouveau(
        "sh",
        vec!["-c".to_string(), FAUX_SERVEUR_SCRIPT.to_string()],
        tx,
    );

    println!("Lancement du faux serveur MCP (script sh)...");
    println!();

    // On lance le wrapper dans une tâche séparée pour pouvoir
    // consommer le channel en parallèle.
    let handle = tokio::spawn(async move { wrapper.executer().await });

    // Collecte et affichage des événements.
    let mut compteur = 0usize;
    while let Some(evt) = rx.recv().await {
        compteur += 1;
        afficher_evenement(compteur, &evt);
    }

    let code = handle.await??;
    println!();
    println!("--- Résumé ---");
    println!("Événements captés    : {}", compteur);
    println!("Code de sortie       : {}", code);
    println!("Transport            : stdio");
    println!();
    println!("Note : les lignes non-JSON ont été ignorées sans interrompre le relais.");
    println!("Note : les params.arguments de tools/call ne sont jamais persistés.");

    Ok(())
}

/// Affiche un événement de manière lisible.
fn afficher_evenement(n: usize, evt: &EvenementBrut) {
    println!("[Événement #{n}]");
    println!("  Session      : {}", evt.session_id);
    println!("  Transport    : {:?}", evt.transport);
    println!("  Direction    : {:?}", evt.direction);
    println!("  Méthode      : {:?}", evt.methode);
    println!("  Horodatage   : {}", evt.horodatage.format("%H:%M:%S%.3f"));

    // Affichage du payload tronqué pour la lisibilité.
    let payload_str = serde_json::to_string_pretty(&evt.payload)
        .unwrap_or_else(|_| "<erreur de sérialisation>".to_string());
    let tronque = if payload_str.len() > 200 {
        format!("{}... (tronqué)", &payload_str[..200])
    } else {
        payload_str
    };
    println!("  Payload      : {}", tronque);
    println!();
}
