//! Exemple — scan d'un vrai serveur MCP (@modelcontextprotocol/server-filesystem).
//!
//! Exécution :
//!   cargo run -p sentinel-scan --example scan_real_mcp
//!
//! Variables d'environnement optionnelles :
//!   SENTINEL_DIR   répertoire exposé au serveur filesystem (défaut : /tmp)
//!   RUST_LOG       niveau de log tracing (défaut : info)
//!
//! Le binaire affiche :
//!   - chaque message JSON-RPC capturé (filtre grossier + confirmation)
//!   - la liste des outils découverts
//!   - le temps écoulé

use std::time::Instant;

use chrono::Utc;
use sentinel_protocol::{Direction, EvenementBrut, Transport};
use sentinel_scan::{
    confirmer_message, filtre_grossier, parser_reponse_tools_list,
    signature::SuiviSessions,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// ---------------------------------------------------------------------------
// Messages JSON-RPC
// ---------------------------------------------------------------------------

const MSG_INITIALIZE: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"#,
    r#"{"protocolVersion":"2024-11-05","capabilities":{},"#,
    r#""clientInfo":{"name":"sentinel-scan","version":"0.1.0"}}}"#
);

const MSG_INITIALIZED: &str =
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

const MSG_TOOLS_LIST: &str =
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evenement_depuis_ligne(session_id: &str, serveur: &str, ligne: &str) -> Option<EvenementBrut> {
    let valeur: serde_json::Value = serde_json::from_str(ligne.trim()).ok()?;
    let methode = valeur
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());
    Some(EvenementBrut {
        session_id: session_id.to_string(),
        transport: Transport::Stdio,
        serveur: serveur.to_string(),
        direction: Direction::ServeurVersClient,
        methode,
        payload: valeur,
        horodatage: Utc::now(),
    })
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=== Sentinel MCP — Real MCP Server Scan ===");
    println!();

    // Vérification de npx.
    let npx_ok = std::process::Command::new("which")
        .arg("npx")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !npx_ok {
        eprintln!("ERROR: npx not found in PATH — install Node.js to use this example");
        std::process::exit(1);
    }

    let repertoire = std::env::var("SENTINEL_DIR").unwrap_or_else(|_| "/tmp".to_string());
    println!("[info] Target directory: {repertoire}");

    let debut = Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();
    let nom_serveur = "npx:@modelcontextprotocol/server-filesystem".to_string();

    // --- Lancement du serveur --------------------------------------------
    println!("[info] Launching: npx -y @modelcontextprotocol/server-filesystem {repertoire}");
    println!("[info] (first run may download the package — this is expected)");
    println!();

    let mut enfant = tokio::process::Command::new("npx")
        .args(["-y", "@modelcontextprotocol/server-filesystem", &repertoire])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch npx: {e}"))?;

    let mut stdin_enfant = enfant
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stdin unavailable"))?;

    let stdout_enfant = enfant
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stdout unavailable"))?;

    // --- Envoi des messages d'handshake + discovery ----------------------
    println!("[capture] Starting JSON-RPC handshake...");
    for msg in [MSG_INITIALIZE, MSG_INITIALIZED, MSG_TOOLS_LIST] {
        let ligne = format!("{msg}\n");
        stdin_enfant.write_all(ligne.as_bytes()).await?;
        stdin_enfant.flush().await?;
        println!("  -> {}", &msg[..msg.len().min(100)]);
    }
    println!();

    // --- Lecture des réponses -------------------------------------------
    let mut lecteur = BufReader::new(stdout_enfant);
    let mut ligne = String::new();
    let mut suivi = SuiviSessions::nouveau();
    let mut nb_evenements = 0usize;
    let mut nb_confirmes = 0usize;
    let mut reponse_tools_list: Option<serde_json::Value> = None;

    println!("[capture] Reading server responses (timeout: 5 s)...");

    let resultat = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        async {
            loop {
                ligne.clear();
                let n = lecteur.read_line(&mut ligne).await?;
                if n == 0 {
                    break;
                }
                let ligne_trim = ligne.trim();
                if ligne_trim.is_empty() {
                    continue;
                }

                if let Some(evt) = evenement_depuis_ligne(&session_id, &nom_serveur, ligne_trim) {
                    if filtre_grossier(&evt) {
                        nb_evenements += 1;
                        println!(
                            "  [event #{nb_evenements}] coarse filter PASS | direction={:?} | methode={:?}",
                            evt.direction, evt.methode
                        );

                        if let Some(msg_confirme) = confirmer_message(&evt, &mut suivi) {
                            nb_confirmes += 1;
                            println!(
                                "  [confirm #{nb_confirmes}] MCP confirmed | methode={:?}",
                                msg_confirme.methode
                            );
                        }

                        // Capture de la réponse tools/list (id == 2 + result.tools).
                        if evt.payload.get("id").and_then(|v| v.as_i64()) == Some(2)
                            && evt
                                .payload
                                .get("result")
                                .and_then(|r| r.get("tools"))
                                .is_some()
                        {
                            reponse_tools_list = Some(evt.payload.clone());
                            println!("  [tools/list] Response received — stopping capture.");
                            break;
                        }
                    } else {
                        println!(
                            "  [event] coarse filter REJECT | {:?}",
                            &ligne_trim[..ligne_trim.len().min(60)]
                        );
                    }
                }
            }
            anyhow::Ok(())
        },
    )
    .await;

    // Nettoyage du processus.
    let _ = enfant.kill().await;
    let _ = enfant.wait().await;

    match resultat {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            eprintln!("[warn] Timeout reached after 5 s — server may be slow or offline");
        }
    }

    let duree_ms = debut.elapsed().as_millis();

    // --- Rapport ---------------------------------------------------------
    println!();
    println!("=== Sentinel MCP — Scan Report ===");
    println!("  Server           : {nom_serveur}");
    println!("  Session ID       : {session_id}");
    println!("  Events captured  : {nb_evenements}");
    println!("  Events confirmed : {nb_confirmes}");

    match reponse_tools_list {
        Some(payload) => {
            match parser_reponse_tools_list(&payload) {
                Ok(reponse) => {
                    println!("  Tools discovered : {}", reponse.outils.len());
                    println!();
                    for (i, outil) in reponse.outils.iter().enumerate() {
                        let desc = outil
                            .description
                            .as_deref()
                            .unwrap_or("(no description)");
                        let desc_court = &desc[..desc.len().min(70)];
                        println!("    [{:02}] {:30}  {}", i + 1, outil.nom, desc_court);
                    }
                }
                Err(e) => {
                    println!("  Tools discovered : (parse error: {e})");
                }
            }
        }
        None => {
            println!("  Tools discovered : (no tools/list response received)");
        }
    }

    println!();
    println!("  Elapsed          : {duree_ms} ms");
    if duree_ms < 5_000 {
        println!("  Target (<5 000 ms): ACHIEVED");
    } else {
        println!("  Target (<5 000 ms): EXCEEDED");
    }
    println!("==================================");

    Ok(())
}
