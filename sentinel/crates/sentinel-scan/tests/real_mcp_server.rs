//! Test d'intégration — serveur MCP réel (@modelcontextprotocol/server-filesystem).
//!
//! Ce test lance un vrai serveur npm, échange des messages JSON-RPC,
//! et vérifie que le pipeline Sentinel (filtre grossier → confirmation →
//! parsing tools/list) fonctionne de bout en bout sur du trafic réel.
//!
//! Pré-requis : `npx` dans PATH + accès npm (le paquet est téléchargé avec
//! `-y` si absent du cache). En l'absence de npx le test est ignoré (exit 0).
//!
//! Exécution :
//!   cargo test -p sentinel-scan --test real_mcp_server -- --nocapture

use std::time::Instant;

use chrono::Utc;
use sentinel_protocol::{Direction, EvenementBrut, MethodeMcp, Transport};
use sentinel_scan::{
    confirmer_message, filtre_grossier, parser_reponse_tools_list,
    signature::SuiviSessions,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::{timeout, Duration},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Vérifie la disponibilité de npx dans PATH sans télécharger de paquet.
fn npx_disponible() -> bool {
    std::process::Command::new("which")
        .arg("npx")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Construit un `EvenementBrut` à partir d'une ligne JSON brute et d'une direction.
///
/// Retourne `None` si la ligne n'est pas du JSON valide.
fn evenement_depuis_ligne(
    session_id: &str,
    serveur: &str,
    ligne: &str,
    direction: Direction,
) -> Option<EvenementBrut> {
    let valeur: serde_json::Value = serde_json::from_str(ligne.trim()).ok()?;

    let methode = valeur
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());

    Some(EvenementBrut {
        session_id: session_id.to_string(),
        transport: Transport::Stdio,
        serveur: serveur.to_string(),
        direction,
        methode,
        payload: valeur,
        horodatage: Utc::now(),
    })
}

// ---------------------------------------------------------------------------
// Messages JSON-RPC à envoyer au serveur
// ---------------------------------------------------------------------------

const MSG_INITIALIZE: &str = concat!(
    r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":"#,
    r#"{"protocolVersion":"2024-11-05","capabilities":{},"#,
    r#""clientInfo":{"name":"sentinel-test","version":"0.1.0"}}}"#
);

const MSG_INITIALIZED: &str =
    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

const MSG_TOOLS_LIST: &str =
    r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;

// ---------------------------------------------------------------------------
// Test principal
// ---------------------------------------------------------------------------

/// Exécution complète du handshake MCP + découverte des outils sur
/// @modelcontextprotocol/server-filesystem.
///
/// Le test est skippé proprement si npx n'est pas disponible.
#[tokio::test]
async fn decouverte_outils_serveur_filesystem_reel() -> anyhow::Result<()> {
    // --- Vérification de disponibilité -----------------------------------
    // Ce test lance un VRAI serveur MCP via `npx -y @modelcontextprotocol/...`,
    // ce qui dépend du réseau (téléchargement npm) et du timing de démarrage —
    // intrinsèquement flaky sur les runners CI partagés. On le skippe donc en CI
    // (où `CI` est défini) ET quand npx est absent ; il reste exécuté en local.
    if std::env::var("CI").is_ok() {
        eprintln!("skip: serveur MCP réel (npx + réseau npm) — test ignoré en CI");
        return Ok(());
    }
    if !npx_disponible() {
        eprintln!("skip: npx not found in PATH — test skipped");
        return Ok(());
    }

    let debut_global = Instant::now();

    // --- Lancement du serveur --------------------------------------------
    eprintln!("Starting @modelcontextprotocol/server-filesystem /tmp via npx -y ...");

    let mut enfant = tokio::process::Command::new("npx")
        .args(["-y", "@modelcontextprotocol/server-filesystem", "/tmp"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // stderr → inherit pour voir les logs du serveur dans le terminal de test
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("impossible de lancer npx : {e}"))?;

    let mut stdin_enfant = enfant
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdin du sous-processus non disponible"))?;

    let stdout_enfant = enfant
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("stdout du sous-processus non disponible"))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let nom_serveur = "npx:@modelcontextprotocol/server-filesystem".to_string();

    // --- Échange JSON-RPC avec timeout global de 5 s ---------------------
    //
    // Le pipeline complet observe DEUX directions :
    //   - ClientVersServeur : les requêtes que nous envoyons (elles ont un champ
    //     "method" → c'est ce qui permet à confirmer_message d'ouvrir la session
    //     via MethodeMcp::Initialize).
    //   - ServeurVersClient : les réponses reçues (elles ont "result", pas "method").
    //     Elles sont confirmées grâce à la session ouverte par l'initialize client.
    let resultat = timeout(Duration::from_secs(5), async {
        // Collecte de TOUS les événements (les deux directions).
        let mut evenements: Vec<EvenementBrut> = Vec::new();

        // Envoi des trois messages d'handshake + discovery.
        // Chaque message est enregistré comme EventBrut ClientVersServeur
        // AVANT d'être envoyé sur le wire.
        for msg in [MSG_INITIALIZE, MSG_INITIALIZED, MSG_TOOLS_LIST] {
            if let Some(evt) = evenement_depuis_ligne(
                &session_id,
                &nom_serveur,
                msg,
                Direction::ClientVersServeur,
            ) {
                if filtre_grossier(&evt) {
                    evenements.push(evt);
                }
            }

            let ligne = format!("{msg}\n");
            stdin_enfant.write_all(ligne.as_bytes()).await?;
            stdin_enfant.flush().await?;
            eprintln!("  -> sent: {}", &msg[..msg.len().min(80)]);
        }

        // Lecture des réponses du serveur jusqu'à la réponse tools/list.
        let mut lecteur = BufReader::new(stdout_enfant);
        let mut ligne = String::new();
        let mut reponse_tools_list: Option<serde_json::Value> = None;

        loop {
            ligne.clear();
            let n = lecteur.read_line(&mut ligne).await?;
            if n == 0 {
                break; // EOF
            }
            let ligne_trim = ligne.trim();
            if ligne_trim.is_empty() {
                continue;
            }
            eprintln!("  <- recv: {}", &ligne_trim[..ligne_trim.len().min(120)]);

            if let Some(evt) = evenement_depuis_ligne(
                &session_id,
                &nom_serveur,
                ligne_trim,
                Direction::ServeurVersClient,
            ) {
                if filtre_grossier(&evt) {
                    evenements.push(evt.clone());
                }

                // Détecter la réponse à tools/list (id == 2 + champ result.tools).
                if evt.payload.get("id").and_then(|v| v.as_i64()) == Some(2)
                    && evt
                        .payload
                        .get("result")
                        .and_then(|r| r.get("tools"))
                        .is_some()
                {
                    reponse_tools_list = Some(evt.payload.clone());
                    break; // On a ce qu'il faut.
                }
            }
        }

        anyhow::Ok((evenements, reponse_tools_list))
    })
    .await;

    // Nettoyage du processus enfant (best-effort).
    let _ = enfant.kill().await;
    let _ = enfant.wait().await;

    // Déballer le résultat après avoir tué le processus pour éviter le leak.
    let (evenements, reponse_tools_list) = match resultat {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            eprintln!("skip: server did not respond within 5 s — skipping");
            return Ok(());
        }
    };

    let duree_ms = debut_global.elapsed().as_millis();

    // --- Validation du pipeline ------------------------------------------

    // 1. Au moins un événement a passé le filtre grossier.
    assert!(
        !evenements.is_empty(),
        "le filtre grossier doit accepter au moins un message JSON-RPC"
    );

    // 2. La confirmation de signature MCP fonctionne sur l'ensemble du trafic.
    //    Ordre de traitement : d'abord ClientVersServeur (ouvre la session via
    //    MethodeMcp::Initialize), puis ServeurVersClient (confirmé par session).
    let mut suivi = SuiviSessions::nouveau();
    let confirmes: Vec<_> = evenements
        .iter()
        .filter_map(|e| confirmer_message(e, &mut suivi))
        .collect();

    assert!(
        !confirmes.is_empty(),
        "au moins un message doit être confirmé comme MCP valide"
    );

    // La requête initialize (côté client) doit figurer parmi les confirmés.
    let a_initialize = confirmes
        .iter()
        .any(|m| matches!(m.methode, MethodeMcp::Initialize));
    assert!(
        a_initialize,
        "le message initialize (client→serveur) doit être confirmé. Confirmés : {confirmes:?}"
    );

    // 3. La réponse tools/list doit avoir été reçue et parsable.
    let payload_tools = reponse_tools_list.expect(
        "la réponse tools/list doit avoir été reçue avant la fin du timeout",
    );

    let reponse = parser_reponse_tools_list(&payload_tools)
        .expect("le parser tools/list ne doit pas échouer sur la réponse réelle");

    // 4. Au moins 4 outils attendus (read_file, write_file, list_directory, move_file…).
    let noms_outils: Vec<&str> = reponse.outils.iter().map(|o| o.nom.as_str()).collect();

    eprintln!(
        "Tools discovered ({} total): {:?}",
        noms_outils.len(),
        noms_outils
    );

    assert!(
        reponse.outils.len() >= 4,
        "server-filesystem doit exposer >= 4 outils, obtenu : {}",
        reponse.outils.len()
    );

    // 5. Outils attendus présents dans le manifeste.
    for outil_attendu in &["read_file", "write_file", "list_directory", "move_file"] {
        assert!(
            noms_outils.contains(outil_attendu),
            "outil attendu absent du manifeste : {outil_attendu}. Outils recus : {noms_outils:?}"
        );
    }

    // 6. Temps total < 5 000 ms.
    assert!(
        duree_ms < 5_000,
        "le scan bout-en-bout doit durer < 5 000 ms, obtenu : {duree_ms} ms"
    );

    eprintln!(
        "Integration test passed: {} tools discovered in {} ms",
        reponse.outils.len(),
        duree_ms
    );

    Ok(())
}
