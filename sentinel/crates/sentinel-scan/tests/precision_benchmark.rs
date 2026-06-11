//! Banc de mesure du taux de faux positifs et du débit — Agent 1.8.
//!
//! Exécuter avec :
//!   cargo test -p sentinel-scan precision_benchmark -- --nocapture

use sentinel_scan::precision::{BancMesure, filtre_combine};
use sentinel_scan::{filtre_grossier, confirmer_message, SuiviSessions};
use sentinel_protocol::EvenementBrut;

// ------------------------------------------------------------------ //
// Test 1 — taille minimale du corpus                                  //
// ------------------------------------------------------------------ //

/// Vérifie que `jeu_par_defaut` contient au moins 30 messages MCP et 30 leurres.
#[test]
fn test_corpus_taille_minimale() {
    let banc = BancMesure::jeu_par_defaut();

    let nb_mcp = banc.corpus_mcp.len();
    let nb_leurre = banc.corpus_leurre.len();

    println!("[corpus] {} messages MCP, {} leurres", nb_mcp, nb_leurre);

    assert!(
        nb_mcp >= 30,
        "le corpus MCP doit contenir ≥ 30 messages, seulement {} trouvés",
        nb_mcp
    );
    assert!(
        nb_leurre >= 30,
        "le corpus leurres doit contenir ≥ 30 messages, seulement {} trouvés",
        nb_leurre
    );
}

// ------------------------------------------------------------------ //
// Test 2 — F1 ≥ 0.95 sur filtre grossier + confirmation             //
// ------------------------------------------------------------------ //

/// Le pipeline complet (filtre grossier + confirmation sans session) doit
/// atteindre un score F1 ≥ 0.95 sur le corpus contrôlé.
#[test]
fn test_pipeline_f1_superieur_095() {
    let banc = BancMesure::jeu_par_defaut();

    let rapport = banc.evaluer(filtre_combine);

    println!(
        "[f1] VP={} FP={} FN={} VN={} | précision={:.3} rappel={:.3} F1={:.3} | débit={:.0} msg/s",
        rapport.vrais_positifs,
        rapport.faux_positifs,
        rapport.faux_negatifs,
        rapport.vrais_negatifs,
        rapport.precision(),
        rapport.rappel(),
        rapport.f1(),
        rapport.debit_msg_par_sec,
    );

    assert!(
        rapport.f1() >= 0.95,
        "F1={:.3} < 0.95 — pipeline trop imprécis",
        rapport.f1()
    );
}

// ------------------------------------------------------------------ //
// Test 3 — débit filtre grossier ≥ 100 000 msg/s sur un thread      //
// ------------------------------------------------------------------ //

/// Mesure le débit du filtre grossier seul sur un thread unique.
/// Objectif : > 100 000 msg/s (la cible réelle est ≥ 1 M msg/s ; on fixe
/// 100 k comme seuil CI conservateur). On garde la meilleure de plusieurs
/// mesures pour neutraliser la contention quand toute la suite tourne en
/// parallèle (`cargo test --workspace`).
#[test]
fn test_debit_filtre_grossier_100k_msg_par_sec() {
    use std::time::Instant;

    let banc = BancMesure::jeu_par_defaut();

    // Mélange corpus MCP + leurres pour un trafic réaliste.
    let tous: Vec<&EvenementBrut> = banc
        .corpus_mcp
        .iter()
        .chain(banc.corpus_leurre.iter())
        .collect();

    // Répéter jusqu'à couvrir ≥ 100 000 appels.
    let repetitions: u64 = 2_000;
    let total = repetitions * tous.len() as u64;
    const ESSAIS: usize = 5;
    const SEUIL: f64 = 100_000.0;

    let mut meilleur: f64 = 0.0;
    for essai in 1..=ESSAIS {
        let debut = Instant::now();
        let mut compteur: u64 = 0;
        for _ in 0..repetitions {
            for evt in &tous {
                if filtre_grossier(evt) {
                    compteur += 1;
                }
            }
        }
        let duree = debut.elapsed();

        let msgs_par_sec = total as f64 / duree.as_secs_f64();
        meilleur = meilleur.max(msgs_par_sec);

        println!(
            "[débit] essai {}/{} : {} appels en {:.2?} → {:.0} msg/s ({} acceptés)",
            essai, ESSAIS, total, duree, msgs_par_sec, compteur
        );

        if msgs_par_sec >= SEUIL {
            return;
        }
    }

    panic!(
        "débit filtre grossier {:.0} msg/s < {:.0} msg/s après {} essais",
        meilleur, SEUIL, ESSAIS
    );
}

// ------------------------------------------------------------------ //
// Test 4 — piège LSP : rejeté par la confirmation                    //
// ------------------------------------------------------------------ //

/// Démontre que des messages LSP (JSON-RPC 2.0 mais non-MCP) passent le
/// filtre grossier (ils contiennent bien "jsonrpc":"2.0") mais sont rejetés
/// par la confirmation, qui n'accepte que les méthodes MCP connues.
#[test]
fn test_lsp_rejete_par_confirmation() {
    use chrono::Utc;
    use sentinel_protocol::{Direction, EvenementBrut, Transport};
    use serde_json::json;

    // Méthodes LSP qui passent le filtre grossier (JSON-RPC 2.0 valide).
    let messages_lsp = vec![
        EvenementBrut {
            session_id: "lsp-session".to_string(),
            transport: Transport::Http,
            serveur: "lsp-server:2087".to_string(),
            direction: Direction::ClientVersServeur,
            methode: Some("textDocument/hover".to_string()),
            payload: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "textDocument/hover",
                "params": {
                    "textDocument": { "uri": "file:///src/main.rs" },
                    "position": { "line": 5, "character": 8 }
                }
            }),
            horodatage: Utc::now(),
        },
        EvenementBrut {
            session_id: "lsp-session".to_string(),
            transport: Transport::Http,
            serveur: "lsp-server:2087".to_string(),
            direction: Direction::ClientVersServeur,
            methode: Some("textDocument/completion".to_string()),
            payload: json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "textDocument/completion",
                "params": {
                    "textDocument": { "uri": "file:///src/lib.rs" },
                    "position": { "line": 20, "character": 4 }
                }
            }),
            horodatage: Utc::now(),
        },
        EvenementBrut {
            session_id: "lsp-session".to_string(),
            transport: Transport::Stdio,
            serveur: "rust-analyzer".to_string(),
            direction: Direction::ClientVersServeur,
            methode: Some("workspace/symbol".to_string()),
            payload: json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "workspace/symbol",
                "params": { "query": "BancMesure" }
            }),
            horodatage: Utc::now(),
        },
    ];

    let mut suivi = SuiviSessions::nouveau();

    for msg in &messages_lsp {
        // Étape 1 : le filtre grossier accepte (JSON-RPC 2.0 valide).
        let passe_grossier = filtre_grossier(msg);
        assert!(
            passe_grossier,
            "le filtre grossier doit accepter le message LSP '{}' (JSON-RPC 2.0 valide)",
            msg.methode.as_deref().unwrap_or("?")
        );

        // Étape 2 : la confirmation rejette (méthode non reconnue par MCP).
        let confirme = confirmer_message(msg, &mut suivi);
        assert!(
            confirme.is_none(),
            "la confirmation ne doit PAS accepter le message LSP '{}' sans session MCP ouverte",
            msg.methode.as_deref().unwrap_or("?")
        );
    }

    println!(
        "[lsp] {} messages LSP : tous passent le filtre grossier, tous rejetés par la confirmation",
        messages_lsp.len()
    );
}
