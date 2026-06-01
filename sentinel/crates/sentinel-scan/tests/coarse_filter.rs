//! Tests d'intégration du filtre grossier (agent 1.4).
//!
//! Ces tests couvrent le trafic mixte réaliste que le capteur verra
//! en production : MCP valide, HTTP banal, JSON sans RPC, payloads
//! vides ou larges. Objectif : zéro faux négatif sur les cas MCP
//! normaux, rejet systématique du trafic non pertinent.

use chrono::Utc;
use sentinel_protocol::{Direction, EvenementBrut, Transport};
use sentinel_scan::signature::{filtre_grossier, coarse::filtre_grossier_bytes};
use serde_json::json;

// ------------------------------------------------------------------ //
// Utilitaire                                                          //
// ------------------------------------------------------------------ //

fn evenement(payload: serde_json::Value) -> EvenementBrut {
    EvenementBrut {
        session_id: "integ-session".to_string(),
        transport: Transport::Http,
        serveur: "mcp-server:8080".to_string(),
        direction: Direction::ClientVersServeur,
        methode: None,
        payload,
        horodatage: Utc::now(),
    }
}

// ------------------------------------------------------------------ //
// Tests filtre_grossier (EvenementBrut)                               //
// ------------------------------------------------------------------ //

/// Un message `initialize` MCP complet doit être accepté.
#[test]
fn integ_initialize_mcp_accepte() {
    let e = evenement(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test-agent", "version": "0.1" }
        }
    }));
    assert!(filtre_grossier(&e), "initialize MCP doit être accepté");
}

/// Un message `tools/list` doit être accepté.
#[test]
fn integ_tools_list_mcp_accepte() {
    let e = evenement(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }));
    assert!(filtre_grossier(&e), "tools/list MCP doit être accepté");
}

/// Une réponse `tools/list` (côté serveur, sans `method`) doit être acceptée.
#[test]
fn integ_reponse_tools_list_acceptee() {
    let e = evenement(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "bash",
                    "description": "Run a bash command",
                    "inputSchema": { "type": "object" }
                }
            ]
        }
    }));
    assert!(filtre_grossier(&e), "une réponse tools/list doit être acceptée");
}

/// Un événement JSON ordinaire (webhook Slack, par ex.) doit être rejeté.
#[test]
fn integ_webhook_slack_rejete() {
    let e = evenement(json!({
        "type": "message",
        "channel": "C0123ABCD",
        "user": "U0123ABCD",
        "text": "hello world",
        "ts": "1609459200.000100"
    }));
    assert!(!filtre_grossier(&e), "un webhook Slack doit être rejeté");
}

/// Un objet JSON vide doit être rejeté.
#[test]
fn integ_payload_vide_rejete() {
    let e = evenement(json!({}));
    assert!(!filtre_grossier(&e), "un payload vide doit être rejeté");
}

/// Une notification `notifications/tools/list_changed` doit être acceptée.
#[test]
fn integ_notification_list_changed_acceptee() {
    let e = evenement(json!({
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed"
    }));
    assert!(filtre_grossier(&e), "notifications/tools/list_changed doit être accepté");
}

// ------------------------------------------------------------------ //
// Tests filtre_grossier_bytes (octets bruts)                         //
// ------------------------------------------------------------------ //

/// Trafic HTTP banal (GET /health) — doit être rejeté.
#[test]
fn integ_http_get_rejete() {
    let raw = b"GET /health HTTP/1.1\r\nHost: mcp.internal\r\n\r\n";
    assert!(!filtre_grossier_bytes(raw), "trafic HTTP GET doit être rejeté");
}

/// Réponse HTTP 200 avec JSON non-RPC — doit être rejetée.
#[test]
fn integ_http_200_json_non_rpc_rejete() {
    let raw = br#"HTTP/1.1 200 OK
Content-Type: application/json

{"status":"healthy","uptime":3600}"#;
    assert!(!filtre_grossier_bytes(raw), "réponse HTTP 200 sans JSON-RPC doit être rejetée");
}

/// Message vide — doit être rejeté sans panic.
#[test]
fn integ_bytes_vides_rejetes() {
    assert!(!filtre_grossier_bytes(b""), "bytes vides doivent être rejetés");
}

/// JSON avec `jsonrpc` mais sans version `2.0` — doit être rejeté.
#[test]
fn integ_jsonrpc_sans_version_rejete() {
    let raw = br#"{"jsonrpc":"1.0","id":1,"method":"test"}"#;
    // "1.0" ne contient pas "2.0" donc rejeté
    assert!(!filtre_grossier_bytes(raw), "jsonrpc 1.0 doit être rejeté");
}

/// Gros payload UTF-8 avec séquences multi-octets — ne doit pas paniquer.
#[test]
fn integ_utf8_large_pas_de_panic() {
    // 64 Ko de caractères UTF-8 à deux octets
    let contenu = "ñ".repeat(32_768);
    let rpc = format!(r#"{{"jsonrpc":"2.0","method":"tools/list","data":"{}"}}"#, contenu);
    // Doit accepter sans crash
    assert!(filtre_grossier_bytes(rpc.as_bytes()));

    // Sans jsonrpc — doit rejeter sans crash
    let non_rpc = format!(r#"{{"data":"{}"}}"#, contenu);
    assert!(!filtre_grossier_bytes(non_rpc.as_bytes()));
}

/// JSON avec `jsonrpc` et `2.0` dans des contextes séparés non adjacents.
/// Ex : une clé `jsonrpc` dans un objet imbriqué éloigné de `2.0`.
#[test]
fn integ_jsonrpc_et_version_trop_eloignes_rejete() {
    // On construit un payload où jsonrpc est suivi de plus de 32 caractères
    // avant que "2.0" apparaisse.
    let remplissage = "a".repeat(40);
    let raw = format!(r#"{{"jsonrpc":"{}","version":"2.0"}}"#, remplissage);
    assert!(
        !filtre_grossier_bytes(raw.as_bytes()),
        "jsonrpc et 2.0 trop éloignés doivent être rejetés"
    );
}

/// Corpus mixte : vérifier les comptages acceptés/rejetés.
#[test]
fn integ_corpus_mixte_comptage() {
    let corpus: &[(&[u8], bool)] = &[
        (br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, true),
        (br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, true),
        (br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#, true),
        (b"GET /api/v1/status HTTP/1.1", false),
        (br#"{"event":"deploy","env":"prod","version":"2.0.1"}"#, false),
        (b"", false),
        (br#"{"type":"heartbeat","ts":1700000000}"#, false),
    ];

    let attendus_acceptes = corpus.iter().filter(|(_, attendu)| *attendu).count();
    let attendus_rejetes = corpus.iter().filter(|(_, attendu)| !*attendu).count();

    let mut acceptes = 0usize;
    let mut rejetes = 0usize;

    for (raw, attendu) in corpus {
        let resultat = filtre_grossier_bytes(raw);
        assert_eq!(
            resultat, *attendu,
            "résultat inattendu pour : {:?}",
            std::str::from_utf8(raw).unwrap_or("<binaire>")
        );
        if resultat { acceptes += 1; } else { rejetes += 1; }
    }

    assert_eq!(acceptes, attendus_acceptes);
    assert_eq!(rejetes, attendus_rejetes);
}
