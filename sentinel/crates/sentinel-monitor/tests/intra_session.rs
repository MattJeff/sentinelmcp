//! Tests d'intégration pour le détecteur intra-session (agent 2.4).

use chrono::Utc;
use sentinel_monitor::intra_session::{DetecteurIntraSession, SignalChangement};
use sentinel_protocol::{
    Baseline, Direction, Empreinte, MessageMcp, MethodeMcp, Transport,
};
use std::collections::BTreeMap;
use uuid::Uuid;

// ── Helpers ────────────────────────────────────────────────────────────────

fn baseline(empreinte: &str) -> Baseline {
    Baseline {
        id: Uuid::new_v4(),
        serveur_id: Uuid::new_v4(),
        empreinte_serveur: Empreinte::new(empreinte),
        empreintes_outils: BTreeMap::new(),
        outils: vec![],
        date_approbation: Utc::now(),
        approuve_par: "test".to_string(),
    }
}

fn message(methode: MethodeMcp, direction: Direction) -> MessageMcp {
    MessageMcp {
        session_id: "session-test".to_string(),
        transport: Transport::Http,
        serveur: "srv-test".to_string(),
        direction,
        methode,
        id_jsonrpc: None,
        payload: serde_json::Value::Null,
        horodatage: Utc::now(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// Cas 1 : notification officielle — `ToolsListChanged` présent, empreinte identique à la baseline.
#[test]
fn test_notification_officielle() {
    let b = baseline("aabbcc");
    let empreinte_identique = Empreinte::new("aabbcc");

    let messages = vec![
        message(MethodeMcp::ToolsListChanged, Direction::ServeurVersClient),
        message(MethodeMcp::ToolsList, Direction::ServeurVersClient),
    ];

    let signal = DetecteurIntraSession::evaluer(&messages, Some(&b), Some(&empreinte_identique));
    assert_eq!(signal, SignalChangement::NotificationOfficielle);
}

/// Cas 2 : changement silencieux — réponse `tools/list` sans `ToolsListChanged` préalable.
#[test]
fn test_changement_silencieux() {
    let b = baseline("aabbcc");
    let empreinte_identique = Empreinte::new("aabbcc");

    // Pas de ToolsListChanged dans la session, mais une réponse tools/list apparaît.
    let messages = vec![
        message(MethodeMcp::Initialize, Direction::ClientVersServeur),
        message(MethodeMcp::ToolsList, Direction::ServeurVersClient),
    ];

    let signal = DetecteurIntraSession::evaluer(&messages, Some(&b), Some(&empreinte_identique));
    assert_eq!(signal, SignalChangement::ChangementSilencieux);
}

/// Cas 3 : divergence d'empreinte — priorité maximale, même avec notification officielle.
#[test]
fn test_divergence_empreinte_prioritaire() {
    let b = baseline("aabbcc");
    let empreinte_differente = Empreinte::new("112233"); // diverge

    // Même si une notification officielle est présente, la divergence prend le dessus.
    let messages = vec![
        message(MethodeMcp::ToolsListChanged, Direction::ServeurVersClient),
        message(MethodeMcp::ToolsList, Direction::ServeurVersClient),
    ];

    let signal = DetecteurIntraSession::evaluer(&messages, Some(&b), Some(&empreinte_differente));
    assert_eq!(signal, SignalChangement::DivergenceEmpreinte);
}

/// Cas 4 : aucune divergence — session normale sans changement.
#[test]
fn test_aucune_divergence() {
    let b = baseline("aabbcc");
    let empreinte_identique = Empreinte::new("aabbcc");

    // Aucune notification, aucune réponse tools/list dans la session.
    let messages = vec![
        message(MethodeMcp::Initialize, Direction::ClientVersServeur),
        message(MethodeMcp::ToolsCall, Direction::ClientVersServeur),
    ];

    let signal = DetecteurIntraSession::evaluer(&messages, Some(&b), Some(&empreinte_identique));
    assert_eq!(signal, SignalChangement::Aucun);
}

/// Cas 5 : sans baseline — changement silencieux détecté quand même.
#[test]
fn test_sans_baseline_changement_silencieux() {
    let messages = vec![
        message(MethodeMcp::ToolsList, Direction::ServeurVersClient),
    ];

    let signal = DetecteurIntraSession::evaluer(&messages, None, None);
    assert_eq!(signal, SignalChangement::ChangementSilencieux);
}

/// Cas 6 : helper `diverge` — identité et différence.
#[test]
fn test_diverge_helper() {
    let b = baseline("cafebabe");
    assert!(!DetecteurIntraSession::diverge(&Empreinte::new("cafebabe"), &b));
    assert!(DetecteurIntraSession::diverge(&Empreinte::new("deadbeef"), &b));
}
