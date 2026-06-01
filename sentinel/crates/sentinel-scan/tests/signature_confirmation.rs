//! Tests de l'agent 1.5 — Confirmation de signature MCP.
//!
//! Six scénarios couvrent les chemins nominaux, les rejets de faux positifs
//! et le comportement de purge des sessions inactives.

use chrono::Utc;
use sentinel_protocol::{Direction, EvenementBrut, MethodeMcp, Transport};
use sentinel_scan::signature::confirm::{confirmer_message, InfoSession, SuiviSessions};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn evenement(session_id: &str, serveur: &str, methode: Option<&str>) -> EvenementBrut {
    let mut payload = serde_json::json!({ "jsonrpc": "2.0", "id": 1 });
    if let Some(m) = methode {
        payload["method"] = serde_json::Value::String(m.to_string());
    }
    EvenementBrut {
        session_id: session_id.to_string(),
        transport: Transport::Http,
        serveur: serveur.to_string(),
        direction: Direction::ClientVersServeur,
        methode: methode.map(|s| s.to_string()),
        payload,
        horodatage: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Test 1 : `initialize` → session ouverte
// ---------------------------------------------------------------------------

#[test]
fn initialize_ouvre_une_session() {
    let mut suivi = SuiviSessions::nouveau();
    let evt = evenement("sess-1", "mcp://serveur-a", Some("initialize"));

    let msg = confirmer_message(&evt, &mut suivi);

    assert!(msg.is_some(), "initialize doit être confirmé");
    assert_eq!(msg.unwrap().methode, MethodeMcp::Initialize);
    assert!(
        suivi.sessions_actives.contains_key("sess-1"),
        "la session doit être enregistrée"
    );
    assert!(
        suivi.sessions_actives["sess-1"].initialize_vu,
        "initialize_vu doit être vrai"
    );
}

// ---------------------------------------------------------------------------
// Test 2 : méthode JSON-RPC interne ("ping") hors session → rejetée
// ---------------------------------------------------------------------------
//
// `tools/call` est une méthode MCP connue : elle est confirmée même sans session.
// En revanche, "ping" n'est pas dans la liste MCP → rejeté hors session.

#[test]
fn ping_jsonrpc_hors_session_est_rejete() {
    let mut suivi = SuiviSessions::nouveau();
    // "ping" est JSON-RPC standard mais absent de la liste MCP reconnue.
    let evt = evenement("sess-inconnue", "autre-systeme", Some("ping"));

    let msg = confirmer_message(&evt, &mut suivi);

    assert!(
        msg.is_none(),
        "ping JSON-RPC hors session MCP doit être rejeté (anti faux positif)"
    );
}

// ---------------------------------------------------------------------------
// Test 3 : `tools/call` dans une session ouverte → accepté
// ---------------------------------------------------------------------------

#[test]
fn tools_call_dans_session_est_accepte() {
    let mut suivi = SuiviSessions::nouveau();

    // Ouvrir la session via initialize.
    let init = evenement("sess-2", "mcp://serveur-c", Some("initialize"));
    confirmer_message(&init, &mut suivi);

    // Envoyer tools/call dans la même session.
    let appel = evenement("sess-2", "mcp://serveur-c", Some("tools/call"));
    let msg = confirmer_message(&appel, &mut suivi);

    assert!(msg.is_some(), "tools/call dans une session ouverte doit être accepté");
    assert_eq!(msg.unwrap().methode, MethodeMcp::ToolsCall);
}

// ---------------------------------------------------------------------------
// Test 4 : réponse JSON-RPC sans champ `method` hors session → rejetée
// ---------------------------------------------------------------------------
//
// Un message de réponse (result/error) n'a pas de champ `method`.
// Hors session ouverte il ne peut pas être rattaché au protocole MCP → rejet.

#[test]
fn reponse_sans_methode_hors_session_est_rejetee() {
    let mut suivi = SuiviSessions::nouveau();
    // Réponse générique JSON-RPC 2.0, pas de méthode.
    let evt = EvenementBrut {
        session_id: "sess-orpheline".to_string(),
        transport: Transport::Http,
        serveur: "autre-systeme".to_string(),
        direction: Direction::ServeurVersClient,
        methode: None,
        payload: serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": {} }),
        horodatage: Utc::now(),
    };

    let msg = confirmer_message(&evt, &mut suivi);

    assert!(
        msg.is_none(),
        "réponse sans méthode hors session doit être rejetée"
    );
}

// ---------------------------------------------------------------------------
// Test 5 : méthode inconnue dans une session ouverte → acceptée
// ---------------------------------------------------------------------------

#[test]
fn methode_inconnue_dans_session_est_acceptee() {
    let mut suivi = SuiviSessions::nouveau();

    // Ouvrir la session.
    let init = evenement("sess-4", "mcp://serveur-d", Some("initialize"));
    confirmer_message(&init, &mut suivi);

    // Méthode inconnue dans cette session (extension propriétaire).
    let evt = evenement("sess-4", "mcp://serveur-d", Some("vendor/custom_method"));
    let msg = confirmer_message(&evt, &mut suivi);

    assert!(
        msg.is_some(),
        "méthode inconnue dans une session ouverte doit être acceptée"
    );
    assert!(
        matches!(msg.unwrap().methode, MethodeMcp::Autre(_)),
        "la méthode doit être classifiée Autre"
    );
}

// ---------------------------------------------------------------------------
// Test 6 : purger_inactives supprime les sessions expirées
// ---------------------------------------------------------------------------

#[test]
fn purge_supprime_les_sessions_inactives() {
    let mut suivi = SuiviSessions::nouveau();

    // Insérer manuellement une session avec une dernière activité ancienne.
    let ancienne = chrono::Utc::now() - chrono::Duration::seconds(3600);
    suivi.sessions_actives.insert(
        "sess-vieille".to_string(),
        InfoSession {
            serveur: "mcp://vieux-serveur".to_string(),
            ouverte_a: ancienne,
            initialize_vu: true,
            derniere_activite: ancienne,
        },
    );

    // Insérer une session récente.
    suivi.marquer_initialize("sess-recente", "mcp://nouveau-serveur");

    assert_eq!(suivi.sessions_actives.len(), 2);

    // Purger avec max_age de 10 minutes.
    suivi.purger_inactives(Duration::from_secs(600));

    assert_eq!(
        suivi.sessions_actives.len(),
        1,
        "la session ancienne doit être purgée"
    );
    assert!(
        suivi.sessions_actives.contains_key("sess-recente"),
        "la session récente doit survivre"
    );
    assert!(
        !suivi.sessions_actives.contains_key("sess-vieille"),
        "la session ancienne ne doit plus exister"
    );
}
