//! Tests d'intégration — Normalisateur d'événements (Agent 1.3).
//!
//! Commande : `cargo test -p sentinel-scan event_normalisation`

use sentinel_protocol::{Direction, Transport};
use sentinel_scan::event::Normaliseur;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn session() -> &'static str {
    "session-test-001"
}

fn serveur() -> &'static str {
    "localhost:3000"
}

// ---------------------------------------------------------------------------
// Test 1 — Requête JSON-RPC via stdio
// ---------------------------------------------------------------------------

#[test]
fn test_requete_stdio() {
    let ligne = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let evt = Normaliseur::depuis_ligne_stdio(ligne, session(), serveur(), Direction::ClientVersServeur)
        .expect("doit produire un événement pour une requête valide");

    assert_eq!(evt.session_id, session());
    assert_eq!(evt.transport, Transport::Stdio);
    assert_eq!(evt.serveur, serveur());
    assert_eq!(evt.direction, Direction::ClientVersServeur);
    assert_eq!(evt.methode.as_deref(), Some("tools/list"));
}

// ---------------------------------------------------------------------------
// Test 2 — Réponse JSON-RPC (pas de champ `method`)
// ---------------------------------------------------------------------------

#[test]
fn test_reponse_stdio_sans_methode() {
    let ligne = br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
    let evt = Normaliseur::depuis_ligne_stdio(ligne, session(), serveur(), Direction::ServeurVersClient)
        .expect("une réponse valide doit produire un événement");

    assert_eq!(evt.direction, Direction::ServeurVersClient);
    // Les réponses n'ont pas de champ `method`.
    assert!(evt.methode.is_none(), "une réponse JSON-RPC n'a pas de méthode");
}

// ---------------------------------------------------------------------------
// Test 3 — Notification via stdio
// ---------------------------------------------------------------------------

#[test]
fn test_notification_stdio() {
    let ligne = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    let evt = Normaliseur::depuis_ligne_stdio(ligne, session(), serveur(), Direction::ServeurVersClient)
        .expect("la notification doit être normalisée");

    assert_eq!(evt.methode.as_deref(), Some("notifications/tools/list_changed"));
    // Les notifications n'ont pas d'identifiant JSON-RPC.
    assert!(evt.payload.get("id").is_none(), "la notification ne doit pas avoir d'id");
}

// ---------------------------------------------------------------------------
// Test 4 — Batch JSON-RPC HTTP
// ---------------------------------------------------------------------------

#[test]
fn test_batch_http() {
    let corps = br#"[
        {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}},
        {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
    ]"#;

    let evts = Normaliseur::depuis_corps_http(corps, session(), serveur(), Direction::ClientVersServeur);

    assert_eq!(evts.len(), 2, "un batch de 2 messages doit produire 2 événements");
    assert_eq!(evts[0].methode.as_deref(), Some("initialize"));
    assert_eq!(evts[1].methode.as_deref(), Some("tools/list"));
    // Chaque événement du batch partage la même session.
    for evt in &evts {
        assert_eq!(evt.session_id, session());
        assert_eq!(evt.transport, Transport::Http);
    }
}

// ---------------------------------------------------------------------------
// Test 5 — JSON invalide : stdio
// ---------------------------------------------------------------------------

#[test]
fn test_json_invalide_stdio() {
    let ligne = b"pas du json { invalid";
    let resultat = Normaliseur::depuis_ligne_stdio(ligne, session(), serveur(), Direction::ClientVersServeur);
    assert!(resultat.is_none(), "un JSON invalide doit retourner None");
}

// ---------------------------------------------------------------------------
// Test 6 — JSON invalide : HTTP
// ---------------------------------------------------------------------------

#[test]
fn test_json_invalide_http() {
    let corps = b"<html>Not Found</html>";
    let evts = Normaliseur::depuis_corps_http(corps, session(), serveur(), Direction::ClientVersServeur);
    assert!(evts.is_empty(), "un corps non-JSON doit retourner un vecteur vide");
}

// ---------------------------------------------------------------------------
// Test 7 — UTF-8 multi-octet dans la description (emojis / caractères CJK)
// ---------------------------------------------------------------------------

#[test]
fn test_utf8_multibyte() {
    // Caractères japonais + emoji dans la valeur d'un champ.
    let ligne = "{ \"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"サーバー\",\"note\":\"🔒\"} }"
        .as_bytes();
    let evt = Normaliseur::depuis_ligne_stdio(ligne, session(), serveur(), Direction::ClientVersServeur)
        .expect("les caractères multi-octets doivent être acceptés");

    assert_eq!(evt.methode.as_deref(), Some("tools/call"));
    // Vérifie que les caractères multi-octets sont préservés dans le payload.
    let nom = evt.payload["params"]["name"].as_str().unwrap();
    assert_eq!(nom, "サーバー");
}

// ---------------------------------------------------------------------------
// Test 8 — Round-trip : payload préservé bit-exact
// ---------------------------------------------------------------------------

#[test]
fn test_round_trip_payload_exact() {
    // On construit un objet JSON-RPC avec des valeurs variées.
    let json_original = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "fs_read",
            "arguments": {
                "path": "/etc/hosts",
                "encoding": "utf-8"
            }
        }
    });

    let ligne = json_original.to_string();
    let evt = Normaliseur::depuis_ligne_stdio(ligne.as_bytes(), session(), serveur(), Direction::ClientVersServeur)
        .expect("le round-trip doit réussir");

    // La valeur désérialisée doit être sémantiquement identique à l'originale.
    assert_eq!(
        evt.payload, json_original,
        "le payload doit être préservé de manière exacte après normalisation"
    );

    // Vérifie également via re-sérialisation canonique.
    let re_serialise = serde_json::to_string(&evt.payload).unwrap();
    let re_parse: serde_json::Value = serde_json::from_str(&re_serialise).unwrap();
    assert_eq!(re_parse, json_original, "le payload doit survivre à une re-sérialisation");
}

// ---------------------------------------------------------------------------
// Test 9 — SSE : ligne « data: … »
// ---------------------------------------------------------------------------

#[test]
fn test_sse_data_line() {
    let data = r#"data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
    let evt = Normaliseur::depuis_event_sse(data, session(), serveur())
        .expect("une ligne SSE valide doit produire un événement");

    assert_eq!(evt.transport, Transport::Http);
    assert_eq!(evt.direction, Direction::ServeurVersClient);
    assert_eq!(evt.methode.as_deref(), Some("notifications/tools/list_changed"));
}

// ---------------------------------------------------------------------------
// Test 10 — SSE : JSON invalide retourne None
// ---------------------------------------------------------------------------

#[test]
fn test_sse_invalide() {
    let data = "data: pas-du-json";
    let resultat = Normaliseur::depuis_event_sse(data, session(), serveur());
    assert!(resultat.is_none(), "une ligne SSE non-JSON doit retourner None");
}
