//! Tests de confidentialité — agent 2.8.
//!
//! Vérifie que les contrôles anti-fuite fonctionnent correctement et qu'aucun
//! argument d'appel ne peut être stocké sans avoir été préalablement nettoyé.

use chrono::Utc;
use sentinel_monitor::privacy::{AuditFuite, PolitiqueRetention, aucun_contenu_persiste};
use sentinel_protocol::{MessageMcp, MethodeMcp, Transport, Direction};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn message_tools_call_avec_arguments() -> MessageMcp {
    MessageMcp {
        session_id: "session-test-001".to_string(),
        transport: Transport::Http,
        serveur: "mcp.exemple.com".to_string(),
        direction: Direction::ClientVersServeur,
        methode: MethodeMcp::ToolsCall,
        id_jsonrpc: Some(serde_json::json!(1)),
        payload: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "lire_fichier",
                "arguments": {
                    "chemin": "/etc/passwd",
                    "secret": "mon-mot-de-passe-secret"
                }
            }
        }),
        horodatage: Utc::now(),
    }
}

fn message_tools_call_avec_input() -> MessageMcp {
    MessageMcp {
        session_id: "session-test-002".to_string(),
        transport: Transport::Stdio,
        serveur: "mcp.local".to_string(),
        direction: Direction::ClientVersServeur,
        methode: MethodeMcp::ToolsCall,
        id_jsonrpc: Some(serde_json::json!(2)),
        payload: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "envoyer_email",
                "input": {
                    "destinataire": "user@example.com",
                    "corps": "contenu confidentiel"
                }
            }
        }),
        horodatage: Utc::now(),
    }
}

fn message_initialize() -> MessageMcp {
    MessageMcp {
        session_id: "session-test-003".to_string(),
        transport: Transport::Http,
        serveur: "mcp.exemple.com".to_string(),
        direction: Direction::ClientVersServeur,
        methode: MethodeMcp::Initialize,
        id_jsonrpc: Some(serde_json::json!(0)),
        payload: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {}
            }
        }),
        horodatage: Utc::now(),
    }
}

fn message_tools_list_response() -> MessageMcp {
    MessageMcp {
        session_id: "session-test-004".to_string(),
        transport: Transport::Http,
        serveur: "mcp.exemple.com".to_string(),
        direction: Direction::ServeurVersClient,
        methode: MethodeMcp::ToolsList,
        id_jsonrpc: Some(serde_json::json!(3)),
        payload: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "tools": [
                    {
                        "name": "lire_fichier",
                        "description": "Lit un fichier local",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "chemin": { "type": "string" }
                            }
                        }
                    }
                ]
            }
        }),
        horodatage: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// Tests des chemins à supprimer
// ---------------------------------------------------------------------------

#[test]
fn test_chemins_detectes_sur_tools_call_avec_arguments() {
    let msg = message_tools_call_avec_arguments();
    let chemins = AuditFuite::chemins_a_supprimer(&msg);

    assert!(
        chemins.contains(&"$.params.arguments".to_string()),
        "Le chemin $.params.arguments doit être détecté sur un tools/call"
    );
    assert_eq!(chemins.len(), 1, "Un seul chemin sensible attendu");
}

#[test]
fn test_chemins_detectes_sur_tools_call_avec_input() {
    let msg = message_tools_call_avec_input();
    let chemins = AuditFuite::chemins_a_supprimer(&msg);

    assert!(
        chemins.contains(&"$.params.input".to_string()),
        "Le chemin $.params.input doit être détecté sur un tools/call"
    );
    assert_eq!(chemins.len(), 1, "Un seul chemin sensible attendu");
}

#[test]
fn test_nettoyer_remplace_arguments_par_redacted() {
    let mut msg = message_tools_call_avec_arguments();

    // Vérifie que les arguments sont présents avant nettoyage
    let avant = msg.payload["params"]["arguments"].clone();
    assert!(avant.is_object(), "Les arguments doivent être un objet avant nettoyage");

    AuditFuite::nettoyer(&mut msg);

    let apres = &msg.payload["params"]["arguments"];
    assert_eq!(
        apres.as_str(),
        Some("<<redacted>>"),
        "Les arguments doivent être remplacés par <<redacted>>"
    );
}

#[test]
fn test_nettoyer_remplace_input_par_redacted() {
    let mut msg = message_tools_call_avec_input();

    AuditFuite::nettoyer(&mut msg);

    let apres = &msg.payload["params"]["input"];
    assert_eq!(
        apres.as_str(),
        Some("<<redacted>>"),
        "Le champ input doit être remplacé par <<redacted>>"
    );
}

#[test]
fn test_initialize_aucun_chemin_sensible() {
    let msg = message_initialize();
    let chemins = AuditFuite::chemins_a_supprimer(&msg);

    assert!(
        chemins.is_empty(),
        "Un message initialize ne doit produire aucun chemin sensible"
    );
}

#[test]
fn test_tools_list_response_aucun_chemin_sensible() {
    let msg = message_tools_list_response();
    let chemins = AuditFuite::chemins_a_supprimer(&msg);

    assert!(
        chemins.is_empty(),
        "Une réponse tools/list (read-only) ne doit produire aucun chemin sensible"
    );
}

#[test]
fn test_nettoyer_initialize_sans_effet() {
    let mut msg = message_initialize();
    let payload_avant = msg.payload.clone();

    AuditFuite::nettoyer(&mut msg);

    assert_eq!(
        msg.payload, payload_avant,
        "nettoyer ne doit pas modifier un message initialize"
    );
}

// ---------------------------------------------------------------------------
// Tests de la politique de rétention
// ---------------------------------------------------------------------------

#[test]
fn test_politique_retention_par_defaut() {
    use chrono::Duration;

    let politique = PolitiqueRetention::par_defaut();

    assert_eq!(
        politique.historique_contacts,
        Duration::days(90),
        "Historique contacts : 90 jours"
    );
    assert_eq!(
        politique.constats,
        Duration::days(365),
        "Constats : 1 an"
    );
    assert_eq!(
        politique.alertes,
        Duration::days(180),
        "Alertes : 180 jours"
    );
}

// ---------------------------------------------------------------------------
// Déclaration statique de non-stockage
// ---------------------------------------------------------------------------

#[test]
fn test_aucun_contenu_persiste_est_toujours_vrai() {
    assert!(
        aucun_contenu_persiste(),
        "La déclaration de non-stockage doit toujours retourner true"
    );
}
