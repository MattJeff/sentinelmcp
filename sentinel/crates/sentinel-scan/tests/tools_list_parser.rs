//! Tests du parseur `tools/list` — Agent 1.6.

use serde_json::{json, Value};
use sentinel_scan::tools_list::{parser_reponse_tools_list, ErreurParseToolsList};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn reponse_ok(tools: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": tools
        }
    })
}

fn reponse_avec_cursor(tools: Value, cursor: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": tools,
            "nextCursor": cursor
        }
    })
}

// ─── Test 1 : réponse classique avec deux outils ────────────────────────────

#[test]
fn test_reponse_classique() {
    let payload = reponse_ok(json!([
        {
            "name": "read_file",
            "description": "Lit un fichier local",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }
        },
        {
            "name": "write_file",
            "description": "Écrit dans un fichier",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "content": { "type": "string" }
                },
                "required": ["path", "content"]
            }
        }
    ]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 2);
    assert_eq!(res.outils[0].nom, "read_file");
    assert_eq!(res.outils[0].description.as_deref(), Some("Lit un fichier local"));
    assert_eq!(res.outils[1].nom, "write_file");
    assert!(res.next_cursor.is_none());
}

// ─── Test 2 : réponse avec pagination nextCursor ───────────────────────────

#[test]
fn test_reponse_avec_pagination() {
    let payload = reponse_avec_cursor(
        json!([{ "name": "tool_a", "inputSchema": null }]),
        "cursor-xyz-42",
    );

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 1);
    assert_eq!(res.next_cursor.as_deref(), Some("cursor-xyz-42"));
}

// ─── Test 3 : outil sans description ───────────────────────────────────────

#[test]
fn test_outil_sans_description() {
    let payload = reponse_ok(json!([
        {
            "name": "ping",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 1);
    assert!(res.outils[0].description.is_none());
}

// ─── Test 4 : inputSchema profond (nested objects + arrays d'enums) ─────────

#[test]
fn test_input_schema_profond() {
    let schema = json!({
        "type": "object",
        "properties": {
            "config": {
                "type": "object",
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": ["read", "write", "append"]
                    },
                    "filters": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "field": { "type": "string" },
                                "operator": {
                                    "type": "string",
                                    "enum": ["eq", "ne", "gt", "lt"]
                                },
                                "value": {}
                            }
                        }
                    }
                }
            },
            "tags": {
                "type": "array",
                "items": { "type": "string" }
            }
        },
        "required": ["config"]
    });

    let payload = reponse_ok(json!([
        {
            "name": "query_database",
            "description": "Requête base de données avec filtres imbriqués",
            "inputSchema": schema.clone()
        }
    ]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 1);
    // Vérifie que le schema imbriqué est préservé exactement
    assert_eq!(res.outils[0].input_schema, schema);
    // Vérifie l'accès profond au schema
    assert_eq!(
        res.outils[0].input_schema["properties"]["config"]["properties"]["mode"]["enum"][1],
        json!("write")
    );
}

// ─── Test 5 : champs custom passent dans meta ───────────────────────────────

#[test]
fn test_champs_custom_dans_meta() {
    let payload = reponse_ok(json!([
        {
            "name": "annotated_tool",
            "description": "Outil avec annotations",
            "inputSchema": { "type": "object" },
            "annotations": {
                "readOnlyHint": true,
                "idempotentHint": false
            },
            "x_custom_field": "valeur_libre",
            "version": "1.2.3"
        }
    ]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 1);
    let meta = &res.outils[0].meta;
    assert!(meta.contains_key("annotations"));
    assert_eq!(meta["annotations"]["readOnlyHint"], json!(true));
    assert!(meta.contains_key("x_custom_field"));
    assert_eq!(meta["x_custom_field"], json!("valeur_libre"));
    assert!(meta.contains_key("version"));
    // Les champs connus ne doivent pas être dans meta
    assert!(!meta.contains_key("name"));
    assert!(!meta.contains_key("description"));
    assert!(!meta.contains_key("inputSchema"));
}

// ─── Test 6 : réponse vide { tools: [] } ───────────────────────────────────

#[test]
fn test_reponse_vide() {
    let payload = reponse_ok(json!([]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert!(res.outils.is_empty());
    assert!(res.next_cursor.is_none());
}

// ─── Test 7 : payload non-réponse JSON-RPC (rejet) ─────────────────────────

#[test]
fn test_payload_non_jsonrpc() {
    // Requête JSON-RPC (pas de "result")
    let requete = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {}
    });
    let err = parser_reponse_tools_list(&requete).unwrap_err();
    assert!(matches!(err, ErreurParseToolsList::ResultManquant));

    // Objet quelconque sans "jsonrpc"
    let objet_arbitraire = json!({ "foo": "bar" });
    let err = parser_reponse_tools_list(&objet_arbitraire).unwrap_err();
    assert!(matches!(err, ErreurParseToolsList::PasUneReponse));

    // Tableau JSON
    let tableau = json!([1, 2, 3]);
    let err = parser_reponse_tools_list(&tableau).unwrap_err();
    assert!(matches!(err, ErreurParseToolsList::PasUneReponse));
}

// ─── Test 8 : outils sans name ignorés sans crash ──────────────────────────

#[test]
fn test_outils_sans_name_ignores() {
    let payload = reponse_ok(json!([
        { "description": "pas de nom", "inputSchema": {} },
        { "name": "", "description": "nom vide", "inputSchema": {} },
        { "name": "outil_valide", "inputSchema": {} },
        { "inputSchema": { "type": "object" } }
    ]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir sans crash");
    // Seul l'outil avec un nom non-vide doit être conservé
    assert_eq!(res.outils.len(), 1);
    assert_eq!(res.outils[0].nom, "outil_valide");
}

// ─── Test 9 : payload réel style Anthropic everything-server ───────────────

#[test]
fn test_payload_reel_everything_server() {
    // Inspiré du MCP everything-server d'Anthropic
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes back the input",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "description": "Message to echo"
                            }
                        },
                        "required": ["message"]
                    }
                },
                {
                    "name": "add",
                    "description": "Adds two numbers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "a": { "type": "number", "description": "First number" },
                            "b": { "type": "number", "description": "Second number" }
                        },
                        "required": ["a", "b"]
                    }
                },
                {
                    "name": "longRunningOperation",
                    "description": "Demonstrates a long running operation with progress updates",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "duration": {
                                "type": "number",
                                "description": "Duration in seconds",
                                "default": 10
                            },
                            "steps": {
                                "type": "number",
                                "description": "Number of steps",
                                "default": 5
                            }
                        }
                    }
                },
                {
                    "name": "sampleLLM",
                    "description": "Samples from an LLM using MCP's sampling feature",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "prompt": { "type": "string" },
                            "maxTokens": { "type": "number", "default": 100 }
                        },
                        "required": ["prompt"]
                    }
                }
            ]
        }
    });

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 4);
    assert_eq!(res.outils[0].nom, "echo");
    assert_eq!(res.outils[1].nom, "add");
    assert_eq!(res.outils[2].nom, "longRunningOperation");
    assert_eq!(res.outils[3].nom, "sampleLLM");

    // Vérifie description et schema du premier outil
    assert_eq!(res.outils[0].description.as_deref(), Some("Echoes back the input"));
    assert_eq!(
        res.outils[0].input_schema["properties"]["message"]["type"],
        json!("string")
    );

    // Vérifie que inputSchema avec default est préservé
    assert_eq!(
        res.outils[2].input_schema["properties"]["duration"]["default"],
        json!(10)
    );

    assert!(res.next_cursor.is_none());
}

// ─── Test 10 : inputSchema null explicite préservé ─────────────────────────

#[test]
fn test_input_schema_null_explicite() {
    let payload = reponse_ok(json!([
        {
            "name": "no_schema_tool",
            "description": "Outil sans schema",
            "inputSchema": null
        }
    ]));

    let res = parser_reponse_tools_list(&payload).expect("doit réussir");
    assert_eq!(res.outils.len(), 1);
    assert_eq!(res.outils[0].input_schema, Value::Null);
}

// ─── Test 11 : result.tools n'est pas un tableau ───────────────────────────

#[test]
fn test_tools_pas_un_tableau() {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": "pas un tableau"
        }
    });
    let err = parser_reponse_tools_list(&payload).unwrap_err();
    assert!(matches!(err, ErreurParseToolsList::ToolsInvalide));

    let payload_objet = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": { "name": "outil" }
        }
    });
    let err = parser_reponse_tools_list(&payload_objet).unwrap_err();
    assert!(matches!(err, ErreurParseToolsList::ToolsInvalide));
}

// ─── Test 12 : result sans champ tools ─────────────────────────────────────

#[test]
fn test_result_sans_tools() {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {}
    });
    let err = parser_reponse_tools_list(&payload).unwrap_err();
    assert!(matches!(err, ErreurParseToolsList::ToolsInvalide));
}
