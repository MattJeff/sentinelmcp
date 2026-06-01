//! Parseur de réponses `tools/list` — Agent 1.6.
//!
//! Extrait le tableau d'outils depuis une réponse JSON-RPC 2.0 à `tools/list`,
//! avec gestion robuste des variations et des payloads malformés.

use std::collections::BTreeMap;

use sentinel_protocol::Outil;
use serde_json::Value;
use tracing::warn;

/// Réponse parsée d'un appel `tools/list`.
#[derive(Debug, Default)]
pub struct ReponseToolsList {
    pub outils: Vec<Outil>,
    pub next_cursor: Option<String>,
}

/// Erreurs possibles lors du parsing d'une réponse `tools/list`.
#[derive(Debug, thiserror::Error)]
pub enum ErreurParseToolsList {
    #[error("non-réponse JSON-RPC")]
    PasUneReponse,
    #[error("champ result manquant")]
    ResultManquant,
    #[error("champ tools manquant ou de mauvais type")]
    ToolsInvalide,
    #[error("erreur JSON: {0}")]
    Json(String),
}

/// Parse une réponse JSON-RPC 2.0 à `tools/list`.
///
/// Accepte : `{"jsonrpc":"2.0","id":..,"result":{"tools":[…],"nextCursor":"…"}}`.
/// Les outils sans champ `name` sont ignorés silencieusement (log tracing).
/// `inputSchema` est préservé exactement tel que reçu, structure imbriquée intacte.
/// Les champs inconnus d'un outil (hors `name`, `description`, `inputSchema`)
/// sont collectés dans `meta`.
pub fn parser_reponse_tools_list(
    payload: &Value,
) -> Result<ReponseToolsList, ErreurParseToolsList> {
    // Vérifie la présence de "jsonrpc"
    if payload.get("jsonrpc").is_none() {
        return Err(ErreurParseToolsList::PasUneReponse);
    }

    // Récupère `result`
    let result = payload
        .get("result")
        .ok_or(ErreurParseToolsList::ResultManquant)?;

    // Récupère `result.tools` comme tableau
    let tools_array = result
        .get("tools")
        .and_then(|v| v.as_array())
        .ok_or(ErreurParseToolsList::ToolsInvalide)?;

    // Extrait `nextCursor` optionnel
    let next_cursor = result
        .get("nextCursor")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    let mut outils: Vec<Outil> = Vec::with_capacity(tools_array.len());

    for (index, outil_val) in tools_array.iter().enumerate() {
        // `name` est obligatoire : on ignore silencieusement si absent
        let nom = match outil_val.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n.to_owned(),
            _ => {
                warn!(
                    index = index,
                    "outil sans champ 'name' ignoré lors du parsing tools/list"
                );
                continue;
            }
        };

        let description = outil_val
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());

        // `inputSchema` préservé tel quel (null si absent)
        let input_schema = outil_val
            .get("inputSchema")
            .cloned()
            .unwrap_or(Value::Null);

        // Champs connus que l'on ne met pas dans `meta`
        const CHAMPS_CONNUS: &[&str] = &["name", "description", "inputSchema"];

        // Tous les autres champs → meta (BTreeMap pour ordre stable)
        let mut meta: BTreeMap<String, Value> = BTreeMap::new();
        if let Some(obj) = outil_val.as_object() {
            for (cle, valeur) in obj {
                if !CHAMPS_CONNUS.contains(&cle.as_str()) {
                    meta.insert(cle.clone(), valeur.clone());
                }
            }
        }

        outils.push(Outil {
            nom,
            description,
            input_schema,
            meta,
        });
    }

    Ok(ReponseToolsList { outils, next_cursor })
}
