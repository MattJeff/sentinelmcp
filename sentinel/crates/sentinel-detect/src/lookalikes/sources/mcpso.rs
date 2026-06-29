//! Implémentation HTTP du connecteur mcp.so.
//!
//! Interroge l'API publique `https://mcp.so/api/servers?limit=100`
//! et convertit chaque entrée du tableau `data[]` en `EntreeRegistre`.
//! En cas d'erreur réseau, de statut non-2xx ou de payload JSON invalide,
//! retourne un Vec vide avec un log d'avertissement — la collecte
//! multi-registres ne doit jamais être bloquée par la défaillance d'un
//! registre.
//!
//! Le parsing est volontairement défensif : on s'appuie sur
//! `serde_json::Value` + `.get(...)` pour tolérer les évolutions du
//! contrat de l'API (champs renommés, ajoutés ou retirés).

use std::time::Duration;

use serde_json::Value;
use tracing::warn;

use crate::lookalikes::EntreeRegistre;

/// URL par défaut de l'API publique mcp.so.
pub const MCPSO_DEFAULT_URL: &str = "https://mcp.so/api/servers?limit=100";

/// Timeout HTTP appliqué à la requête (cf. spec : 6 s).
const TIMEOUT_REQUETE: Duration = Duration::from_secs(6);

/// Récupère la liste des serveurs mcp.so depuis l'URL par défaut.
pub async fn lister_serveurs() -> Vec<EntreeRegistre> {
    lister_serveurs_depuis(MCPSO_DEFAULT_URL).await
}

/// Variante paramétrable de `lister_serveurs` — utilisée par les tests
/// d'intégration pour pointer vers un serveur wiremock.
pub async fn lister_serveurs_depuis(url: &str) -> Vec<EntreeRegistre> {
    let client = match reqwest::Client::builder().timeout(TIMEOUT_REQUETE).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "mcp.so : impossible de construire le client HTTP");
            return Vec::new();
        }
    };

    let reponse = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url, "mcp.so : échec de la requête HTTP");
            return Vec::new();
        }
    };

    if !reponse.status().is_success() {
        warn!(statut = %reponse.status(), url = %url, "mcp.so : statut HTTP non-2xx");
        return Vec::new();
    }

    let corps: Value = match reponse.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(erreur = %e, "mcp.so : payload JSON invalide");
            return Vec::new();
        }
    };

    parser_liste(&corps)
}

/// Extrait les entrées du tableau `data` d'un corps JSON mcp.so déjà
/// désérialisé. Fonction pure (aucun réseau) : renvoie un Vec vide si `data`
/// est absent ou non-tableau.
fn parser_liste(corps: &Value) -> Vec<EntreeRegistre> {
    let entrees = match corps.get("data").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            warn!("mcp.so : champ `data` absent ou non-tableau");
            return Vec::new();
        }
    };

    entrees.iter().filter_map(extraire_entree).collect()
}

/// Parse un payload JSON de liste mcp.so en entrées de base. Aucune requête
/// réseau — fonction pure et testable hors-ligne. Renvoie un Vec vide si le
/// JSON est invalide ou si `data` est absent (jamais de panique). Sert aussi
/// à ré-hydrater un payload mis en cache.
pub fn parser_payload(texte: &str) -> Vec<EntreeRegistre> {
    match serde_json::from_str::<Value>(texte) {
        Ok(corps) => parser_liste(&corps),
        Err(e) => {
            warn!(erreur = %e, "mcp.so : payload JSON invalide (parser_payload)");
            Vec::new()
        }
    }
}

/// Extrait une `EntreeRegistre` à partir d'un nœud JSON mcp.so.
/// Une entrée sans `name` exploitable est ignorée.
fn extraire_entree(node: &Value) -> Option<EntreeRegistre> {
    let nom = node.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if nom.is_empty() {
        return None;
    }

    let description = node
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    Some(EntreeRegistre::depuis_nom_description(
        "mcp.so",
        nom,
        description,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Échantillon réaliste de `GET /api/servers` de mcp.so : tableau `data[]`
    /// portant `name` + `description`, avec une enveloppe de pagination.
    const FIXTURE: &str = r#"{
      "data": [
        { "name": "github", "description": "Manage repositories, issues and pull requests." },
        { "name": "postgres", "description": "Query and inspect PostgreSQL databases." },
        { "description": "entrée sans nom, à ignorer" }
      ],
      "page": 1,
      "limit": 100,
      "total": 3210
    }"#;

    #[test]
    fn parse_fixture_reelle() {
        let entrees = parser_payload(FIXTURE);
        // L'entrée sans `name` exploitable est ignorée.
        assert_eq!(entrees.len(), 2);
        assert_eq!(entrees[0].registre, "mcp.so");
        assert_eq!(entrees[0].nom, "github");
        assert_eq!(
            entrees[0].description.as_deref(),
            Some("Manage repositories, issues and pull requests.")
        );
        assert_eq!(entrees[1].nom, "postgres");
    }

    #[test]
    fn data_absent_ou_json_invalide_renvoie_vide() {
        assert!(parser_payload("{\"items\":[]}").is_empty());
        assert!(parser_payload("xx").is_empty());
    }
}
