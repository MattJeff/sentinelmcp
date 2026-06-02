//! Implémentation HTTP du connecteur Smithery.
//!
//! Interroge l'API publique `https://registry.smithery.ai/servers?page_size=100`
//! et convertit chaque entrée du tableau `servers[]` en `EntreeRegistre`.
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

/// URL par défaut de l'API publique Smithery.
pub const SMITHERY_DEFAULT_URL: &str = "https://registry.smithery.ai/servers?page_size=100";

/// Timeout HTTP appliqué à la requête (cf. spec : 6 s).
const TIMEOUT_REQUETE: Duration = Duration::from_secs(6);

/// Récupère la liste des serveurs Smithery depuis l'URL par défaut.
pub async fn lister_serveurs() -> Vec<EntreeRegistre> {
    lister_serveurs_depuis(SMITHERY_DEFAULT_URL).await
}

/// Variante paramétrable de `lister_serveurs` — utilisée par les tests
/// d'intégration pour pointer vers un serveur wiremock.
pub async fn lister_serveurs_depuis(url: &str) -> Vec<EntreeRegistre> {
    let client = match reqwest::Client::builder().timeout(TIMEOUT_REQUETE).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "smithery : impossible de construire le client HTTP");
            return Vec::new();
        }
    };

    let reponse = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url, "smithery : échec de la requête HTTP");
            return Vec::new();
        }
    };

    if !reponse.status().is_success() {
        warn!(statut = %reponse.status(), url = %url, "smithery : statut HTTP non-2xx");
        return Vec::new();
    }

    let corps: Value = match reponse.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(erreur = %e, "smithery : payload JSON invalide");
            return Vec::new();
        }
    };

    let serveurs = match corps.get("servers").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            warn!("smithery : champ `servers` absent ou non-tableau");
            return Vec::new();
        }
    };

    serveurs
        .iter()
        .filter_map(extraire_entree)
        .collect()
}

/// Extrait une `EntreeRegistre` à partir d'un nœud JSON Smithery.
///
/// Le nom canonique est `displayName` s'il existe, sinon `qualifiedName`.
/// Une entrée sans nom utilisable est ignorée.
fn extraire_entree(node: &Value) -> Option<EntreeRegistre> {
    let qualified = node.get("qualifiedName").and_then(|v| v.as_str()).unwrap_or("");
    let display = node.get("displayName").and_then(|v| v.as_str()).unwrap_or("");
    let nom = if !display.is_empty() {
        display
    } else if !qualified.is_empty() {
        qualified
    } else {
        return None;
    };

    let description = node
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Some(EntreeRegistre {
        registre: "smithery".to_string(),
        nom: nom.to_string(),
        description,
        hash_binaire: None,
        sbom_url: None,
        publie_par: None,
        url_serveur: None,
    })
}
