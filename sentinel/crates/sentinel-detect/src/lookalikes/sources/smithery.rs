//! Implémentation HTTP du connecteur Smithery.
//!
//! Interroge l'API publique `https://registry.smithery.ai/servers?page_size=100`
//! et convertit chaque entrée du tableau `servers[]` en `EntreeRegistre`.
//! En cas d'erreur réseau, de statut non-2xx ou de payload JSON invalide,
//! retourne un Vec vide avec un log d'avertissement — la collecte
//! multi-registres ne doit jamais être bloquée par la défaillance d'un
//! registre.
//!
//! Enrichissement par détail : pour chaque entrée listée, on tente
//! d'interroger `{base}/servers/{qualifiedName}` (l'endpoint de détail
//! Smithery). Quand ce payload expose un tableau `tools` dont chaque
//! item porte `name` (string) et `inputSchema` (objet), on remplit
//! `outils` avec les `SignatureOutil` correspondantes. Les requêtes de
//! détail sont parallélisées avec une concurrence plafonnée à 5 via
//! `futures::stream::buffer_unordered`. Toute défaillance d'un appel de
//! détail est avalée silencieusement (l'entrée garde `outils: None`).
//!
//! Le parsing est volontairement défensif : on s'appuie sur
//! `serde_json::Value` + `.get(...)` pour tolérer les évolutions du
//! contrat de l'API (champs renommés, ajoutés ou retirés).

use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde_json::Value;
use tracing::warn;

use crate::lookalikes::{signature_outil_depuis_outil, EntreeRegistre, SignatureOutil};

/// URL par défaut de l'API publique Smithery.
pub const SMITHERY_DEFAULT_URL: &str = "https://registry.smithery.ai/servers?page_size=100";

/// Timeout HTTP appliqué à la requête (cf. spec : 6 s).
const TIMEOUT_REQUETE: Duration = Duration::from_secs(6);

/// Nombre maximum de requêtes de détail exécutées en parallèle.
const CONCURRENCE_DETAIL: usize = 5;

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

    // Étape 1 : extraction défensive (`(entrée, qualifiedName)`).
    let bruts: Vec<(EntreeRegistre, String)> = serveurs.iter().filter_map(extraire_entree).collect();

    // Étape 2 : base de l'API à partir de l'URL de liste (sans query, sans
    // le dernier segment de chemin). Si on ne peut pas la dériver, on
    // renvoie les entrées telles quelles (pas d'enrichissement).
    let base = match derivee_base_api(url) {
        Some(b) => b,
        None => {
            warn!(url = %url, "smithery : impossible de dériver la base API pour enrichir les outils");
            return bruts.into_iter().map(|(e, _)| e).collect();
        }
    };

    // Étape 3 : enrichissement parallèle, concurrence plafonnée.
    let client_partage = client;
    stream::iter(bruts.into_iter())
        .map(|(mut entree, qualified)| {
            let client = client_partage.clone();
            let base = base.clone();
            async move {
                if !qualified.is_empty() {
                    let url_detail = format!("{}/{}", base, encoder_segment(&qualified));
                    if let Some(outils) = recuperer_outils_detail(&client, &url_detail).await {
                        entree.outils = Some(outils);
                    }
                }
                entree
            }
        })
        .buffer_unordered(CONCURRENCE_DETAIL)
        .collect::<Vec<_>>()
        .await
}

/// Dérive la base de l'endpoint `/servers` à partir de l'URL de liste.
///
/// Exemples :
///   `https://registry.smithery.ai/servers?page_size=100`
///       → `https://registry.smithery.ai/servers`
///   `http://127.0.0.1:1234/servers?page_size=100`
///       → `http://127.0.0.1:1234/servers`
///
/// On supprime simplement la query string. Si l'URL n'est pas parsable
/// ou ne se termine pas par un chemin `/servers`, on renvoie `None`.
fn derivee_base_api(url: &str) -> Option<String> {
    let (sans_query, _) = url.split_once('?').unwrap_or((url, ""));
    // On accepte aussi la forme sans query.
    let base = sans_query.trim_end_matches('/');
    if base.ends_with("/servers") {
        Some(base.to_string())
    } else {
        None
    }
}

/// Encodage minimal d'un segment de chemin URL.
///
/// Smithery utilise des `qualifiedName` du type `@acme/github-mcp` qui
/// contiennent `/` et `@` : on doit les encoder pour que l'ensemble
/// reste un segment unique côté serveur. `reqwest` n'expose pas d'aide
/// publique simple ici, on fait donc un encodage manuel ciblé sur les
/// caractères réservés courants.
fn encoder_segment(segment: &str) -> String {
    let mut sortie = String::with_capacity(segment.len());
    for octet in segment.bytes() {
        match octet {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                sortie.push(octet as char);
            }
            _ => {
                sortie.push_str(&format!("%{:02X}", octet));
            }
        }
    }
    sortie
}

/// Extrait une `EntreeRegistre` à partir d'un nœud JSON Smithery.
///
/// Le nom canonique est `displayName` s'il existe, sinon `qualifiedName`.
/// Une entrée sans nom utilisable est ignorée. Renvoie aussi le
/// `qualifiedName` brut (utilisé pour construire l'URL de détail).
fn extraire_entree(node: &Value) -> Option<(EntreeRegistre, String)> {
    let qualified = node
        .get("qualifiedName")
        .and_then(|v| v.as_str())
        .unwrap_or("");
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

    let entree = EntreeRegistre::depuis_nom_description("smithery", nom, description);
    Some((entree, qualified.to_string()))
}

/// Tente de récupérer et parser le payload de détail d'un serveur
/// Smithery pour en extraire la liste de `SignatureOutil`.
///
/// Renvoie `Some(vec)` même si le vec est vide tant que le champ
/// `tools` est présent et est un tableau. Renvoie `None` en cas
/// d'erreur réseau, statut non-2xx, payload invalide ou absence de
/// `tools`. Les erreurs sont avalées silencieusement (au plus un
/// `tracing::warn` non-fatal).
async fn recuperer_outils_detail(client: &reqwest::Client, url: &str) -> Option<Vec<SignatureOutil>> {
    let reponse = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url, "smithery : échec requête détail (ignorée)");
            return None;
        }
    };

    if !reponse.status().is_success() {
        return None;
    }

    let corps: Value = match reponse.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(erreur = %e, url = %url, "smithery : payload détail JSON invalide (ignoré)");
            return None;
        }
    };

    let tools = corps.get("tools").and_then(|v| v.as_array())?;
    let outils = tools
        .iter()
        .filter_map(|t| {
            let nom = t.get("name").and_then(|v| v.as_str())?;
            let schema = t.get("inputSchema").cloned().unwrap_or(Value::Null);
            // On exige que `inputSchema` soit un objet (cf. JSON Schema).
            if !schema.is_object() {
                return None;
            }
            let description = t.get("description").and_then(|v| v.as_str());
            Some(signature_outil_depuis_outil(nom, description, &schema))
        })
        .collect();

    Some(outils)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivee_base_api_supprime_la_query() {
        assert_eq!(
            derivee_base_api("https://registry.smithery.ai/servers?page_size=100").as_deref(),
            Some("https://registry.smithery.ai/servers")
        );
        assert_eq!(
            derivee_base_api("http://127.0.0.1:1234/servers").as_deref(),
            Some("http://127.0.0.1:1234/servers")
        );
        assert!(derivee_base_api("https://example.invalid/autre?x=1").is_none());
    }

    #[test]
    fn encoder_segment_chappe_arobase_et_slash() {
        assert_eq!(encoder_segment("@acme/github-mcp"), "%40acme%2Fgithub-mcp");
        assert_eq!(encoder_segment("simple"), "simple");
    }
}
