//! Implémentation HTTP du connecteur PulseMCP.
//!
//! Interroge l'API publique `https://api.pulsemcp.com/v0/servers?count_per_page=100`
//! et convertit chaque entrée en `EntreeRegistre`. En cas d'erreur réseau
//! ou de statut non-2xx, retourne un Vec vide avec un log d'avertissement
//! (pas de propagation d'erreur — la collecte multi-registres ne doit pas
//! être bloquée par la défaillance d'un registre).

use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

use crate::lookalikes::EntreeRegistre;

/// URL par défaut de l'API publique PulseMCP.
pub const PULSEMCP_DEFAULT_URL: &str = "https://api.pulsemcp.com/v0/servers?count_per_page=100";

/// Timeout HTTP appliqué à la requête (cf. spec : 6 s).
const TIMEOUT_REQUETE: Duration = Duration::from_secs(6);

/// Représentation brute d'un serveur PulseMCP.
/// On lit uniquement les champs utiles à `EntreeRegistre` ; les inconnus
/// sont ignorés (serde ne signale pas d'erreur sur champs supplémentaires).
#[derive(Debug, Deserialize)]
struct ServeurPulse {
    #[serde(default)]
    name: String,
    #[serde(default)]
    short_description: Option<String>,
}

/// Enveloppe de la réponse PulseMCP.
#[derive(Debug, Deserialize)]
struct ReponsePulse {
    #[serde(default)]
    servers: Vec<ServeurPulse>,
}

/// Récupère la liste des serveurs PulseMCP depuis l'URL par défaut.
pub async fn lister_serveurs() -> Vec<EntreeRegistre> {
    lister_serveurs_depuis(PULSEMCP_DEFAULT_URL).await
}

/// Variante paramétrable de `lister_serveurs` — utilisée par les tests
/// d'intégration pour pointer vers un serveur wiremock.
pub async fn lister_serveurs_depuis(url: &str) -> Vec<EntreeRegistre> {
    let client = match reqwest::Client::builder().timeout(TIMEOUT_REQUETE).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "pulsemcp : impossible de construire le client HTTP");
            return Vec::new();
        }
    };

    let reponse = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url, "pulsemcp : échec de la requête HTTP");
            return Vec::new();
        }
    };

    if !reponse.status().is_success() {
        warn!(statut = %reponse.status(), url = %url, "pulsemcp : statut HTTP non-2xx");
        return Vec::new();
    }

    let corps: ReponsePulse = match reponse.json().await {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "pulsemcp : payload JSON invalide");
            return Vec::new();
        }
    };

    corps
        .servers
        .into_iter()
        .map(|s| EntreeRegistre {
            registre: "pulsemcp".to_string(),
            nom: s.name,
            description: s.short_description.unwrap_or_default(),
            hash_binaire: None,
            sbom_url: None,
            publie_par: None,
            url_serveur: None,
        })
        .collect()
}
