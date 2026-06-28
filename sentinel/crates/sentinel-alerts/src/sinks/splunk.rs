//! Sink Splunk HEC : POST des alertes vers `/services/collector/event`.

use serde_json::{json, Value};
use std::time::Duration;
use thiserror::Error;

/// Erreurs possibles lors de l'envoi vers un sink SIEM externe.
#[derive(Debug, Error)]
pub enum SinkError {
    /// Erreur réseau, timeout, DNS, etc.
    #[error("erreur réseau lors de l'envoi: {0}")]
    Reseau(String),
    /// Réponse HTTP non-2xx.
    #[error("réponse HTTP non-2xx (statut={statut}): {corps}")]
    Http {
        /// Code de statut HTTP retourné par le serveur.
        statut: u16,
        /// Corps de la réponse (peut être tronqué).
        corps: String,
    },
    /// Erreur de sérialisation.
    #[error("erreur de sérialisation: {0}")]
    Serialisation(String),
}

/// Client Splunk HEC (HTTP Event Collector).
///
/// Construit une charge utile `{"event": ..., "sourcetype": ..., "source": "sentinel-mcp"}`
/// et la POST vers `<base_url>/services/collector/event` avec l'entête
/// `Authorization: Splunk <token>`.
pub struct ClientSplunkHec {
    base_url: String,
    token: String,
    sourcetype: String,
    client: reqwest::Client,
}

impl ClientSplunkHec {
    /// Construit un nouveau client Splunk HEC.
    ///
    /// `sourcetype` par défaut : `"sentinel:alert"`. Timeout fixé à 10 secondes.
    /// La vérification TLS est laissée activée (jamais désactivée).
    pub fn nouveau(base_url: String, token: String, sourcetype: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("construction du client reqwest impossible");
        Self {
            base_url,
            token,
            sourcetype: sourcetype.unwrap_or_else(|| "sentinel:alert".to_string()),
            client,
        }
    }

    /// URL complète de l'endpoint HEC.
    fn url_endpoint(&self) -> String {
        let base = self.base_url.trim_end_matches('/');
        format!("{}/services/collector/event", base)
    }

    /// Construit la charge utile à envoyer à Splunk HEC.
    pub fn charge_utile(&self, alerte_json: &Value) -> Value {
        json!({
            "event": alerte_json,
            "sourcetype": self.sourcetype,
            "source": "sentinel-mcp"
        })
    }

    /// Envoie l'alerte sérialisée vers Splunk HEC.
    ///
    /// Le token est résolu via le trousseau OS s'il s'agit d'une référence
    /// `keyring:<nom>` (cf. [`Self::envoyer_avec_coffre`]).
    pub async fn envoyer(&self, alert_json: &Value) -> Result<(), SinkError> {
        self.envoyer_avec_coffre(alert_json, crate::secrets::coffre_actif().as_deref())
            .await
    }

    /// Variante de [`Self::envoyer`] avec coffre de secrets injectable.
    ///
    /// Avant de construire l'en-tête `Authorization`, un token resté sous forme
    /// de référence `keyring:<nom>` est résolu via `coffre` — un secret ne doit
    /// jamais partir en clair sous forme de référence (défense en profondeur).
    pub async fn envoyer_avec_coffre(
        &self,
        alert_json: &Value,
        coffre: Option<&dyn crate::secrets::CoffreSecrets>,
    ) -> Result<(), SinkError> {
        let corps = self.charge_utile(alert_json);
        let corps_str = serde_json::to_string(&corps)
            .map_err(|e| SinkError::Serialisation(e.to_string()))?;

        let token = super::resoudre_secret(&self.token, coffre).map_err(SinkError::Reseau)?;

        let reponse = self
            .client
            .post(self.url_endpoint())
            .header("Authorization", format!("Splunk {}", token))
            .header("Content-Type", "application/json")
            .body(corps_str)
            .send()
            .await
            .map_err(|e| SinkError::Reseau(e.to_string()))?;

        let statut = reponse.status();
        if !statut.is_success() {
            let code = statut.as_u16();
            let corps = reponse
                .text()
                .await
                .unwrap_or_else(|_| "<corps illisible>".to_string());
            return Err(SinkError::Http { statut: code, corps });
        }

        Ok(())
    }
}
