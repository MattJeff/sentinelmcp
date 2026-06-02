//! Sink Elastic — agent V18.
//!
//! Pousse une alerte sérialisée en JSON vers un cluster Elasticsearch via
//! `POST <base_url>/<index>/_doc`. Authentification HTTP Basic facultative.

use std::time::Duration;

/// Erreur d'émission vers un sink SIEM.
///
/// Définie ici en redondance de V17 (splunk) pour permettre la compilation
/// indépendamment de l'ordre d'arrivée des modules. Si V17 a déjà défini
/// `SinkError` dans `sinks::splunk`, on aliase via le re-export en tête de
/// `sinks/mod.rs` (ce module garde sa propre définition pour rester autonome).
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("erreur HTTP: {0}")]
    Http(String),
    #[error("statut HTTP non-2xx: {0}")]
    StatusNon2xx(u16),
    #[error("erreur de sérialisation: {0}")]
    Serialisation(String),
    #[error("erreur réseau/IO: {0}")]
    Io(String),
}

impl From<reqwest::Error> for SinkError {
    fn from(e: reqwest::Error) -> Self {
        SinkError::Http(e.to_string())
    }
}

/// Client minimal pour pousser des documents JSON vers un index Elasticsearch.
pub struct ClientElastic {
    base_url: String,
    index: String,
    auth: Option<(String, String)>,
    client: reqwest::Client,
}

impl ClientElastic {
    /// Construit un client Elastic.
    ///
    /// * `base_url` : URL racine du cluster, ex. `http://localhost:9200`.
    /// * `index`    : nom de l'index destination.
    /// * `auth`     : couple `(user, pass)` pour l'authentification HTTP Basic.
    pub fn nouveau(base_url: String, index: String, auth: Option<(String, String)>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("construction du client reqwest impossible");
        Self { base_url, index, auth, client }
    }

    /// Pousse `alert_json` comme un nouveau document vers l'index.
    ///
    /// Retourne `Ok(())` si le statut HTTP est 2xx, sinon une `SinkError`.
    pub async fn envoyer(&self, alert_json: &serde_json::Value) -> Result<(), SinkError> {
        let base = self.base_url.trim_end_matches('/');
        let url = format!("{}/{}/_doc", base, self.index);

        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(alert_json);

        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req.send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(SinkError::StatusNon2xx(status.as_u16()))
        }
    }
}
