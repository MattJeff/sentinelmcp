//! Canal webhook (générique + Slack + Teams) — agent 4.5.

use super::CanalEmetteur;
use async_trait::async_trait;
use sentinel_protocol::{Alerte, Severite};
use serde_json::{json, Value};

/// Type de webhook cible.
#[derive(Debug, Clone)]
pub enum TypeWebhook {
    Generique,
    Slack,
    Teams,
}

/// Canal d'émission vers un endpoint webhook.
pub struct CanalWebhook {
    pub url: String,
    pub type_webhook: TypeWebhook,
    pub client: reqwest::Client,
    /// Si vrai : ne pose pas vraiment de requête HTTP (dry-run pour tests).
    pub dry_run: bool,
    /// Captures dry-run pour vérification : (url, body).
    pub captures: std::sync::Mutex<Vec<(String, String)>>,
}

impl CanalWebhook {
    /// Crée un canal webhook réel avec timeout 10 s.
    pub fn nouveau(url: String, type_webhook: TypeWebhook) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("construction du client reqwest impossible");
        Self {
            url,
            type_webhook,
            client,
            dry_run: false,
            captures: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Crée un canal webhook en mode dry-run (aucune requête HTTP émise).
    pub fn dry_run(url: String, type_webhook: TypeWebhook) -> Self {
        Self {
            url,
            type_webhook,
            client: reqwest::Client::new(),
            dry_run: true,
            captures: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Dispatch vers le formateur adapté au type de webhook.
    pub fn charge_utile(&self, alerte: &Alerte) -> Value {
        match self.type_webhook {
            TypeWebhook::Slack => Self::charge_utile_slack(alerte),
            TypeWebhook::Teams => Self::charge_utile_teams(alerte),
            TypeWebhook::Generique => Self::charge_utile_generique(alerte),
        }
    }

    /// Charge utile au format Slack Incoming Webhook.
    pub fn charge_utile_slack(alerte: &Alerte) -> Value {
        let couleur = match alerte.severite {
            Severite::Critique => "danger",
            Severite::Haute => "danger",
            Severite::Moyenne => "warning",
            Severite::Info => "good",
        };

        let texte = format!("🚨 [{}] {}", libelle_severite(&alerte.severite), alerte.titre);

        let mut champs = vec![
            json!({ "title": "Message", "value": alerte.message, "short": false }),
            json!({ "title": "Horodatage", "value": alerte.horodatage.to_rfc3339(), "short": true }),
            json!({ "title": "ID alerte", "value": alerte.id.to_string(), "short": true }),
        ];

        if let Some(diff) = &alerte.diff {
            champs.push(json!({ "title": "Diff", "value": diff, "short": false }));
        }

        json!({
            "text": texte,
            "attachments": [
                {
                    "color": couleur,
                    "fields": champs
                }
            ]
        })
    }

    /// Charge utile au format Microsoft Teams MessageCard.
    pub fn charge_utile_teams(alerte: &Alerte) -> Value {
        let couleur_theme = match alerte.severite {
            Severite::Critique => "FF0000",
            Severite::Haute => "FF6600",
            Severite::Moyenne => "FFA500",
            Severite::Info => "00AA00",
        };

        let mut faits = vec![
            json!({ "name": "Sévérité", "value": libelle_severite(&alerte.severite) }),
            json!({ "name": "Message", "value": alerte.message }),
            json!({ "name": "Horodatage", "value": alerte.horodatage.to_rfc3339() }),
            json!({ "name": "ID alerte", "value": alerte.id.to_string() }),
        ];

        if let Some(diff) = &alerte.diff {
            faits.push(json!({ "name": "Diff", "value": diff }));
        }

        json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": couleur_theme,
            "summary": alerte.titre,
            "sections": [
                {
                    "activityTitle": format!("🚨 {}", alerte.titre),
                    "facts": faits
                }
            ]
        })
    }

    /// Charge utile générique structurée.
    pub fn charge_utile_generique(alerte: &Alerte) -> Value {
        json!({
            "alerte": {
                "id": alerte.id.to_string(),
                "severite": libelle_severite(&alerte.severite),
                "titre": alerte.titre,
                "message": alerte.message,
                "diff": alerte.diff,
                "horodatage": alerte.horodatage.to_rfc3339()
            }
        })
    }
}

/// Convertit une sévérité en libellé textuel français.
fn libelle_severite(s: &Severite) -> &'static str {
    match s {
        Severite::Critique => "CRITIQUE",
        Severite::Haute => "HAUTE",
        Severite::Moyenne => "MOYENNE",
        Severite::Info => "INFO",
    }
}

#[async_trait]
impl CanalEmetteur for CanalWebhook {
    async fn emettre(&self, alerte: &Alerte) -> anyhow::Result<()> {
        let corps = self.charge_utile(alerte);
        let corps_str = serde_json::to_string(&corps)?;

        if self.dry_run {
            let mut verrous = self.captures.lock().unwrap();
            verrous.push((self.url.clone(), corps_str));
            return Ok(());
        }

        self.client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(corps_str)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("erreur envoi webhook: {}", e))?
            .error_for_status()
            .map_err(|e| anyhow::anyhow!("webhook a répondu avec erreur: {}", e))?;

        Ok(())
    }

    fn nom(&self) -> &'static str {
        "webhook"
    }
}
