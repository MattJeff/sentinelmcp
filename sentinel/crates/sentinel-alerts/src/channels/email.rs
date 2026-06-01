//! Canal e-mail — agent 4.4.
//!
//! Envoie les alertes hautes et critiques par SMTP (lettre 0.11).
//! Mode `dry_run` : écrit le message dans `/tmp/sentinel-emails/<id>.eml`
//! au lieu de contacter le serveur SMTP.

use super::CanalEmetteur;
use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use sentinel_protocol::Alerte;
use std::path::PathBuf;
use tracing::warn;

// ────────────────────────────────────────────────────────────────────────────
// Types publics
// ────────────────────────────────────────────────────────────────────────────

/// Configuration du canal e-mail.
#[derive(Debug, Clone)]
pub struct ConfigEmail {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub utilisateur: Option<String>,
    pub mot_de_passe: Option<String>,
    pub expediteur: String,
    pub destinataire: String,
}

/// Canal d'alerte par e-mail (SMTP via `lettre`).
pub struct CanalEmail {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub utilisateur: Option<String>,
    pub mot_de_passe: Option<String>,
    pub expediteur: String,
    pub destinataire: String,
    /// Si `true`, écrit dans `/tmp/sentinel-emails/<id>.eml` (pas d'envoi SMTP).
    pub dry_run: bool,
}

impl CanalEmail {
    /// Constructeur normal (envoi SMTP réel).
    pub fn nouveau(c: ConfigEmail) -> Self {
        Self {
            smtp_host: c.smtp_host,
            smtp_port: c.smtp_port,
            utilisateur: c.utilisateur,
            mot_de_passe: c.mot_de_passe,
            expediteur: c.expediteur,
            destinataire: c.destinataire,
            dry_run: false,
        }
    }

    /// Constructeur mode test/dry-run (écriture sur disque).
    pub fn dry_run(c: ConfigEmail) -> Self {
        Self {
            dry_run: true,
            ..Self::nouveau(c)
        }
    }

    // ── Gabarits ─────────────────────────────────────────────────────────────

    /// Corps texte brut.
    pub fn corps_texte(a: &Alerte) -> String {
        let severite = format!("{:?}", a.severite).to_uppercase();
        let refs = if a.diff.is_none() {
            // Pas de diff : les références conformité se trouvent dans le
            // message si elles y sont incluses (format libre).
            String::new()
        } else {
            String::new()
        };
        let _ = refs;

        let mut corps = format!(
            "=== Alerte Sentinel MCP ===\n\
             Sévérité  : {severite}\n\
             Titre     : {titre}\n\
             Horodatage: {ts}\n\
             \n\
             {message}\n",
            severite = severite,
            titre = a.titre,
            ts = a.horodatage.format("%Y-%m-%d %H:%M:%S UTC"),
            message = a.message,
        );

        if let Some(diff) = &a.diff {
            corps.push_str("\n--- Diff détecté ---\n");
            corps.push_str(diff);
            corps.push('\n');
        }

        corps.push_str(
            "\n---\n\
             Références de conformité : OWASP MCP09 (Shadow MCP), MCP03 (Tool Poisoning), \
             SAFE-T1001 (poisoning), SAFE-T1201 (rug-pull)\n\
             Sentinel MCP — surveillance continue, read-only.\n",
        );

        corps
    }

    /// Corps HTML.
    pub fn corps_html(a: &Alerte) -> String {
        let severite = format!("{:?}", a.severite).to_uppercase();
        let couleur = match a.severite {
            sentinel_protocol::Severite::Critique => "#c0392b",
            sentinel_protocol::Severite::Haute => "#e67e22",
            sentinel_protocol::Severite::Moyenne => "#f39c12",
            sentinel_protocol::Severite::Info => "#2980b9",
        };

        let diff_html = if let Some(diff) = &a.diff {
            format!(
                "<h3>Diff détecté</h3><pre style=\"background:#f4f4f4;padding:12px;\
                 border-left:4px solid {couleur};overflow:auto;\">{diff}</pre>",
                couleur = couleur,
                diff = html_escape(diff),
            )
        } else {
            String::new()
        };

        format!(
            r#"<!DOCTYPE html>
<html lang="fr">
<body style="font-family:sans-serif;color:#222;max-width:700px;margin:auto;">
  <h2 style="color:{couleur};">[Sentinel MCP] {severite} — {titre}</h2>
  <p><strong>Horodatage :</strong> {ts}</p>
  <p>{message}</p>
  {diff_html}
  <hr/>
  <p style="font-size:0.85em;color:#555;">
    Références de conformité :
    OWASP MCP09 (Shadow MCP), MCP03 (Tool Poisoning),
    SAFE-T1001 (poisoning), SAFE-T1201 (rug-pull)<br/>
    Sentinel MCP — surveillance continue, read-only.
  </p>
</body>
</html>"#,
            couleur = couleur,
            severite = severite,
            titre = html_escape(&a.titre),
            ts = a.horodatage.format("%Y-%m-%d %H:%M:%S UTC"),
            message = html_escape(&a.message),
            diff_html = diff_html,
        )
    }

    // ── Helpers internes ─────────────────────────────────────────────────────

    fn construire_message(&self, alerte: &Alerte) -> anyhow::Result<Message> {
        let severite = format!("{:?}", alerte.severite).to_uppercase();
        let sujet = format!("[Sentinel MCP] {} — {}", severite, alerte.titre);

        let expediteur: Mailbox = self
            .expediteur
            .parse()
            .map_err(|e| anyhow::anyhow!("expéditeur invalide: {}", e))?;
        let destinataire: Mailbox = self
            .destinataire
            .parse()
            .map_err(|e| anyhow::anyhow!("destinataire invalide: {}", e))?;

        let texte = Self::corps_texte(alerte);
        let html = Self::corps_html(alerte);

        let message = Message::builder()
            .from(expediteur)
            .to(destinataire)
            .subject(sujet)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(texte),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )?;

        Ok(message)
    }

    async fn ecrire_dry_run(&self, alerte: &Alerte, message: &Message) -> anyhow::Result<()> {
        let dossier = PathBuf::from("/tmp/sentinel-emails");
        tokio::fs::create_dir_all(&dossier).await?;

        let chemin = dossier.join(format!("{}.eml", alerte.id));
        let contenu = message.formatted();
        tokio::fs::write(&chemin, contenu).await?;

        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Implémentation du trait
// ────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl CanalEmetteur for CanalEmail {
    async fn emettre(&self, alerte: &Alerte) -> anyhow::Result<()> {
        let message = self.construire_message(alerte).map_err(|e| {
            warn!(canal = "email", alerte_id = %alerte.id, erreur = %e,
                  "échec construction du message");
            e
        })?;

        if self.dry_run {
            return self.ecrire_dry_run(alerte, &message).await.map_err(|e| {
                warn!(canal = "email", alerte_id = %alerte.id, erreur = %e,
                      "échec écriture dry-run");
                e
            });
        }

        // Connexion SMTP réelle
        let transporteur = {
            let base = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.smtp_host)
                .map_err(|e| anyhow::anyhow!("relay SMTP: {}", e))?
                .port(self.smtp_port);

            if let (Some(u), Some(p)) = (&self.utilisateur, &self.mot_de_passe) {
                base.credentials(Credentials::new(u.clone(), p.clone()))
                    .build()
            } else {
                base.build()
            }
        };

        transporteur.send(message).await.map_err(|e| {
            warn!(canal = "email", alerte_id = %alerte.id, erreur = %e,
                  "échec envoi SMTP — alerte non remise");
            anyhow::anyhow!("envoi SMTP échoué: {}", e)
        })?;

        Ok(())
    }

    fn nom(&self) -> &'static str {
        "email"
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Utilitaire
// ────────────────────────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
