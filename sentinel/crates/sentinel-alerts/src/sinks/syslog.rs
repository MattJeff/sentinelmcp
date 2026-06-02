//! Sink Syslog UDP (RFC 5424) — agent V18.
//!
//! Émet une ligne au format syslog RFC 5424 en UDP. Le corps du message est le
//! JSON d'alerte sérialisé. Aucune dépendance externe : on s'appuie sur
//! `std::net::UdpSocket`.

use std::net::UdpSocket;

/// Erreur d'émission pour le sink syslog.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("erreur réseau/IO: {0}")]
    Io(String),
    #[error("erreur de sérialisation: {0}")]
    Serialisation(String),
}

impl From<std::io::Error> for SinkError {
    fn from(e: std::io::Error) -> Self {
        SinkError::Io(e.to_string())
    }
}

/// Client UDP syslog RFC 5424.
pub struct ClientSyslogUdp {
    pub addr: String,
    pub hostname: String,
    pub app_name: String,
}

impl ClientSyslogUdp {
    /// Crée un client à destination de `addr` (ex. `127.0.0.1:514`).
    ///
    /// Le `hostname` est auto-détecté via la variable d'environnement
    /// `HOSTNAME` (sinon `unknown`). `app_name` est fixé à `sentinel-mcp`.
    pub fn nouveau(addr: String) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        Self {
            addr,
            hostname,
            app_name: "sentinel-mcp".to_string(),
        }
    }

    /// Envoie l'alerte JSON via UDP au format RFC 5424.
    ///
    /// `severity_num` doit être compris entre 0 et 7 (0=Emergency, 7=Debug).
    /// La facilité est fixée à 1 (user-level messages).
    pub fn envoyer(
        &self,
        severity_num: u8,
        alert_json: &serde_json::Value,
    ) -> Result<(), SinkError> {
        // RFC 5424 : PRI = facility * 8 + severity
        let facility: u8 = 1;
        let pri: u16 = (facility as u16) * 8 + (severity_num.min(7) as u16);

        // Timestamp ISO-8601 UTC.
        let now = chrono::Utc::now()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        // Corps : JSON compact, sans saut de ligne intermédiaire.
        let body = serde_json::to_string(alert_json)
            .map_err(|e| SinkError::Serialisation(e.to_string()))?;

        // Format : <PRI>1 TIMESTAMP HOST APP - - - JSON\n
        let message = format!(
            "<{}>1 {} {} {} - - - {}\n",
            pri, now, self.hostname, self.app_name, body
        );

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.send_to(message.as_bytes(), &self.addr)?;
        Ok(())
    }
}
