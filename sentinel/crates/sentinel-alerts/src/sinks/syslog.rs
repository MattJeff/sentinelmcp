//! Sinks Syslog (UDP RFC 5424, TCP octet-counted, TCP/TLS RFC 5425) — agent V19.
//!
//! Trois clients :
//! * [`ClientSyslogUdp`] : UDP RFC 5424 (legacy, agent V18).
//! * [`ClientSyslogTcp`] : TCP plain, framing octet-counted (`<LEN> <MSG>`).
//! * [`ClientSyslogTls`] : TCP+TLS RFC 5425, framing octet-counted.
//!
//! Tous trois exposent une API commune via le trait [`ClientSyslog`].

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket as TokioUdpSocket};

/// Erreur d'émission pour le sink syslog.
///
/// On garde la variante historique `Io` (V18) pour rétrocompat, tout en
/// ajoutant `Reseau` et `Tls` utilisées par les nouveaux clients TCP/TLS.
#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    /// Erreur réseau/IO bas-niveau (UDP V18).
    #[error("erreur réseau/IO: {0}")]
    Io(String),
    /// Erreur réseau (connexion TCP refusée, timeout, DNS, etc.).
    #[error("erreur réseau lors de l'envoi: {0}")]
    Reseau(String),
    /// Erreur lors de la négociation TLS ou de la configuration cryptographique.
    #[error("erreur TLS: {0}")]
    Tls(String),
    /// Erreur de sérialisation JSON.
    #[error("erreur de sérialisation: {0}")]
    Serialisation(String),
}

impl From<std::io::Error> for SinkError {
    fn from(e: std::io::Error) -> Self {
        SinkError::Io(e.to_string())
    }
}

/// Trait commun à tous les clients Syslog.
///
/// `severity` : 0..=7 (RFC 5424 — 0=Emergency, 7=Debug).
/// `payload`  : alerte JSON, sérialisée comme corps du message.
#[async_trait]
pub trait ClientSyslog: Send + Sync {
    async fn envoyer(
        &self,
        severity: u8,
        payload: &serde_json::Value,
    ) -> Result<(), SinkError>;
}

/// Construit le message RFC 5424 brut : `<PRI>1 TIMESTAMP HOST APP - - - JSON`.
///
/// Pas de `\n` final : le caller décide du framing (line-feed pour UDP,
/// octet-counted pour TCP/TLS).
fn format_rfc5424(
    severity: u8,
    hostname: &str,
    app_name: &str,
    payload: &serde_json::Value,
) -> Result<String, SinkError> {
    let facility: u8 = 1;
    let pri: u16 = (facility as u16) * 8 + (severity.min(7) as u16);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let body = serde_json::to_string(payload)
        .map_err(|e| SinkError::Serialisation(e.to_string()))?;
    Ok(format!(
        "<{}>1 {} {} {} - - - {}",
        pri, now, hostname, app_name, body
    ))
}

/// Encadre un message en octet-counted (RFC 5425) : `<len> <msg>`.
fn encadrer_octet_counted(msg: &str) -> Vec<u8> {
    let prefix = format!("{} ", msg.len());
    let mut buf = Vec::with_capacity(prefix.len() + msg.len());
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(msg.as_bytes());
    buf
}

// ---------------------------------------------------------------------------
// UDP — RFC 5424 (legacy V18)
// ---------------------------------------------------------------------------

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
    ///
    /// Implémentation synchrone (`std::net::UdpSocket`) inchangée pour
    /// rétrocompatibilité avec V18.
    pub fn envoyer(
        &self,
        severity_num: u8,
        alert_json: &serde_json::Value,
    ) -> Result<(), SinkError> {
        let msg = format_rfc5424(severity_num, &self.hostname, &self.app_name, alert_json)?;
        // RFC 5424 UDP : on conserve le `\n` historique (V18).
        let message = format!("{}\n", msg);
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.send_to(message.as_bytes(), &self.addr)?;
        Ok(())
    }
}

#[async_trait]
impl ClientSyslog for ClientSyslogUdp {
    async fn envoyer(
        &self,
        severity: u8,
        payload: &serde_json::Value,
    ) -> Result<(), SinkError> {
        let msg = format_rfc5424(severity, &self.hostname, &self.app_name, payload)?;
        let message = format!("{}\n", msg);
        let socket = TokioUdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| SinkError::Reseau(e.to_string()))?;
        socket
            .send_to(message.as_bytes(), &self.addr)
            .await
            .map_err(|e| SinkError::Reseau(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TCP plain — framing octet-counted
// ---------------------------------------------------------------------------

/// Client Syslog TCP (framing octet-counted RFC 5425, sans TLS).
pub struct ClientSyslogTcp {
    pub addr: String,
    pub hostname: String,
    pub app_name: String,
    pub timeout: Duration,
}

impl ClientSyslogTcp {
    /// Crée un client TCP à destination de `addr` (ex. `127.0.0.1:6514`).
    pub fn nouveau(addr: String) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        Self {
            addr,
            hostname,
            app_name: "sentinel-mcp".to_string(),
            timeout: Duration::from_secs(10),
        }
    }

    /// Variante avec timeout personnalisé.
    pub fn avec_timeout(addr: String, timeout: Duration) -> Self {
        let mut c = Self::nouveau(addr);
        c.timeout = timeout;
        c
    }
}

#[async_trait]
impl ClientSyslog for ClientSyslogTcp {
    async fn envoyer(
        &self,
        severity: u8,
        payload: &serde_json::Value,
    ) -> Result<(), SinkError> {
        let msg = format_rfc5424(severity, &self.hostname, &self.app_name, payload)?;
        let frame = encadrer_octet_counted(&msg);

        let stream_fut = TcpStream::connect(&self.addr);
        let mut stream = tokio::time::timeout(self.timeout, stream_fut)
            .await
            .map_err(|_| SinkError::Reseau(format!("timeout connexion à {}", self.addr)))?
            .map_err(|e| SinkError::Reseau(e.to_string()))?;

        let write_fut = async {
            stream.write_all(&frame).await?;
            stream.flush().await?;
            stream.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };
        tokio::time::timeout(self.timeout, write_fut)
            .await
            .map_err(|_| SinkError::Reseau("timeout écriture TCP".to_string()))?
            .map_err(|e| SinkError::Reseau(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TCP/TLS — RFC 5425
// ---------------------------------------------------------------------------

/// Client Syslog TCP/TLS (RFC 5425, port 6514 par défaut, framing octet-counted).
pub struct ClientSyslogTls {
    pub addr: String,
    pub server_name: Option<String>,
    pub hostname: String,
    pub app_name: String,
    pub ca_pem: Option<Vec<u8>>,
    pub timeout: Duration,
}

impl ClientSyslogTls {
    /// Crée un client TLS avec valeurs par défaut.
    ///
    /// Si `ca_pem` est `None`, la vérification s'appuiera sur les CAs système
    /// (`rustls-platform-verifier`).
    pub fn nouveau(addr: String, ca_pem: Option<Vec<u8>>) -> Self {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
        Self {
            addr,
            server_name: None,
            hostname,
            app_name: "sentinel-mcp".to_string(),
            ca_pem,
            timeout: Duration::from_secs(10),
        }
    }

    /// Construit la configuration `rustls::ClientConfig` à partir des champs.
    fn construire_config(&self) -> Result<Arc<rustls::ClientConfig>, SinkError> {
        // L'installation du provider crypto par défaut est idempotente :
        // `set_default` échoue si un provider est déjà installé, ce qu'on
        // ignore sciemment.
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        );

        let config = if let Some(pem) = &self.ca_pem {
            let mut root_store = rustls::RootCertStore::empty();
            let mut reader = std::io::Cursor::new(pem.as_slice());
            for cert in rustls_pemfile::certs(&mut reader) {
                let cert = cert.map_err(|e| SinkError::Tls(format!("CA PEM invalide: {}", e)))?;
                root_store
                    .add(cert)
                    .map_err(|e| SinkError::Tls(format!("ajout CA refusé: {}", e)))?;
            }
            if root_store.is_empty() {
                return Err(SinkError::Tls(
                    "aucun certificat valide dans ca_pem".to_string(),
                ));
            }
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            // Vérification déléguée au store système.
            let verifier = rustls_platform_verifier::Verifier::new();
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        };

        Ok(Arc::new(config))
    }

    /// Extrait le nom de serveur (SNI) depuis `server_name` ou la partie host de `addr`.
    fn nom_serveur(&self) -> Result<rustls::pki_types::ServerName<'static>, SinkError> {
        let raw = match &self.server_name {
            Some(s) => s.clone(),
            None => {
                // Partie host de `host:port` (gère IPv6 entre crochets sommairement).
                let s = &self.addr;
                if let Some(stripped) = s.strip_prefix('[') {
                    // IPv6 littéral : `[::1]:6514`
                    let end = stripped
                        .find(']')
                        .ok_or_else(|| SinkError::Tls(format!("addr IPv6 mal formée: {}", s)))?;
                    stripped[..end].to_string()
                } else {
                    s.rsplit_once(':')
                        .map(|(h, _)| h.to_string())
                        .unwrap_or_else(|| s.clone())
                }
            }
        };
        rustls::pki_types::ServerName::try_from(raw.clone())
            .map(|n| n.to_owned())
            .map_err(|e| SinkError::Tls(format!("SNI invalide '{}': {}", raw, e)))
    }
}

#[async_trait]
impl ClientSyslog for ClientSyslogTls {
    async fn envoyer(
        &self,
        severity: u8,
        payload: &serde_json::Value,
    ) -> Result<(), SinkError> {
        let msg = format_rfc5424(severity, &self.hostname, &self.app_name, payload)?;
        let frame = encadrer_octet_counted(&msg);

        let config = self.construire_config()?;
        let server_name = self.nom_serveur()?;
        let connector = tokio_rustls::TlsConnector::from(config);

        let tcp_fut = TcpStream::connect(&self.addr);
        let tcp = tokio::time::timeout(self.timeout, tcp_fut)
            .await
            .map_err(|_| SinkError::Reseau(format!("timeout connexion à {}", self.addr)))?
            .map_err(|e| SinkError::Reseau(e.to_string()))?;

        let tls_fut = connector.connect(server_name, tcp);
        let mut tls = tokio::time::timeout(self.timeout, tls_fut)
            .await
            .map_err(|_| SinkError::Reseau("timeout handshake TLS".to_string()))?
            .map_err(|e| SinkError::Reseau(format!("handshake TLS échoué: {}", e)))?;

        let write_fut = async {
            tls.write_all(&frame).await?;
            tls.flush().await?;
            tls.shutdown().await?;
            Ok::<(), std::io::Error>(())
        };
        tokio::time::timeout(self.timeout, write_fut)
            .await
            .map_err(|_| SinkError::Reseau("timeout écriture TLS".to_string()))?
            .map_err(|e| SinkError::Reseau(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn format_rfc5424_pri_correct() {
        let v = json!({"k":"v"});
        let s = format_rfc5424(6, "host", "app", &v).unwrap();
        // facility=1, severity=6 → PRI=14
        assert!(s.starts_with("<14>1 "), "got: {}", s);
        assert!(s.contains(" host app - - - "), "got: {}", s);
        assert!(s.ends_with("{\"k\":\"v\"}"), "got: {}", s);
    }

    #[test]
    fn octet_counted_frame_correct() {
        let buf = encadrer_octet_counted("hello");
        assert_eq!(buf, b"5 hello");
    }
}
