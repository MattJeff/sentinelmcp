//! Tests d'intégration pour le sink Syslog TCP/TLS (RFC 5425) — agent V19.

use rcgen::{generate_simple_self_signed, CertifiedKey};
use sentinel_alerts::sinks::syslog::{ClientSyslog, ClientSyslogTls, SinkError};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

fn parser_frame(buf: &[u8]) -> String {
    let s = std::str::from_utf8(buf).expect("utf8");
    let (len_str, rest) = s.split_once(' ').expect("séparateur ' ' manquant");
    let len: usize = len_str.parse().expect("longueur entière");
    assert_eq!(
        rest.len(),
        len,
        "longueur déclarée ({}) ≠ longueur réelle ({})",
        len,
        rest.len()
    );
    rest.to_string()
}

/// Installe le provider crypto par défaut au plus tôt (idempotent).
fn assurer_provider() {
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
}

/// Génère un cert auto-signé (CN=localhost, SAN=localhost) et retourne
/// `(cert_pem, cert_der, key_der)`.
fn cert_autosigne_localhost() -> (String, Vec<u8>, Vec<u8>) {
    let subject_alt_names = vec!["localhost".to_string()];
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(subject_alt_names).expect("rcgen self-signed");
    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    (cert_pem, cert_der, key_der)
}

fn config_serveur(cert_der: Vec<u8>, key_der: Vec<u8>) -> Arc<rustls::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("pkcs8 key");
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
    Arc::new(cfg)
}

#[tokio::test]
async fn tls_emet_frame_octet_counted_avec_ca_pem() {
    assurer_provider();

    let (cert_pem, cert_der, key_der) = cert_autosigne_localhost();
    let server_cfg = config_serveur(cert_der, key_der);
    let acceptor = TlsAcceptor::from(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
    let port = listener.local_addr().expect("local_addr").port();
    let addr = format!("localhost:{}", port);

    let serveur = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("handshake serveur");
        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.expect("read_to_end");
        buf
    });

    let mut client = ClientSyslogTls::nouveau(addr, Some(cert_pem.into_bytes()));
    client.hostname = "host-tls".to_string();
    client.app_name = "sentinel-mcp".to_string();
    client.timeout = Duration::from_secs(5);

    let alert = json!({
        "id": "alert-tls",
        "severity": "WARNING",
        "message": "ping TLS"
    });
    // severity=4 (warning), facility=1 → PRI=12
    client.envoyer(4, &alert).await.expect("envoi TLS");

    let recu = serveur.await.expect("join serveur");
    assert!(!recu.is_empty(), "rien reçu côté serveur");
    let msg = parser_frame(&recu);

    assert!(msg.starts_with("<12>1 "), "PRI attendu '<12>1 ', got: {}", msg);
    assert!(
        msg.contains(" host-tls sentinel-mcp - - - "),
        "HOST/APP attendus, got: {}",
        msg
    );
    assert!(msg.contains("\"id\":\"alert-tls\""), "id JSON manquant: {}", msg);
}

#[tokio::test]
async fn tls_ca_pem_invalide_renvoie_erreur_tls() {
    assurer_provider();

    let mut client = ClientSyslogTls::nouveau(
        "127.0.0.1:1".to_string(),
        Some(b"-----BEGIN CERTIFICATE-----\nNOT_A_CERT\n-----END CERTIFICATE-----\n".to_vec()),
    );
    client.timeout = Duration::from_secs(2);
    let r = client.envoyer(6, &json!({"x":1})).await;
    match r {
        Err(SinkError::Tls(_)) => {}
        other => panic!("attendu SinkError::Tls, got: {:?}", other),
    }
}

#[tokio::test]
async fn tls_cert_non_trusted_renvoie_erreur_reseau() {
    assurer_provider();

    // Serveur avec son propre cert auto-signé que le client NE FAIT PAS confiance.
    let (_serveur_pem, cert_der, key_der) = cert_autosigne_localhost();
    let server_cfg = config_serveur(cert_der, key_der);
    let acceptor = TlsAcceptor::from(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
    let port = listener.local_addr().expect("local_addr").port();
    let addr = format!("localhost:{}", port);

    // Tâche serveur (le handshake peut échouer côté serveur, on l'ignore).
    let _serveur = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    // CA fournie par le client = un AUTRE cert auto-signé (donc ne valide pas
    // le cert du serveur).
    let (autre_pem, _a, _b) = cert_autosigne_localhost();
    let mut client = ClientSyslogTls::nouveau(addr, Some(autre_pem.into_bytes()));
    client.timeout = Duration::from_secs(3);

    let r = client.envoyer(6, &json!({"x":1})).await;
    match r {
        // Le handshake TLS échoue → notre code mappe en `Reseau`.
        Err(SinkError::Reseau(_)) => {}
        other => panic!("attendu SinkError::Reseau, got: {:?}", other),
    }
}
