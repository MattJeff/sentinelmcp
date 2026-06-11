//! Tests d'intégration pour le sink Syslog TCP (octet-counted) — agent V19.

use sentinel_alerts::sinks::syslog::{ClientSyslog, ClientSyslogTcp, SinkError};
use serde_json::json;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// Parse un frame octet-counted "LEN MSG" et retourne MSG.
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

#[tokio::test]
async fn tcp_emet_frame_octet_counted_rfc5424() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind TCP");
    let addr = listener.local_addr().expect("local_addr").to_string();

    // Tâche serveur : accepte une connexion, lit jusqu'à EOF.
    let serveur = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        sock.read_to_end(&mut buf).await.expect("read_to_end");
        buf
    });

    let mut client = ClientSyslogTcp::nouveau(addr);
    client.hostname = "host-test".to_string();
    client.app_name = "sentinel-mcp".to_string();

    let alert = json!({
        "id": "alert-tcp",
        "severity": "INFO",
        "message": "ping TCP"
    });

    // severity=6 (informational), facility=1 → PRI=14
    client.envoyer(6, &alert).await.expect("envoi TCP");

    let recu = serveur.await.expect("join serveur");
    assert!(!recu.is_empty(), "rien reçu côté serveur");

    let msg = parser_frame(&recu);

    // PRI
    assert!(msg.starts_with("<14>1 "), "PRI attendu '<14>1 ', got: {}", msg);
    // Champs RFC 5424
    assert!(
        msg.contains(" host-test sentinel-mcp - - - "),
        "HOST/APP/SD attendus, got: {}",
        msg
    );
    // Payload JSON intact
    assert!(msg.contains("\"id\":\"alert-tcp\""), "id JSON manquant: {}", msg);
    assert!(msg.contains("\"message\":\"ping TCP\""), "message JSON manquant: {}", msg);
}

#[tokio::test]
async fn tcp_port_ferme_renvoie_erreur_reseau() {
    // Adresse réservée IANA pour test ; refus ou timeout attendu.
    // On utilise localhost sur un port très probablement libre puis on ne bind pas.
    // Pour fiabiliser, on bind+drop pour récupérer un port "occupé puis libéré".
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind éphémère");
    let addr = listener.local_addr().expect("local_addr").to_string();
    drop(listener);

    let mut client = ClientSyslogTcp::nouveau(addr);
    client.timeout = Duration::from_secs(2);
    let alert = json!({"x": 1});
    let r = client.envoyer(6, &alert).await;
    match r {
        Err(SinkError::Reseau(_)) => {}
        other => panic!("attendu SinkError::Reseau, got: {:?}", other),
    }
}
