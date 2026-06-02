//! Tests d'intégration pour le sink Syslog UDP — agent V18.

use sentinel_alerts::sinks::syslog::ClientSyslogUdp;
use serde_json::json;
use std::net::UdpSocket;

#[test]
fn syslog_emet_message_rfc5424() {
    // Socket récepteur sur loopback, port choisi par l'OS.
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind UDP");
    let addr = receiver.local_addr().expect("local_addr").to_string();
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set timeout");

    let client = ClientSyslogUdp::nouveau(addr);

    let alert = json!({
        "id": "test-syslog",
        "severity": "HIGH",
        "message": "alerte de test"
    });

    client.envoyer(4, &alert).expect("envoi UDP");

    let mut buf = [0u8; 4096];
    let (n, _src) = receiver.recv_from(&mut buf).expect("réception datagramme");
    let received = std::str::from_utf8(&buf[..n]).expect("utf8");

    // Le message doit commencer par "<PRI>1 " (RFC 5424, version 1).
    assert!(
        received.starts_with('<'),
        "doit commencer par '<' : {:?}",
        received
    );
    let close = received.find('>').expect("doit contenir '>'");
    let after = &received[close + 1..];
    assert!(
        after.starts_with("1 "),
        "doit débuter par '1 ' après PRI: {:?}",
        received
    );

    // Le JSON d'alerte doit être présent dans la charge utile.
    assert!(
        received.contains("test-syslog"),
        "message doit contenir l'id JSON : {:?}",
        received
    );
}
