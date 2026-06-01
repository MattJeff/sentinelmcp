//! Parseur SSE (Server-Sent Events) pour les réponses MCP HTTP.
//!
//! Le transport Streamable HTTP peut renvoyer des réponses en `text/event-stream`.
//! Ce module parse le flux ligne par ligne et extrait les champs `data:` portant
//! des messages JSON-RPC. Un `EvenementBrut` est émis pour chaque message.

use bytes::Bytes;
use sentinel_protocol::{Direction, EvenementBrut, Transport};
use tokio::sync::mpsc::Sender;
use chrono::Utc;

/// Parse un flux SSE brut (corps complet ou partiel) et émet un `EvenementBrut`
/// par ligne `data:` contenant du JSON valide.
///
/// `reste` est le tampon résiduel des octets non encore terminés par `\n`.
/// Le caller doit le conserver et le passer à l'appel suivant.
pub async fn parser_flux_sse(
    chunk: &Bytes,
    reste: &mut Vec<u8>,
    session_id: &str,
    serveur: &str,
    emetteur: &Sender<EvenementBrut>,
) {
    reste.extend_from_slice(chunk);

    // Traite les lignes complètes (terminées par \n).
    while let Some(pos) = reste.iter().position(|&b| b == b'\n') {
        let ligne = reste.drain(..=pos).collect::<Vec<u8>>();
        let ligne = String::from_utf8_lossy(&ligne);
        let ligne = ligne.trim_end_matches(['\n', '\r']);

        if let Some(data) = ligne.strip_prefix("data:") {
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(data) {
                Ok(payload) => {
                    let methode = payload
                        .get("method")
                        .and_then(|v| v.as_str())
                        .map(String::from);

                    let evt = EvenementBrut {
                        session_id: session_id.to_string(),
                        transport: Transport::Http,
                        serveur: serveur.to_string(),
                        direction: Direction::ServeurVersClient,
                        methode,
                        payload,
                        horodatage: Utc::now(),
                    };

                    // On ignore l'erreur si le récepteur est fermé (arrêt normal).
                    let _ = emetteur.send(evt).await;
                }
                Err(_) => {
                    // Donnée SSE non-JSON (commentaire, heartbeat) : ignorée.
                    tracing::trace!(data = %data, "ligne SSE non-JSON ignorée");
                }
            }
        }
        // Les lignes `event:`, `id:`, `retry:` et les commentaires (`:`) sont ignorées.
    }
}

/// Détermine si un `Content-Type` correspond à du SSE.
pub fn est_sse(content_type: &str) -> bool {
    content_type.starts_with("text/event-stream")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn flux(s: &str) -> Bytes {
        Bytes::from(s.to_string())
    }

    #[tokio::test]
    async fn parse_deux_messages_sse() {
        let (tx, mut rx) = mpsc::channel(10);
        let mut reste: Vec<u8> = Vec::new();

        let corps = concat!(
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":1}\n",
            "data: {\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[]},\"id\":1}\n",
        );

        parser_flux_sse(&flux(corps), &mut reste, "sess-1", "http://localhost:3000", &tx).await;

        let evt1 = rx.recv().await.expect("premier événement");
        assert_eq!(evt1.methode.as_deref(), Some("tools/list"));
        assert_eq!(evt1.session_id, "sess-1");
        assert_eq!(evt1.direction, Direction::ServeurVersClient);

        let evt2 = rx.recv().await.expect("second événement");
        assert_eq!(evt2.methode, None); // réponse sans champ `method`
    }

    #[tokio::test]
    async fn lignes_non_json_ignorees() {
        let (tx, mut rx) = mpsc::channel(10);
        let mut reste: Vec<u8> = Vec::new();

        let corps = concat!(
            ": heartbeat\n",
            "event: message\n",
            "data: {\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"id\":0}\n",
            "data: [DONE]\n",
        );

        parser_flux_sse(&flux(corps), &mut reste, "sess-2", "srv", &tx).await;

        let evt = rx.recv().await.expect("un seul événement JSON-RPC");
        assert_eq!(evt.methode.as_deref(), Some("initialize"));
        assert!(rx.try_recv().is_err(), "pas d'événement supplémentaire");
    }

    #[tokio::test]
    async fn reste_tampon_flux_partiel() {
        let (tx, mut rx) = mpsc::channel(10);
        let mut reste: Vec<u8> = Vec::new();

        // Première livraison : ligne incomplète.
        let part1 = Bytes::from("data: {\"jsonrpc\":\"2.0\",\"method\":\"ping\"");
        parser_flux_sse(&part1, &mut reste, "sess-3", "srv", &tx).await;
        assert!(rx.try_recv().is_err(), "ligne incomplète : rien émis");

        // Deuxième livraison : fin de la ligne.
        let part2 = Bytes::from(",\"id\":5}\n");
        parser_flux_sse(&part2, &mut reste, "sess-3", "srv", &tx).await;

        let evt = rx.recv().await.expect("événement complet");
        assert_eq!(evt.methode.as_deref(), Some("ping"));
    }

    #[test]
    fn detection_content_type_sse() {
        assert!(est_sse("text/event-stream"));
        assert!(est_sse("text/event-stream; charset=utf-8"));
        assert!(!est_sse("application/json"));
    }
}
