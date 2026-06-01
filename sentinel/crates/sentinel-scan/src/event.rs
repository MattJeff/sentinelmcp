//! Normalisateur d'événements — Agent 1.3.
//!
//! Transforme les flux hétérogènes (stdio, HTTP, SSE) en `EvenementBrut`,
//! format unifié consommé par tout le pipeline en aval.
//!
//! Règles :
//! - On normalise tout JSON-RPC observé, sans valider que c'est du MCP.
//! - Si le JSON est invalide → `None` / vec vide.
//! - Le contenu des arguments n'est jamais stocké séparément : on conserve
//!   le `payload` complet mais sans en extraire les valeurs sensibles.
//! - `horodatage` = `chrono::Utc::now()` au moment de l'appel.

use chrono::Utc;
use sentinel_protocol::{Direction, EvenementBrut, Transport};

// ---------------------------------------------------------------------------
// Normaliseur principal
// ---------------------------------------------------------------------------

pub struct Normaliseur;

impl Normaliseur {
    /// stdio : une ligne UTF-8 JSON-RPC + métadonnées de session.
    ///
    /// Retourne `None` si la ligne n'est pas un JSON valide.
    pub fn depuis_ligne_stdio(
        ligne: &[u8],
        session_id: &str,
        serveur: &str,
        direction: Direction,
    ) -> Option<EvenementBrut> {
        let texte = std::str::from_utf8(ligne).ok()?;
        let valeur: serde_json::Value = serde_json::from_str(texte.trim()).ok()?;
        let methode = extraire_methode(&valeur);
        Some(EvenementBrut {
            session_id: session_id.to_string(),
            transport: Transport::Stdio,
            serveur: serveur.to_string(),
            direction,
            methode,
            payload: valeur,
            horodatage: Utc::now(),
        })
    }

    /// HTTP : un corps JSON-RPC — message unique ou batch (tableau).
    ///
    /// Les batches sont dépliés : chaque message du tableau produit un
    /// `EvenementBrut` indépendant. Retourne un vecteur vide si invalide.
    pub fn depuis_corps_http(
        corps: &[u8],
        session_id: &str,
        endpoint: &str,
        direction: Direction,
    ) -> Vec<EvenementBrut> {
        let texte = match std::str::from_utf8(corps) {
            Ok(t) => t,
            Err(_) => return vec![],
        };
        let valeur: serde_json::Value = match serde_json::from_str(texte.trim()) {
            Ok(v) => v,
            Err(_) => return vec![],
        };

        match valeur {
            // Batch JSON-RPC : tableau de messages.
            serde_json::Value::Array(items) => items
                .into_iter()
                .map(|item| {
                    let methode = extraire_methode(&item);
                    EvenementBrut {
                        session_id: session_id.to_string(),
                        transport: Transport::Http,
                        serveur: endpoint.to_string(),
                        direction,
                        methode,
                        payload: item,
                        horodatage: Utc::now(),
                    }
                })
                .collect(),
            // Message unique.
            item => {
                let methode = extraire_methode(&item);
                vec![EvenementBrut {
                    session_id: session_id.to_string(),
                    transport: Transport::Http,
                    serveur: endpoint.to_string(),
                    direction,
                    methode,
                    payload: item,
                    horodatage: Utc::now(),
                }]
            }
        }
    }

    /// SSE : une ligne « data: … » provenant d'un flux Server-Sent Events.
    ///
    /// La direction est toujours `ServeurVersClient` pour SSE.
    pub fn depuis_event_sse(
        data: &str,
        session_id: &str,
        endpoint: &str,
    ) -> Option<EvenementBrut> {
        // Accepte "data: {...}" ou directement "{...}".
        let json_str = if let Some(reste) = data.trim().strip_prefix("data:") {
            reste.trim()
        } else {
            data.trim()
        };

        let valeur: serde_json::Value = serde_json::from_str(json_str).ok()?;
        let methode = extraire_methode(&valeur);
        Some(EvenementBrut {
            session_id: session_id.to_string(),
            transport: Transport::Http,
            serveur: endpoint.to_string(),
            direction: Direction::ServeurVersClient,
            methode,
            payload: valeur,
            horodatage: Utc::now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Wrappers compatibles pipeline (API sans contexte de session)
// ---------------------------------------------------------------------------

/// Normalise une ligne stdio brute sans contexte de session.
/// Utilisé par les modules en aval qui ne connaissent pas encore la session.
pub fn normaliser_stdio(ligne: &[u8]) -> Option<EvenementBrut> {
    Normaliseur::depuis_ligne_stdio(ligne, "inconnu", "inconnu", Direction::ClientVersServeur)
}

/// Normalise un corps HTTP brut sans contexte de session.
/// Retourne le premier événement du batch s'il y en a plusieurs.
pub fn normaliser_http(corps: &[u8]) -> Option<EvenementBrut> {
    Normaliseur::depuis_corps_http(corps, "inconnu", "inconnu", Direction::ClientVersServeur)
        .into_iter()
        .next()
}

// ---------------------------------------------------------------------------
// Utilitaires internes
// ---------------------------------------------------------------------------

/// Extrait le champ `method` d'un objet JSON-RPC, s'il est présent.
///
/// Retourne `None` pour les réponses et les erreurs JSON-RPC (qui n'ont pas
/// de champ `method`).
#[inline]
fn extraire_methode(valeur: &serde_json::Value) -> Option<String> {
    valeur
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}
