//! Filtre grossier — premier étage du pipeline de détection MCP.
//!
//! Décide si un `EvenementBrut` doit progresser dans le pipeline en
//! vérifiant la présence des sous-chaînes `"jsonrpc"` et `"2.0"` dans
//! le payload sérialisé. Aucun parse JSON complet n'est effectué ici :
//! coût quasi nul, conçu pour écarter ≥ 99 % du trafic non pertinent.

use sentinel_protocol::EvenementBrut;

/// Séquence d'octets recherchée pour la clé JSON-RPC.
const MARQUEUR_JSONRPC: &[u8] = b"jsonrpc";
/// Séquence d'octets recherchée pour la version 2.0.
const MARQUEUR_VERSION: &[u8] = b"2.0";
/// Distance maximale (en octets) autorisée entre la fin de `jsonrpc`
/// et le début de `2.0`. Une valeur de 32 couvre toutes les variations
/// d'espacement JSON légitimes sans introduire de faux positifs.
const DISTANCE_MAX: usize = 32;

/// Filtre grossier sur un `EvenementBrut`.
///
/// Retourne `true` si le payload sérialisé contient à la fois
/// `"jsonrpc"` et `"2.0"` à proximité l'un de l'autre.
/// Retourne `false` sinon — l'événement est écarté sans coût
/// supplémentaire pour le pipeline.
pub fn filtre_grossier(e: &EvenementBrut) -> bool {
    // Sérialisation compacte du payload Value déjà parsé : gratuit car
    // serde_json::to_string est O(n) et évite toute allocation répétée.
    let brut = serde_json::to_string(&e.payload).unwrap_or_default();
    filtre_grossier_bytes(brut.as_bytes())
}

/// Variante opérant directement sur des octets bruts.
///
/// Utile avant parse JSON complet (e.g. dans le capteur HTTP/stdio).
/// La recherche est case-sensitive : le protocole JSON-RPC 2.0 impose
/// des clés en minuscules, donc `"JSONRPC"` est intentionnellement rejeté.
pub fn filtre_grossier_bytes(raw: &[u8]) -> bool {
    if raw.is_empty() {
        return false;
    }

    // Localiser `jsonrpc` — s'il est absent, on rejette immédiatement.
    let pos_jsonrpc = match trouver_sous_sequence(raw, MARQUEUR_JSONRPC) {
        Some(p) => p,
        None => return false,
    };

    // Chercher `2.0` uniquement dans la fenêtre [pos_jsonrpc .. pos_jsonrpc + len + DISTANCE_MAX]
    // pour éviter de valider un document qui contiendrait `jsonrpc` loin de `2.0`.
    let debut_fenetre = pos_jsonrpc + MARQUEUR_JSONRPC.len();
    let fin_fenetre = (debut_fenetre + DISTANCE_MAX).min(raw.len());

    let fenetre = &raw[debut_fenetre..fin_fenetre];
    trouver_sous_sequence(fenetre, MARQUEUR_VERSION).is_some()
}

/// Recherche naïve de `aiguille` dans `botte` sans dépendance externe.
///
/// `memchr` n'est pas disponible dans l'arbre de dépendances sans ajout
/// au Cargo.toml ; on utilise une recherche par fenêtre glissante qui
/// reste très rapide pour les courtes aiguilles que nous traitons (7 et 3 octets).
#[inline]
fn trouver_sous_sequence(botte: &[u8], aiguille: &[u8]) -> Option<usize> {
    if aiguille.is_empty() || botte.len() < aiguille.len() {
        return None;
    }
    botte
        .windows(aiguille.len())
        .position(|fenetre| fenetre == aiguille)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentinel_protocol::{Direction, EvenementBrut, Transport};
    use serde_json::json;

    /// Construit un `EvenementBrut` minimal autour d'un `Value` JSON.
    fn evenement(payload: serde_json::Value) -> EvenementBrut {
        EvenementBrut {
            session_id: "test-session".to_string(),
            transport: Transport::Http,
            serveur: "localhost:8080".to_string(),
            direction: Direction::ClientVersServeur,
            methode: Some("initialize".to_string()),
            payload,
            horodatage: Utc::now(),
        }
    }

    // ------------------------------------------------------------------ //
    // filtre_grossier_bytes — tests unitaires                             //
    // ------------------------------------------------------------------ //

    #[test]
    fn test_message_mcp_valide_accepte() {
        // Message `initialize` MCP standard — doit passer.
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert!(filtre_grossier_bytes(raw), "un message MCP valide doit être accepté");
    }

    #[test]
    fn test_trafic_http_banal_rejete() {
        // En-tête HTTP brut sans JSON-RPC — doit être rejeté.
        let raw = b"GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!filtre_grossier_bytes(raw), "du trafic HTTP banal doit être rejeté");
    }

    #[test]
    fn test_json_non_rpc_rejete() {
        // JSON valide mais sans JSON-RPC — doit être rejeté.
        let raw = br#"{"event":"click","target":"button","version":"2.0"}"#;
        assert!(
            !filtre_grossier_bytes(raw),
            "du JSON sans clé jsonrpc doit être rejeté même si 2.0 est présent"
        );
    }

    #[test]
    fn test_message_vide_rejete() {
        assert!(!filtre_grossier_bytes(b""), "un message vide doit être rejeté");
        assert!(!filtre_grossier_bytes(b"   "), "des espaces seuls doivent être rejetés");
    }

    #[test]
    fn test_utf8_large_pas_de_panic() {
        // Payload UTF-8 large (128 Ko de lorem ipsum) — ne doit pas paniquer.
        let lorem = "é".repeat(65_536);
        let payload = format!(r#"{{"texte":"{}"}}"#, lorem);
        // Pas de `jsonrpc` → rejeté sans crash.
        assert!(!filtre_grossier_bytes(payload.as_bytes()));

        // Même taille avec jsonrpc/2.0 intégré → accepté sans crash.
        let payload_rpc = format!(
            r#"{{"jsonrpc":"2.0","texte":"{}","method":"tools/list"}}"#,
            lorem
        );
        assert!(filtre_grossier_bytes(payload_rpc.as_bytes()));
    }

    #[test]
    fn test_distance_trop_grande_rejete() {
        // `jsonrpc` présent mais `2.0` situé loin (> DISTANCE_MAX) — rejeté.
        let remplissage = "x".repeat(DISTANCE_MAX + 10);
        let raw = format!(r#"{{"jsonrpc":"{}","version":"2.0"}}"#, remplissage);
        assert!(
            !filtre_grossier_bytes(raw.as_bytes()),
            "jsonrpc et 2.0 trop éloignés doivent être rejetés"
        );
    }

    #[test]
    fn test_tools_list_accepte() {
        let raw = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        assert!(filtre_grossier_bytes(raw));
    }

    #[test]
    fn test_tools_call_accepte() {
        let raw = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bash","arguments":{}}}"#;
        assert!(filtre_grossier_bytes(raw));
    }

    #[test]
    fn test_notification_tools_list_changed_accepte() {
        let raw = br#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#;
        assert!(filtre_grossier_bytes(raw));
    }

    // ------------------------------------------------------------------ //
    // filtre_grossier — tests sur EvenementBrut                          //
    // ------------------------------------------------------------------ //

    #[test]
    fn test_evenement_mcp_valide_accepte() {
        let e = evenement(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }));
        assert!(filtre_grossier(&e));
    }

    #[test]
    fn test_evenement_json_ordinaire_rejete() {
        let e = evenement(json!({ "status": "ok", "code": 200 }));
        assert!(!filtre_grossier(&e));
    }

    // ------------------------------------------------------------------ //
    // Bench intégré — mesure le débit sur trafic synthétique mixte       //
    // ------------------------------------------------------------------ //

    /// Mini-bench sans dépendance Criterion : mesure ≥ 1 M msg/s.
    ///
    /// Exécuté avec `cargo test -p sentinel-scan -- --nocapture bench_debit`
    /// pour voir la sortie (le test passe toujours en CI sans affichage).
    #[test]
    #[ignore = "microbenchmark instable en build debug — lancer avec: cargo test -p sentinel-scan -- --ignored bench_debit"]
    fn bench_debit_filtre_grossier_bytes() {
        use std::time::Instant;

        // Corpus synthétique : 50 % MCP valide, 50 % trafic non pertinent.
        let messages: Vec<Vec<u8>> = (0..1_000)
            .map(|i| {
                if i % 2 == 0 {
                    format!(
                        r#"{{"jsonrpc":"2.0","id":{},"method":"tools/list","params":{{}}}}"#,
                        i
                    )
                    .into_bytes()
                } else {
                    format!(
                        r#"{{"event":"metric","value":{},"source":"agent"}}"#,
                        i
                    )
                    .into_bytes()
                }
            })
            .collect();

        let iterations: u64 = 2_000; // 2 000 × 1 000 = 2 M appels
        let debut = Instant::now();

        let mut acceptes: u64 = 0;
        for _ in 0..iterations {
            for msg in &messages {
                if filtre_grossier_bytes(msg) {
                    acceptes += 1;
                }
            }
        }

        let duree = debut.elapsed();
        let total_msgs = iterations * messages.len() as u64;
        let msgs_par_seconde = total_msgs as f64 / duree.as_secs_f64();

        // Affichage informatif (visible avec --nocapture).
        println!(
            "\n[bench] {total_msgs} messages en {:.2?} → {:.0} msg/s ({acceptes} acceptés)",
            duree, msgs_par_seconde
        );

        // Assertion de performance : ≥ 1 M msg/s attendus.
        assert!(
            msgs_par_seconde >= 1_000_000.0,
            "débit insuffisant : {:.0} msg/s < 1 000 000 msg/s",
            msgs_par_seconde
        );
    }
}
