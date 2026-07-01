//! Détecteur de combinaison exfiltration — agent 3.7.
//!
//! Détecte l'attaque combinée lecture-secret + écriture-externe sur une même
//! session (cas Invariant Labs WhatsApp / SAFE-T1201).

use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use sentinel_protocol::{
    Constat, EtatConstat, MessageMcp, MethodeMcp, Outil, ServeurId, Severite, TypeConstat,
};
use std::collections::HashMap;

// --------------------------------------------------------------------------
// Expressions régulières de classification
// --------------------------------------------------------------------------

static RE_LECTURE_SECRET_NOM: Lazy<Regex> = Lazy::new(|| {
    // Les mots génériques `ssh`/`key`/`token`/`secret` sont BORNÉS par des
    // frontières de jeton (début/fin de nom, `_`, `-`, ou tout caractère non
    // alphanumérique) au lieu de l'ancien `.*ssh|.*token|.*key` qui matchait
    // n'importe quelle sous-chaîne. On élimine ainsi des faux secrets très
    // courants — `extract_keywords` (« key »), `count_tokens`/`tokenize`
    // (« token ») — qui, combinés à un `fetch`, fabriquaient une fausse
    // TRIFECTA CRITIQUE. Les noms de secrets réels (`get_ssh_key`, `api_key`,
    // `access_token`, `fetch_secret`, `get_credential`…) restent couverts.
    Regex::new(
        r"(?i)(read_file|read_env|credential|password|passwd|(^|[^a-z0-9])(ssh|key|token|secret)([^a-z0-9]|$))",
    )
    .expect("regex lecture_secret_nom valide")
});

static RE_LECTURE_SECRET_PAYLOAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(~/\.ssh|\.env|id_rsa|password=)")
        .expect("regex lecture_secret_payload valide")
});

static RE_ECRITURE_EXTERNE_NOM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(send|post|upload|webhook|http_request|fetch|curl)")
        .expect("regex ecriture_externe_nom valide")
});

static RE_ECRITURE_EXTERNE_PAYLOAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"https?://")
        .expect("regex ecriture_externe_payload valide")
});

// --------------------------------------------------------------------------
// 3e jambe de la trifecta létale (D4) — « entrée non fiable » (Risk_A)
//
// La trifecta létale (Simon Willison / Invariant Labs) combine TROIS
// capacités sur une même session :
//   1. accès à des données privées          → `est_lecture_secret` ;
//   2. exposition à du contenu NON FIABLE    → `est_entree_non_fiable` (ci-dessous) ;
//   3. capacité d'exfiltration externe       → `est_ecriture_externe`.
// Quand les trois coexistent, une instruction injectée dans le contenu non
// fiable peut piloter la lecture d'un secret puis son exfiltration. C'est la
// défense déterministe la plus citée du domaine.
// --------------------------------------------------------------------------

/// Noms d'outils dénotant l'ingestion de contenu externe / non fiable :
/// récupération web (fetch/browse/scrape/crawl), URL distante, téléchargement,
/// ou lecture de contenu produit par des tiers (e-mails, issues, commentaires,
/// pages). Ce sont les vecteurs classiques d'injection indirecte (Willison
/// « fetch tool », attaque GitHub MCP).
static RE_ENTREE_NON_FIABLE_NOM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(fetch|web_?search|search_?web|web_?browse|browse_?web|browser|crawl|scrap(e|ing)|read_?url|get_?url|open_?url|load_?url|fetch_?url|http_?get|http_?request|download|wget|curl|\brss\b|read_?email|read_?inbox|read_?issue|read_?comment|read_?webpage|read_?page|wikipedia)",
    )
    .expect("regex entree_non_fiable_nom valide")
});

/// Payload dénotant la récupération d'une ressource distante : une URL
/// `http(s)` portée par une clé de RÉCUPÉRATION (`url`, `uri`, `link`,
/// `source_url`, `feed`…). Volontairement ciblé sur ces clés pour ne pas
/// confondre n'importe quelle URL apparaissant dans un payload d'écriture.
static RE_ENTREE_NON_FIABLE_PAYLOAD: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)"(url|uri|link|source_?url|page_?url|feed_?url|feed|webpage|rss)"\s*:\s*"https?://"#,
    )
    .expect("regex entree_non_fiable_payload valide")
});

// --------------------------------------------------------------------------
// Types publics
// --------------------------------------------------------------------------

/// Signal structuré émis lorsqu'une session présente la combinaison exfiltration.
#[derive(Debug, Clone)]
pub struct SignalExfiltration {
    /// Identifiant de la session fautive.
    pub session_id: String,
    /// Noms des outils ayant lu un secret.
    pub lecture_secret: Vec<String>,
    /// Noms des outils ayant écrit vers l'extérieur.
    pub ecriture_externe: Vec<String>,
    /// Explication textuelle lisible pour l'interface / l'auditeur.
    pub raison: String,
}

/// Signal structuré de **trifecta létale** (D4) — les TROIS jambes coexistent
/// dans une même session. Plus grave que la combinaison 2-jambes
/// (`SignalExfiltration`) : la sévérité est figée à `Critique`.
#[derive(Debug, Clone)]
pub struct SignalTrifecta {
    /// Identifiant de la session fautive.
    pub session_id: String,
    /// Noms des outils ayant ingéré du contenu externe / non fiable (jambe 1).
    pub entree_non_fiable: Vec<String>,
    /// Noms des outils ayant lu un secret (jambe 2).
    pub lecture_secret: Vec<String>,
    /// Noms des outils ayant écrit vers l'extérieur (jambe 3).
    pub ecriture_externe: Vec<String>,
    /// Sévérité du signal : toujours `Critique` pour la trifecta complète.
    pub severite: Severite,
    /// Explication textuelle lisible pour l'interface / l'auditeur.
    pub raison: String,
}

/// Détecteur transversal de session pour la combinaison exfiltration.
pub struct DetecteurExfiltration;

// --------------------------------------------------------------------------
// Logique de classification d'un appel d'outil
// --------------------------------------------------------------------------

/// Sérialise le payload en chaîne pour la correspondance regex.
fn payload_en_texte(payload: &serde_json::Value) -> String {
    match payload {
        serde_json::Value::String(s) => s.clone(),
        autre => autre.to_string(),
    }
}

/// Renvoie `true` si cet appel `tools/call` lit un secret.
fn est_lecture_secret(nom_outil: &str, payload: &serde_json::Value) -> bool {
    if RE_LECTURE_SECRET_NOM.is_match(nom_outil) {
        return true;
    }
    RE_LECTURE_SECRET_PAYLOAD.is_match(&payload_en_texte(payload))
}

/// Renvoie `true` si cet appel `tools/call` écrit vers l'extérieur.
///
/// Un outil déjà classifié comme lecture de secret n'est pas reclassifié
/// en écriture externe pour éviter les faux positifs (ex. `fetch_secret`).
fn est_ecriture_externe(nom_outil: &str, payload: &serde_json::Value) -> bool {
    // Un outil de lecture de secret ne peut pas simultanément être une écriture externe.
    if est_lecture_secret(nom_outil, payload) {
        return false;
    }
    if RE_ECRITURE_EXTERNE_NOM.is_match(nom_outil) {
        return true;
    }
    RE_ECRITURE_EXTERNE_PAYLOAD.is_match(&payload_en_texte(payload))
}

/// Renvoie `true` si cet appel `tools/call` ingère du contenu externe / non
/// fiable (3e jambe de la trifecta létale — D4).
///
/// Deux signaux :
///   1. le **nom** dénote une récupération de contenu externe (fetch, browse,
///      scrape, read_email/issue/comment, download…) — signal le plus fiable ;
///   2. à défaut, le **payload** porte une URL `http(s)` sous une clé de
///      récupération (`url`/`link`/`feed`…). Ce repli est neutralisé pour un
///      outil déjà classé écriture externe (ex. `webhook` avec `{"url":…}`),
///      afin de ne pas transformer une exfiltration 2-jambes en faux
///      « trifecta ».
pub fn est_entree_non_fiable(nom_outil: &str, payload: &serde_json::Value) -> bool {
    if RE_ENTREE_NON_FIABLE_NOM.is_match(nom_outil) {
        return true;
    }
    // Repli payload neutralisé quand le NOM dénote déjà une écriture externe
    // (ex. `webhook`, `send`, `upload`) : sans cette garde, un outil
    // d'exfiltration portant `{"url":"https://…"}` serait compté comme 3e
    // jambe et transformerait une exfiltration 2-jambes en faux « trifecta ».
    // On gate sur le NOM seul (pas `est_ecriture_externe`, dont le volet
    // payload matche TOUTE URL `http(s)` et masquerait alors ce repli).
    if RE_ECRITURE_EXTERNE_NOM.is_match(nom_outil) {
        return false;
    }
    RE_ENTREE_NON_FIABLE_PAYLOAD.is_match(&payload_en_texte(payload))
}

/// Extrait le nom de l'outil depuis `params.name` d'un message `tools/call`.
fn extraire_nom_outil(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
}

// --------------------------------------------------------------------------
// Implémentation publique
// --------------------------------------------------------------------------

impl DetecteurExfiltration {
    /// Évalue une session entière (séquence de messages observée).
    ///
    /// Renvoie une raison textuelle si la combinaison lecture-secret +
    /// écriture-externe est détectée dans la **même** `session_id`.
    pub fn evaluer_session(messages: &[MessageMcp]) -> Option<String> {
        // On regroupe par session_id, puis pour chaque session on cherche la combo.
        let mut sessions: HashMap<&str, (Vec<String>, Vec<String>)> = HashMap::new();

        for msg in messages {
            if msg.methode != MethodeMcp::ToolsCall {
                continue;
            }
            let nom = match extraire_nom_outil(&msg.payload) {
                Some(n) => n,
                None => continue,
            };

            let entree = sessions.entry(msg.session_id.as_str()).or_default();

            if est_lecture_secret(&nom, &msg.payload) {
                entree.0.push(nom.clone());
            }
            if est_ecriture_externe(&nom, &msg.payload) {
                entree.1.push(nom.clone());
            }
        }

        for (session_id, (lectures, ecritures)) in &sessions {
            if !lectures.is_empty() && !ecritures.is_empty() {
                return Some(format!(
                    "Session {}: exfiltration detected — secret read ({}) + external write ({})",
                    session_id,
                    lectures.join(", "),
                    ecritures.join(", "),
                ));
            }
        }

        None
    }

    /// Variante riche qui retourne le signal structuré complet.
    ///
    /// `outils_par_serveur` est la portée produite par l'agent 1.7 ; elle
    /// n'est pas utilisée pour la classification heuristique (déjà dans les
    /// noms et payloads) mais peut enrichir le signal à l'avenir.
    pub fn evaluer_signal(
        messages: &[MessageMcp],
        _outils_par_serveur: &HashMap<String, Vec<Outil>>,
    ) -> Option<SignalExfiltration> {
        // On cherche la première session fautive.
        let mut sessions: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

        for msg in messages {
            if msg.methode != MethodeMcp::ToolsCall {
                continue;
            }
            let nom = match extraire_nom_outil(&msg.payload) {
                Some(n) => n,
                None => continue,
            };

            let entree = sessions.entry(msg.session_id.clone()).or_default();

            if est_lecture_secret(&nom, &msg.payload) {
                entree.0.push(nom.clone());
            }
            if est_ecriture_externe(&nom, &msg.payload) {
                entree.1.push(nom.clone());
            }
        }

        for (session_id, (lectures, ecritures)) in sessions {
            if !lectures.is_empty() && !ecritures.is_empty() {
                let raison = format!(
                    "Session {}: exfiltration detected — secret read ({}) + external write ({}). Identifier SAFE-T1201.",
                    session_id,
                    lectures.join(", "),
                    ecritures.join(", "),
                );
                return Some(SignalExfiltration {
                    session_id,
                    lecture_secret: lectures,
                    ecriture_externe: ecritures,
                    raison,
                });
            }
        }

        None
    }

    // -----------------------------------------------------------------------
    // D4 — Trifecta létale (3 jambes). API ADDITIVE : ne modifie pas les
    // évaluations 2-jambes ci-dessus.
    // -----------------------------------------------------------------------

    /// Évalue une session pour la **trifecta létale** : entrée non fiable +
    /// lecture secret + écriture externe coexistant dans la **même** session.
    ///
    /// Renvoie une raison textuelle uniquement quand les TROIS jambes sont
    /// présentes. Plus restrictif (donc plus grave) que `evaluer_session`.
    pub fn evaluer_trifecta(messages: &[MessageMcp]) -> Option<String> {
        Self::evaluer_trifecta_signal(messages, &HashMap::new()).map(|s| s.raison)
    }

    /// Variante riche qui retourne le `SignalTrifecta` structuré (sévérité
    /// `Critique`). `_outils_par_serveur` est accepté pour la symétrie avec
    /// `evaluer_signal` mais n'intervient pas dans la classification.
    pub fn evaluer_trifecta_signal(
        messages: &[MessageMcp],
        _outils_par_serveur: &HashMap<String, Vec<Outil>>,
    ) -> Option<SignalTrifecta> {
        // Trois jambes accumulées par session : (entrées, lectures, écritures).
        type Jambes = (Vec<String>, Vec<String>, Vec<String>);
        let mut sessions: HashMap<String, Jambes> = HashMap::new();

        for msg in messages {
            if msg.methode != MethodeMcp::ToolsCall {
                continue;
            }
            let nom = match extraire_nom_outil(&msg.payload) {
                Some(n) => n,
                None => continue,
            };

            let entree = sessions.entry(msg.session_id.clone()).or_default();

            // Un même outil peut légitimement porter plusieurs jambes (ex. un
            // `fetch` est à la fois ingestion non fiable et canal externe) ; on
            // déduplique pour ne pas gonfler artificiellement les listes.
            if est_entree_non_fiable(&nom, &msg.payload) && !entree.0.contains(&nom) {
                entree.0.push(nom.clone());
            }
            if est_lecture_secret(&nom, &msg.payload) && !entree.1.contains(&nom) {
                entree.1.push(nom.clone());
            }
            if est_ecriture_externe(&nom, &msg.payload) && !entree.2.contains(&nom) {
                entree.2.push(nom.clone());
            }
        }

        for (session_id, (entrees, lectures, ecritures)) in sessions {
            if !entrees.is_empty() && !lectures.is_empty() && !ecritures.is_empty() {
                let raison = format!(
                    "Session {}: LETHAL TRIFECTA detected (critical severity, more severe than \
                     the 2-leg combination) — untrusted input ({}) + secret read ({}) + \
                     external write ({}). Identifier SAFE-T1201 (lethal trifecta, Willison/Invariant).",
                    session_id,
                    entrees.join(", "),
                    lectures.join(", "),
                    ecritures.join(", "),
                );
                return Some(SignalTrifecta {
                    session_id,
                    entree_non_fiable: entrees,
                    lecture_secret: lectures,
                    ecriture_externe: ecritures,
                    severite: Severite::Critique,
                    raison,
                });
            }
        }

        None
    }

    /// Convertit un `SignalTrifecta` en `Constat` formel (CRITIQUE) pour le store.
    pub fn vers_constat_trifecta(signal: &SignalTrifecta, serveur_id: ServeurId) -> Constat {
        Constat {
            id: crate::id_constat(&["trifecta", &serveur_id.to_string()]),
            serveur_id,
            outil_nom: None,
            type_constat: TypeConstat::Exfiltration,
            severite: signal.severite,
            titre: "Lethal trifecta — untrusted input + secret read + external write"
                .to_string(),
            detail: signal.raison.clone(),
            diff: None,
            references_conformite: vec![
                "SAFE-T1201".to_string(),
                "OWASP MCP09".to_string(),
                "ATT&CK T1567".to_string(),
            ],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        }
    }
}
