//! Détecteur de combinaison exfiltration — agent 3.7.
//!
//! Détecte l'attaque combinée lecture-secret + écriture-externe sur une même
//! session (cas Invariant Labs WhatsApp / SAFE-T1201).

use once_cell::sync::Lazy;
use regex::Regex;
use sentinel_protocol::{MessageMcp, MethodeMcp, Outil};
use std::collections::HashMap;

// --------------------------------------------------------------------------
// Expressions régulières de classification
// --------------------------------------------------------------------------

static RE_LECTURE_SECRET_NOM: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(read_file|fetch_secret|get_credential|read_env|.*ssh|.*token|.*key)")
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
                    "Session {} : exfiltration détectée — lecture secret ({}) + écriture externe ({})",
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
                    "Session {} : exfiltration détectée — lecture secret ({}) + écriture externe ({}). Identifiant SAFE-T1201.",
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
}
