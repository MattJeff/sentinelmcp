//! Détecteur d'abus des primitives sampling / elicitation.
//!
//! Trois détections (voir docs/DETECTION-MATRIX.md, section 3) :
//!   1. Drain de quota — volume de `sampling/createMessage` par session au-delà
//!      d'un seuil configurable (resource theft, Unit 42).
//!   2. Injection persistante via sampling — le prompt contient une directive
//!      de persistance (« add to your next response ») ; contourne l'intégrité
//!      des outils et le sandboxing, le monitoring est la défense principale.
//!   3. Elicitation de secrets — un serveur demande mot de passe / clé API /
//!      paiement / PII via `elicitation/create`, interdit par la spec MCP.
//!
//! Confidentialité : l'inspection se fait en mémoire ; seul l'extrait
//! déclencheur (≤ 120 caractères) est conservé dans le signal.

use crate::poisoning::InspecteurPoisoning;
use chrono::Utc;
use sentinel_protocol::{
    Constat, EtatConstat, MessageMcp, MethodeMcp, ServeurId, Severite, TypeConstat,
};
use std::collections::HashMap;

/// Configuration du détecteur.
#[derive(Debug, Clone)]
pub struct ConfigSampling {
    /// Nombre de requêtes `sampling/createMessage` par session au-delà duquel
    /// un signal de drain de quota est émis.
    pub seuil_volume_session: usize,
}

impl Default for ConfigSampling {
    fn default() -> Self {
        Self {
            seuil_volume_session: 10,
        }
    }
}

/// Nature du signal émis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatureSignalSampling {
    DrainQuota,
    InjectionPersistante,
    ElicitationSecrets,
}

/// Signal structuré émis par le détecteur.
#[derive(Debug, Clone)]
pub struct SignalSampling {
    pub session_id: String,
    pub serveur: String,
    pub nature: NatureSignalSampling,
    pub severite: Severite,
    /// Extrait déclencheur (≤ 120 caractères) ou compteur pour le drain.
    pub extrait: String,
    pub raison: String,
}

pub struct DetecteurSampling;

/// Extrait les textes inspectables d'une requête `sampling/createMessage` :
/// `params.systemPrompt` + chaque `params.messages[].content.text`.
fn textes_sampling(payload: &serde_json::Value) -> Vec<String> {
    let mut textes = Vec::new();
    let params = match payload.get("params") {
        Some(p) => p,
        None => return textes,
    };
    if let Some(sp) = params.get("systemPrompt").and_then(|v| v.as_str()) {
        textes.push(sp.to_string());
    }
    if let Some(messages) = params.get("messages").and_then(|v| v.as_array()) {
        for m in messages {
            if let Some(t) = m
                .get("content")
                .and_then(|c| c.get("text"))
                .and_then(|t| t.as_str())
            {
                textes.push(t.to_string());
            }
        }
    }
    textes
}

/// Extrait le message d'une requête `elicitation/create`.
fn texte_elicitation(payload: &serde_json::Value) -> Option<String> {
    payload
        .get("params")
        .and_then(|p| p.get("message"))
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}

impl DetecteurSampling {
    /// Évalue une séquence de messages observée et retourne tous les signaux.
    pub fn evaluer(messages: &[MessageMcp], config: &ConfigSampling) -> Vec<SignalSampling> {
        let mut signaux = Vec::new();
        let mut volume_par_session: HashMap<(String, String), usize> = HashMap::new();

        for msg in messages {
            match msg.methode {
                MethodeMcp::SamplingCreateMessage => {
                    *volume_par_session
                        .entry((msg.session_id.clone(), msg.serveur.clone()))
                        .or_default() += 1;

                    for texte in textes_sampling(&msg.payload) {
                        for (pattern, categorie, extrait, _sev) in
                            InspecteurPoisoning::inspecter_texte(&texte)
                        {
                            if categorie == "persistance_memoire"
                                || categorie == "instructions_imperatives"
                            {
                                signaux.push(SignalSampling {
                                    session_id: msg.session_id.clone(),
                                    serveur: msg.serveur.clone(),
                                    nature: NatureSignalSampling::InjectionPersistante,
                                    severite: Severite::Critique,
                                    extrait: extrait.clone(),
                                    raison: format!(
                                        "Sampling prompt containing an injection directive \
                                         (pattern \"{}\", category {}). Excerpt: \"{}\"",
                                        pattern, categorie, extrait
                                    ),
                                });
                            }
                        }
                    }
                }
                MethodeMcp::ElicitationCreate => {
                    if let Some(texte) = texte_elicitation(&msg.payload) {
                        for (pattern, categorie, extrait, _sev) in
                            InspecteurPoisoning::inspecter_texte(&texte)
                        {
                            if categorie == "demande_secrets" {
                                signaux.push(SignalSampling {
                                    session_id: msg.session_id.clone(),
                                    serveur: msg.serveur.clone(),
                                    nature: NatureSignalSampling::ElicitationSecrets,
                                    severite: Severite::Critique,
                                    extrait: extrait.clone(),
                                    raison: format!(
                                        "Elicitation requesting a secret (pattern \"{}\") — \
                                         forbidden by the MCP spec. Excerpt: \"{}\"",
                                        pattern, extrait
                                    ),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        for ((session_id, serveur), volume) in volume_par_session {
            if volume > config.seuil_volume_session {
                signaux.push(SignalSampling {
                    session_id: session_id.clone(),
                    serveur: serveur.clone(),
                    nature: NatureSignalSampling::DrainQuota,
                    severite: Severite::Haute,
                    extrait: format!("{} requests", volume),
                    raison: format!(
                        "Session {}: {} sampling/createMessage requests issued by \"{}\" \
                         (threshold: {}) — possible quota drain.",
                        session_id, volume, serveur, config.seuil_volume_session
                    ),
                });
            }
        }

        signaux
    }

    /// Convertit un signal en `Constat` formel pour le store.
    pub fn vers_constat(s: &SignalSampling, serveur_id: ServeurId) -> Constat {
        let (type_constat, titre, references) = match s.nature {
            NatureSignalSampling::DrainQuota => (
                TypeConstat::AbusSampling,
                format!("Sampling abuse — abnormal volume ({})", s.extrait),
                vec!["SOC2 CC7.2".to_string(), "ISO A.12.4.1".to_string()],
            ),
            NatureSignalSampling::InjectionPersistante => (
                TypeConstat::AbusSampling,
                "Sampling abuse — persistent prompt injection".to_string(),
                vec!["OWASP ASI06".to_string(), "SOC2 CC7.2".to_string()],
            ),
            NatureSignalSampling::ElicitationSecrets => (
                TypeConstat::ElicitationSensible,
                "Elicitation requesting sensitive information".to_string(),
                vec!["MCP Spec Elicitation".to_string(), "SOC2 CC6.1".to_string()],
            ),
        };
        Constat {
            id: crate::id_constat(&["sampling", &serveur_id.to_string(), &titre]),
            serveur_id,
            outil_nom: None,
            type_constat,
            severite: s.severite,
            titre,
            detail: s.raison.clone(),
            diff: None,
            references_conformite: references,
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        }
    }
}
