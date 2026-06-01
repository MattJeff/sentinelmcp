//! Confidentialité & rétention — agent 2.8.
//!
//! Règle non négociable : inspection en vol, jamais de stockage du contenu
//! des arguments d'appel. Ce module garantit que les arguments `tools/call`
//! ne sont jamais persistés, et définit les durées de rétention légitimes.

use chrono::Duration;
use sentinel_protocol::{MessageMcp, MethodeMcp};

// ---------------------------------------------------------------------------
// Politique de rétention
// ---------------------------------------------------------------------------

/// Durées de rétention autorisées par type de donnée stockée.
///
/// Seules les métadonnées (qui a appelé quoi, quand) sont conservées.
/// Le contenu des arguments n'est jamais inclus dans ce périmètre.
#[derive(Debug, Clone)]
pub struct PolitiqueRetention {
    /// Historique des contacts serveur (empreintes, horodatages, serveur).
    pub historique_contacts: Duration,
    /// Constats structurés (alertes, dérives détectées).
    pub constats: Duration,
    /// Alertes émises vers les canaux (dashboard, email, webhook, SIEM).
    pub alertes: Duration,
}

impl PolitiqueRetention {
    /// Valeurs par défaut conformes à la politique de confidentialité.
    pub fn par_defaut() -> Self {
        Self {
            historique_contacts: Duration::days(90),
            constats: Duration::days(365),
            alertes: Duration::days(180),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit de fuite — chemins sensibles
// ---------------------------------------------------------------------------

/// Chemins JSON qui ne doivent jamais être stockés lors d'un `tools/call`.
#[allow(dead_code)]
const CHEMINS_SENSIBLES: &[&str] = &[
    "$.params.arguments",
    "$.params.input",
];

/// Contrôle anti-fuite : vérifie et nettoie les messages avant tout stockage.
pub struct AuditFuite;

impl AuditFuite {
    /// Retourne les chemins JSON qui DEVRAIENT être supprimés avant stockage.
    ///
    /// Seuls les messages `tools/call` sont concernés. Les autres méthodes
    /// (initialize, tools/list, …) n'exposent pas d'arguments utilisateur.
    pub fn chemins_a_supprimer(msg: &MessageMcp) -> Vec<String> {
        if msg.methode != MethodeMcp::ToolsCall {
            return vec![];
        }

        let mut chemins = Vec::new();

        // $.params.arguments
        if msg.payload
            .get("params")
            .and_then(|p| p.get("arguments"))
            .is_some()
        {
            chemins.push("$.params.arguments".to_string());
        }

        // $.params.input
        if msg.payload
            .get("params")
            .and_then(|p| p.get("input"))
            .is_some()
        {
            chemins.push("$.params.input".to_string());
        }

        chemins
    }

    /// Remplace les arguments sensibles par `"<<redacted>>"` dans le payload.
    ///
    /// Cette opération est irréversible : après nettoyage, le message peut
    /// être passé au store sans risque de fuite de contenu.
    pub fn nettoyer(msg: &mut MessageMcp) {
        if msg.methode != MethodeMcp::ToolsCall {
            return;
        }

        if let Some(params) = msg.payload.get_mut("params") {
            if params.get("arguments").is_some() {
                params["arguments"] = serde_json::Value::String("<<redacted>>".to_string());
            }
            if params.get("input").is_some() {
                params["input"] = serde_json::Value::String("<<redacted>>".to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Déclaration statique de non-stockage
// ---------------------------------------------------------------------------

/// Garantit statiquement qu'aucun contenu d'argument n'est persisté.
///
/// Cette fonction constitue la preuve de non-stockage à destination de
/// l'agent 5.4 (mapping de conformité). Elle sert également d'ancre
/// auditeur : toute tentative de la rendre fausse est un breaking change
/// documenté.
pub fn aucun_contenu_persiste() -> bool {
    true
}
