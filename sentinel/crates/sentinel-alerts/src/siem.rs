//! Préparation SIEM (v2) — agent 4.9.
//!
//! Ce module définit le contrat de sortie SIEM sans implémenter de transport HTTP.
//! L'architecture anticipe la v2 (intégration native SIEM) par un trait extensible
//! et trois formats de sérialisation standard : CEF, LEEF, ECS.

use chrono::SecondsFormat;
use sentinel_protocol::{Alerte, Severite};

// ─── Enregistrement SIEM ────────────────────────────────────────────────────

/// Enregistrement normalisé destiné à un SIEM.
/// Tous les champs sont sérialisables JSON ; `diff` est facultatif.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnregistrementSiem {
    /// Identifiant de la source — toujours "sentinel-mcp".
    pub source: &'static str,
    /// Catégorie fonctionnelle : "shadow-mcp", "rug-pull", "poisoning", etc.
    pub categorie: &'static str,
    /// Gravité textuelle normalisée : "INFO", "MEDIUM", "HIGH", "CRITICAL".
    pub gravite: &'static str,
    /// Message humain lisible.
    pub message: String,
    /// Références de conformité (OWASP MCP09, SAFE-T1001, …).
    pub references: Vec<String>,
    /// Horodatage ISO-8601 UTC.
    pub horodatage_iso8601: String,
    /// Identifiant UUID de l'alerte d'origine.
    pub alerte_id: String,
    /// Diff Markdown (rug-pull, drift) si disponible.
    pub diff: Option<String>,
}

// ─── Mapping de sévérité ────────────────────────────────────────────────────

/// Convertit une `Severite` en chaîne SIEM standard.
pub fn gravite_siem(s: Severite) -> &'static str {
    match s {
        Severite::Info    => "INFO",
        Severite::Moyenne => "MEDIUM",
        Severite::Haute   => "HIGH",
        Severite::Critique => "CRITICAL",
    }
}

// ─── Mapping de catégorie ───────────────────────────────────────────────────

/// Déduit une catégorie SIEM lisible depuis le titre de l'alerte.
///
/// Convention : le pipeline place les mots-clés canoniques dans le titre.
/// En l'absence de correspondance, "autre" est retourné.
fn categorie_depuis_titre(titre: &str) -> &'static str {
    let t = titre.to_ascii_lowercase();
    if t.contains("shadow") {
        "shadow-mcp"
    } else if t.contains("rug-pull") || t.contains("rug pull") || t.contains("rugpull") {
        "rug-pull"
    } else if t.contains("poison") {
        "poisoning"
    } else if t.contains("sosie") || t.contains("imposteur") {
        "sosie"
    } else if t.contains("exfiltration") {
        "exfiltration"
    } else if t.contains("dérive") || t.contains("drift") {
        "derive-inter-session"
    } else {
        "autre"
    }
}

// ─── Trait ContratSiem ───────────────────────────────────────────────────────

/// Point d'extension : tout adaptateur SIEM tiers doit implémenter ce trait.
///
/// La méthode est statique pour rester sans état (règle pipeline sans état).
/// En v2, un adaptateur par SIEM cible (Splunk, QRadar, Elastic) sera branché ici.
pub trait ContratSiem {
    fn vers_enregistrement(a: &Alerte) -> EnregistrementSiem;
}

// ─── Implémentation de référence ─────────────────────────────────────────────

/// Adaptateur standard : produit un `EnregistrementSiem` canonique depuis une `Alerte`.
pub struct AdaptateurStandard;

impl ContratSiem for AdaptateurStandard {
    fn vers_enregistrement(a: &Alerte) -> EnregistrementSiem {
        EnregistrementSiem {
            source: "sentinel-mcp",
            categorie: categorie_depuis_titre(&a.titre),
            gravite: gravite_siem(a.severite),
            message: a.message.clone(),
            // Les références de conformité ne sont pas portées par `Alerte` directement ;
            // le champ est laissé vide ici — l'enrichisseur de v2 le peuplera via le
            // `Constat` d'origine.  Le champ est maintenu dans le contrat pour la v2.
            references: Vec::new(),
            horodatage_iso8601: a.horodatage.to_rfc3339_opts(SecondsFormat::Millis, true),
            alerte_id: a.id.to_string(),
            diff: a.diff.clone(),
        }
    }
}

// ─── Formats de sortie ───────────────────────────────────────────────────────

/// Produit une ligne **CEF** (ArcSight Common Event Format).
///
/// Format :
/// `CEF:0|Sentinel|MCP|1.0|<categorie>|<message>|<gravite_num>|cs1=<alerte_id> cs1Label=AlerteId ...`
pub fn vers_cef(e: &EnregistrementSiem) -> String {
    // Échappement CEF : `|` et `\` dans les champs de l'en-tête doivent être échappés.
    let message_safe = e.message.replace('\\', "\\\\").replace('|', "\\|");
    let categorie_safe = e.categorie.replace('\\', "\\\\").replace('|', "\\|");

    // Gravité numérique CEF déduite depuis la chaîne textuelle.
    let gravite_num: u8 = match e.gravite {
        "INFO"     => 1,
        "MEDIUM"   => 5,
        "HIGH"     => 8,
        "CRITICAL" => 10,
        _          => 0,
    };

    let extensions = format!(
        "cs1={} cs1Label=AlerteId src={} rt={} cat={}{}",
        e.alerte_id,
        e.source,
        e.horodatage_iso8601,
        e.categorie,
        e.diff.as_deref().map(|d| format!(" reason={}", d.replace('\n', " "))).unwrap_or_default(),
    );

    format!(
        "CEF:0|Sentinel|MCP|1.0|{}|{}|{}|{}",
        categorie_safe, message_safe, gravite_num, extensions
    )
}

/// Produit une ligne **LEEF** (IBM QRadar Log Event Extended Format).
///
/// Format :
/// `LEEF:2.0|Sentinel|MCP|1.0|<categorie>|^|<champs tab-séparés>`
pub fn vers_leef(e: &EnregistrementSiem) -> String {
    // LEEF 2.0 utilise `^` comme délimiteur de champs dans l'en-tête étendu.
    let champs = [
        format!("devTime={}", e.horodatage_iso8601),
        format!("sev={}", e.gravite),
        format!("cat={}", e.categorie),
        format!("msg={}", e.message.replace('\t', " ").replace('\n', " ")),
        format!("src={}", e.source),
        format!("alerteId={}", e.alerte_id),
    ]
    .join("\t");

    format!(
        "LEEF:2.0|Sentinel|MCP|1.0|{}|^|{}",
        e.categorie, champs
    )
}

/// Produit un objet JSON conforme **ECS** (Elastic Common Schema) v8.
///
/// Champs minimaux garantis : `@timestamp`, `event.category`, `event.severity`,
/// `event.dataset`, `message`, `labels.alerte_id`, `labels.source`.
pub fn vers_ecs_json(e: &EnregistrementSiem) -> serde_json::Value {
    let gravite_num: u8 = match e.gravite {
        "INFO"     => 1,
        "MEDIUM"   => 5,
        "HIGH"     => 8,
        "CRITICAL" => 10,
        _          => 0,
    };

    let mut val = serde_json::json!({
        "@timestamp": e.horodatage_iso8601,
        "event": {
            "category": ["intrusion_detection"],
            "type": ["info"],
            "dataset": "sentinel.mcp",
            "severity": gravite_num,
            "kind": "alert",
            "provider": e.source,
            "action": e.categorie,
        },
        "message": e.message,
        "labels": {
            "alerte_id": e.alerte_id,
            "source": e.source,
            "categorie": e.categorie,
            "gravite": e.gravite,
        },
        "tags": ["sentinel-mcp", e.categorie],
    });

    // Champ optionnel : diff présent seulement si renseigné (pas de null dans ECS).
    if let Some(diff) = &e.diff {
        val["event"]["reason"] = serde_json::Value::String(diff.clone());
    }

    // Références de conformité si présentes.
    if !e.references.is_empty() {
        val["related"]["compliance"] = serde_json::Value::Array(
            e.references.iter().map(|r| serde_json::Value::String(r.clone())).collect(),
        );
    }

    val
}
