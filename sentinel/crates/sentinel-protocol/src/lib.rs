//! sentinel-protocol — types partagés entre tous les modules de Sentinel MCP.
//!
//! Ce crate est intentionnellement sans logique métier. Il fixe les contrats
//! d'interface entre Capteur → Pipeline → Store → Interface, pour que les
//! cinq modules puissent évoluer en parallèle sans se bloquer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod ids {
    use super::*;
    pub type ServeurId = Uuid;
    pub type OutilId = Uuid;
    pub type SessionId = String;
    pub type ConstatId = Uuid;
    pub type AlerteId = Uuid;
    pub type BaselineId = Uuid;
}
pub use ids::*;

/// Transport MCP observé.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Stdio,
    Http,
}

/// Direction du message JSON-RPC sur le fil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientVersServeur,
    ServeurVersClient,
}

/// Méthode MCP reconnue par le pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MethodeMcp {
    Initialize,
    Initialized,
    ToolsList,
    ToolsCall,
    ResourcesList,
    PromptsList,
    ToolsListChanged,
    Autre(String),
}

impl MethodeMcp {
    pub fn from_str(s: &str) -> Self {
        match s {
            "initialize" => Self::Initialize,
            "notifications/initialized" => Self::Initialized,
            "tools/list" => Self::ToolsList,
            "tools/call" => Self::ToolsCall,
            "resources/list" => Self::ResourcesList,
            "prompts/list" => Self::PromptsList,
            "notifications/tools/list_changed" => Self::ToolsListChanged,
            other => Self::Autre(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Initialize => "initialize",
            Self::Initialized => "notifications/initialized",
            Self::ToolsList => "tools/list",
            Self::ToolsCall => "tools/call",
            Self::ResourcesList => "resources/list",
            Self::PromptsList => "prompts/list",
            Self::ToolsListChanged => "notifications/tools/list_changed",
            Self::Autre(s) => s,
        }
    }
}

/// Événement brut émis par le capteur, format unifié stdio/HTTP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvenementBrut {
    pub session_id: SessionId,
    pub transport: Transport,
    pub serveur: String,
    pub direction: Direction,
    pub methode: Option<String>,
    pub payload: serde_json::Value,
    pub horodatage: DateTime<Utc>,
}

/// Message MCP confirmé après filtrage de signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMcp {
    pub session_id: SessionId,
    pub transport: Transport,
    pub serveur: String,
    pub direction: Direction,
    pub methode: MethodeMcp,
    pub id_jsonrpc: Option<serde_json::Value>,
    pub payload: serde_json::Value,
    pub horodatage: DateTime<Utc>,
}

/// Outil exposé par un serveur MCP (extrait de `tools/list`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outil {
    pub nom: String,
    pub description: Option<String>,
    /// `inputSchema` complet, brut, conservé pour empreinte canonique.
    pub input_schema: serde_json::Value,
    /// Métadonnées libres (annotations, etc.).
    #[serde(default)]
    pub meta: BTreeMap<String, serde_json::Value>,
}

/// Portée fonctionnelle inférée d'un serveur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Portee {
    Filesystem,
    BaseDonnees,
    ApiExterne,
    Secrets,
    Reseau,
    Lecture,
    Ecriture,
    Inconnu,
}

/// Statut opérationnel d'un serveur dans l'inventaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatutServeur {
    Approuve,
    Inconnu,
    Suspect,
    AInvestiguer,
    Bloque,
}

/// Couleur de criticité présentée à l'utilisateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Couleur {
    Vert,
    Orange,
    Rouge,
}

/// Description d'un serveur dans l'inventaire (vue store).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Serveur {
    pub id: ServeurId,
    pub endpoint: String,
    pub transport: Transport,
    pub portees: Vec<Portee>,
    pub statut: StatutServeur,
    pub couleur: Couleur,
    pub premiere_vue: DateTime<Utc>,
    pub derniere_vue: DateTime<Utc>,
    pub empreinte_courante: Option<String>,
}

/// Empreinte SHA-256 d'un outil ou d'un serveur (hex lower-case).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Empreinte(pub String);

impl Empreinte {
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Baseline approuvée d'un serveur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub id: BaselineId,
    pub serveur_id: ServeurId,
    pub empreinte_serveur: Empreinte,
    pub empreintes_outils: BTreeMap<String, Empreinte>,
    pub outils: Vec<Outil>,
    pub date_approbation: DateTime<Utc>,
    pub approuve_par: String,
}

/// Sévérité d'un constat / d'une alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severite {
    Info,
    Moyenne,
    Haute,
    Critique,
}

/// Catégorie de constat produit par le pipeline ou la surveillance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeConstat {
    NouveauServeur,
    ShadowMcp,
    RugPull,
    Poisoning,
    Sosie,
    Exfiltration,
    SansAuthentification,
    DeriveInterSession,
    Autre,
}

/// État du cycle de vie d'un constat / d'une alerte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtatConstat {
    Ouvert,
    Investigue,
    Resolu,
    Ignore,
}

/// Constat structuré écrit dans le store par le pipeline / la surveillance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constat {
    pub id: ConstatId,
    pub serveur_id: ServeurId,
    pub outil_nom: Option<String>,
    pub type_constat: TypeConstat,
    pub severite: Severite,
    pub titre: String,
    pub detail: String,
    /// Diff lisible (Markdown) si pertinent (rug-pull).
    pub diff: Option<String>,
    /// Mapping de conformité (OWASP MCP09, MCP03, SAFE-T1001, SAFE-T1201, …).
    #[serde(default)]
    pub references_conformite: Vec<String>,
    pub horodatage: DateTime<Utc>,
    pub etat: EtatConstat,
}

/// Canal d'émission d'alerte.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanalAlerte {
    Dashboard,
    Email,
    Webhook,
    Siem,
}

/// Alerte émise vers un canal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alerte {
    pub id: AlerteId,
    pub constat_id: ConstatId,
    pub canal: CanalAlerte,
    pub severite: Severite,
    pub titre: String,
    pub message: String,
    pub diff: Option<String>,
    pub horodatage: DateTime<Utc>,
    pub envoyee: bool,
    pub tentatives: u32,
}

/// Erreur générique du pipeline / store.
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("erreur de parsing JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("erreur d'IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("erreur store: {0}")]
    Store(String),
    #[error("erreur protocole MCP: {0}")]
    Protocole(String),
    #[error("autre: {0}")]
    Autre(String),
}

pub type Resultat<T> = std::result::Result<T, SentinelError>;
