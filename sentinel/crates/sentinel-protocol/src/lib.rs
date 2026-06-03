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

/// Portée de déclaration d'un serveur MCP.
///
/// Source-of-truth unique pour le **wire format** (commandes Tauri →
/// UI) et le **stockage SQL** (colonne `serveurs.scope` ajoutée par
/// la migration V3). La sérialisation SQL passe par `vers_sql` /
/// `depuis_sql` ; la sérialisation JSON suit le pattern serde
/// `tag = "kind"` pour rester explicite côté UI.
///
/// Un même serveur peut être déclaré au niveau utilisateur
/// (`mcpServers` racine de `.claude.json`) ou au niveau projet
/// (`projects.<chemin>.mcpServers`). Les deux cas coexistent et la
/// dédup user/project est gérée à la couche de découverte.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ScopeServeur {
    /// Scope utilisateur (top-level `mcpServers`).
    User,
    /// Scope projet (`projects.<path>.mcpServers`).
    ///
    /// `path` est stocké comme `String` (et non `PathBuf`) pour que le
    /// type reste sérialisable JSON sans gymnastique et que la wire
    /// representation soit stable cross-plateforme.
    Project { path: String },
}

impl Default for ScopeServeur {
    fn default() -> Self {
        ScopeServeur::User
    }
}

impl ScopeServeur {
    /// Sérialise vers la colonne TEXT `serveurs.scope`.
    ///
    /// Format : `"user"` ou `"project:<chemin>"`. Le premier `:` après
    /// `project` est le séparateur ; un chemin contenant des `:`
    /// (e.g. Windows `C:\Users\...`) est conservé tel quel et reparsé
    /// correctement par `depuis_sql` via `strip_prefix("project:")`.
    pub fn vers_sql(&self) -> String {
        match self {
            ScopeServeur::User => "user".to_string(),
            ScopeServeur::Project { path } => format!("project:{}", path),
        }
    }

    /// Parse une valeur lue depuis la colonne SQL `serveurs.scope`.
    ///
    /// Toute valeur inconnue (ou ancienne par défaut `user`) retombe
    /// sur `ScopeServeur::User`.
    pub fn depuis_sql(s: &str) -> Self {
        if let Some(rest) = s.strip_prefix("project:") {
            ScopeServeur::Project {
                path: rest.to_string(),
            }
        } else {
            ScopeServeur::User
        }
    }
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
    /// Étiquettes libres ajoutées par l'opérateur (env, owner, sensibilité…).
    /// `#[serde(default)]` pour rétrocompat des JSON existants qui ne portent
    /// pas encore le champ.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Portée de déclaration : utilisateur (top-level) ou projet
    /// (`projects.<path>.mcpServers`). `#[serde(default)]` pour la
    /// rétrocompat des wire payloads et des baselines persistées.
    #[serde(default)]
    pub scope: ScopeServeur,
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

/// Extrait l'identité canonique d'un serveur MCP depuis son `endpoint` et
/// son `transport`. C'est cette identité — pas la ligne de commande brute
/// — qui sert de clé de dédup au store et de discriminateur d'identité au
/// détecteur de sosies.
///
/// Pour un transport stdio, on cherche le **paquet** invoqué par la ligne
/// de commande : `npx -y @scope/pkg arg1 arg2` → `@scope/pkg`. Les suffixes
/// de version (`pkg@1.2.3`, `pkg@latest`) sont retirés. Les wrappers
/// reconnus (`npx`, `uvx`, `bunx`, `pnpm exec`, `npm exec`, `yarn dlx`,
/// `deno run`) sont strippés ; les flags entre le wrapper et le paquet
/// (`-y`, `--yes`, …) sont ignorés. Quand rien ne matche un wrapper connu,
/// le premier token (qui est lui-même le binaire) sert d'identité.
///
/// Pour un transport HTTP, l'identité est `host[:port]` issu de l'URL,
/// indépendant du chemin et de la query — deux clients qui pointent vers
/// `https://api.example.com/mcp` et `https://api.example.com/mcp?token=…`
/// désignent le même endpoint logique.
///
/// La fonction est **totale** : elle retourne toujours quelque chose,
/// quitte à renvoyer l'endpoint trimé en dernier recours. Aucun panic
/// possible.
pub fn extraire_package_id(endpoint: &str, transport: Transport) -> String {
    match transport {
        Transport::Http => extraire_host_port(endpoint).unwrap_or_else(|| endpoint.trim().to_string()),
        Transport::Stdio => extraire_package_stdio(endpoint),
    }
}

/// Parse `scheme://[user[:pass]@]host[:port][/...]` sans dépendre d'une
/// crate URL. Renvoie `host[:port]` quand le parsing réussit, `None`
/// sinon.
fn extraire_host_port(url: &str) -> Option<String> {
    let trim = url.trim();
    let after_scheme = trim.split_once("://").map(|(_, rest)| rest).unwrap_or(trim);
    // Coupe au premier `/`, `?` ou `#`.
    let authority_end = after_scheme
        .find(|c: char| c == '/' || c == '?' || c == '#')
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Strip userinfo si présent.
    let host_port = authority.rsplit_once('@').map(|(_, hp)| hp).unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }
    Some(host_port.to_string())
}

/// Extrait le paquet d'une ligne de commande stdio. Liste les wrappers
/// connus puis cherche le premier argument non-flag derrière. Si rien ne
/// matche, on retombe sur le premier token (le binaire lui-même).
fn extraire_package_stdio(endpoint: &str) -> String {
    let tokens: Vec<&str> = endpoint.split_whitespace().collect();
    if tokens.is_empty() {
        return endpoint.trim().to_string();
    }

    // Wrappers à un seul mot (`npx pkg`, `uvx pkg`, `bunx pkg`, `pnpx pkg`).
    const WRAPPERS_DIRECTS: &[&str] = &["npx", "uvx", "bunx", "pnpx"];
    // Wrappers à deux mots (`npm exec pkg`, `pnpm exec pkg`, `yarn dlx pkg`,
    // `deno run pkg`, …).
    const WRAPPERS_DOUBLES: &[(&str, &[&str])] = &[
        ("npm", &["exec", "x"]),
        ("pnpm", &["exec", "dlx"]),
        ("yarn", &["dlx", "exec"]),
        ("deno", &["run"]),
        ("bun", &["x", "run"]),
    ];

    let start = if WRAPPERS_DIRECTS.contains(&tokens[0]) {
        1
    } else if tokens.len() >= 2
        && WRAPPERS_DOUBLES
            .iter()
            .any(|(cmd, subs)| *cmd == tokens[0] && subs.contains(&tokens[1]))
    {
        2
    } else {
        // Pas de wrapper reconnu : le binaire lui-même est l'identité.
        return strip_version_suffix(tokens[0]);
    };

    for tok in &tokens[start..] {
        // `--` est un terminateur d'options : on passe au token suivant
        // mais on continue à le considérer comme une zone de flags.
        if *tok == "--" {
            continue;
        }
        if tok.starts_with('-') {
            continue;
        }
        return strip_version_suffix(tok);
    }
    endpoint.trim().to_string()
}

/// Retire un éventuel suffixe `@version` ou `@latest`. Gère le cas
/// scopé (`@scope/pkg@version` → `@scope/pkg`) où le premier `@` fait
/// partie du nom et ne doit pas être confondu avec le séparateur de
/// version.
fn strip_version_suffix(s: &str) -> String {
    if let Some(rest) = s.strip_prefix('@') {
        if let Some(slash) = rest.find('/') {
            let after_slash = &rest[slash + 1..];
            if let Some(at) = after_slash.find('@') {
                return format!("@{}/{}", &rest[..slash], &after_slash[..at]);
            }
        }
        return s.to_string();
    }
    match s.find('@') {
        Some(at) => s[..at].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests_package_id {
    use super::*;

    #[test]
    fn npx_paquet_scope_avec_args_ignores() {
        assert_eq!(
            extraire_package_id(
                "npx -y @modelcontextprotocol/server-postgres postgresql://localhost:5432/db",
                Transport::Stdio,
            ),
            "@modelcontextprotocol/server-postgres"
        );
    }

    #[test]
    fn npx_paquet_simple_avec_version_strippee() {
        assert_eq!(
            extraire_package_id("npx chrome-devtools-mcp@latest", Transport::Stdio),
            "chrome-devtools-mcp"
        );
    }

    #[test]
    fn npx_paquet_scope_avec_version() {
        assert_eq!(
            extraire_package_id("npx -y @anthropic-ai/mcp@1.2.3", Transport::Stdio),
            "@anthropic-ai/mcp"
        );
    }

    #[test]
    fn uvx_paquet_python() {
        assert_eq!(
            extraire_package_id("uvx mcp-server-time --tz Europe/Paris", Transport::Stdio),
            "mcp-server-time"
        );
    }

    #[test]
    fn npm_exec_paquet() {
        assert_eq!(
            extraire_package_id("npm exec -- mcp-toolbox --port 8080", Transport::Stdio),
            "mcp-toolbox"
        );
    }

    #[test]
    fn binaire_direct_sans_wrapper() {
        // Cas où l'utilisateur a installé le binaire localement (les sosies
        // honeypots de la démo).
        assert_eq!(
            extraire_package_id("filesystm-mcp", Transport::Stdio),
            "filesystm-mcp"
        );
        assert_eq!(
            extraire_package_id("mcp-postgres-helper /path/to/db", Transport::Stdio),
            "mcp-postgres-helper"
        );
    }

    #[test]
    fn http_host_port() {
        assert_eq!(
            extraire_package_id("http://localhost:8765/mcp", Transport::Http),
            "localhost:8765"
        );
        assert_eq!(
            extraire_package_id(
                "https://api.example.com/v1/mcp?token=abc",
                Transport::Http,
            ),
            "api.example.com"
        );
    }

    #[test]
    fn http_avec_userinfo() {
        assert_eq!(
            extraire_package_id("https://user:pass@mcp.example.com:8443/path", Transport::Http),
            "mcp.example.com:8443"
        );
    }

    #[test]
    fn deux_endpoints_meme_paquet_meme_id() {
        // Le cœur du fix : deux configs déclarant le même paquet officiel
        // avec des args différents ont le même `package_id`.
        let a = extraire_package_id(
            "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/db_dev",
            Transport::Stdio,
        );
        let b = extraire_package_id(
            "npx -y @modelcontextprotocol/server-postgres postgresql://localhost/db_test",
            Transport::Stdio,
        );
        assert_eq!(a, b);
        assert_eq!(a, "@modelcontextprotocol/server-postgres");
    }
}
