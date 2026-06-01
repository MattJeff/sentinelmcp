//! Détection de sosies (mode C registres) — agents 3.8 (lead) et 3.9 (similarité/SBOM).
//!
//! Architecture mode C :
//!   ConnecteurRegistres agrège N sources (trait SourceRegistre).
//!   Chaque source est interrogeable individuellement ou en bloc (interroger_tous).
//!   Les 4 sources prédéfinies sont des stubs v1 — les vraies requêtes HTTP arrivent en v2.
//!   SourceStatique permet l'injection de données de test sans réseau.

pub mod similarity;

use std::sync::Arc;

use futures::future::BoxFuture;

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

/// Entrée canonique issue d'un registre public MCP.
#[derive(Debug, Clone, PartialEq)]
pub struct EntreeRegistre {
    /// Identifiant court du registre source (ex. "pulsemcp", "smithery").
    pub registre: String,
    /// Nom du serveur tel qu'annoncé dans le registre.
    pub nom: String,
    /// Description courte du serveur.
    pub description: String,
    /// Hash SHA-256 du binaire annoncé, le cas échéant.
    pub hash_binaire: Option<String>,
    /// URL du document SBOM pour vérification agent 3.9.
    pub sbom_url: Option<String>,
    /// Organisation ou individu ayant publié le serveur.
    pub publie_par: Option<String>,
    /// URL de déploiement ou dépôt du serveur.
    pub url_serveur: Option<String>,
}

// ---------------------------------------------------------------------------
// Trait source
// ---------------------------------------------------------------------------

/// Contrat qu'implémente chaque connecteur de registre public.
pub trait SourceRegistre: Send + Sync {
    /// Renvoie la liste de toutes les entrées exposées par ce registre.
    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>>;

    /// Nom court du registre (pour audit et corrélation).
    fn nom(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Connecteur principal
// ---------------------------------------------------------------------------

/// Agrège plusieurs sources de registres et les interroge en parallèle ou par nom.
pub struct ConnecteurRegistres {
    pub sources: Vec<Arc<dyn SourceRegistre>>,
}

impl ConnecteurRegistres {
    /// Crée un connecteur vide — ajouter des sources via `ajouter`.
    pub fn nouveau() -> Self {
        Self { sources: Vec::new() }
    }

    /// Ajoute une source au connecteur.
    pub fn ajouter(&mut self, source: Arc<dyn SourceRegistre>) {
        self.sources.push(source);
    }

    /// Interroge une seule source identifiée par son nom court.
    /// Retourne une erreur si aucune source ne correspond au nom fourni.
    pub async fn interroger(&self, nom_registre: &str) -> anyhow::Result<Vec<EntreeRegistre>> {
        for source in &self.sources {
            if source.nom() == nom_registre {
                return source.lister().await;
            }
        }
        anyhow::bail!("registre inconnu : {}", nom_registre)
    }

    /// Interroge toutes les sources et retourne leurs résultats (même en cas d'erreur partielle).
    pub async fn interroger_tous(&self) -> Vec<(String, anyhow::Result<Vec<EntreeRegistre>>)> {
        let mut resultats = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            let nom = source.nom().to_string();
            let res = source.lister().await;
            resultats.push((nom, res));
        }
        resultats
    }
}

// ---------------------------------------------------------------------------
// Sources prédéfinies (stubs v1 — appels HTTP en v2)
// ---------------------------------------------------------------------------

/// Connecteur vers PulseMCP (https://pulsemcp.com/api).
/// V1 : stub sans appel réseau. V2 : GET /api/servers avec pagination.
pub struct SourcePulseMCP;

impl SourcePulseMCP {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourcePulseMCP {
    fn nom(&self) -> &'static str {
        "pulsemcp"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move {
            // TODO v2 : GET https://pulsemcp.com/api/servers?page=1&limit=100
            Ok(Vec::new())
        })
    }
}

/// Connecteur vers le registre officiel MCP (https://github.com/modelcontextprotocol/servers).
/// V1 : stub sans appel réseau. V2 : lecture du fichier registry.json via GitHub API.
pub struct SourceMcpRegistry;

impl SourceMcpRegistry {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourceMcpRegistry {
    fn nom(&self) -> &'static str {
        "mcp-registry"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move {
            // TODO v2 : GET https://api.github.com/repos/modelcontextprotocol/servers/contents/registry.json
            Ok(Vec::new())
        })
    }
}

/// Connecteur vers Smithery (https://smithery.ai).
/// V1 : stub sans appel réseau. V2 : GET /api/packages avec pagination.
pub struct SourceSmithery;

impl SourceSmithery {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourceSmithery {
    fn nom(&self) -> &'static str {
        "smithery"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move {
            // TODO v2 : GET https://smithery.ai/api/packages?page=1&limit=50
            Ok(Vec::new())
        })
    }
}

/// Connecteur vers mcp.so (https://mcp.so).
/// V1 : stub sans appel réseau. V2 : parsing du catalogue JSON public.
pub struct SourceMcpSo;

impl SourceMcpSo {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourceMcpSo {
    fn nom(&self) -> &'static str {
        "mcp.so"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move {
            // TODO v2 : GET https://mcp.so/api/catalog
            Ok(Vec::new())
        })
    }
}

// ---------------------------------------------------------------------------
// Source statique — injection de test
// ---------------------------------------------------------------------------

/// Source de test injectable : retourne des entrées fixées à la construction.
/// Permet de tester ConnecteurRegistres sans réseau.
pub struct SourceStatique {
    pub nom: &'static str,
    pub entrees: Vec<EntreeRegistre>,
}

impl SourceStatique {
    pub fn nouveau(nom: &'static str, entrees: Vec<EntreeRegistre>) -> Arc<dyn SourceRegistre> {
        Arc::new(Self { nom, entrees })
    }
}

impl SourceRegistre for SourceStatique {
    fn nom(&self) -> &'static str {
        self.nom
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        let entrees = self.entrees.clone();
        Box::pin(async move { Ok(entrees) })
    }
}
