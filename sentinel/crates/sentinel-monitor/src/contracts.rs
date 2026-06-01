//! Contrat surveillance ↔ détection (module 3) ↔ alertes (module 4) — agent 2.10.
//!
//! Version : 1.0.0. Les champs existants ne sont jamais supprimés ; tout ajout
//! porte une valeur par défaut pour ne pas casser les appelants existants.

use sentinel_protocol::{Empreinte, Outil, ServeurId, Severite, TypeConstat};

/// Version sémantique du contrat inter-modules.
/// Incrémentée uniquement lors d'un retrait ou renommage de champ.
pub const VERSION_CONTRAT: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Fait émis par la surveillance
// ---------------------------------------------------------------------------

/// Fait structuré émis par la surveillance vers la détection et les alertes.
///
/// Règles de stabilité :
/// - Champs `serveur_id`, `type_fait`, `empreinte_courante`, `baseline`,
///   `session_id`, `detail` : présents depuis la v1, jamais retirés.
/// - `outils_courants` et `severite_suggeree` : ajoutés en v1.0.0.
#[derive(Debug, Clone)]
pub struct FaitSurveillance {
    /// Identifiant stable du serveur MCP observé.
    pub serveur_id: ServeurId,
    /// Catégorie du fait (rug-pull, poisoning, nouveau serveur, …).
    pub type_fait: TypeConstat,
    /// Empreinte SHA-256 de la liste d'outils au moment du fait.
    pub empreinte_courante: Option<Empreinte>,
    /// Empreinte approuvée de référence (None si aucune baseline connue).
    pub baseline: Option<Empreinte>,
    /// Identifiant de la session MCP à l'origine du fait.
    pub session_id: String,
    /// Description lisible du fait (jamais les arguments d'appel).
    pub detail: String,
    /// Outils observés au moment du fait (utile pour la détection rug-pull).
    /// Vec vide par défaut si non pertinent.
    pub outils_courants: Vec<Outil>,
    /// Sévérité suggérée par la surveillance.
    /// La matrice alertes (module 4) peut la surcharger.
    pub severite_suggeree: Severite,
}

impl FaitSurveillance {
    /// Constructeur minimal : produit un fait valide avec les valeurs par défaut
    /// pour les champs ajoutés en v1.0.0 (`outils_courants` vide, sévérité Info).
    pub fn nouveau(
        serveur_id: ServeurId,
        type_fait: TypeConstat,
        session_id: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            serveur_id,
            type_fait,
            empreinte_courante: None,
            baseline: None,
            session_id: session_id.into(),
            detail: detail.into(),
            outils_courants: Vec::new(),
            severite_suggeree: Severite::Info,
        }
    }
}

// ---------------------------------------------------------------------------
// Trait de contrat
// ---------------------------------------------------------------------------

/// Canal abstrait d'émission de faits.
///
/// Implémenté par `ContratMpsc` (production) et `ContratMock` (tests).
/// Les modules 3 et 4 dépendent uniquement de ce trait.
#[async_trait::async_trait]
pub trait ContratSurveillance: Send + Sync {
    /// Émet un fait vers le module abonné.
    /// Retourne une erreur si le canal est fermé ou saturé.
    async fn emettre(&self, fait: FaitSurveillance) -> anyhow::Result<()>;
}

// ---------------------------------------------------------------------------
// Implémentation production : canal mpsc Tokio
// ---------------------------------------------------------------------------

/// Implémentation production du contrat sur un `Sender` Tokio.
pub struct ContratMpsc(pub tokio::sync::mpsc::Sender<FaitSurveillance>);

#[async_trait::async_trait]
impl ContratSurveillance for ContratMpsc {
    async fn emettre(&self, fait: FaitSurveillance) -> anyhow::Result<()> {
        self.0
            .send(fait)
            .await
            .map_err(|e| anyhow::anyhow!("ContratMpsc : canal fermé — {e}"))
    }
}

// ---------------------------------------------------------------------------
// Implémentation mock : collecte en mémoire pour tests modules 3, 4 et 5
// ---------------------------------------------------------------------------

/// Mock en mémoire du contrat.
///
/// Fourni aux modules 3, 4 et 5 pour avancer en parallèle sans dépendance
/// sur l'implémentation production.
pub struct ContratMock {
    pub faits: std::sync::Mutex<Vec<FaitSurveillance>>,
}

impl ContratMock {
    /// Crée un mock vide.
    pub fn nouveau() -> Self {
        Self {
            faits: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Retourne le nombre de faits collectés.
    pub fn nb_faits(&self) -> usize {
        self.faits.lock().unwrap().len()
    }

    /// Vide la collection (utile entre deux scénarios de test).
    pub fn vider(&self) {
        self.faits.lock().unwrap().clear();
    }
}

#[async_trait::async_trait]
impl ContratSurveillance for ContratMock {
    async fn emettre(&self, fait: FaitSurveillance) -> anyhow::Result<()> {
        self.faits.lock().unwrap().push(fait);
        Ok(())
    }
}
