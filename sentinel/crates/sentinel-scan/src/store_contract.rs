//! Contrat scan → store — version 1.0.0
//!
//! Interface stable par laquelle le pipeline de scan écrit serveurs et outils
//! dans le store. Les modules 2, 3 et 5 consomment ce contrat via le mock.
//!
//! Règles :
//! - Statut initial `StatutServeur::Inconnu`, couleur `Couleur::Orange`.
//! - Empreinte outil : placeholder vide (module 3 calcule la vraie valeur).
//! - Upsert idempotent sur `endpoint` : `premiere_vue` préservée si connu.

use async_trait::async_trait;
use chrono::Utc;
use sentinel_protocol::{
    Couleur, Empreinte, Outil, Portee, Serveur, ServeurId, StatutServeur, Transport,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Événement produit par le pipeline de scan
// ---------------------------------------------------------------------------

/// Événement émis par le pipeline (agents 1.3, 1.6, 1.7) quand un serveur
/// MCP est découvert ou re-observé. Version du contrat : 1.
#[derive(Debug, Clone)]
pub struct EvenementInventaire {
    pub endpoint: String,
    pub transport: Transport,
    pub outils: Vec<Outil>,
    pub portees: Vec<Portee>,
}

// ---------------------------------------------------------------------------
// Trait principal
// ---------------------------------------------------------------------------

/// API par laquelle le scan écrit dans le store.
///
/// Contrat v1 — stable pour les modules 2, 3 et 5.
#[async_trait]
pub trait ContratScanStore: Send + Sync {
    /// Enregistre ou met à jour un serveur et ses outils.
    /// Retourne le `ServeurId` (nouveau ou existant).
    async fn enregistrer_inventaire(&self, e: EvenementInventaire) -> anyhow::Result<ServeurId>;

    /// Retourne la liste complète des serveurs connus.
    async fn lister_serveurs(&self) -> anyhow::Result<Vec<Serveur>>;
}

// ---------------------------------------------------------------------------
// Adaptateur réel — `sentinel_store::Store`
// ---------------------------------------------------------------------------

/// Implémente `ContratScanStore` sur le store SQLite embarqué.
pub struct AdaptateurStore {
    store: sentinel_store::Store,
}

impl AdaptateurStore {
    pub fn nouveau(store: sentinel_store::Store) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ContratScanStore for AdaptateurStore {
    async fn enregistrer_inventaire(&self, e: EvenementInventaire) -> anyhow::Result<ServeurId> {
        let store = self.store.clone();
        let maintenant = Utc::now();

        // Résolution upsert : préserver `premiere_vue` si le serveur est déjà connu.
        let serveur = match store.get_serveur_par_endpoint(&e.endpoint)? {
            Some(existant) => Serveur {
                derniere_vue: maintenant,
                portees: e.portees.clone(),
                ..existant
            },
            None => Serveur {
                id: Uuid::new_v4(),
                endpoint: e.endpoint.clone(),
                transport: e.transport,
                portees: e.portees.clone(),
                statut: StatutServeur::Inconnu,
                couleur: Couleur::Orange,
                premiere_vue: maintenant,
                derniere_vue: maintenant,
                empreinte_courante: None,
            },
        };

        let serveur_id = serveur.id;
        store.upsert_serveur(&serveur)?;

        // Upsert de chaque outil avec empreinte placeholder.
        let empreinte_placeholder = Empreinte::new("");
        for outil in &e.outils {
            store.upsert_outil(serveur_id, outil, &empreinte_placeholder)?;
        }

        Ok(serveur_id)
    }

    async fn lister_serveurs(&self) -> anyhow::Result<Vec<Serveur>> {
        Ok(self.store.lister_serveurs()?)
    }
}

// ---------------------------------------------------------------------------
// Mock — pour les modules 2, 3 et 5
// ---------------------------------------------------------------------------

/// Mock en mémoire du contrat. Utilisé par les autres modules pour avancer
/// en parallèle sans dépendre du store SQLite.
pub struct MockStore {
    pub inventaires: std::sync::Mutex<Vec<EvenementInventaire>>,
}

impl MockStore {
    pub fn nouveau() -> Self {
        Self {
            inventaires: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl ContratScanStore for MockStore {
    async fn enregistrer_inventaire(&self, e: EvenementInventaire) -> anyhow::Result<ServeurId> {
        let id = Uuid::new_v4();
        self.inventaires.lock().unwrap().push(e);
        Ok(id)
    }

    async fn lister_serveurs(&self) -> anyhow::Result<Vec<Serveur>> {
        // Le mock retourne des serveurs synthétiques depuis les inventaires enregistrés.
        let maintenant = Utc::now();
        let inventaires = self.inventaires.lock().unwrap();
        let serveurs = inventaires
            .iter()
            .map(|e| Serveur {
                id: Uuid::new_v4(),
                endpoint: e.endpoint.clone(),
                transport: e.transport,
                portees: e.portees.clone(),
                statut: StatutServeur::Inconnu,
                couleur: Couleur::Orange,
                premiere_vue: maintenant,
                derniere_vue: maintenant,
                empreinte_courante: None,
            })
            .collect();
        Ok(serveurs)
    }
}
