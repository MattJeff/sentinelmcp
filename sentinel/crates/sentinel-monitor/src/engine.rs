//! Lead surveillance continue — agent 2.1.
//!
//! Moteur principal : consomme des `MessageMcp`, enregistre chaque contact
//! dans le store, émet des `FaitSurveillance` vers la détection et les alertes.

use anyhow::Result;
use chrono::Utc;
use sentinel_protocol::{
    Couleur, Empreinte, MessageMcp, MethodeMcp, Portee, Serveur, ServeurId, StatutServeur,
    TypeConstat,
};
use sentinel_store::Store;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::contracts::FaitSurveillance;

// ---------------------------------------------------------------------------
// MoteurSurveillance
// ---------------------------------------------------------------------------

/// Boucle de surveillance permanente.
pub struct MoteurSurveillance {
    pub store: Store,
    pub recepteur_messages: mpsc::Receiver<MessageMcp>,
    pub emetteur_faits: mpsc::Sender<FaitSurveillance>,
    /// Compteur de serveurs distincts vus en mémoire (endpoint → ServeurId).
    serveurs_vus: HashMap<String, ServeurId>,
}

impl MoteurSurveillance {
    pub fn nouveau(
        store: Store,
        recepteur_messages: mpsc::Receiver<MessageMcp>,
        emetteur_faits: mpsc::Sender<FaitSurveillance>,
    ) -> Self {
        Self {
            store,
            recepteur_messages,
            emetteur_faits,
            serveurs_vus: HashMap::new(),
        }
    }

    /// Boucle principale — s'arrête quand le canal d'entrée est fermé.
    pub async fn boucle(mut self) -> Result<()> {
        info!("MoteurSurveillance démarré");

        while let Some(msg) = self.recepteur_messages.recv().await {
            if let Err(e) = self.traiter_message(msg).await {
                warn!("Erreur traitement message : {e}");
            }
        }

        info!("MoteurSurveillance arrêté (canal fermé)");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Logique interne
    // -----------------------------------------------------------------------

    async fn traiter_message(&mut self, msg: MessageMcp) -> Result<()> {
        let serveur_id = self.resoudre_serveur_id(&msg).await?;

        // Enregistrement du contact (bloquant, délégué à spawn_blocking dans le store).
        let methode_str = msg.methode.as_str().to_owned();
        let store = self.store.clone();
        let session = msg.session_id.clone();
        let ts = msg.horodatage;
        tokio::task::spawn_blocking(move || {
            store.enregistrer_contact(serveur_id, &session, &methode_str, ts)
        })
        .await??;

        debug!(
            serveur = %msg.serveur,
            methode = %msg.methode.as_str(),
            "contact enregistré"
        );

        // Émission d'un fait si la réponse contient une liste d'outils.
        if self.est_reponse_tools_list(&msg) {
            let fait = self.construire_fait(serveur_id, &msg);
            if let Err(e) = self.emetteur_faits.send(fait).await {
                warn!("Canal faits fermé, fait perdu : {e}");
            }
        }

        Ok(())
    }

    /// Résout ou crée l'identifiant du serveur à partir de son endpoint.
    async fn resoudre_serveur_id(&mut self, msg: &MessageMcp) -> Result<ServeurId> {
        if let Some(&id) = self.serveurs_vus.get(&msg.serveur) {
            return Ok(id);
        }

        // Vérifie si le serveur existe déjà en base.
        let store = self.store.clone();
        let endpoint = msg.serveur.clone();
        let transport = msg.transport;

        let serveur_id = tokio::task::spawn_blocking(move || -> Result<ServeurId> {
            if let Some(s) = store.get_serveur_par_endpoint(&endpoint)? {
                return Ok(s.id);
            }
            // Premier contact : on crée l'entrée.
            let id = Uuid::new_v4();
            let maintenant = Utc::now();
            let s = Serveur {
                id,
                endpoint: endpoint.clone(),
                transport,
                portees: vec![Portee::Inconnu],
                statut: StatutServeur::Inconnu,
                couleur: Couleur::Orange,
                premiere_vue: maintenant,
                derniere_vue: maintenant,
                empreinte_courante: None,
            };
            store.upsert_serveur(&s)?;
            Ok(id)
        })
        .await??;

        self.serveurs_vus.insert(msg.serveur.clone(), serveur_id);
        Ok(serveur_id)
    }

    /// Détermine si le message est une réponse à `tools/list`.
    ///
    /// Critère simplifié v1 : direction ServeurVersClient et méthode ToolsList,
    /// ou payload contenant une clé `"tools"` (réponse JSON-RPC sans méthode).
    fn est_reponse_tools_list(&self, msg: &MessageMcp) -> bool {
        use sentinel_protocol::Direction;
        match &msg.methode {
            MethodeMcp::ToolsList => {
                msg.direction == Direction::ServeurVersClient
                    || msg.payload.get("tools").is_some()
                    || msg.payload.get("result").and_then(|r| r.get("tools")).is_some()
            }
            _ => false,
        }
    }

    /// Construit un `FaitSurveillance` à partir d'un message `tools/list`.
    fn construire_fait(&self, serveur_id: ServeurId, msg: &MessageMcp) -> FaitSurveillance {
        // Empreinte simplifiée v1 : hash du payload sérialisé (canonicalisé).
        let empreinte = Self::empreinte_payload(&msg.payload);

        // Logique v1 : tout changement observé → NouveauServeur.
        // Les agents 2.4/2.5/3.4 affineront en RugPull ou Poisoning.
        let type_fait = TypeConstat::NouveauServeur;

        FaitSurveillance {
            serveur_id,
            type_fait,
            empreinte_courante: Some(empreinte),
            baseline: None,
            session_id: msg.session_id.clone(),
            detail: format!(
                "tools/list reçu pour le serveur « {} » (session {})",
                msg.serveur, msg.session_id
            ),
            outils_courants: Vec::new(),
            severite_suggeree: sentinel_protocol::Severite::Info,
        }
    }

    /// Empreinte SHA-256 du payload JSON canonicalisé (clés triées).
    fn empreinte_payload(payload: &serde_json::Value) -> Empreinte {
        use sha2::{Digest, Sha256};
        let canonical = serde_json::to_string(payload).unwrap_or_default();
        let hash = Sha256::digest(canonical.as_bytes());
        Empreinte::new(hex::encode(hash))
    }
}

// ---------------------------------------------------------------------------
// PoigneeSurveillance + demarrer
// ---------------------------------------------------------------------------

/// Poignée retournée à l'appelant après démarrage du moteur.
pub struct PoigneeSurveillance {
    pub emetteur_messages: mpsc::Sender<MessageMcp>,
    pub recepteur_faits: mpsc::Receiver<FaitSurveillance>,
    pub _task: tokio::task::JoinHandle<Result<()>>,
}

/// Lance le moteur dans une tâche Tokio et retourne la poignée de contrôle.
pub async fn demarrer(store: Store) -> PoigneeSurveillance {
    let (tx_messages, rx_messages) = mpsc::channel::<MessageMcp>(256);
    let (tx_faits, rx_faits) = mpsc::channel::<FaitSurveillance>(256);

    let moteur = MoteurSurveillance::nouveau(store, rx_messages, tx_faits);
    let handle = tokio::spawn(moteur.boucle());

    PoigneeSurveillance {
        emetteur_messages: tx_messages,
        recepteur_faits: rx_faits,
        _task: handle,
    }
}
