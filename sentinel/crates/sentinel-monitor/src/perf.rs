//! Performance surveillance continue — agent 2.9.
//! Mesure le débit de messages et l'empreinte ressources de la boucle de
//! surveillance. CPU et mémoire sont stubés à 0.0 en v1 (contrat posé).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// MesureCharge
// ---------------------------------------------------------------------------

/// Instantané de la charge à un instant donné.
#[derive(Debug, Clone)]
pub struct MesureCharge {
    pub cpu_pct: f64,
    pub memoire_mo: f64,
    pub serveurs_observes: u64,
    pub messages_traites_par_sec: f64,
}

// ---------------------------------------------------------------------------
// CompteurCharge
// ---------------------------------------------------------------------------

/// Compteurs atomiques partagés entre threads pour la boucle de surveillance.
#[derive(Clone)]
pub struct CompteurCharge {
    messages: Arc<AtomicU64>,
    serveurs: Arc<AtomicU64>,
    /// Référence temporelle pour calculer le débit sur la fenêtre.
    debut: Instant,
}

impl CompteurCharge {
    /// Crée un nouveau compteur avec des compteurs remis à zéro.
    pub fn nouveau() -> Self {
        Self {
            messages: Arc::new(AtomicU64::new(0)),
            serveurs: Arc::new(AtomicU64::new(0)),
            debut: Instant::now(),
        }
    }

    /// Incrémente le compteur de messages traités (appelable depuis n'importe quel thread).
    pub fn incrementer_messages(&self) {
        self.messages.fetch_add(1, Ordering::Relaxed);
    }

    /// Met à jour le nombre de serveurs actuellement observés.
    pub fn definir_serveurs(&self, n: u64) {
        self.serveurs.store(n, Ordering::Relaxed);
    }

    /// Retourne une mesure de charge sur la fenêtre temporelle écoulée depuis
    /// la création du compteur.
    ///
    /// CPU et mémoire sont stubés à 0.0 en v1 ; le débit de messages est réel.
    pub fn mesure(&self, _fenetre: Duration) -> MesureCharge {
        let total_messages = self.messages.load(Ordering::Relaxed);
        let serveurs = self.serveurs.load(Ordering::Relaxed);

        // Calcul du débit sur la durée totale depuis la création du compteur.
        let duree_secs = self.debut.elapsed().as_secs_f64().max(f64::EPSILON);
        let debit = total_messages as f64 / duree_secs;

        MesureCharge {
            cpu_pct: 0.0,         // v1 : stub — /proc lu en v2
            memoire_mo: 0.0,      // v1 : stub — /proc lu en v2
            serveurs_observes: serveurs,
            messages_traites_par_sec: debit,
        }
    }
}

// ---------------------------------------------------------------------------
// SeuilsRessources
// ---------------------------------------------------------------------------

/// Seuils opérationnels validés par l'agent 5.10.
#[derive(Debug, Clone)]
pub struct SeuilsRessources {
    pub cpu_max_pct: f64,
    pub memoire_max_mo: f64,
    pub max_serveurs_charge: u64,
}

impl SeuilsRessources {
    /// Seuils par défaut : 5 % CPU, 100 Mo RAM, 1 000 serveurs simultanés.
    pub fn par_defaut() -> Self {
        Self {
            cpu_max_pct: 5.0,
            memoire_max_mo: 100.0,
            max_serveurs_charge: 1_000,
        }
    }

    /// Retourne `true` si au moins un seuil est dépassé.
    pub fn depasse(&self, m: &MesureCharge) -> bool {
        m.cpu_pct > self.cpu_max_pct
            || m.memoire_mo > self.memoire_max_mo
            || m.serveurs_observes > self.max_serveurs_charge
    }
}
