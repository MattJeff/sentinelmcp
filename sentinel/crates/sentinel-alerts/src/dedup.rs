//! Déduplication et anti-bruit — agent 4.7.
//!
//! Filtre les alertes répétitives par fenêtre temporelle glissante.
//! La sévérité Critique bénéficie d'une fenêtre réduite pour ne pas
//! retarder une vraie urgence.

use chrono::{DateTime, Duration, Utc};
use sentinel_protocol::{Alerte, Severite};
use std::collections::HashMap;

/// Configuration du moteur anti-bruit.
#[derive(Debug, Clone)]
pub struct ConfigAntiBruit {
    /// Fenêtre de déduplication pour les alertes Info / Moyenne / Haute.
    pub fenetre_normale: Duration,
    /// Fenêtre plus courte pour Critique (laisse passer plus vite).
    pub fenetre_critique: Duration,
    /// Au-delà de N alertes du même type dans la fenêtre, on regroupe.
    pub max_par_fenetre: u32,
}

impl ConfigAntiBruit {
    /// Valeurs par défaut : fenêtre normale = 10 min, critique = 1 min, max = 5.
    pub fn par_defaut() -> Self {
        Self {
            fenetre_normale: Duration::minutes(10),
            fenetre_critique: Duration::minutes(1),
            max_par_fenetre: 5,
        }
    }
}

/// Entrée de la map de déduplication : horodatage de la dernière émission + compteur.
struct EntreDedup {
    dernier_ts: DateTime<Utc>,
    compteur: u32,
}

/// Moteur de déduplication et d'anti-bruit.
///
/// Doit être placé en aval du moteur d'alertes (agent 4.1) et en amont
/// des canaux d'émission (agents 4.3 / 4.4 / 4.5).
pub struct DedupAntiBruit {
    pub config: ConfigAntiBruit,
    /// `"titre|canal"` → (horodatage dernière émission, compteur dans la fenêtre).
    derniers: HashMap<String, EntreDedup>,
}

impl Default for DedupAntiBruit {
    fn default() -> Self {
        Self::nouveau(ConfigAntiBruit::par_defaut())
    }
}

impl DedupAntiBruit {
    /// Crée un nouveau moteur avec la configuration fournie.
    pub fn nouveau(config: ConfigAntiBruit) -> Self {
        Self {
            config,
            derniers: HashMap::new(),
        }
    }

    /// Retourne la fenêtre pertinente selon la sévérité de l'alerte.
    fn fenetre(&self, severite: Severite) -> Duration {
        if severite == Severite::Critique {
            self.config.fenetre_critique
        } else {
            self.config.fenetre_normale
        }
    }

    /// Clé de déduplication : titre + canal.
    fn cle(a: &Alerte) -> String {
        format!("{}|{:?}", a.titre, a.canal)
    }

    /// Décide si l'alerte doit être émise.
    ///
    /// Règles :
    /// - Première occurrence → émet, enregistre (now, 1).
    /// - Dans la fenêtre :
    ///   - compteur < max_par_fenetre → incrémente, supprime.
    ///   - compteur == max_par_fenetre → émet une fois (message de regroupement),
    ///     incrémente au-delà pour comptabilisation.
    /// - Hors fenêtre → reset (now, 1), émet.
    pub fn doit_emettre(&mut self, a: &Alerte) -> bool {
        let maintenant = Utc::now();
        let fenetre = self.fenetre(a.severite);
        let cle = Self::cle(a);

        match self.derniers.get_mut(&cle) {
            None => {
                // Première occurrence.
                self.derniers.insert(
                    cle,
                    EntreDedup {
                        dernier_ts: maintenant,
                        compteur: 1,
                    },
                );
                true
            }
            Some(entree) => {
                let dans_fenetre = maintenant - entree.dernier_ts < fenetre;
                if dans_fenetre {
                    entree.compteur += 1;
                    // On émet une unique fois au seuil de regroupement.
                    entree.compteur == self.config.max_par_fenetre
                } else {
                    // Hors fenêtre : on recommence.
                    entree.dernier_ts = maintenant;
                    entree.compteur = 1;
                    true
                }
            }
        }
    }

    /// Nombre d'entrées suivies dans la fenêtre glissante.
    ///
    /// Lecture seule, exposée pour la métrique `sentinel_dedup_size`.
    pub fn taille(&self) -> u64 {
        self.derniers.len() as u64
    }

    /// Retourne les regroupements actifs : paires (clé, compteur) dont le
    /// compteur dépasse le seuil. Utile pour construire un résumé périodique.
    pub fn regroupements(&self) -> Vec<(String, u32)> {
        self.derniers
            .iter()
            .filter(|(_, e)| e.compteur >= self.config.max_par_fenetre)
            .map(|(k, e)| (k.clone(), e.compteur))
            .collect()
    }
}
