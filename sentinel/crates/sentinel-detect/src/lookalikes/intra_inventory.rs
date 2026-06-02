//! Détection de sosies intra-inventaire — agent L10.
//!
//! Compare deux à deux tous les serveurs déclarés de notre propre
//! inventaire et signale les paires dont le score `similarite_combinee_v2`
//! atteint au moins 0.85 alors que leurs noms diffèrent. Permet de mettre
//! en évidence les serveurs qui imitent un autre serveur de l'inventaire
//! en réutilisant exactement ses outils sous un nom légèrement différent.

use super::similarity::similarite_combinee_v2;
use super::SignatureOutil;

/// Entrée d'inventaire pour la détection intra : identifiant unique,
/// nom déclaré, description optionnelle et signatures d'outils probées
/// localement (les enums sont disponibles puisqu'on contrôle ces serveurs).
#[derive(Debug, Clone)]
pub struct EntreeInventaire {
    /// Identifiant unique du serveur dans l'inventaire local.
    pub id: String,
    /// Nom déclaré par le serveur.
    pub nom: String,
    /// Description déclarée par le serveur, si présente.
    pub description: Option<String>,
    /// Signatures d'outils obtenues par sondage local du serveur.
    pub outils: Vec<SignatureOutil>,
}

/// Paire de serveurs déclarés détectée comme sosies au sein de
/// l'inventaire. Le couple est rapporté dans l'ordre d'apparition
/// `(a, b)` au sein du vecteur source.
#[derive(Debug, Clone, PartialEq)]
pub struct SosieIntra {
    /// Identifiant du premier serveur de la paire.
    pub a_id: String,
    /// Nom du premier serveur de la paire.
    pub a_nom: String,
    /// Identifiant du second serveur de la paire.
    pub b_id: String,
    /// Nom du second serveur de la paire.
    pub b_nom: String,
    /// Score combiné v2 obtenu pour la paire (≥ 0.85).
    pub score: f64,
    /// Composantes ayant individuellement franchi le seuil 0.7, telles
    /// que rapportées par `similarite_combinee_v2`.
    pub signaux: Vec<String>,
}

/// Détecte les sosies intra-inventaire : parcours O(n²) sur les paires,
/// exclusion des paires dont les noms sont strictement identiques,
/// conservation des paires dont le score combiné v2 atteint 0.85, tri
/// final par score décroissant.
pub fn detecter_sosies_intra(inventaire: &[EntreeInventaire]) -> Vec<SosieIntra> {
    let mut sosies = Vec::new();

    for i in 0..inventaire.len() {
        for j in (i + 1)..inventaire.len() {
            let a = &inventaire[i];
            let b = &inventaire[j];

            // Exclusion des doublons stricts de noms : on cherche les
            // imitations à nom différent, pas les enregistrements
            // dupliqués légitimes.
            if a.nom == b.nom {
                continue;
            }

            let score = similarite_combinee_v2(
                &a.nom,
                a.description.as_deref(),
                &a.outils,
                &b.nom,
                b.description.as_deref(),
                Some(&b.outils),
            );

            if score.score >= 0.85 {
                sosies.push(SosieIntra {
                    a_id: a.id.clone(),
                    a_nom: a.nom.clone(),
                    b_id: b.id.clone(),
                    b_nom: b.nom.clone(),
                    score: score.score,
                    signaux: score.signaux,
                });
            }
        }
    }

    // Tri décroissant par score
    sosies.sort_by(|x, y| {
        y.score
            .partial_cmp(&x.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    sosies
}
