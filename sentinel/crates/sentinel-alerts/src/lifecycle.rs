//! Cycle de vie des alertes — agent 4.8.
//! Machine à états : Ouvert → Investigue → Resolu | Ignore, avec réouverture.

use sentinel_protocol::EtatConstat;

/// Machine à états du cycle de vie d'une alerte.
pub struct EtatAlerteMachine;

/// Erreur de transition d'état invalide.
#[derive(Debug, thiserror::Error)]
pub enum ErreurTransition {
    #[error("transition {de:?} -> {vers:?} invalide")]
    Invalide { de: EtatConstat, vers: EtatConstat },
}

impl EtatAlerteMachine {
    /// Transitions autorisées :
    /// - `Ouvert → Investigue` ✓
    /// - `Ouvert → Ignore` ✓
    /// - `Investigue → Resolu` ✓
    /// - `Investigue → Ignore` ✓
    /// - `Resolu → Ouvert` ✓ (réouverture)
    /// - `Ignore → Ouvert` ✓
    /// - Toutes les autres → `ErreurTransition::Invalide`
    pub fn transiter(de: EtatConstat, vers: EtatConstat) -> Result<EtatConstat, ErreurTransition> {
        let autorisee = match (de, vers) {
            (EtatConstat::Ouvert, EtatConstat::Investigue) => true,
            (EtatConstat::Ouvert, EtatConstat::Ignore) => true,
            (EtatConstat::Investigue, EtatConstat::Resolu) => true,
            (EtatConstat::Investigue, EtatConstat::Ignore) => true,
            (EtatConstat::Resolu, EtatConstat::Ouvert) => true,
            (EtatConstat::Ignore, EtatConstat::Ouvert) => true,
            _ => false,
        };

        if autorisee {
            Ok(vers)
        } else {
            Err(ErreurTransition::Invalide { de, vers })
        }
    }

    /// Retourne la liste des états atteignables depuis `de`.
    pub fn etats_suivants(de: EtatConstat) -> Vec<EtatConstat> {
        match de {
            EtatConstat::Ouvert => vec![EtatConstat::Investigue, EtatConstat::Ignore],
            EtatConstat::Investigue => vec![EtatConstat::Resolu, EtatConstat::Ignore],
            EtatConstat::Resolu => vec![EtatConstat::Ouvert],
            EtatConstat::Ignore => vec![EtatConstat::Ouvert],
        }
    }

    /// Compatibilité ancienne API : wrap anyhow.
    pub fn transiter_anyhow(de: EtatConstat, vers: EtatConstat) -> anyhow::Result<EtatConstat> {
        Self::transiter(de, vers).map_err(|e| anyhow::anyhow!("{}", e))
    }
}

// Compatibilité ancienne signature exposée publiquement via la fonction libre.
pub fn transiter(de: EtatConstat, vers: EtatConstat) -> anyhow::Result<EtatConstat> {
    EtatAlerteMachine::transiter_anyhow(de, vers)
}
