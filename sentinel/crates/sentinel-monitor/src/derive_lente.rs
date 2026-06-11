//! Détection de dérive lente — fenêtre glissante sur les N dernières sessions.
//!
//! Le diff simple (`DetecteurInterSession`) compare chaque session à la
//! baseline : un serveur malveillant peut rester sous ce radar en ne
//! changeant qu'« un petit peu à chaque session » (1 outil par session,
//! par exemple), de sorte que chaque pas paraisse anodin. Ce module
//! regarde la **trajectoire** : si chaque session modifie peu d'outils
//! mais que le cumul des changements par rapport à la baseline dépasse
//! un seuil sur la fenêtre, on déclenche un constat de dérive lente
//! avec le détail cumulé (outils modifiés / ajoutés / supprimés).

use anyhow::Result;
use chrono::{DateTime, Utc};
use sentinel_protocol::{
    Constat, Empreinte, EtatConstat, ServeurId, Severite, TypeConstat,
};
use sentinel_store::Store;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Empreintes outil-par-outil observées lors d'une session donnée.
#[derive(Debug, Clone)]
pub struct SessionEmpreintes {
    pub session_id: String,
    pub horodatage: DateTime<Utc>,
    /// nom d'outil → empreinte canonique observée pendant la session.
    pub empreintes_outils: BTreeMap<String, Empreinte>,
}

/// Paramètres de la fenêtre glissante.
#[derive(Debug, Clone)]
pub struct ParametresDeriveLente {
    /// Taille de la fenêtre : nombre de sessions récentes examinées.
    pub fenetre: usize,
    /// Nombre maximal de changements par session pour qu'un pas soit
    /// considéré « petit » (sous le radar du diff simple). Au-delà,
    /// c'est une rupture franche — du ressort du rug-pull, pas de la
    /// dérive lente.
    pub seuil_pas: usize,
    /// Cumul de changements (vs baseline) qui déclenche le constat.
    pub seuil_cumul: usize,
    /// Nombre minimal de sessions observées avant que le détecteur ne
    /// puisse se prononcer — en deçà, l'historique est trop court pour
    /// distinguer une trajectoire d'un bruit ponctuel.
    pub min_sessions: usize,
}

impl Default for ParametresDeriveLente {
    fn default() -> Self {
        Self {
            fenetre: 5,
            seuil_pas: 2,
            seuil_cumul: 3,
            min_sessions: 3,
        }
    }
}

/// Cumul des changements constatés sur la fenêtre.
#[derive(Debug, Clone)]
pub struct BilanDeriveLente {
    /// Outils présents dans la baseline dont l'empreinte a changé.
    pub outils_modifies: Vec<String>,
    /// Outils absents de la baseline, apparus au fil des sessions.
    pub outils_ajoutes: Vec<String>,
    /// Outils de la baseline disparus au fil des sessions.
    pub outils_supprimes: Vec<String>,
    /// Nombre de changements à chaque pas (session i-1 → session i ;
    /// le premier pas part de la baseline).
    pub changements_par_session: Vec<usize>,
    /// Nombre de sessions effectivement examinées dans la fenêtre.
    pub sessions_examinees: usize,
}

impl BilanDeriveLente {
    /// Nombre total d'outils touchés par rapport à la baseline.
    pub fn cumul(&self) -> usize {
        self.outils_modifies.len() + self.outils_ajoutes.len() + self.outils_supprimes.len()
    }
}

/// Moteur de détection de dérive lente.
pub struct DetecteurDeriveLente {
    pub parametres: ParametresDeriveLente,
}

impl DetecteurDeriveLente {
    pub fn nouveau() -> Self {
        Self {
            parametres: ParametresDeriveLente::default(),
        }
    }

    pub fn avec_parametres(parametres: ParametresDeriveLente) -> Self {
        Self { parametres }
    }

    /// Évalue la fenêtre glissante. `sessions` est l'historique
    /// chronologique (plus ancien en premier) ; seules les `fenetre`
    /// dernières sessions sont examinées.
    ///
    /// Rien n'est évalué tant que moins de `min_sessions` sessions ont
    /// été observées. Déclenche (retourne `Some`) si, sur la fenêtre :
    ///   1. chaque pas (baseline → s1, s1 → s2, …) reste « petit »
    ///      (≤ `seuil_pas` changements) — sinon c'est une rupture
    ///      franche, hors périmètre ;
    ///   2. au moins deux pas portent un changement — la dérive est
    ///      progressive, pas un événement isolé ;
    ///   3. le cumul des changements vs baseline atteint `seuil_cumul`.
    pub fn evaluer(
        &self,
        empreintes_baseline: &BTreeMap<String, Empreinte>,
        sessions: &[SessionEmpreintes],
    ) -> Option<BilanDeriveLente> {
        if sessions.len() < self.parametres.min_sessions {
            return None;
        }
        let debut = sessions.len().saturating_sub(self.parametres.fenetre);
        let fenetre = &sessions[debut..];

        // Pas par pas : baseline → s1 → s2 → …
        let mut precedent = empreintes_baseline;
        let mut changements_par_session = Vec::with_capacity(fenetre.len());
        for session in fenetre {
            let (modifies, ajoutes, supprimes) =
                Self::diff(precedent, &session.empreintes_outils);
            let pas = modifies.len() + ajoutes.len() + supprimes.len();
            if pas > self.parametres.seuil_pas {
                // Rupture franche : le diff simple la voit déjà.
                return None;
            }
            changements_par_session.push(pas);
            precedent = &session.empreintes_outils;
        }

        let pas_actifs = changements_par_session.iter().filter(|&&p| p > 0).count();
        if pas_actifs < 2 {
            return None;
        }

        // Cumul : baseline vs dernier état observé.
        let derniere = &fenetre[fenetre.len() - 1].empreintes_outils;
        let (outils_modifies, outils_ajoutes, outils_supprimes) =
            Self::diff(empreintes_baseline, derniere);
        let bilan = BilanDeriveLente {
            outils_modifies,
            outils_ajoutes,
            outils_supprimes,
            changements_par_session,
            sessions_examinees: fenetre.len(),
        };
        if bilan.cumul() >= self.parametres.seuil_cumul {
            Some(bilan)
        } else {
            None
        }
    }

    /// Construit le constat de dérive lente à partir d'un bilan.
    ///
    /// `TypeConstat::DeriveInterSession` est la catégorie protocole la
    /// plus proche ; le titre et le détail portent la qualification
    /// « dérive lente » et le cumul des changements.
    pub fn construire_constat(
        &self,
        serveur_id: ServeurId,
        bilan: &BilanDeriveLente,
    ) -> Constat {
        let mut lignes = vec![format!(
            "Dérive lente : {} changement(s) cumulé(s) sur {} sessions \
             (chaque session sous le seuil de {} changement(s)).",
            bilan.cumul(),
            bilan.sessions_examinees,
            self.parametres.seuil_pas,
        )];
        if !bilan.outils_modifies.is_empty() {
            lignes.push(format!("Outils modifiés : {}", bilan.outils_modifies.join(", ")));
        }
        if !bilan.outils_ajoutes.is_empty() {
            lignes.push(format!("Outils ajoutés : {}", bilan.outils_ajoutes.join(", ")));
        }
        if !bilan.outils_supprimes.is_empty() {
            lignes.push(format!("Outils supprimés : {}", bilan.outils_supprimes.join(", ")));
        }

        let mut diff = String::new();
        for nom in &bilan.outils_modifies {
            diff.push_str(&format!("~ `{}` (empreinte modifiée)\n", nom));
        }
        for nom in &bilan.outils_ajoutes {
            diff.push_str(&format!("+ `{}` (absent de la baseline)\n", nom));
        }
        for nom in &bilan.outils_supprimes {
            diff.push_str(&format!("- `{}` (disparu)\n", nom));
        }

        Constat {
            id: Uuid::new_v4(),
            serveur_id,
            outil_nom: None,
            type_constat: TypeConstat::DeriveInterSession,
            severite: Severite::Haute,
            titre: format!(
                "Dérive lente détectée : {} changement(s) cumulé(s) sur {} sessions",
                bilan.cumul(),
                bilan.sessions_examinees
            ),
            detail: lignes.join("\n"),
            diff: if diff.is_empty() { None } else { Some(diff) },
            references_conformite: vec![
                "SAFE-T1201".to_string(),
                "OWASP MCP03".to_string(),
            ],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        }
    }

    /// Évalue la fenêtre et, si dérive lente, persiste le constat dans
    /// le store. Retourne le constat enregistré le cas échéant.
    pub fn detecter_et_enregistrer(
        &self,
        store: &Store,
        serveur_id: ServeurId,
        empreintes_baseline: &BTreeMap<String, Empreinte>,
        sessions: &[SessionEmpreintes],
    ) -> Result<Option<Constat>> {
        match self.evaluer(empreintes_baseline, sessions) {
            None => Ok(None),
            Some(bilan) => {
                let constat = self.construire_constat(serveur_id, &bilan);
                store.enregistrer_constat(&constat)?;
                Ok(Some(constat))
            }
        }
    }

    /// Diff entre deux états outil → empreinte. Retourne
    /// (modifiés, ajoutés, supprimés), chaque liste triée (BTreeMap).
    fn diff(
        avant: &BTreeMap<String, Empreinte>,
        apres: &BTreeMap<String, Empreinte>,
    ) -> (Vec<String>, Vec<String>, Vec<String>) {
        let mut modifies = vec![];
        let mut ajoutes = vec![];
        let mut supprimes = vec![];
        for (nom, empreinte) in apres {
            match avant.get(nom) {
                Some(avant_emp) if avant_emp != empreinte => modifies.push(nom.clone()),
                Some(_) => {}
                None => ajoutes.push(nom.clone()),
            }
        }
        for nom in avant.keys() {
            if !apres.contains_key(nom) {
                supprimes.push(nom.clone());
            }
        }
        (modifies, ajoutes, supprimes)
    }
}

impl Default for DetecteurDeriveLente {
    fn default() -> Self {
        Self::nouveau()
    }
}
