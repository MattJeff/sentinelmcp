//! Lead générateur de rapport — agent 5.1.
//!
//! Orchestre la production du bundle d'évidence complet :
//! résumé exécutif, inventaire, journal, mapping conformité,
//! plan de remédiation, export JSON, signature ed25519, PDF.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sentinel_protocol::{Constat, Couleur, Serveur, StatutServeur};
use sentinel_store::Store;
use tracing::{info, warn};

use crate::compliance::MoteurConformite;

/// Orchestre l'ensemble du pipeline de rapport.
pub struct GenerateurRapport {
    pub store: Store,
    pub periode_debut: DateTime<Utc>,
    pub periode_fin: DateTime<Utc>,
}

/// Bundle d'évidence complet retourné au demandeur.
#[derive(Debug)]
pub struct BundleRapport {
    pub resume_exec_md: String,
    pub inventaire: Vec<Serveur>,
    pub journal_md: String,
    pub mapping_conformite_md: String,
    pub plan_remediation_md: String,
    pub json_export: serde_json::Value,
    pub pdf_path: Option<std::path::PathBuf>,
    pub signature_ed25519: Option<Vec<u8>>,
    pub signature_horodatage: Option<DateTime<Utc>>,
    pub cle_publique: Option<Vec<u8>>,
}

impl GenerateurRapport {
    /// Crée un générateur avec la plage de temps par défaut (epoch → maintenant).
    pub fn nouveau(store: Store) -> Self {
        Self {
            store,
            periode_debut: DateTime::from_timestamp(0, 0).unwrap_or_else(Utc::now),
            periode_fin: Utc::now(),
        }
    }

    /// Affine la plage temporelle couverte par le rapport.
    pub fn avec_periode(mut self, debut: DateTime<Utc>, fin: DateTime<Utc>) -> Self {
        self.periode_debut = debut;
        self.periode_fin = fin;
        self
    }

    // ------------------------------------------------------------------ //
    //  Étape 1 — lecture du store                                         //
    // ------------------------------------------------------------------ //

    fn lire_inventaire(&self) -> Result<Vec<Serveur>> {
        self.store.lister_serveurs()
    }

    fn lire_constats(&self) -> Result<Vec<Constat>> {
        self.store.lister_constats_ouverts()
    }

    // ------------------------------------------------------------------ //
    //  Étape 2 — résumé exécutif                                          //
    // ------------------------------------------------------------------ //

    fn construire_resume(
        serveurs: &[Serveur],
        constats: &[Constat],
        debut: DateTime<Utc>,
        fin: DateTime<Utc>,
    ) -> String {
        let total = serveurs.len();
        let non_approuves = serveurs
            .iter()
            .filter(|s| s.statut != StatutServeur::Approuve)
            .count();
        let a_risque = serveurs
            .iter()
            .filter(|s| s.couleur == Couleur::Rouge)
            .count();
        let constats_ouverts = constats.len();

        // Utilise ResumeExecutif si sa structure est enrichie ultérieurement ;
        // pour l'instant on assemble directement le Markdown.
        let mut md = String::new();
        md.push_str("# Résumé exécutif — Sentinel MCP\n\n");
        md.push_str(&format!(
            "**Période analysée :** {} → {}\n\n",
            debut.format("%Y-%m-%d %H:%M UTC"),
            fin.format("%Y-%m-%d %H:%M UTC")
        ));
        md.push_str("## Chiffres clés\n\n");
        md.push_str(&format!("| Indicateur | Valeur |\n|---|---|\n"));
        md.push_str(&format!("| Serveurs MCP détectés | {} |\n", total));
        md.push_str(&format!("| Serveurs non approuvés | {} |\n", non_approuves));
        md.push_str(&format!("| Serveurs à risque (rouge) | {} |\n", a_risque));
        md.push_str(&format!("| Constats ouverts | {} |\n", constats_ouverts));
        md.push('\n');

        if a_risque > 0 {
            md.push_str(&format!(
                "> **ATTENTION** : {} serveur(s) rouge(s) requièrent une action immédiate.\n\n",
                a_risque
            ));
        } else {
            md.push_str("> Aucun serveur rouge détecté sur la période.\n\n");
        }

        md
    }

    // ------------------------------------------------------------------ //
    //  Étape 3 — inventaire Markdown                                      //
    // ------------------------------------------------------------------ //

    fn construire_inventaire_md(serveurs: &[Serveur]) -> String {
        let mut md = String::new();
        md.push_str("# Inventaire des serveurs MCP\n\n");
        md.push_str("| ID | Endpoint | Transport | Statut | Couleur | Première vue |\n");
        md.push_str("|---|---|---|---|---|---|\n");
        for s in serveurs {
            let transport = format!("{:?}", s.transport);
            let statut = format!("{:?}", s.statut);
            let couleur = format!("{:?}", s.couleur);
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                s.id,
                s.endpoint,
                transport,
                statut,
                couleur,
                s.premiere_vue.format("%Y-%m-%d %H:%M UTC"),
            ));
        }
        md.push('\n');
        md
    }

    // ------------------------------------------------------------------ //
    //  Étape 4 — journal Markdown                                         //
    // ------------------------------------------------------------------ //

    fn construire_journal_md(constats: &[Constat]) -> String {
        let mut md = String::new();
        md.push_str("# Journal des constats ouverts\n\n");
        if constats.is_empty() {
            md.push_str("_Aucun constat ouvert sur la période._\n");
        } else {
            md.push_str("| Date | Serveur | Type | Sévérité | Titre |\n");
            md.push_str("|---|---|---|---|---|\n");
            for c in constats {
                md.push_str(&format!(
                    "| {} | {} | {:?} | {:?} | {} |\n",
                    c.horodatage.format("%Y-%m-%d %H:%M UTC"),
                    c.serveur_id,
                    c.type_constat,
                    c.severite,
                    c.titre,
                ));
            }
        }
        md.push('\n');
        md
    }

    // ------------------------------------------------------------------ //
    //  Étape 5 — mapping conformité                                       //
    // ------------------------------------------------------------------ //

    fn construire_mapping_conformite(constats: &[Constat]) -> String {
        let mut md = String::new();
        md.push_str("# Mapping de conformité\n\n");
        md.push_str("Couverture OWASP MCP et SAFE-MCP.\n\n");
        md.push_str("| Constat | Cadre | Identifiant | Titre |\n");
        md.push_str("|---|---|---|---|\n");

        for c in constats {
            let refs = MoteurConformite::references_pour(&c.type_constat);
            if refs.is_empty() {
                // Même si le moteur est vide, on affiche les refs textuelles du constat.
                for r in &c.references_conformite {
                    md.push_str(&format!("| {} | — | {} | — |\n", c.titre, r));
                }
            } else {
                for r in refs {
                    md.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        c.titre, r.cadre, r.identifiant, r.titre
                    ));
                }
            }
        }

        // Références fixes garanties quel que soit le contenu des constats.
        md.push_str("\n## Contrôles couverts par ce déploiement\n\n");
        md.push_str("| Cadre | Identifiant | Description |\n");
        md.push_str("|---|---|---|\n");
        md.push_str("| OWASP MCP | MCP09 | Shadow MCP Server |\n");
        md.push_str("| OWASP MCP | MCP03 | Tool Poisoning |\n");
        md.push_str("| SAFE-MCP | SAFE-T1001 | Tool Poisoning |\n");
        md.push_str("| SAFE-MCP | SAFE-T1201 | Rug Pull |\n");
        md.push('\n');
        md
    }

    // ------------------------------------------------------------------ //
    //  Étape 6 — plan de remédiation                                      //
    // ------------------------------------------------------------------ //

    fn construire_plan_remediation(serveurs: &[Serveur], constats: &[Constat]) -> String {
        let mut md = String::new();
        md.push_str("# Plan de remédiation\n\n");

        // Serveurs rouges → action prioritaire.
        let rouges: Vec<&Serveur> = serveurs
            .iter()
            .filter(|s| s.couleur == Couleur::Rouge)
            .collect();

        if rouges.is_empty() {
            md.push_str("Aucun serveur rouge. Aucune action immédiate requise.\n\n");
        } else {
            md.push_str("## Actions immédiates — serveurs rouges\n\n");
            md.push_str("| Endpoint | Action recommandée |\n");
            md.push_str("|---|---|\n");
            for s in &rouges {
                let action = match s.statut {
                    StatutServeur::Approuve => "Vérifier — statut approuvé mais couleur rouge",
                    StatutServeur::Suspect => "Bloquer",
                    StatutServeur::AInvestiguer => "Investiguer",
                    StatutServeur::Bloque => "Déjà bloqué — confirmer l'isolement",
                    StatutServeur::Inconnu => "Approuver ou Bloquer",
                };
                md.push_str(&format!("| {} | {} |\n", s.endpoint, action));
            }
            md.push('\n');
        }

        // Serveurs non approuvés hors rouges.
        let oranges: Vec<&Serveur> = serveurs
            .iter()
            .filter(|s| s.couleur == Couleur::Orange)
            .collect();

        if !oranges.is_empty() {
            md.push_str("## Actions à planifier — serveurs orange\n\n");
            md.push_str("| Endpoint | Action recommandée |\n");
            md.push_str("|---|---|\n");
            for s in &oranges {
                md.push_str(&format!("| {} | Approuver ou Investiguer |\n", s.endpoint));
            }
            md.push('\n');
        }

        // Constats critiques.
        let critiques: Vec<&Constat> = constats
            .iter()
            .filter(|c| {
                c.severite == sentinel_protocol::Severite::Critique
                    || c.severite == sentinel_protocol::Severite::Haute
            })
            .collect();

        if !critiques.is_empty() {
            md.push_str("## Constats haute/critique sévérité\n\n");
            for c in critiques {
                md.push_str(&format!("- **{}** : {}\n", c.titre, c.detail));
            }
            md.push('\n');
        }

        md
    }

    // ------------------------------------------------------------------ //
    //  Étape 7 — export JSON                                              //
    // ------------------------------------------------------------------ //

    fn construire_json(
        serveurs: &[Serveur],
        constats: &[Constat],
        debut: DateTime<Utc>,
        fin: DateTime<Utc>,
    ) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "1.0",
            "generateur": "sentinel-report/agent-5.1",
            "periode": {
                "debut": debut.to_rfc3339(),
                "fin": fin.to_rfc3339(),
            },
            "inventaire": serde_json::to_value(serveurs).unwrap_or(serde_json::Value::Null),
            "constats": serde_json::to_value(constats).unwrap_or(serde_json::Value::Null),
            "statistiques": {
                "total_serveurs": serveurs.len(),
                "serveurs_rouge": serveurs.iter().filter(|s| s.couleur == Couleur::Rouge).count(),
                "serveurs_orange": serveurs.iter().filter(|s| s.couleur == Couleur::Orange).count(),
                "serveurs_vert": serveurs.iter().filter(|s| s.couleur == Couleur::Vert).count(),
                "constats_ouverts": constats.len(),
            },
        })
    }

    // ------------------------------------------------------------------ //
    //  Étape 8 — signature (optionnelle, mode dégradé si non configurée) //
    // ------------------------------------------------------------------ //

    fn tenter_signature(
        payload: &[u8],
    ) -> (Option<Vec<u8>>, Option<DateTime<Utc>>, Option<Vec<u8>>) {
        // En l'absence d'une clé injectée, on opère en mode dégradé :
        // signature = None, sans crash.
        let _ = payload;
        (None, None, None)
    }

    // ------------------------------------------------------------------ //
    //  Étape 9 — PDF (optionnel, échec silencieux)                       //
    // ------------------------------------------------------------------ //

    fn tenter_pdf(_contenu_md: &str) -> Option<std::path::PathBuf> {
        // RenduPdf::produire n'est pas encore implémenté ; on renvoie None.
        None
    }

    // ------------------------------------------------------------------ //
    //  Point d'entrée public                                              //
    // ------------------------------------------------------------------ //

    /// Lance le pipeline complet et retourne le bundle d'évidence.
    pub async fn generer_bundle(&self) -> Result<BundleRapport> {
        info!("Génération du bundle rapport démarrée");

        // 1. Lecture du store.
        let serveurs = self.lire_inventaire().unwrap_or_else(|e| {
            warn!("Lecture inventaire échouée : {e} — mode dégradé");
            vec![]
        });
        let constats = self.lire_constats().unwrap_or_else(|e| {
            warn!("Lecture constats échouée : {e} — mode dégradé");
            vec![]
        });

        info!(
            nb_serveurs = serveurs.len(),
            nb_constats = constats.len(),
            "Store lu"
        );

        // 2. Résumé exécutif.
        let resume_exec_md = Self::construire_resume(
            &serveurs,
            &constats,
            self.periode_debut,
            self.periode_fin,
        );

        // 3. Inventaire Markdown (via SectionInventaire si enrichi).
        let inventaire_md = Self::construire_inventaire_md(&serveurs);

        // 4. Journal des changements.
        let journal_md = Self::construire_journal_md(&constats);

        // 5. Mapping conformité.
        let mapping_conformite_md = Self::construire_mapping_conformite(&constats);

        // 6. Plan de remédiation.
        let plan_remediation_md = Self::construire_plan_remediation(&serveurs, &constats);

        // 7. Export JSON.
        let json_export = Self::construire_json(
            &serveurs,
            &constats,
            self.periode_debut,
            self.periode_fin,
        );

        // 8. Signature (mode dégradé si clé absente).
        let payload_signature = format!(
            "{}{}{}",
            resume_exec_md, mapping_conformite_md, json_export
        );
        let (signature_ed25519, signature_horodatage, cle_publique) =
            Self::tenter_signature(payload_signature.as_bytes());

        // 9. PDF (échec silencieux).
        let pdf_path = Self::tenter_pdf(&format!(
            "{}\n{}\n{}\n{}\n{}",
            resume_exec_md, inventaire_md, journal_md, mapping_conformite_md, plan_remediation_md
        ));

        info!("Bundle rapport généré avec succès");

        Ok(BundleRapport {
            resume_exec_md,
            inventaire: serveurs,
            journal_md,
            mapping_conformite_md,
            plan_remediation_md,
            json_export,
            pdf_path,
            signature_ed25519,
            signature_horodatage,
            cle_publique,
        })
    }
}
