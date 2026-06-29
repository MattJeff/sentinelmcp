//! Lead générateur de rapport — agent 5.1.
//!
//! Orchestre la production du bundle d'évidence complet :
//! résumé exécutif, inventaire, journal, mapping conformité,
//! plan de remédiation, export JSON, signature ed25519, PDF.

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use sentinel_protocol::{Constat, Couleur, Serveur, StatutServeur};
use sentinel_store::Store;
use tracing::{info, warn};

use crate::compliance::MoteurConformite;
use crate::pdf::{ContenuPdf, RenduPdf};
use crate::signature::SignataireBundle;

/// Service du trousseau OS hébergeant la clé de signature des rapports.
const SERVICE_TROUSSEAU: &str = "sentinel-mcp";
/// Compte (clé logique) de la graine Ed25519 dans le trousseau OS.
const COMPTE_CLE_SIGNATURE: &str = "report-signing-key";
/// Variable d'environnement d'opt-out du trousseau (CI / headless) : `=1`.
const ENV_DESACTIVATION_TROUSSEAU: &str = "SENTINEL_NO_KEYRING";

/// Orchestre l'ensemble du pipeline de rapport.
pub struct GenerateurRapport {
    pub store: Store,
    pub periode_debut: DateTime<Utc>,
    pub periode_fin: DateTime<Utc>,
    /// Signataire explicite injecté (prioritaire sur la clé persistée).
    signataire: Option<SignataireBundle>,
    /// Active la signature Ed25519 du bundle (vrai par défaut).
    signer: bool,
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
            signataire: None,
            signer: true,
        }
    }

    /// Affine la plage temporelle couverte par le rapport.
    pub fn avec_periode(mut self, debut: DateTime<Utc>, fin: DateTime<Utc>) -> Self {
        self.periode_debut = debut;
        self.periode_fin = fin;
        self
    }

    /// Injecte un signataire Ed25519 explicite (prioritaire sur la clé
    /// persistée dans le trousseau). Réactive la signature si elle avait été
    /// désactivée.
    pub fn avec_signataire(mut self, signataire: SignataireBundle) -> Self {
        self.signataire = Some(signataire);
        self.signer = true;
        self
    }

    /// Désactive la signature : le bundle est produit sans signature Ed25519.
    pub fn sans_signature(mut self) -> Self {
        self.signer = false;
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
            // Mapping affiné par la NATURE du constat (Vague D : CVE, OAuth/SSRF,
            // cross-server shadowing, trifecta…), pas seulement par son type.
            let refs = MoteurConformite::references_pour_constat(c);
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

        // D10 / Vague D — estampillage multi-référentiels affiné par la nature
        // du constat (les CVE / OAuth-SSRF / cross-server shadowing / trifecta
        // partagent un même type et seraient sinon invisibles).
        md.push_str(&MoteurConformite::frameworks_markdown_constats(constats));
        md.push_str("\n\n");

        // P3 — matrice de couverture honnête (OWASP MCP / ASI) pour l'auditeur.
        md.push_str(&MoteurConformite::matrice_couverture_markdown());
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
            // P3 — matrice de couverture OWASP MCP / ASI (honnête, angles morts inclus).
            "matrice_couverture": MoteurConformite::matrice_couverture_json(),
        })
    }

    // ------------------------------------------------------------------ //
    //  Étape 8 — signature (optionnelle, mode dégradé si non configurée) //
    // ------------------------------------------------------------------ //

    fn signer_payload(
        &self,
        payload: &[u8],
    ) -> (Option<Vec<u8>>, Option<DateTime<Utc>>, Option<Vec<u8>>) {
        // Signature désactivée explicitement (cf. `sans_signature`).
        if !self.signer {
            return (None, None, None);
        }
        let signataire = self.resoudre_signataire();
        let signe = signataire.signer_bundle(payload.to_vec());
        (
            Some(signe.signature),
            Some(signe.horodatage),
            Some(signe.cle_publique),
        )
    }

    /// Construit le payload signé de façon **non ambiguë** : chaque section est
    /// un champ JSON nommé et distinctement délimité. Deux contenus logiquement
    /// différents ne peuvent donc pas produire le même payload (pas de collision
    /// de signature, contrairement à une simple concaténation). Exposé pour
    /// permettre la vérification a posteriori avec
    /// [`crate::signature::verifier_signature`] à partir des champs publics du
    /// [`BundleRapport`].
    pub fn payload_signature(
        resume_exec: &str,
        mapping_conformite: &str,
        json_export: &serde_json::Value,
    ) -> Vec<u8> {
        let objet = serde_json::json!({
            "resume_exec": resume_exec,
            "mapping_conformite": mapping_conformite,
            "json_export": json_export,
        });
        // Sérialisation déterministe ; payload vide en cas d'échec improbable.
        serde_json::to_vec(&objet).unwrap_or_default()
    }

    /// Résout le signataire : signataire injecté en priorité, sinon clé
    /// persistée du trousseau OS (ou éphémère si indisponible).
    fn resoudre_signataire(&self) -> SignataireBundle {
        if let Some(s) = &self.signataire {
            // Reconstruit un signataire indépendant depuis la graine injectée.
            return SignataireBundle::depuis_bytes(&s.cle_secrete)
                .unwrap_or_else(|_| SignataireBundle::generer());
        }
        Self::charger_cle_persistee_ou_ephemere()
    }

    /// Charge la graine Ed25519 depuis le trousseau OS (créée et persistée au
    /// 1er lancement). Si le trousseau est indisponible — ou explicitement
    /// désactivé via `SENTINEL_NO_KEYRING=1` (CI / headless) — génère une clé
    /// éphémère pour ce run et loggue un avertissement explicite.
    fn charger_cle_persistee_ou_ephemere() -> SignataireBundle {
        // Opt-out explicite : clé éphémère sans toucher au trousseau.
        if std::env::var(ENV_DESACTIVATION_TROUSSEAU)
            .ok()
            .as_deref()
            .map(str::trim)
            == Some("1")
        {
            return SignataireBundle::generer();
        }

        match Self::cle_depuis_trousseau() {
            Ok(Some(signataire)) => signataire,
            Ok(None) => {
                // 1er lancement : on génère la clé puis on la persiste.
                let signataire = SignataireBundle::generer();
                if let Err(e) = Self::persister_cle_trousseau(&signataire) {
                    warn!(
                        "Persistance de la clé de signature dans le trousseau échouée : {e} \
                         — clé éphémère pour ce run"
                    );
                }
                signataire
            }
            Err(e) => {
                warn!("Trousseau indisponible ({e}) — clé de signature éphémère pour ce run");
                SignataireBundle::generer()
            }
        }
    }

    /// Lit la graine Ed25519 (hex) stockée dans le trousseau OS, le cas échéant.
    fn cle_depuis_trousseau() -> Result<Option<SignataireBundle>> {
        let entree = keyring::Entry::new(SERVICE_TROUSSEAU, COMPTE_CLE_SIGNATURE)?;
        match entree.get_password() {
            Ok(graine_hex) => {
                let graine = hex::decode(graine_hex.trim()).map_err(|e| {
                    anyhow::anyhow!("graine de signature invalide dans le trousseau : {e}")
                })?;
                Ok(Some(SignataireBundle::depuis_bytes(&graine)?))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("lecture du trousseau échouée : {e}")),
        }
    }

    /// Persiste la graine Ed25519 (encodée en hex) dans le trousseau OS.
    fn persister_cle_trousseau(signataire: &SignataireBundle) -> Result<()> {
        let entree = keyring::Entry::new(SERVICE_TROUSSEAU, COMPTE_CLE_SIGNATURE)?;
        entree
            .set_password(&hex::encode(&signataire.cle_secrete))
            .map_err(|e| anyhow::anyhow!("écriture du trousseau échouée : {e}"))?;
        Ok(())
    }

    // ------------------------------------------------------------------ //
    //  Étape 9 — PDF (optionnel, échec silencieux)                       //
    // ------------------------------------------------------------------ //

    fn tenter_pdf(contenu: &ContenuPdf) -> Option<std::path::PathBuf> {
        // Nom unique par bundle (UUID v4) plutôt que par timestamp-ms : plusieurs
        // génération concurrentes (tests en parallèle, plusieurs rapports en un
        // cycle) ne doivent JAMAIS collide-r sur le même fichier temporaire, au
        // risque d'écrire dans un fichier en cours de lecture → PDF vide/corrompu.
        let nom = format!(
            "sentinel-rapport-{}-{}.pdf",
            Utc::now().format("%Y%m%d-%H%M%S"),
            Uuid::new_v4()
        );
        let chemin = std::env::temp_dir().join(nom);
        match RenduPdf::produire_contenu(contenu, &chemin) {
            Ok(p) => Some(p),
            Err(e) => {
                // Échec loggué (jamais silencieux) ; le bundle reste produit.
                warn!("Génération du PDF échouée : {e} — rapport produit sans PDF");
                None
            }
        }
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

        // 8. Signature Ed25519 (clé persistée par défaut, payload non ambigu).
        let payload_signature =
            Self::payload_signature(&resume_exec_md, &mapping_conformite_md, &json_export);
        let (signature_ed25519, signature_horodatage, cle_publique) =
            self.signer_payload(&payload_signature);

        // 9. PDF (échec loggué, jamais silencieux).
        let contenu_pdf = ContenuPdf {
            titre: "Rapport de conformité — Sentinel MCP".to_string(),
            sous_titre: "Bundle d'évidence MCP09 / MCP03".to_string(),
            resume_exec: resume_exec_md.clone(),
            inventaire: inventaire_md.clone(),
            journal: journal_md.clone(),
            mapping_conformite: mapping_conformite_md.clone(),
            plan_remediation: plan_remediation_md.clone(),
            horodatage: Utc::now().to_rfc3339(),
        };
        let pdf_path = Self::tenter_pdf(&contenu_pdf);

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
