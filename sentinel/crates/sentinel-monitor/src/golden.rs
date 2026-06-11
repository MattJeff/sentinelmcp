//! Golden baselines — export/import JSON signé Ed25519 pour partage d'équipe.
//!
//! Un opérateur exporte les baselines courantes de son inventaire dans un
//! fichier `baselines.json` signé (signature Ed25519 réutilisée de
//! `sentinel-report::signature`). Un coéquipier importe le fichier : la
//! clé publique embarquée est d'abord confrontée à une liste de clés de
//! confiance fournie par l'importateur (ancre de confiance — la clé du
//! fichier seule ne prouve rien, un attaquant peut auto-signer un fichier
//! forgé avec sa propre paire), puis la signature est vérifiée avant
//! toute écriture, et chaque baseline est ré-enregistrée (versionnée) au
//! nom de l'importateur — la provenance reste tracée dans la raison de
//! l'historique.

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use sentinel_protocol::Baseline;
use sentinel_report::signature::{verifier_signature, SignataireBundle};
use sentinel_store::Store;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Version du format de fichier — incrémentée en cas de rupture.
pub const FORMAT_GOLDEN_V1: u32 = 1;

/// Une baseline exportée, accompagnée de l'endpoint du serveur pour que
/// l'import puisse résoudre le serveur local correspondant même si les
/// UUID diffèrent d'un poste à l'autre.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntreeGolden {
    pub endpoint: String,
    pub baseline: Baseline,
}

/// Charge utile signée du fichier `baselines.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadGolden {
    pub format: u32,
    pub exporte_a: DateTime<Utc>,
    pub exporte_par: String,
    pub baselines: Vec<EntreeGolden>,
}

/// Enveloppe du fichier : payload + signature Ed25519 (hex) + clé
/// publique (hex). La signature couvre la sérialisation JSON compacte
/// du payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FichierGolden {
    pub payload: serde_json::Value,
    pub signature_ed25519_hex: String,
    pub cle_publique_hex: String,
}

/// Résultat d'un import de golden baselines.
#[derive(Debug, Clone, Default)]
pub struct BilanImport {
    /// Baselines importées (serveur résolu localement).
    pub importees: usize,
    /// Entrées ignorées faute de serveur local correspondant.
    pub ignorees: Vec<String>,
}

/// Gestionnaire d'export/import des golden baselines.
pub struct GoldenBaselines {
    pub store: Store,
}

impl GoldenBaselines {
    pub fn nouveau(store: Store) -> Self {
        Self { store }
    }

    /// Exporte la baseline courante de chaque serveur de l'inventaire en
    /// JSON signé. Les serveurs sans baseline sont omis. Retourne le
    /// contenu du fichier `baselines.json`.
    pub fn exporter(&self, signataire: &SignataireBundle, exporte_par: &str) -> Result<String> {
        let mut baselines = vec![];
        for serveur in self.store.lister_serveurs()? {
            if let Some(baseline) = self.store.derniere_baseline(serveur.id)? {
                baselines.push(EntreeGolden {
                    endpoint: serveur.endpoint.clone(),
                    baseline,
                });
            }
        }
        let payload = PayloadGolden {
            format: FORMAT_GOLDEN_V1,
            exporte_a: Utc::now(),
            exporte_par: exporte_par.to_string(),
            baselines,
        };
        let payload_value = serde_json::to_value(&payload)?;
        let octets = serde_json::to_vec(&payload_value)?;
        let signature = signataire.signer(&octets);
        let fichier = FichierGolden {
            payload: payload_value,
            signature_ed25519_hex: hex::encode(signature),
            cle_publique_hex: hex::encode(&signataire.cle_publique),
        };
        Ok(serde_json::to_string_pretty(&fichier)?)
    }

    /// Vérifie un fichier golden sans rien écrire. Retourne le payload
    /// désérialisé si — et seulement si — la clé publique embarquée
    /// figure dans `cles_de_confiance` (octets bruts de clés Ed25519,
    /// 32 octets chacune) ET que la signature est valide.
    ///
    /// L'ancre de confiance est indispensable : la clé publique du
    /// fichier est fournie par le fichier lui-même, donc un attaquant
    /// peut forger un payload, le signer avec sa propre paire et
    /// embarquer sa propre clé — la signature serait « valide ». Seule
    /// la confrontation à une liste de clés attendues, fournie hors
    /// bande par l'importateur, distingue un export légitime d'un
    /// fichier auto-signé. Une liste vide rejette tout fichier.
    pub fn verifier_fichier(
        contenu: &str,
        cles_de_confiance: &[Vec<u8>],
    ) -> Result<PayloadGolden> {
        let fichier: FichierGolden = serde_json::from_str(contenu)
            .map_err(|e| anyhow!("fichier golden illisible : {e}"))?;
        let octets = serde_json::to_vec(&fichier.payload)?;
        let signature = hex::decode(&fichier.signature_ed25519_hex)
            .map_err(|e| anyhow!("signature hex invalide : {e}"))?;
        let cle_publique = hex::decode(&fichier.cle_publique_hex)
            .map_err(|e| anyhow!("clé publique hex invalide : {e}"))?;
        if !cles_de_confiance.iter().any(|cle| cle == &cle_publique) {
            bail!(
                "clé publique non reconnue : fichier golden rejeté \
                 (la clé embarquée ne figure pas parmi les clés de confiance)"
            );
        }
        if !verifier_signature(&cle_publique, &octets, &signature) {
            bail!("signature Ed25519 invalide : fichier golden rejeté");
        }
        let payload: PayloadGolden = serde_json::from_value(fichier.payload)?;
        if payload.format != FORMAT_GOLDEN_V1 {
            bail!("format golden non supporté : {}", payload.format);
        }
        Ok(payload)
    }

    /// Importe un fichier golden après vérification de la clé publique
    /// (contre `cles_de_confiance` — voir [`Self::verifier_fichier`])
    /// puis de la signature. Rien n'est écrit en cas de rejet.
    ///
    /// Chaque entrée est résolue vers un serveur local — d'abord par
    /// `serveur_id`, sinon par `endpoint`. Les entrées sans serveur
    /// local correspondant sont ignorées (listées dans le bilan). Les
    /// baselines importées sont ré-enregistrées (versionnées) au nom de
    /// `approbateur`, avec une raison qui trace la provenance.
    pub fn importer(
        &self,
        contenu: &str,
        approbateur: &str,
        cles_de_confiance: &[Vec<u8>],
    ) -> Result<BilanImport> {
        let payload = Self::verifier_fichier(contenu, cles_de_confiance)?;

        let serveurs = self.store.lister_serveurs()?;
        let mut bilan = BilanImport::default();
        for entree in payload.baselines {
            let serveur_local = serveurs
                .iter()
                .find(|s| s.id == entree.baseline.serveur_id)
                .or_else(|| serveurs.iter().find(|s| s.endpoint == entree.endpoint));
            let Some(serveur) = serveur_local else {
                bilan.ignorees.push(entree.endpoint.clone());
                continue;
            };
            let baseline = Baseline {
                id: Uuid::new_v4(),
                serveur_id: serveur.id,
                empreinte_serveur: entree.baseline.empreinte_serveur,
                empreintes_outils: entree.baseline.empreintes_outils,
                outils: entree.baseline.outils,
                date_approbation: Utc::now(),
                approuve_par: approbateur.to_string(),
            };
            self.store.enregistrer_baseline_versionnee(
                &baseline,
                &format!(
                    "import golden baseline (exportée par {} le {})",
                    payload.exporte_par,
                    payload.exporte_a.to_rfc3339()
                ),
            )?;
            bilan.importees += 1;
        }
        Ok(bilan)
    }
}
