//! `sentinel report` — génère le rapport d'évidence via sentinel-report.
//!
//! `--format json` écrit le bundle JSON signé (schéma `ExportJson`) ;
//! `--format pdf` rend le rapport complet via `RenduPdf`.

use anyhow::{Context, Result};
use chrono::Utc;
use std::path::Path;

use sentinel_protocol::Severite;
use sentinel_report::pdf::ContenuPdf;
use sentinel_report::{GenerateurRapport, RenduPdf};

use crate::db::ouvrir_store;
use crate::sortie::{code_depuis_severites, imprimer, CodeSortie};

pub async fn executer(
    pdf: bool,
    output: &Path,
    db: Option<std::path::PathBuf>,
    quiet: bool,
) -> Result<CodeSortie> {
    let store = ouvrir_store(db.as_deref())?;
    let severites: Vec<Severite> = store
        .lister_constats_ouverts()?
        .iter()
        .map(|c| c.severite)
        .collect();

    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur.generer_bundle().await?;

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création du répertoire {parent:?}"))?;
        }
    }

    if pdf {
        let inventaire_md = {
            let mut md = String::from("# Inventaire des serveurs MCP\n\n");
            for s in &bundle.inventaire {
                md.push_str(&format!(
                    "- {} — transport {:?}, statut {:?}, couleur {:?}\n",
                    s.endpoint, s.transport, s.statut, s.couleur
                ));
            }
            md
        };
        let contenu = ContenuPdf {
            titre: "Sentinel MCP — Rapport de conformité".into(),
            sous_titre: "OWASP MCP09 / MCP03 — surveillance des serveurs MCP".into(),
            resume_exec: bundle.resume_exec_md.clone(),
            inventaire: inventaire_md,
            journal: bundle.journal_md.clone(),
            mapping_conformite: bundle.mapping_conformite_md.clone(),
            plan_remediation: bundle.plan_remediation_md.clone(),
            horodatage: Utc::now().format("%Y-%m-%d %H:%M UTC").to_string(),
            ..Default::default()
        };
        RenduPdf::produire_contenu(&contenu, output)
            .with_context(|| format!("rendu PDF vers {}", output.display()))?;
    } else {
        let json = serde_json::to_string_pretty(&bundle.json_export)?;
        std::fs::write(output, json)
            .with_context(|| format!("écriture du rapport JSON vers {}", output.display()))?;
    }

    imprimer(
        quiet,
        &format!(
            "Rapport généré : {} ({} serveur(s), {} constat(s) ouvert(s)).",
            output.display(),
            bundle.inventaire.len(),
            severites.len()
        ),
    );

    Ok(code_depuis_severites(severites.iter()))
}
