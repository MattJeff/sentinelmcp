//! `sentinel monitor` — boucle de surveillance continue.
//!
//! Re-balaye périodiquement la découverte (sentinel-discovery), compare
//! l'inventaire observé au store via le détecteur de nouveaux serveurs de
//! sentinel-monitor, persiste serveurs + constats. Logs structurés sur
//! stderr, arrêt propre sur SIGINT/SIGTERM en mode `--daemon`.

use anyhow::Result;
use chrono::Utc;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

use sentinel_discovery::OrchestrateurDecouverte;
use sentinel_monitor::DetecteurNouveauxServeurs;
use sentinel_protocol::{
    extraire_package_id, Couleur, Portee, Serveur, Severite, StatutServeur, Transport,
};
use sentinel_store::Store;

use crate::db::ouvrir_store;
use crate::sortie::{code_depuis_severites, CodeSortie};

/// Une itération de surveillance : découverte → comparaison → persistance.
/// Retourne les sévérités des constats émis pendant l'itération.
async fn iteration(store: &Store, detecteur: &DetecteurNouveauxServeurs) -> Result<Vec<Severite>> {
    let rapport = OrchestrateurDecouverte::default().balayer().await;
    let connus = store.lister_serveurs()?;
    let mut severites = Vec::new();
    let mut nb_serveurs = 0usize;
    let mut nb_nouveaux = 0usize;

    for client in &rapport.clients {
        for serv in &client.serveurs {
            if serv.disabled {
                continue;
            }
            nb_serveurs += 1;

            let transport = if serv.transport.eq_ignore_ascii_case("http")
                || serv.transport.eq_ignore_ascii_case("sse")
            {
                Transport::Http
            } else {
                Transport::Stdio
            };
            let endpoint = match (&serv.commande, &serv.url) {
                (Some(c), _) if !c.is_empty() => {
                    if serv.args.is_empty() {
                        c.clone()
                    } else {
                        format!("{} {}", c, serv.args.join(" "))
                    }
                }
                (_, Some(u)) => u.clone(),
                _ => serv.nom.clone(),
            };
            let package_id = extraire_package_id(&endpoint, transport);
            let maintenant = Utc::now();

            let observe = match store.get_serveur_par_identite(&package_id, &serv.scope)? {
                Some(mut existant) => {
                    existant.derniere_vue = maintenant;
                    existant
                }
                None => Serveur {
                    id: Uuid::new_v4(),
                    endpoint: endpoint.clone(),
                    transport,
                    portees: vec![Portee::Inconnu],
                    statut: StatutServeur::Inconnu,
                    couleur: Couleur::Orange,
                    premiere_vue: maintenant,
                    derniere_vue: maintenant,
                    empreinte_courante: None,
                    tags: vec![],
                    scope: serv.scope.clone(),
                },
            };

            if let Some(constat) = detecteur.evaluer(&observe, &connus) {
                nb_nouveaux += 1;
                severites.push(constat.severite);
                info!(
                    serveur = %observe.endpoint,
                    severite = ?constat.severite,
                    "nouveau serveur MCP détecté"
                );
                if let Err(e) = store.enregistrer_constat(&constat) {
                    warn!("constat non persisté ({}): {e}", observe.endpoint);
                }
            }

            if let Err(e) = store.upsert_serveur(&observe) {
                warn!("serveur non persisté ({}): {e}", observe.endpoint);
            }
        }
    }

    info!(
        clients = rapport.clients.len(),
        serveurs = nb_serveurs,
        nouveaux = nb_nouveaux,
        "balayage terminé"
    );
    Ok(severites)
}

pub async fn executer(
    daemon: bool,
    interval: u64,
    db: Option<PathBuf>,
    _quiet: bool,
) -> Result<CodeSortie> {
    let store = ouvrir_store(db.as_deref())?;
    let detecteur = DetecteurNouveauxServeurs::nouveau();
    let mut severites: Vec<Severite> = Vec::new();

    if !daemon {
        severites.extend(iteration(&store, &detecteur).await?);
        return Ok(code_depuis_severites(severites.iter()));
    }

    // Handlers installés AVANT le premier balayage pour qu'un signal reçu
    // pendant la première itération produise déjà un arrêt propre.
    #[cfg(unix)]
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    info!(interval_secs = interval, "mode daemon démarré — Ctrl-C ou SIGTERM pour arrêter");

    loop {
        let travail = async {
            match iteration(&store, &detecteur).await {
                Ok(s) => severites.extend(s),
                Err(e) => warn!("itération en échec : {e:#}"),
            }
            tokio::time::sleep(Duration::from_secs(interval.max(1))).await;
        };

        #[cfg(unix)]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("SIGINT reçu — arrêt propre");
                    break;
                }
                _ = sigterm.recv() => {
                    info!("SIGTERM reçu — arrêt propre");
                    break;
                }
                _ = travail => {}
            }
        }
        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl-C reçu — arrêt propre");
                    break;
                }
                _ = travail => {}
            }
        }
    }

    Ok(code_depuis_severites(severites.iter()))
}
