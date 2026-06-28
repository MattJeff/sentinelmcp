//! `sentinel scan` — découverte complète des clients IA + inventaire des
//! serveurs MCP déclarés, probing actif opt-in (`--probe`), persistance
//! dans le store SQLite et sortie table ou JSON.

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

use sentinel_detect::{ConfigDetection, InspecteurPoisoning};
use sentinel_discovery::{EtatProbe, OrchestrateurDecouverte, ProbeurActif, ServeurMcpDeclare};
use sentinel_protocol::{
    extraire_package_id, Couleur, Portee, Serveur, Severite, StatutServeur, Transport,
};
use sentinel_scan::scope::inferer_portee;
use sentinel_scan::store_contract::{AdaptateurStore, ContratScanStore, EvenementInventaire};
use sentinel_store::Store;

use crate::db::ouvrir_store;
use crate::sortie::{
    code_depuis_severites, imprimer, libelle_severite, libelle_type, rendre_table, CodeSortie,
};

pub struct OptionsScan {
    pub probe: bool,
    pub db: Option<PathBuf>,
    pub json: bool,
    pub quiet: bool,
    /// Configuration du pipeline de détection hybride (patterns + smuggling +
    /// line-jumping + YARA local + juge LLM optionnel). Voir `--yara`/`--llm`.
    pub detection: ConfigDetection,
}

#[derive(Serialize)]
struct ProbeJson {
    etat: String,
    nb_outils: usize,
    empreinte: Option<String>,
    erreur: Option<String>,
}

#[derive(Serialize)]
struct EntreeInventaireJson {
    client: String,
    nom: String,
    transport: String,
    endpoint: String,
    package_id: String,
    disabled: bool,
    probe: Option<ProbeJson>,
}

#[derive(Serialize, Clone)]
struct ConstatJson {
    serveur: String,
    outil: Option<String>,
    #[serde(rename = "type")]
    type_constat: String,
    severite: String,
    titre: String,
    detail: String,
}

#[derive(Serialize)]
struct SortieScan {
    demarre_a: String,
    termine_a: String,
    nb_clients_detectes: usize,
    inventaire: Vec<EntreeInventaireJson>,
    constats: Vec<ConstatJson>,
}

fn libelle_etat_probe(etat: &EtatProbe) -> &'static str {
    match etat {
        EtatProbe::Reussi => "reussi",
        EtatProbe::EchecLancement => "echec-lancement",
        EtatProbe::EchecHandshake => "echec-handshake",
        EtatProbe::EchecParseur => "echec-parseur",
    }
}

/// Endpoint canonique d'un serveur déclaré : ligne de commande complète
/// (stdio) ou URL (http) — même convention que l'app desktop.
fn endpoint_declare(s: &ServeurMcpDeclare) -> String {
    match (&s.commande, &s.url) {
        (Some(c), _) if !c.is_empty() => {
            if s.args.is_empty() {
                c.clone()
            } else {
                format!("{} {}", c, s.args.join(" "))
            }
        }
        (_, Some(u)) => u.clone(),
        _ => s.nom.clone(),
    }
}

fn transport_declare(s: &ServeurMcpDeclare) -> Transport {
    if s.transport.eq_ignore_ascii_case("http") || s.transport.eq_ignore_ascii_case("sse") {
        Transport::Http
    } else {
        Transport::Stdio
    }
}

/// Upsert d'un serveur déclaré (sans probe) : résolution par identité
/// canonique `(package_id, scope)` pour ne pas dupliquer les lignes.
fn upsert_declare(store: &Store, s: &ServeurMcpDeclare) -> Result<()> {
    let endpoint = endpoint_declare(s);
    let transport = transport_declare(s);
    let package_id = extraire_package_id(&endpoint, transport);
    let maintenant = Utc::now();

    let serveur = match store.get_serveur_par_identite(&package_id, &s.scope)? {
        Some(mut existant) => {
            existant.derniere_vue = maintenant;
            existant
        }
        None => Serveur {
            id: Uuid::new_v4(),
            endpoint,
            transport,
            portees: vec![Portee::Inconnu],
            statut: StatutServeur::Inconnu,
            couleur: Couleur::Orange,
            premiere_vue: maintenant,
            derniere_vue: maintenant,
            empreinte_courante: None,
            tags: vec![],
            scope: s.scope.clone(),
        },
    };
    store.upsert_serveur(&serveur)
}

pub async fn executer(opts: OptionsScan) -> Result<CodeSortie> {
    let rapport = OrchestrateurDecouverte::default().balayer().await;
    let store = ouvrir_store(opts.db.as_deref())?;
    let adaptateur = Arc::new(AdaptateurStore::nouveau(store.clone()));
    let probeur = ProbeurActif::par_defaut();

    let mut inventaire: Vec<EntreeInventaireJson> = Vec::new();
    let mut constats: Vec<ConstatJson> = Vec::new();
    let mut severites: Vec<Severite> = Vec::new();

    for client in &rapport.clients {
        for serv in &client.serveurs {
            if serv.disabled {
                continue;
            }
            let endpoint = endpoint_declare(serv);
            let transport = transport_declare(serv);
            let package_id = extraire_package_id(&endpoint, transport);

            let mut probe_json: Option<ProbeJson> = None;

            if opts.probe && transport == Transport::Stdio {
                let rp = probeur.probe_serveur(serv).await;
                if rp.etat == EtatProbe::Reussi {
                    let portees = inferer_portee(&rp.outils);
                    let evenement = EvenementInventaire {
                        endpoint: endpoint.clone(),
                        transport,
                        outils: rp.outils.clone(),
                        portees,
                    };
                    match adaptateur.enregistrer_inventaire(evenement).await {
                        Ok(serveur_id) => {
                            // Pipeline de détection hybride : patterns + smuggling +
                            // line-jumping + YARA local (+ juge LLM si `--llm`). Superset
                            // strict des constats poisoning du probe (`rp.constats_poisoning`,
                            // qui n'est que `InspecteurPoisoning::inspecter`).
                            let constats_detection = InspecteurPoisoning::inspecter_complet(
                                &rp.outils,
                                serveur_id,
                                &opts.detection,
                            )
                            .await;
                            for constat in &constats_detection {
                                severites.push(constat.severite);
                                constats.push(ConstatJson {
                                    serveur: serv.nom.clone(),
                                    outil: constat.outil_nom.clone(),
                                    type_constat: libelle_type(&constat.type_constat).into(),
                                    severite: libelle_severite(&constat.severite).into(),
                                    titre: constat.titre.clone(),
                                    detail: constat.detail.clone(),
                                });
                                if let Err(e) = store.enregistrer_constat(constat) {
                                    tracing::warn!(
                                        "constat de détection non persisté pour {}: {e}",
                                        serv.nom
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("inventaire non persisté pour {}: {e}", serv.nom);
                        }
                    }
                } else if let Err(e) = upsert_declare(&store, serv) {
                    tracing::warn!("serveur déclaré non persisté ({}): {e}", serv.nom);
                }
                probe_json = Some(ProbeJson {
                    etat: libelle_etat_probe(&rp.etat).into(),
                    nb_outils: rp.outils.len(),
                    empreinte: rp.empreinte_serveur.map(|e| e.as_str().to_string()),
                    erreur: rp.erreur.clone(),
                });
            } else if let Err(e) = upsert_declare(&store, serv) {
                tracing::warn!("serveur déclaré non persisté ({}): {e}", serv.nom);
            }

            inventaire.push(EntreeInventaireJson {
                client: client.libelle.clone(),
                nom: serv.nom.clone(),
                transport: serv.transport.clone(),
                endpoint,
                package_id,
                disabled: serv.disabled,
                probe: probe_json,
            });
        }
    }

    if opts.json {
        let sortie = SortieScan {
            demarre_a: rapport.demarre_a.to_rfc3339(),
            termine_a: rapport.termine_a.to_rfc3339(),
            nb_clients_detectes: rapport.clients.len(),
            inventaire,
            constats: constats.clone(),
        };
        imprimer(opts.quiet, &serde_json::to_string_pretty(&sortie)?);
    } else {
        imprimer(
            opts.quiet,
            &format!(
                "Scan terminé — {} client(s) IA, {} serveur(s) MCP déclaré(s), {} constat(s).\n",
                rapport.clients.len(),
                inventaire.len(),
                constats.len()
            ),
        );
        if !inventaire.is_empty() {
            let lignes: Vec<Vec<String>> = inventaire
                .iter()
                .map(|e| {
                    vec![
                        e.client.clone(),
                        e.nom.clone(),
                        e.transport.clone(),
                        e.package_id.clone(),
                        e.probe
                            .as_ref()
                            .map(|p| format!("{} ({} outils)", p.etat, p.nb_outils))
                            .unwrap_or_else(|| "-".into()),
                    ]
                })
                .collect();
            imprimer(
                opts.quiet,
                &rendre_table(&["CLIENT", "SERVEUR", "TRANSPORT", "PACKAGE", "PROBE"], &lignes),
            );
        }
        if !constats.is_empty() {
            let lignes: Vec<Vec<String>> = constats
                .iter()
                .map(|c| {
                    vec![
                        c.severite.clone(),
                        c.serveur.clone(),
                        c.outil.clone().unwrap_or_else(|| "-".into()),
                        c.titre.clone(),
                    ]
                })
                .collect();
            imprimer(
                opts.quiet,
                &format!(
                    "\n{}",
                    rendre_table(&["SEVERITE", "SERVEUR", "OUTIL", "TITRE"], &lignes)
                ),
            );
        }
    }

    Ok(code_depuis_severites(severites.iter()))
}
