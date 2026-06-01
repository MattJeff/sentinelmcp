//! Intégrateur démo « scan qui se remplit » — Agent 1.10.
//!
//! Assemble capteur + signature + parseur en un flux démontrable qui remplit
//! progressivement l'inventaire. Effet « ça travaille, ça trouve ».
//!
//! Flux interne :
//!   1. `mpsc::channel` pour `EvenementBrut`.
//!   2. Capture (http/stdio/fichier) → push.
//!   3. Boucle : `filtre_grossier` → `confirmer_message` → si réponse
//!      `tools/list` → `parser_reponse_tools_list` → `inferer_portee` →
//!      `enregistrer_inventaire(store)`.
//!   4. `tracing::info!` à chaque serveur découvert.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use sentinel_protocol::{Direction, EvenementBrut, MethodeMcp, Transport};
use tokio::sync::mpsc;
use tracing::info;

use crate::signature::{confirmer_message, filtre_grossier, SuiviSessions};
use crate::store_contract::{ContratScanStore, EvenementInventaire, MockStore};
use crate::tools_list::parser_reponse_tools_list;
use crate::scope::inferer_portee;

// ---------------------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------------------

/// Mode de capture de la démo.
pub enum ModeDemo {
    /// Lit des fichiers de trafic pré-enregistrés (démo offline).
    Fichier(PathBuf),
    /// Lance la capture HTTP réelle sur un port.
    Http(SocketAddr, String),
    /// Lance le wrapper stdio sur une commande.
    Stdio(String, Vec<String>),
}

/// Configuration complète de la démo.
pub struct ConfigDemo {
    pub mode: ModeDemo,
    pub store_path: PathBuf,
}

/// Métriques collectées pendant la démo.
#[derive(Debug, Default)]
pub struct MetriqueDemo {
    pub serveurs_decouverts: u64,
    pub outils_decouverts: u64,
    /// Durée en ms entre le lancement et la première carte rouge (Secrets ou
    /// Filesystem avec outil d'écriture).
    pub time_to_first_red_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Points d'entrée publics
// ---------------------------------------------------------------------------

/// Lance la démo avec la configuration par défaut : lecture du fichier de
/// fixture embarqué, store en mémoire.
pub async fn lancer_demo() -> anyhow::Result<()> {
    let store = Arc::new(MockStore::nouveau());
    let _ = executer_demo(ModeDemo::Fichier(fichier_fixture_defaut()), store).await?;
    Ok(())
}

/// Lance la démo avec une configuration explicite et un store en mémoire.
pub async fn lancer_avec_config(c: ConfigDemo) -> anyhow::Result<()> {
    let store = Arc::new(MockStore::nouveau());
    let _ = executer_demo(c.mode, store).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Chemin de fixture par défaut
// ---------------------------------------------------------------------------

fn fichier_fixture_defaut() -> PathBuf {
    // Cherche dans les chemins classiques de l'artefact de build.
    let candidats = [
        PathBuf::from("crates/sentinel-scan/tests/fixtures/trafic_demo.jsonl"),
        PathBuf::from("tests/fixtures/trafic_demo.jsonl"),
    ];
    for c in &candidats {
        if c.exists() {
            return c.clone();
        }
    }
    candidats[0].clone()
}

// ---------------------------------------------------------------------------
// Moteur de démo
// ---------------------------------------------------------------------------

/// Exécute la démo, retourne les métriques.
pub async fn executer_demo(
    mode: ModeDemo,
    store: Arc<dyn ContratScanStore>,
) -> anyhow::Result<MetriqueDemo> {
    let (tx, mut rx) = mpsc::channel::<EvenementBrut>(512);
    let debut = Instant::now();

    // Lance la source de trafic dans une tâche dédiée.
    match mode {
        ModeDemo::Fichier(chemin) => {
            let tx2 = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = lire_fichier_jsonl(chemin, tx2).await {
                    tracing::warn!("lecture fixture : {e}");
                }
            });
        }
        ModeDemo::Http(addr, cible) => {
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let capture = crate::http::CaptureHttp::nouvelle(tx2, cible);
                if let Err(e) = capture.servir(addr).await {
                    tracing::warn!("CaptureHttp : {e}");
                }
            });
        }
        ModeDemo::Stdio(programme, args) => {
            let tx2 = tx.clone();
            tokio::spawn(async move {
                let wrapper = crate::stdio::WrapperStdio::nouveau(programme, args, tx2);
                if let Err(e) = wrapper.executer().await {
                    tracing::warn!("WrapperStdio : {e}");
                }
            });
        }
    }

    // Boucle de consommation du pipeline.
    let mut suivi = SuiviSessions::nouveau();
    let mut metriques = MetriqueDemo::default();

    // Suivi des sessions déjà enregistrées (endpoint → bool) pour détecter les
    // nouveaux serveurs même sans tools/list (p. ex. sur un simple initialize).
    let mut sessions_enregistrees: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();

    // On ferme notre côté émetteur pour que le `recv` termine quand la
    // source est épuisée.
    drop(tx);

    while let Some(evt) = rx.recv().await {
        // Étape 1 : filtre grossier (JSON-RPC ?)
        if !filtre_grossier(&evt) {
            continue;
        }

        // Étape 2 : confirmation MCP (méthode connue ou session ouverte).
        let msg = match confirmer_message(&evt, &mut suivi) {
            Some(m) => m,
            None => continue,
        };

        // Étape 3 : si c'est une réponse tools/list, extraire les outils.
        // Une réponse tools/list n'a pas de champ "method" mais a "result.tools".
        let est_reponse_tools_list =
            msg.payload.get("result")
                .and_then(|r| r.get("tools"))
                .is_some()
            && msg.payload.get("method").is_none();

        if est_reponse_tools_list {
            match parser_reponse_tools_list(&msg.payload) {
                Ok(reponse) if !reponse.outils.is_empty() => {
                    let portees = inferer_portee(&reponse.outils);
                    let nb_outils = reponse.outils.len() as u64;

                    let evenement = EvenementInventaire {
                        endpoint: msg.serveur.clone(),
                        transport: msg.transport,
                        outils: reponse.outils,
                        portees: portees.clone(),
                    };

                    store.enregistrer_inventaire(evenement).await?;

                    // Métrique serveurs (un seul comptage par endpoint).
                    let nouveau = !sessions_enregistrees
                        .insert(msg.serveur.clone(), true)
                        .unwrap_or(false);

                    if nouveau {
                        metriques.serveurs_decouverts += 1;
                    }
                    metriques.outils_decouverts += nb_outils;

                    // Détection time-to-first-red : Secrets ou Filesystem présent.
                    let est_rouge = portees.iter().any(|p| {
                        matches!(
                            p,
                            sentinel_protocol::Portee::Secrets
                                | sentinel_protocol::Portee::Filesystem
                        )
                    });

                    if est_rouge && metriques.time_to_first_red_ms.is_none() {
                        metriques.time_to_first_red_ms = Some(debut.elapsed().as_millis() as u64);
                        info!(
                            endpoint = %msg.serveur,
                            time_ms = metriques.time_to_first_red_ms,
                            portees = ?portees,
                            "[ROUGE] premier serveur à risque détecté"
                        );
                    }

                    info!(
                        endpoint = %msg.serveur,
                        outils = nb_outils,
                        portees = ?portees,
                        "[INVENTAIRE] serveur découvert"
                    );
                }
                Ok(_) => {} // Réponse vide, pas d'outil.
                Err(e) => {
                    tracing::debug!("parse tools/list échoué : {e}");
                }
            }
        } else if matches!(msg.methode, MethodeMcp::Initialize) {
            // Même sans tools/list, on enregistre le serveur comme connu
            // pour l'effet progressif.
            if !sessions_enregistrees.contains_key(&msg.serveur) {
                sessions_enregistrees.insert(msg.serveur.clone(), false);
                info!(
                    endpoint = %msg.serveur,
                    transport = ?msg.transport,
                    "[DÉCOUVERTE] serveur MCP vu pour la première fois"
                );
            }
        }
    }

    info!(
        serveurs = metriques.serveurs_decouverts,
        outils = metriques.outils_decouverts,
        time_to_first_red_ms = ?metriques.time_to_first_red_ms,
        "[DÉMO] scan terminé"
    );

    Ok(metriques)
}

// ---------------------------------------------------------------------------
// Lecteur de fichier JSONL (mode Fichier)
// ---------------------------------------------------------------------------

/// Lit un fichier JSONL ligne par ligne, parse chaque ligne comme un
/// `EvenementBrut` (ou comme un message MCP brut) et l'émet sur `tx`.
async fn lire_fichier_jsonl(
    chemin: PathBuf,
    tx: mpsc::Sender<EvenementBrut>,
) -> anyhow::Result<()> {
    use tokio::io::AsyncBufReadExt;

    let fichier = tokio::fs::File::open(&chemin)
        .await
        .map_err(|e| anyhow::anyhow!("impossible d'ouvrir {:?} : {e}", chemin))?;

    let mut lecteur = tokio::io::BufReader::new(fichier);
    let mut ligne = String::new();

    loop {
        ligne.clear();
        let n = lecteur.read_line(&mut ligne).await?;
        if n == 0 {
            break; // EOF
        }
        let ligne_trim = ligne.trim();
        if ligne_trim.is_empty() || ligne_trim.starts_with("//") {
            continue;
        }

        // Tente de désérialiser directement en EvenementBrut.
        if let Ok(evt) = serde_json::from_str::<EvenementBrut>(ligne_trim) {
            if tx.send(evt).await.is_err() {
                break;
            }
            continue;
        }

        // Sinon, tente de lire comme un payload JSON-RPC brut et synthétise
        // un EvenementBrut minimal.
        if let Ok(payload) = serde_json::from_str::<serde_json::Value>(ligne_trim) {
            let methode = payload
                .get("method")
                .and_then(|v| v.as_str())
                .map(String::from);

            let evt = EvenementBrut {
                session_id: "demo-session".to_string(),
                transport: Transport::Http,
                serveur: "demo-serveur:8080".to_string(),
                direction: Direction::ServeurVersClient,
                methode,
                payload,
                horodatage: chrono::Utc::now(),
            };

            if tx.send(evt).await.is_err() {
                break;
            }
        } else {
            tracing::warn!("ligne JSONL non parseable ignorée : {:?}", &ligne_trim[..ligne_trim.len().min(80)]);
        }
    }

    Ok(())
}
