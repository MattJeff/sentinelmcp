//! Garde stdio temps réel — relaie le trafic JSON-RPC d'un serveur MCP
//! tout en surveillant les réponses `tools/list` au passage.
//!
//! Réutilise les briques existantes, sans duplication :
//! - `sentinel_scan::parser_reponse_tools_list` pour extraire les outils ;
//! - `sentinel_detect::DetecteurRugPull` (empreinte canonique SHA-256
//!   + diff lisible) pour comparer à la baseline approuvée ;
//! - `sentinel_store::Store` pour lire la baseline, écrire le constat
//!   et l'historique de contact.
//!
//! Règles impératives :
//! - Relais fidèle octet-à-octet, ligne par ligne, flush immédiat ;
//!   seules les réponses `tools/list` subissent une analyse avant
//!   retransmission (les autres lignes ne touchent jamais le store).
//! - Mode `--block` : une réponse `tools/list` en dérive **critique**
//!   est remplacée par une erreur JSON-RPC `-32000` ; tout le reste
//!   passe inchangé.
//! - Fail-open : une erreur d'analyse ou de store n'interrompt jamais
//!   le relais — un garde cassé ne doit pas casser le client.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use chrono::Utc;
use sentinel_detect::empreinte_serveur;
use sentinel_detect::rugpull::{ContexteRugPull, DetecteurRugPull};
use sentinel_protocol::{extraire_package_id, Serveur, Severite, Transport};
use sentinel_scan::parser_reponse_tools_list;
use sentinel_store::Store;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

/// Code d'erreur JSON-RPC renvoyé quand une réponse est bloquée.
pub const CODE_BLOCAGE: i64 = -32000;
/// Message d'erreur JSON-RPC renvoyé quand une réponse est bloquée.
pub const MESSAGE_BLOCAGE: &str =
    "Sentinel: tool definitions changed, blocked pending approval";

/// État partagé entre la voie client→serveur et la voie serveur→client.
#[derive(Default)]
struct EtatPartage {
    /// Ids JSON-RPC des requêtes `tools/list` en attente de réponse
    /// (clé : sérialisation de la `Value` id, e.g. `1` ou `"abc"`).
    ids_tools_list: Mutex<HashSet<String>>,
    /// `true` si `notifications/tools/list_changed` a été vu depuis le
    /// dernier `tools/list` — consommé (swap) à chaque réponse analysée.
    notification_recue: AtomicBool,
}

/// Garde autour d'un sous-processus serveur MCP stdio.
pub struct GardeStdio {
    programme: String,
    args: Vec<String>,
    store: Option<Store>,
    mode_block: bool,
}

impl GardeStdio {
    /// `store: None` = observation désactivée (fail-open), relais pur.
    pub fn nouveau(
        programme: impl Into<String>,
        args: Vec<String>,
        store: Option<Store>,
        mode_block: bool,
    ) -> Self {
        Self {
            programme: programme.into(),
            args,
            store,
            mode_block,
        }
    }

    /// Endpoint logique reconstruit — même convention que la découverte
    /// et le CLI : `commande arg1 arg2 …`. C'est cette chaîne qui sert à
    /// retrouver le serveur (et sa baseline) dans le store.
    fn endpoint(&self) -> String {
        if self.args.is_empty() {
            self.programme.clone()
        } else {
            format!("{} {}", self.programme, self.args.join(" "))
        }
    }

    /// Lance le sous-processus, relaie stdin/stdout (stderr passthrough),
    /// observe les `tools/list`, et retourne le code de sortie du
    /// sous-processus.
    pub async fn executer(self) -> anyhow::Result<i32> {
        let mut child = Command::new(&self.programme)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!("impossible de lancer le sous-processus : {}", self.programme)
            })?;

        let child_stdin = child
            .stdin
            .take()
            .context("stdin du sous-processus non disponible")?;
        let child_stdout = child
            .stdout
            .take()
            .context("stdout du sous-processus non disponible")?;

        let etat = Arc::new(EtatPartage::default());
        let endpoint = self.endpoint();
        let analyseur = Analyseur {
            store: self.store,
            endpoint,
            mode_block: self.mode_block,
            session_id: Uuid::new_v4().to_string(),
        };

        let etat_in = etat.clone();
        let tache_stdin =
            tokio::spawn(async move { relayer_client_vers_serveur(child_stdin, etat_in).await });
        let tache_stdout = tokio::spawn(async move {
            relayer_serveur_vers_client(child_stdout, etat, analyseur).await
        });

        let statut = child.wait().await.context("attente du sous-processus")?;

        // La voie serveur→client se termine naturellement sur EOF ; la
        // voie client→serveur peut rester bloquée sur notre stdin une
        // fois le sous-processus mort — on la coupe.
        let _ = tache_stdout.await;
        tache_stdin.abort();

        Ok(statut.code().unwrap_or(-1))
    }
}

/// Analyse des réponses `tools/list` observées sur la voie
/// serveur→client. Tout est fail-open : la moindre erreur retourne
/// « ne pas bloquer » et le relais continue.
struct Analyseur {
    store: Option<Store>,
    endpoint: String,
    mode_block: bool,
    session_id: String,
}

impl Analyseur {
    /// Traite une réponse `tools/list`. Retourne `true` si la réponse
    /// doit être bloquée (mode `--block` + dérive critique).
    fn traiter_reponse(&self, payload: &Value, notification_recue: bool) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        let reponse = match parser_reponse_tools_list(payload) {
            Ok(r) => r,
            Err(_) => return false,
        };
        let serveur = match resoudre_serveur(store, &self.endpoint) {
            Ok(Some(s)) => s,
            Ok(None) => {
                emettre_evenement(&json!({
                    "source": "sentinel-guard",
                    "evenement": "serveur_inconnu",
                    "endpoint": self.endpoint,
                    "horodatage": Utc::now().to_rfc3339(),
                }));
                return false;
            }
            Err(_) => return false,
        };

        let _ = store.enregistrer_contact(serveur.id, &self.session_id, "tools/list", Utc::now());

        let baseline = match store.derniere_baseline(serveur.id) {
            Ok(Some(b)) => b,
            Ok(None) => {
                emettre_evenement(&json!({
                    "source": "sentinel-guard",
                    "evenement": "baseline_absente",
                    "serveur_id": serveur.id.to_string(),
                    "endpoint": self.endpoint,
                    "horodatage": Utc::now().to_rfc3339(),
                }));
                return false;
            }
            Err(_) => return false,
        };

        let empreinte_courante = empreinte_serveur(&reponse.outils);
        let ctx = ContexteRugPull {
            notification_recue,
            baseline,
            outils_courants: reponse.outils,
        };
        let Some(constat) = DetecteurRugPull::evaluer_contexte(&ctx, serveur.id) else {
            return false;
        };

        let bloque = self.mode_block && constat.severite == Severite::Critique;
        let _ = store.enregistrer_constat(&constat);

        emettre_evenement(&json!({
            "source": "sentinel-guard",
            "evenement": "derive_detectee",
            "serveur_id": serveur.id.to_string(),
            "endpoint": self.endpoint,
            "constat_id": constat.id.to_string(),
            "severite": constat.severite,
            "empreinte_baseline": ctx.baseline.empreinte_serveur.as_str(),
            "empreinte_courante": empreinte_courante.as_str(),
            "notification_recue": notification_recue,
            "bloque": bloque,
            "horodatage": Utc::now().to_rfc3339(),
        }));

        bloque
    }
}

/// Retrouve le serveur du store correspondant à l'endpoint relayé :
/// d'abord par endpoint exact, sinon par identité canonique
/// (`package_id`) — en préférant un candidat porteur d'une baseline.
fn resoudre_serveur(store: &Store, endpoint: &str) -> anyhow::Result<Option<Serveur>> {
    if let Some(s) = store.get_serveur_par_endpoint(endpoint)? {
        return Ok(Some(s));
    }
    let package_id = extraire_package_id(endpoint, Transport::Stdio);
    let candidats: Vec<Serveur> = store
        .lister_serveurs()?
        .into_iter()
        .filter(|s| {
            s.transport == Transport::Stdio
                && extraire_package_id(&s.endpoint, Transport::Stdio) == package_id
        })
        .collect();
    for c in &candidats {
        if store.derniere_baseline(c.id)?.is_some() {
            return Ok(Some(c.clone()));
        }
    }
    Ok(candidats.into_iter().next())
}

/// Ligne JSON structurée sur stderr — consommable par un agrégateur de
/// logs sans gêner le client MCP (qui ne lit que stdout).
fn emettre_evenement(evenement: &Value) {
    eprintln!("{evenement}");
}

/// Construit la réponse d'erreur JSON-RPC substituée en mode blocage.
pub(crate) fn reponse_blocage(id: &Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": CODE_BLOCAGE, "message": MESSAGE_BLOCAGE }
    })
    .to_string()
}

/// Si `valeur` est une requête `tools/list` avec id, retourne la clé
/// de suivi de cet id.
pub(crate) fn cle_requete_tools_list(valeur: &Value) -> Option<String> {
    if valeur.get("method").and_then(|m| m.as_str()) == Some("tools/list") {
        valeur.get("id").map(|id| id.to_string())
    } else {
        None
    }
}

/// Voie client→serveur : relais fidèle + enregistrement des ids des
/// requêtes `tools/list` pour reconnaître leurs réponses au retour.
async fn relayer_client_vers_serveur(
    mut child_stdin: tokio::process::ChildStdin,
    etat: Arc<EtatPartage>,
) -> anyhow::Result<()> {
    let mut lecteur = BufReader::new(tokio::io::stdin());
    let mut ligne = String::new();
    loop {
        ligne.clear();
        let n = lecteur.read_line(&mut ligne).await.context("lecture stdin")?;
        if n == 0 {
            break;
        }
        child_stdin
            .write_all(ligne.as_bytes())
            .await
            .context("écriture vers le sous-processus")?;
        child_stdin.flush().await.context("flush vers le sous-processus")?;

        let trim = ligne.trim();
        if trim.is_empty() {
            continue;
        }
        if let Ok(valeur) = serde_json::from_str::<Value>(trim) {
            if let Some(cle) = cle_requete_tools_list(&valeur) {
                etat.ids_tools_list.lock().unwrap().insert(cle);
            }
        }
    }
    // EOF côté client : on ferme le stdin du sous-processus pour qu'il
    // termine proprement.
    let _ = child_stdin.shutdown().await;
    Ok(())
}

/// Voie serveur→client : relais fidèle, sauf réponse `tools/list` en
/// dérive critique en mode blocage (substituée par une erreur -32000).
async fn relayer_serveur_vers_client(
    child_stdout: tokio::process::ChildStdout,
    etat: Arc<EtatPartage>,
    analyseur: Analyseur,
) -> anyhow::Result<()> {
    let mut lecteur = BufReader::new(child_stdout);
    let mut sortie = tokio::io::stdout();
    let mut ligne = String::new();
    loop {
        ligne.clear();
        let n = lecteur
            .read_line(&mut ligne)
            .await
            .context("lecture du sous-processus")?;
        if n == 0 {
            break;
        }

        let trim = ligne.trim();
        let mut substitution: Option<String> = None;
        if !trim.is_empty() {
            if let Ok(valeur) = serde_json::from_str::<Value>(trim) {
                if valeur.get("method").and_then(|m| m.as_str())
                    == Some("notifications/tools/list_changed")
                {
                    etat.notification_recue.store(true, Ordering::SeqCst);
                } else if let Some(id) = valeur.get("id") {
                    let attendu = etat.ids_tools_list.lock().unwrap().remove(&id.to_string());
                    if attendu && valeur.get("result").is_some() {
                        let notif = etat.notification_recue.swap(false, Ordering::SeqCst);
                        if analyseur.traiter_reponse(&valeur, notif) {
                            substitution = Some(reponse_blocage(id));
                        }
                    }
                }
            }
        }

        match substitution {
            Some(s) => {
                sortie.write_all(s.as_bytes()).await.context("écriture stdout")?;
                sortie.write_all(b"\n").await.context("écriture stdout")?;
            }
            None => {
                // Relais fidèle : exactement les octets reçus.
                sortie
                    .write_all(ligne.as_bytes())
                    .await
                    .context("écriture stdout")?;
            }
        }
        sortie.flush().await.context("flush stdout")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests_unitaires {
    use super::*;

    #[test]
    fn cle_requete_tools_list_avec_id_numerique() {
        let v = json!({"jsonrpc":"2.0","id":7,"method":"tools/list"});
        assert_eq!(cle_requete_tools_list(&v), Some("7".to_string()));
    }

    #[test]
    fn cle_requete_tools_list_avec_id_chaine() {
        let v = json!({"jsonrpc":"2.0","id":"abc","method":"tools/list"});
        assert_eq!(cle_requete_tools_list(&v), Some("\"abc\"".to_string()));
    }

    #[test]
    fn autres_methodes_ignorees() {
        let v = json!({"jsonrpc":"2.0","id":1,"method":"tools/call"});
        assert_eq!(cle_requete_tools_list(&v), None);
        let v = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}});
        assert_eq!(cle_requete_tools_list(&v), None);
    }

    #[test]
    fn reponse_blocage_conserve_l_id_et_le_code() {
        let s = reponse_blocage(&json!(42));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["id"], json!(42));
        assert_eq!(v["error"]["code"], json!(CODE_BLOCAGE));
        assert_eq!(v["error"]["message"], json!(MESSAGE_BLOCAGE));
    }

    #[test]
    fn resoudre_serveur_par_package_id() {
        use chrono::Utc;
        use sentinel_protocol::*;
        let store = Store::in_memory().unwrap();
        let s = Serveur {
            id: Uuid::new_v4(),
            endpoint: "npx -y @scope/pkg --flag a".into(),
            transport: Transport::Stdio,
            portees: vec![],
            statut: StatutServeur::Approuve,
            couleur: Couleur::Vert,
            premiere_vue: Utc::now(),
            derniere_vue: Utc::now(),
            empreinte_courante: None,
            tags: vec![],
            scope: ScopeServeur::default(),
        };
        store.upsert_serveur(&s).unwrap();
        // Même paquet, args différents → même identité canonique.
        let trouve = resoudre_serveur(&store, "npx -y @scope/pkg --flag b")
            .unwrap()
            .unwrap();
        assert_eq!(trouve.id, s.id);
        assert!(resoudre_serveur(&store, "npx -y @autre/pkg").unwrap().is_none());
    }
}
