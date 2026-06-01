//! Wrapper stdio — enveloppe un exécutable serveur MCP, relaie stdin/stdout,
//! et observe chaque ligne JSON-RPC au passage sans modifier les octets.
//!
//! Principe : deux tâches tokio concurrentes,
//!   1. stdin_client → stdin_serveur  (direction ClientVersServeur)
//!   2. stdout_serveur → stdout_client (direction ServeurVersClient)
//!
//! Chaque ligne lue est copiée telle quelle vers la destination, puis
//! analysée : si le JSON est valide et contient un champ `method` ou `result`,
//! un `EvenementBrut` est émis sur le channel fourni.
//!
//! Règles impératives :
//! - Read-only : les octets ne sont jamais modifiés avant retransmission.
//! - Inspection en vol : les `params` de `tools/call` ne sont jamais persistés.
//! - Pipeline sans état : tout l'état est dans le store en aval.

use anyhow::Context;
use chrono::Utc;
use sentinel_protocol::{Direction, EvenementBrut, Transport};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc::Sender,
};
use tracing::{debug, warn};
use uuid::Uuid;

/// Wrapper autour d'un sous-processus serveur MCP stdio.
///
/// # Exemple
/// ```no_run
/// use tokio::sync::mpsc;
/// use sentinel_protocol::EvenementBrut;
/// use sentinel_scan::stdio::WrapperStdio;
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let (tx, mut rx) = mpsc::channel::<EvenementBrut>(128);
/// let wrapper = WrapperStdio::nouveau("mon-serveur-mcp", vec![], tx);
/// let code = wrapper.executer().await?;
/// # Ok(())
/// # }
/// ```
pub struct WrapperStdio {
    /// Chemin ou nom du programme à lancer.
    programme: String,
    /// Arguments transmis au sous-processus.
    args: Vec<String>,
    /// Channel vers lequel les `EvenementBrut` sont émis.
    emetteur: Sender<EvenementBrut>,
    /// Identifiant de session, unique par lancement.
    session_id: String,
}

impl WrapperStdio {
    /// Crée un nouveau wrapper pour `programme` avec les `args` donnés.
    /// `emetteur` reçoit les `EvenementBrut` produits par l'observation.
    pub fn nouveau(
        programme: impl Into<String>,
        args: Vec<String>,
        emetteur: Sender<EvenementBrut>,
    ) -> Self {
        Self {
            programme: programme.into(),
            args,
            emetteur,
            session_id: Uuid::new_v4().to_string(),
        }
    }

    /// Lance le sous-processus, relaie stdin/stdout, observe le trafic,
    /// et retourne le code de sortie du sous-processus.
    ///
    /// La fonction retourne dès que le sous-processus se termine.
    /// Les tâches de relais se terminent proprement sur EOF.
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

        let session_id = self.session_id.clone();
        let serveur = self.programme.clone();
        let emetteur = self.emetteur.clone();

        // Tâche 1 : stdin de ce processus → stdin du sous-processus.
        // Direction : ClientVersServeur.
        let session_id_c = session_id.clone();
        let serveur_c = serveur.clone();
        let emetteur_c = emetteur.clone();
        let tache_stdin = tokio::spawn(async move {
            relayer_et_observer(
                tokio::io::stdin(),
                child_stdin,
                Direction::ClientVersServeur,
                session_id_c,
                serveur_c,
                emetteur_c,
            )
            .await
        });

        // Tâche 2 : stdout du sous-processus → stdout de ce processus.
        // Direction : ServeurVersClient.
        let session_id_s = session_id.clone();
        let serveur_s = serveur.clone();
        let tache_stdout = tokio::spawn(async move {
            relayer_et_observer(
                child_stdout,
                tokio::io::stdout(),
                Direction::ServeurVersClient,
                session_id_s,
                serveur_s,
                emetteur,
            )
            .await
        });

        // Attente de la terminaison du sous-processus.
        let statut = child.wait().await.context("attente du sous-processus")?;

        // On laisse les tâches de relais se terminer naturellement (elles
        // obtiennent EOF dès que le sous-processus est mort).
        let _ = tokio::join!(tache_stdin, tache_stdout);

        Ok(statut.code().unwrap_or(-1))
    }
}

/// Relaie le contenu de `source` vers `dest` ligne par ligne.
/// Chaque ligne est d'abord écrite vers `dest` (relais fidèle, octets intacts),
/// puis analysée pour produire un `EvenementBrut` si la ligne est du JSON-RPC.
async fn relayer_et_observer<R, W>(
    source: R,
    mut dest: W,
    direction: Direction,
    session_id: String,
    serveur: String,
    emetteur: Sender<EvenementBrut>,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut lecteur = BufReader::new(source);
    let mut ligne = String::new();

    loop {
        ligne.clear();
        let n = lecteur
            .read_line(&mut ligne)
            .await
            .context("lecture de la source")?;

        if n == 0 {
            // EOF : le producteur a fermé son côté.
            break;
        }

        // Relais fidèle : on écrit exactement les octets reçus.
        dest.write_all(ligne.as_bytes())
            .await
            .context("écriture vers la destination")?;
        dest.flush().await.context("flush vers la destination")?;

        // Observation : on tente de parser la ligne comme JSON-RPC.
        let ligne_trim = ligne.trim();
        if ligne_trim.is_empty() {
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(ligne_trim) {
            Ok(valeur) => {
                let methode = extraire_methode(&valeur, &direction);

                // Règle d'inspection en vol :
                // Pour tools/call en direction ClientVersServeur, on ne
                // conserve jamais les `params` — on transmet un payload épuré.
                let payload = epurer_payload(&valeur, &methode, &direction);

                let evt = EvenementBrut {
                    session_id: session_id.clone(),
                    transport: Transport::Stdio,
                    serveur: serveur.clone(),
                    direction,
                    methode,
                    payload,
                    horodatage: Utc::now(),
                };

                debug!(
                    session_id = %evt.session_id,
                    direction = ?evt.direction,
                    methode = ?evt.methode,
                    "événement stdio émis"
                );

                // Envoi non-bloquant : on abandonne si le récepteur est saturé
                // ou déconnecté, sans jamais interrompre le relais.
                if let Err(e) = emetteur.try_send(evt) {
                    warn!("channel plein ou fermé, événement abandonné : {e}");
                }
            }
            Err(_) => {
                // Ligne non-JSON (stderr redirigé, log, etc.) — ignorée sans
                // interrompre le relais.
                debug!(
                    direction = ?direction,
                    "ligne non-JSON ignorée : {:?}",
                    &ligne_trim[..ligne_trim.len().min(80)]
                );
            }
        }
    }

    Ok(())
}

/// Extrait la méthode d'un message JSON-RPC.
/// Pour les réponses (champ `result` ou `error`), retourne `None`.
fn extraire_methode(
    valeur: &serde_json::Value,
    _direction: &Direction,
) -> Option<String> {
    valeur
        .get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}

/// Épure le payload selon les règles de confidentialité.
///
/// Règle : pour `tools/call` venant du client, les `params.arguments` ne
/// sont jamais persistés (inspection en vol seulement).
fn epurer_payload(
    valeur: &serde_json::Value,
    methode: &Option<String>,
    direction: &Direction,
) -> serde_json::Value {
    let est_tools_call_client = methode.as_deref() == Some("tools/call")
        && matches!(direction, Direction::ClientVersServeur);

    if est_tools_call_client {
        // On garde la structure JSON-RPC (id, method, jsonrpc) mais on
        // supprime params.arguments pour respecter la règle d'inspection en vol.
        let mut epure = valeur.clone();
        if let Some(params) = epure.get_mut("params") {
            if let Some(obj) = params.as_object_mut() {
                obj.remove("arguments");
            }
        }
        epure
    } else {
        valeur.clone()
    }
}

#[cfg(test)]
mod tests_unitaires {
    use super::*;
    use serde_json::json;

    #[test]
    fn extraire_methode_depuis_requete() {
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
        assert_eq!(
            extraire_methode(&msg, &Direction::ClientVersServeur),
            Some("tools/list".to_string())
        );
    }

    #[test]
    fn extraire_methode_depuis_reponse_retourne_none() {
        let msg = json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}});
        assert_eq!(
            extraire_methode(&msg, &Direction::ServeurVersClient),
            None
        );
    }

    #[test]
    fn epurer_supprime_arguments_tools_call_client() {
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "mon_outil",
                "arguments": {"secret": "ne pas conserver"}
            }
        });
        let epure = epurer_payload(
            &msg,
            &Some("tools/call".to_string()),
            &Direction::ClientVersServeur,
        );
        let params = epure.get("params").unwrap();
        assert!(params.get("arguments").is_none(), "arguments doivent être supprimés");
        assert_eq!(params.get("name").unwrap().as_str().unwrap(), "mon_outil");
    }

    #[test]
    fn epurer_conserve_payload_tools_call_serveur() {
        // Pour la réponse du serveur à tools/call, on conserve tout.
        let msg = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "ok"}]}
        });
        let epure = epurer_payload(
            &msg,
            &None,
            &Direction::ServeurVersClient,
        );
        assert!(epure.get("result").is_some());
    }
}
