//! Proxy temps réel — roadmap COMPARISON.md, point 1.
//!
//! Mode proxy stdio qui inspecte les messages MCP **en direct**, au passage
//! du relais, au lieu d'attendre le scan périodique. Trois détections
//! runtime, toutes déléguées à `sentinel-detect` :
//!
//!   1. **Poisoning des arguments de `tools/call`** — chaque chaîne contenue
//!      dans `params.arguments` passe par
//!      `InspecteurPoisoning::inspecter_texte` (injection de prompt, chemins
//!      sensibles, balises pseudo-système, …).
//!   2. **Combo exfiltration en streaming** — la classification
//!      lecture-secret / écriture-externe de `DetecteurExfiltration` est
//!      appliquée appel par appel ; dès qu'une même session cumule les deux
//!      classes, un constat `Exfiltration` est émis immédiatement
//!      (SAFE-T1201, cas Invariant Labs WhatsApp).
//!   3. **Abus sampling / elicitation** — `DetecteurSampling` est appliqué à
//!      chaque `sampling/createMessage` / `elicitation/create` (injection
//!      persistante, demande de secrets) plus un compteur de volume pour le
//!      drain de quota.
//!
//! ## Règle de confidentialité (non négociable)
//!
//! Le contenu des `params` n'est **jamais** persisté. L'inspection se fait
//! en mémoire, sur la ligne en vol ; l'état conservé entre deux messages se
//! limite à des **noms d'outils, des compteurs et des drapeaux**. Les
//! `EvenementBrut` réémis vers le pipeline existant passent par la même
//! épuration que le wrapper stdio (suppression de `params.arguments`).
//! Seul l'extrait déclencheur (≤ 120 caractères) survit dans le constat —
//! même convention que `sentinel-detect` (voir sampling.rs).
//!
//! ## Positionnement
//!
//! Le proxy est en **mode détection** : il relaie les octets bit-exact et
//! n'altère ni ne bloque jamais le trafic (le blocage est le rôle du mode
//! guard). La latence ajoutée est celle d'un passage regex en mémoire.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use chrono::Utc;
use sentinel_detect::{
    ConfigSampling, DetecteurExfiltration, DetecteurSampling, InspecteurPoisoning,
    NatureSignalSampling,
};
use sentinel_detect::poisoning::ConstatPoisoning;
use sentinel_protocol::{
    Constat, Direction, EtatConstat, EvenementBrut, MessageMcp, MethodeMcp, ServeurId, Severite,
    Transport, TypeConstat,
};
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::mpsc::Sender,
};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::stdio::wrapper::{epurer_payload, extraire_methode};

// ---------------------------------------------------------------------------
// Configuration et types publics
// ---------------------------------------------------------------------------

/// Configuration du proxy temps réel.
#[derive(Debug, Clone)]
pub struct ConfigProxy {
    /// Identifiant du serveur dans l'inventaire, si déjà connu (le mode CLI
    /// le résout avant de lancer le proxy). À défaut, les constats portent
    /// `Uuid::nil()` et la résolution se fait en aval.
    pub serveur_id: Option<ServeurId>,
    /// Seuils du détecteur de sampling (drain de quota).
    pub sampling: ConfigSampling,
}

impl Default for ConfigProxy {
    fn default() -> Self {
        Self {
            serveur_id: None,
            sampling: ConfigSampling::default(),
        }
    }
}

/// Constat émis en direct par le proxy, enrichi du contexte de session.
///
/// Le champ `constat` est store-ready ; `session_id` et `serveur` permettent
/// à l'orchestrateur de résoudre le `serveur_id` réel si la config ne le
/// portait pas.
#[derive(Debug, Clone)]
pub struct ConstatTempsReel {
    pub session_id: String,
    pub serveur: String,
    pub constat: Constat,
}

// ---------------------------------------------------------------------------
// Moteur d'inspection (synchrone, un par session)
// ---------------------------------------------------------------------------

/// Moteur d'inspection en vol, **un par session** (un lancement de proxy =
/// une session = un sous-processus).
///
/// État conservé entre deux messages — uniquement des métadonnées,
/// jamais le contenu des `params` :
///   - noms d'outils classés lecture-secret / écriture-externe,
///   - compteur de `sampling/createMessage`,
///   - drapeaux « déjà signalé » (un constat combo / drain par session).
pub struct MoteurInspection {
    session_id: String,
    serveur: String,
    config: ConfigProxy,
    /// Noms d'outils ayant lu un secret dans cette session.
    lectures_secret: Vec<String>,
    /// Noms d'outils ayant écrit vers l'extérieur dans cette session.
    ecritures_externes: Vec<String>,
    /// La combo exfiltration n'est signalée qu'une fois par session.
    exfiltration_signalee: bool,
    /// Volume cumulé de `sampling/createMessage` sur la session.
    volume_sampling: usize,
    /// Le drain de quota n'est signalé qu'une fois par session.
    drain_signale: bool,
}

impl MoteurInspection {
    /// Crée un moteur pour la session donnée.
    pub fn nouveau(
        session_id: impl Into<String>,
        serveur: impl Into<String>,
        config: ConfigProxy,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            serveur: serveur.into(),
            config,
            lectures_secret: Vec::new(),
            ecritures_externes: Vec::new(),
            exfiltration_signalee: false,
            volume_sampling: 0,
            drain_signale: false,
        }
    }

    /// Inspecte un message JSON-RPC en vol et retourne les constats immédiats.
    ///
    /// `valeur` est le payload **complet** (arguments inclus) : il n'est lu
    /// qu'en mémoire, le moteur n'en conserve aucune copie.
    pub fn inspecter(
        &mut self,
        valeur: &serde_json::Value,
        direction: Direction,
    ) -> Vec<Constat> {
        let methode = match valeur.get("method").and_then(|m| m.as_str()) {
            Some(m) => MethodeMcp::from_str(m),
            None => return Vec::new(), // réponse ou notification sans méthode
        };

        match methode {
            // Les arguments de tools/call ne voyagent que du client vers le
            // serveur ; c'est aussi la direction couverte par l'épuration.
            MethodeMcp::ToolsCall if direction == Direction::ClientVersServeur => {
                self.inspecter_tools_call(valeur)
            }
            // sampling/elicitation : requêtes émises PAR le serveur.
            MethodeMcp::SamplingCreateMessage | MethodeMcp::ElicitationCreate => {
                self.inspecter_sampling(valeur, methode)
            }
            _ => Vec::new(),
        }
    }

    /// Identifiant de serveur porté par les constats.
    fn serveur_id(&self) -> ServeurId {
        self.config.serveur_id.unwrap_or_else(Uuid::nil)
    }

    // -----------------------------------------------------------------------
    // tools/call : poisoning des arguments + combo exfiltration
    // -----------------------------------------------------------------------

    fn inspecter_tools_call(&mut self, valeur: &serde_json::Value) -> Vec<Constat> {
        let mut constats = Vec::new();

        let nom_outil = valeur
            .get("params")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string());
        let nom_affiche = nom_outil.clone().unwrap_or_else(|| "(inconnu)".to_string());

        // 1. Poisoning des arguments — inspection en mémoire de chaque chaîne.
        if let Some(arguments) = valeur.get("params").and_then(|p| p.get("arguments")) {
            let mut textes = Vec::new();
            collecter_textes(arguments, 0, &mut textes);
            for texte in &textes {
                for (pattern, categorie, extrait, severite) in
                    InspecteurPoisoning::inspecter_texte(texte)
                {
                    let cp = ConstatPoisoning {
                        outil: nom_affiche.clone(),
                        pattern,
                        categorie,
                        extrait,
                        severite,
                    };
                    let mut constat = InspecteurPoisoning::vers_constat(&cp, self.serveur_id());
                    constat.detail = format!(
                        "[temps réel] Arguments de tools/call (inspection en vol). {}",
                        constat.detail
                    );
                    constats.push(constat);
                }
            }
        }

        // 2. Combo exfiltration en streaming — classification appel par appel.
        if let Some(nom) = nom_outil {
            let message = self.message_appel(&nom, valeur.clone());
            let (est_lecture, est_ecriture) = self.classifier_exfiltration(&message);
            // `message` (et donc le payload complet) sort de portée ici :
            // seul le nom de l'outil est conservé dans l'état de session.
            drop(message);

            if est_lecture && !self.lectures_secret.contains(&nom) {
                self.lectures_secret.push(nom.clone());
            }
            if est_ecriture && !self.ecritures_externes.contains(&nom) {
                self.ecritures_externes.push(nom.clone());
            }

            if !self.exfiltration_signalee
                && !self.lectures_secret.is_empty()
                && !self.ecritures_externes.is_empty()
            {
                self.exfiltration_signalee = true;
                constats.push(Constat {
                    id: Uuid::new_v4(),
                    serveur_id: self.serveur_id(),
                    outil_nom: Some(nom),
                    type_constat: TypeConstat::Exfiltration,
                    severite: Severite::Critique,
                    titre: "Exfiltration en temps réel — lecture secret + écriture externe"
                        .to_string(),
                    detail: format!(
                        "Session {} : exfiltration détectée — lecture secret ({}) + \
                         écriture externe ({}). Identifiant SAFE-T1201.",
                        self.session_id,
                        self.lectures_secret.join(", "),
                        self.ecritures_externes.join(", "),
                    ),
                    diff: None,
                    references_conformite: vec![
                        "SAFE-T1201".to_string(),
                        "OWASP MCP09".to_string(),
                    ],
                    horodatage: Utc::now(),
                    etat: EtatConstat::Ouvert,
                });
            }
        }

        constats
    }

    /// Classifie un appel via `DetecteurExfiltration::evaluer_session` (API
    /// publique de sentinel-detect, qu'on ne modifie pas) : on apparie
    /// l'appel courant à un message témoin de la classe opposée — la combo
    /// ne se déclenche que si l'appel courant porte la classe recherchée.
    fn classifier_exfiltration(&self, message: &MessageMcp) -> (bool, bool) {
        // Témoin écriture externe (nom contenant « upload », payload neutre) :
        // la session synthétique [appel, témoin] ne déclenche que si l'appel
        // est une lecture de secret.
        let temoin_ecriture = self.message_appel(
            "sentinelle_temoin_upload",
            json!({"params": {"name": "sentinelle_temoin_upload"}}),
        );
        let est_lecture =
            DetecteurExfiltration::evaluer_session(&[message.clone(), temoin_ecriture]).is_some();

        // Témoin lecture secret (nom contenant « read_env ») : symétrique.
        let temoin_lecture = self.message_appel(
            "sentinelle_temoin_read_env",
            json!({"params": {"name": "sentinelle_temoin_read_env"}}),
        );
        let est_ecriture =
            DetecteurExfiltration::evaluer_session(&[message.clone(), temoin_lecture]).is_some();

        (est_lecture, est_ecriture)
    }

    /// Construit un `MessageMcp` tools/call en mémoire (jamais persisté).
    fn message_appel(&self, _nom_outil: &str, payload: serde_json::Value) -> MessageMcp {
        MessageMcp {
            session_id: self.session_id.clone(),
            transport: Transport::Stdio,
            serveur: self.serveur.clone(),
            direction: Direction::ClientVersServeur,
            methode: MethodeMcp::ToolsCall,
            id_jsonrpc: None,
            payload,
            horodatage: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // sampling/createMessage + elicitation/create
    // -----------------------------------------------------------------------

    fn inspecter_sampling(
        &mut self,
        valeur: &serde_json::Value,
        methode: MethodeMcp,
    ) -> Vec<Constat> {
        let mut constats = Vec::new();

        // Message complet en mémoire, le temps d'un passage de détecteur.
        let message = MessageMcp {
            session_id: self.session_id.clone(),
            transport: Transport::Stdio,
            serveur: self.serveur.clone(),
            direction: Direction::ServeurVersClient,
            methode: methode.clone(),
            id_jsonrpc: valeur.get("id").cloned(),
            payload: valeur.clone(),
            horodatage: Utc::now(),
        };

        // Détections par message (injection persistante, demande de secrets).
        // Le drain de quota est exclu ici : un seuil à 0 le déclencherait sur
        // chaque message isolé — il est géré par le compteur de session.
        for signal in DetecteurSampling::evaluer(&[message], &self.config.sampling) {
            if signal.nature != NatureSignalSampling::DrainQuota {
                constats.push(DetecteurSampling::vers_constat(&signal, self.serveur_id()));
            }
        }

        // Drain de quota : compteur cumulatif, signalé une seule fois au
        // franchissement du seuil. On rejoue le franchissement avec des
        // messages factices SANS contenu (payload réduit à `params: {}`)
        // pour réutiliser le libellé exact de DetecteurSampling.
        if methode == MethodeMcp::SamplingCreateMessage {
            self.volume_sampling += 1;
            if !self.drain_signale
                && self.volume_sampling > self.config.sampling.seuil_volume_session
            {
                self.drain_signale = true;
                let factices: Vec<MessageMcp> = (0..self.volume_sampling)
                    .map(|_| MessageMcp {
                        session_id: self.session_id.clone(),
                        transport: Transport::Stdio,
                        serveur: self.serveur.clone(),
                        direction: Direction::ServeurVersClient,
                        methode: MethodeMcp::SamplingCreateMessage,
                        id_jsonrpc: None,
                        payload: json!({"params": {}}),
                        horodatage: Utc::now(),
                    })
                    .collect();
                for signal in DetecteurSampling::evaluer(&factices, &self.config.sampling) {
                    if signal.nature == NatureSignalSampling::DrainQuota {
                        constats
                            .push(DetecteurSampling::vers_constat(&signal, self.serveur_id()));
                    }
                }
            }
        }

        constats
    }
}

/// Collecte récursivement les chaînes (valeurs et clés) d'un JSON,
/// profondeur ≤ 8 — utilisé pour inspecter `params.arguments` en mémoire.
fn collecter_textes(valeur: &serde_json::Value, profondeur: u8, textes: &mut Vec<String>) {
    if profondeur > 8 {
        return;
    }
    match valeur {
        serde_json::Value::String(s) => textes.push(s.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collecter_textes(item, profondeur + 1, textes);
            }
        }
        serde_json::Value::Object(obj) => {
            for (clef, val) in obj {
                textes.push(clef.clone());
                collecter_textes(val, profondeur + 1, textes);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Relais avec inspection en vol
// ---------------------------------------------------------------------------

/// Relaie `source` → `dest` ligne par ligne (octets intacts, comme le
/// wrapper stdio), puis inspecte chaque ligne JSON-RPC **en mémoire** :
///   - constats immédiats émis sur `emetteur_constats` (try_send, jamais
///     bloquant : un canal saturé n'interrompt pas le relais) ;
///   - `EvenementBrut` épuré (sans `params.arguments` pour les tools/call
///     client) réémis sur `emetteur_evenements` si fourni, pour alimenter
///     le pipeline d'inventaire existant.
///
/// Fonction publique générique pour permettre les tests d'intégration sur
/// des flux en mémoire (`tokio::io::duplex`).
pub async fn relayer_inspecter<R, W>(
    source: R,
    mut dest: W,
    direction: Direction,
    moteur: Arc<Mutex<MoteurInspection>>,
    emetteur_constats: Sender<ConstatTempsReel>,
    emetteur_evenements: Option<Sender<EvenementBrut>>,
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
            break; // EOF
        }

        // Relais fidèle d'abord : la détection n'ajoute jamais de latence
        // bloquante ni n'altère les octets.
        dest.write_all(ligne.as_bytes())
            .await
            .context("écriture vers la destination")?;
        dest.flush().await.context("flush vers la destination")?;

        let ligne_trim = ligne.trim();
        if ligne_trim.is_empty() {
            continue;
        }

        let valeur: serde_json::Value = match serde_json::from_str(ligne_trim) {
            Ok(v) => v,
            Err(_) => {
                debug!(
                    direction = ?direction,
                    "ligne non-JSON ignorée : {:?}",
                    &ligne_trim[..ligne_trim.len().min(80)]
                );
                continue;
            }
        };

        // Inspection en vol — section critique courte, aucune attente async
        // tant que le verrou est tenu, aucun contenu conservé.
        let (session_id, serveur, constats) = {
            let mut m = moteur.lock().expect("verrou moteur d'inspection");
            let constats = m.inspecter(&valeur, direction);
            (m.session_id.clone(), m.serveur.clone(), constats)
        };

        for constat in constats {
            debug!(
                session_id = %session_id,
                type_constat = ?constat.type_constat,
                "constat temps réel émis"
            );
            if let Err(e) = emetteur_constats.try_send(ConstatTempsReel {
                session_id: session_id.clone(),
                serveur: serveur.clone(),
                constat,
            }) {
                warn!("canal constats plein ou fermé, constat abandonné : {e}");
            }
        }

        // Réémission de l'événement épuré pour le pipeline existant.
        if let Some(emetteur) = &emetteur_evenements {
            let methode = extraire_methode(&valeur, &direction);
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
            if let Err(e) = emetteur.try_send(evt) {
                warn!("canal événements plein ou fermé, événement abandonné : {e}");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Proxy stdio temps réel (sous-processus)
// ---------------------------------------------------------------------------

/// Proxy stdio temps réel : même contrat que `WrapperStdio` (relais
/// bit-exact d'un sous-processus serveur MCP), plus l'inspection en vol et
/// l'émission de constats immédiats.
///
/// # Exemple
/// ```no_run
/// use tokio::sync::mpsc;
/// use sentinel_scan::proxy::{ConstatTempsReel, ProxyStdioTempsReel};
///
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// let (tx_constats, mut rx_constats) = mpsc::channel::<ConstatTempsReel>(64);
/// let proxy = ProxyStdioTempsReel::nouveau("mon-serveur-mcp", vec![], tx_constats);
/// let code = proxy.executer().await?;
/// # Ok(())
/// # }
/// ```
pub struct ProxyStdioTempsReel {
    /// Chemin ou nom du programme à lancer.
    programme: String,
    /// Arguments transmis au sous-processus.
    args: Vec<String>,
    /// Canal des constats immédiats.
    emetteur_constats: Sender<ConstatTempsReel>,
    /// Canal optionnel des événements épurés (pipeline d'inventaire).
    emetteur_evenements: Option<Sender<EvenementBrut>>,
    /// Configuration (serveur_id, seuils sampling).
    config: ConfigProxy,
    /// Identifiant de session, unique par lancement.
    session_id: String,
}

impl ProxyStdioTempsReel {
    /// Crée un proxy pour `programme` avec les `args` donnés.
    pub fn nouveau(
        programme: impl Into<String>,
        args: Vec<String>,
        emetteur_constats: Sender<ConstatTempsReel>,
    ) -> Self {
        Self {
            programme: programme.into(),
            args,
            emetteur_constats,
            emetteur_evenements: None,
            config: ConfigProxy::default(),
            session_id: Uuid::new_v4().to_string(),
        }
    }

    /// Réémet aussi les `EvenementBrut` épurés vers le pipeline existant.
    pub fn avec_evenements(mut self, emetteur: Sender<EvenementBrut>) -> Self {
        self.emetteur_evenements = Some(emetteur);
        self
    }

    /// Remplace la configuration par défaut.
    pub fn avec_config(mut self, config: ConfigProxy) -> Self {
        self.config = config;
        self
    }

    /// Identifiant de session du proxy (utile pour corréler les constats).
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Lance le sous-processus, relaie stdin/stdout avec inspection en vol,
    /// et retourne le code de sortie du sous-processus.
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

        // Moteur partagé entre les deux directions : les tools/call montent
        // (client → serveur) tandis que sampling/elicitation descendent
        // (serveur → client), et la combo exfiltration est par session.
        let moteur = Arc::new(Mutex::new(MoteurInspection::nouveau(
            self.session_id.clone(),
            self.programme.clone(),
            self.config.clone(),
        )));

        // Tâche 1 : stdin de ce processus → stdin du sous-processus.
        let moteur_c = moteur.clone();
        let constats_c = self.emetteur_constats.clone();
        let evenements_c = self.emetteur_evenements.clone();
        let tache_stdin = tokio::spawn(async move {
            relayer_inspecter(
                tokio::io::stdin(),
                child_stdin,
                Direction::ClientVersServeur,
                moteur_c,
                constats_c,
                evenements_c,
            )
            .await
        });

        // Tâche 2 : stdout du sous-processus → stdout de ce processus.
        let moteur_s = moteur.clone();
        let constats_s = self.emetteur_constats.clone();
        let evenements_s = self.emetteur_evenements.clone();
        let tache_stdout = tokio::spawn(async move {
            relayer_inspecter(
                child_stdout,
                tokio::io::stdout(),
                Direction::ServeurVersClient,
                moteur_s,
                constats_s,
                evenements_s,
            )
            .await
        });

        let statut = child.wait().await.context("attente du sous-processus")?;

        // Les tâches de relais se terminent naturellement sur EOF.
        let _ = tokio::join!(tache_stdin, tache_stdout);

        Ok(statut.code().unwrap_or(-1))
    }
}

// ---------------------------------------------------------------------------
// Tests unitaires (logique pure ; l'intégration est dans tests/)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests_unitaires {
    use super::*;

    fn moteur() -> MoteurInspection {
        MoteurInspection::nouveau("sess-test", "serveur-test", ConfigProxy::default())
    }

    #[test]
    fn message_sans_methode_ignore() {
        let mut m = moteur();
        let valeur = json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}});
        assert!(m.inspecter(&valeur, Direction::ServeurVersClient).is_empty());
    }

    #[test]
    fn tools_call_benin_sans_constat() {
        let mut m = moteur();
        let valeur = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "additionner", "arguments": {"a": 1, "b": 2}}
        });
        assert!(m.inspecter(&valeur, Direction::ClientVersServeur).is_empty());
    }

    #[test]
    fn collecter_textes_recursif_et_borne() {
        let valeur = json!({
            "a": "un",
            "b": {"c": ["deux", {"d": "trois"}]},
            "n": 42
        });
        let mut textes = Vec::new();
        collecter_textes(&valeur, 0, &mut textes);
        assert!(textes.contains(&"un".to_string()));
        assert!(textes.contains(&"deux".to_string()));
        assert!(textes.contains(&"trois".to_string()));
        // Les clés sont inspectées aussi.
        assert!(textes.contains(&"a".to_string()));
    }

    #[test]
    fn classification_exfiltration_lecture_et_ecriture() {
        let m = moteur();

        let lecture = m.message_appel(
            "read_file",
            json!({"params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}}),
        );
        assert_eq!(m.classifier_exfiltration(&lecture), (true, false));

        let ecriture = m.message_appel(
            "http_request",
            json!({"params": {"name": "http_request", "arguments": {"url": "https://exfil.example.com"}}}),
        );
        assert_eq!(m.classifier_exfiltration(&ecriture), (false, true));

        let neutre = m.message_appel(
            "additionner",
            json!({"params": {"name": "additionner", "arguments": {"a": 1}}}),
        );
        assert_eq!(m.classifier_exfiltration(&neutre), (false, false));
    }
}
