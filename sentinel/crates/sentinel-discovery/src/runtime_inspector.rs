//! Runtime inspector — finds MCP server processes currently running.

use std::collections::BTreeSet;

use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::Url;
use sentinel_protocol::{Constat, EtatConstat, Severite, TypeConstat};
use serde::{Deserialize, Serialize};

use crate::config_baseline::id_serveur_stable;
use crate::model::ServeurMcpDeclare;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessusObserve {
    pub pid: u32,
    pub command: String,
    pub args: Vec<String>,
    pub parent_pid: Option<u32>,
    /// Heuristic-derived guess at the AI client that spawned this process.
    pub probable_client: Option<String>,
}

pub struct InspecteurRuntime;

impl InspecteurRuntime {
    /// Scans running processes for MCP-server-like patterns.
    /// Implemented by the runtime-inspector agent.
    pub async fn scanner() -> Vec<ProcessusObserve> {
        vec![]
    }
}

// ===========================================================================
// F2 — Énumération PORTABLE des sockets en écoute locale (« NeighborJack »)
// ===========================================================================
//
// Angle mort : un serveur MCP HTTP peut être lancé **hors config** (script,
// docker, autre utilisateur) et binder `0.0.0.0`, l'exposant à tout le réseau
// local. Aucune source disque ne le voit. On énumère donc les sockets TCP en
// écoute observés sur la machine, puis on corrèle avec l'inventaire connu pour
// signaler l'inconnu exposé à toutes les interfaces.
//
// ## Portabilité (limites documentées)
//
//   * **macOS / BSD** : `lsof -nP -iTCP -sTCP:LISTEN` (toujours présent sur
//     macOS) ;
//   * **Linux** : `lsof` si présent, sinon `ss -ltnp` (util-linux / iproute2) ;
//   * **sans `lsof` ni `ss`** (Windows, conteneur minimal…) : aucune erreur,
//     `Vec` vide + `warn!`. L'énumération est **best-effort** ;
//   * le **nom de processus** via `ss` peut manquer sans privilèges (champ
//     `users:((...))` masqué) : on dégrade alors le `processus`/`pid` à `None`
//     sans échouer ;
//   * on ne couvre que **TCP en écoute** (le gros des serveurs MCP HTTP) ; UDP
//     et sockets Unix ne sont pas énumérés.

/// Un socket TCP en écoute observé sur la machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketEnEcoute {
    /// `"tcp"` (IPv4) ou `"tcp6"` (IPv6).
    pub protocole: String,
    /// Adresse de bind telle qu'observée (`0.0.0.0`, `127.0.0.1`, `::`, `*`…).
    pub adresse: String,
    /// Port d'écoute.
    pub port: u16,
    /// PID du processus, si l'outil système l'a fourni.
    pub pid: Option<u32>,
    /// Nom du processus, si disponible (peut manquer sans privilèges via `ss`).
    pub processus: Option<String>,
    /// `true` si l'écoute couvre **toutes** les interfaces (`0.0.0.0` / `::` /
    /// `*`) — donc exposée au réseau local (risque « NeighborJack »).
    pub bind_toutes_interfaces: bool,
}

/// Inspecteur des sockets locaux en écoute.
pub struct InspecteurSockets;

/// Résultat brut d'une tentative de commande système.
enum SortieCommande {
    /// Commande exécutée, sortie non vide.
    Texte(String),
    /// Commande exécutée mais sortie vide (p.ex. aucun listener).
    Vide,
    /// Commande absente / non exécutable.
    Absente,
}

impl InspecteurSockets {
    /// Énumère les sockets TCP en écoute via l'outil système disponible.
    ///
    /// Best-effort et **sans panic** : si ni `lsof` ni `ss` ne sont
    /// disponibles, retourne un `Vec` vide après un `warn!`.
    pub fn scanner_local() -> Vec<SocketEnEcoute> {
        match lancer("lsof", &["-nP", "-iTCP", "-sTCP:LISTEN"]) {
            SortieCommande::Texte(s) => return parser_lsof(&s),
            // `lsof` a tourné mais n'a rien listé : réponse autoritative.
            SortieCommande::Vide => return Vec::new(),
            SortieCommande::Absente => {}
        }
        match lancer("ss", &["-ltnp"]) {
            SortieCommande::Texte(s) => return parser_ss(&s),
            SortieCommande::Vide => return Vec::new(),
            SortieCommande::Absente => {}
        }
        tracing::warn!(
            "runtime_inspector : ni `lsof` ni `ss` disponibles — énumération des sockets ignorée \
             (énumération best-effort, voir limites de portabilité)"
        );
        Vec::new()
    }
}

/// Lance une commande et classe son issue, sans jamais paniquer.
fn lancer(cmd: &str, args: &[&str]) -> SortieCommande {
    match std::process::Command::new(cmd).args(args).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).into_owned();
            if s.trim().is_empty() {
                SortieCommande::Vide
            } else {
                SortieCommande::Texte(s)
            }
        }
        // `Err` = binaire introuvable / non exécutable : on tente le suivant.
        Err(_) => SortieCommande::Absente,
    }
}

/// Sépare `"host:port"` en `(host, port)`, gère la forme IPv6 `[::1]:8080`.
fn separer_hote_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(reste) = s.strip_prefix('[') {
        // IPv6 entre crochets : "[::]:8080".
        let fin = reste.find(']')?;
        let hote = &reste[..fin];
        let apres = &reste[fin + 1..];
        let port = apres.strip_prefix(':')?.parse().ok()?;
        return Some((hote.to_string(), port));
    }
    let (hote, port_s) = s.rsplit_once(':')?;
    let port = port_s.parse().ok()?;
    Some((hote.to_string(), port))
}

/// `true` si l'adresse de bind couvre toutes les interfaces.
fn bind_toutes_interfaces(hote: &str) -> bool {
    matches!(hote, "0.0.0.0" | "*" | "::" | "")
}

/// Parse la sortie de `lsof -nP -iTCP -sTCP:LISTEN`.
///
/// Colonnes : `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME (LISTEN)`.
/// Le token juste avant `(LISTEN)` porte `host:port`.
pub fn parser_lsof(sortie: &str) -> Vec<SocketEnEcoute> {
    let mut out = Vec::new();
    for ligne in sortie.lines() {
        let tokens: Vec<&str> = ligne.split_whitespace().collect();
        // Ignorer l'en-tête et les lignes trop courtes.
        if tokens.first() == Some(&"COMMAND") {
            continue;
        }
        // Position de "(LISTEN)" : l'adresse est le token précédent.
        let Some(pos) = tokens.iter().position(|t| *t == "(LISTEN)") else {
            continue;
        };
        if pos == 0 || tokens.len() < 5 {
            continue;
        }
        let Some((hote, port)) = separer_hote_port(tokens[pos - 1]) else {
            continue;
        };
        let type_col = tokens.get(4).copied().unwrap_or("");
        let protocole = if type_col.eq_ignore_ascii_case("IPv6") {
            "tcp6"
        } else {
            "tcp"
        };
        out.push(SocketEnEcoute {
            protocole: protocole.to_string(),
            bind_toutes_interfaces: bind_toutes_interfaces(&hote),
            adresse: hote,
            port,
            pid: tokens.get(1).and_then(|p| p.parse().ok()),
            processus: tokens.first().map(|s| s.to_string()),
        });
    }
    out
}

/// Process info de `ss` : `users:(("node",pid=1234,fd=23))`.
static RE_SS_PROC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\("(?P<nom>[^"]+)",pid=(?P<pid>\d+)"#).unwrap());

/// Parse la sortie de `ss -ltnp`.
///
/// Colonnes : `State Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process`.
pub fn parser_ss(sortie: &str) -> Vec<SocketEnEcoute> {
    let mut out = Vec::new();
    for ligne in sortie.lines() {
        let tokens: Vec<&str> = ligne.split_whitespace().collect();
        // Seules les lignes d'écoute nous intéressent (saute l'en-tête `State`).
        if tokens.first() != Some(&"LISTEN") || tokens.len() < 4 {
            continue;
        }
        let Some((hote, port)) = separer_hote_port(tokens[3]) else {
            continue;
        };
        let protocole = if hote.contains(':') || tokens[3].starts_with('[') {
            "tcp6"
        } else {
            "tcp"
        };
        // Champ process : tout ce qui suit la 5ᵉ colonne (peut être absent).
        let proc_brut = tokens.get(5..).map(|r| r.join(" ")).unwrap_or_default();
        let (pid, processus) = match RE_SS_PROC.captures(&proc_brut) {
            Some(c) => (
                c.name("pid").and_then(|m| m.as_str().parse().ok()),
                c.name("nom").map(|m| m.as_str().to_string()),
            ),
            None => (None, None),
        };
        out.push(SocketEnEcoute {
            protocole: protocole.to_string(),
            bind_toutes_interfaces: bind_toutes_interfaces(&hote),
            adresse: hote,
            port,
            pid,
            processus,
        });
    }
    out
}

/// Ports déjà connus de l'inventaire MCP (serveurs HTTP déclarés).
pub fn ports_connus(serveurs_connus: &[ServeurMcpDeclare]) -> BTreeSet<u16> {
    serveurs_connus
        .iter()
        .filter_map(|s| s.url.as_deref())
        .filter_map(|u| Url::parse(u).ok())
        .filter_map(|u| u.port_or_known_default())
        .collect()
}

/// Corrèle les sockets observés avec l'inventaire connu et émet un constat par
/// socket **exposé à toutes les interfaces** dont le port n'est pas attribué à
/// un serveur MCP déclaré (« NeighborJack » : serveur MCP lancé hors config).
///
/// ## Faux positifs maîtrisés
///
///   * on ne signale **que** les sockets bind-all (`0.0.0.0` / `::` / `*`) :
///     un service en loopback n'est pas exposé au réseau et n'est jamais
///     remonté ;
///   * les ports **privilégiés** (`< 1024`, services système type ssh/web) sont
///     **exclus** : les serveurs MCP tournent sur des ports hauts ;
///   * un port présent dans l'inventaire n'émet **rien** (corrélation par port).
///
/// On ne peut pas prouver statiquement qu'un socket parle MCP : la sévérité
/// reste `Moyenne` et le libellé invite à vérifier, plutôt que d'accuser.
pub fn correler_avec_inventaire(
    sockets: &[SocketEnEcoute],
    serveurs_connus: &[ServeurMcpDeclare],
) -> Vec<Constat> {
    let connus = ports_connus(serveurs_connus);
    // Dédup dual-stack : un process qui écoute en IPv4 ET IPv6 sur le même port
    // (ex. `ControlCe` sur `0.0.0.0:7000` ET `[::]:7000`) apparaît DEUX fois
    // dans l'énumération (`tcp` + `tcp6`). C'est UN seul listener logique → on
    // ne doit émettre qu'UN constat, pas deux cartes identiques. Clé de dédup :
    // `(port, pid)` — la famille d'adresse ne change pas le risque réseau.
    let mut vus: BTreeSet<(u16, Option<u32>)> = BTreeSet::new();
    sockets
        .iter()
        .filter(|s| s.bind_toutes_interfaces && s.port >= 1024 && !connus.contains(&s.port))
        .filter(|s| vus.insert((s.port, s.pid)))
        .map(constat_socket_inconnu)
        .collect()
}

fn constat_socket_inconnu(socket: &SocketEnEcoute) -> Constat {
    let proc_desc = match (&socket.processus, socket.pid) {
        (Some(p), Some(pid)) => format!("process `{p}` (pid {pid})"),
        (Some(p), None) => format!("process `{p}`"),
        (None, Some(pid)) => format!("pid {pid}"),
        (None, None) => "unknown process".to_string(),
    };
    Constat {
        // Identité déterministe du listener (port + pid) : stable d'un scan à
        // l'autre et identique pour les faces IPv4/IPv6 du même process — pas
        // de doublon ni d'accumulation si un jour ces constats sont persistés.
        id: sentinel_detect::id_constat(&[
            "rogue-socket",
            &socket.port.to_string(),
            &socket.pid.map(|p| p.to_string()).unwrap_or_default(),
        ]),
        // Identité stable dérivée du port (indépendante de la famille d'adresse).
        serveur_id: id_serveur_stable(&format!("socket://:{}", socket.port)),
        outil_nom: None,
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Moyenne,
        titre: format!(
            "Socket listening on all interfaces, outside inventory (port {})",
            socket.port
        ),
        detail: format!(
            "A socket {} is listening on {}:{} ({}), exposed to the whole local network, with no \
             match in the known MCP inventory. If this is an MCP server started outside the config \
             (\"NeighborJack\" blind spot), it escapes monitoring; otherwise, verify that this \
             network exposure is intentional. NB: the MCP nature of the socket is not statically \
             provable.",
            socket.protocole, socket.adresse, socket.port, proc_desc
        ),
        diff: None,
        references_conformite: vec!["OWASP MCP09".to_string(), "shadow-mcp".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::ScopeServeur;

    const LSOF_SAMPLE: &str = "\
COMMAND   PID  USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node    12345  alice   23u  IPv4 0x1234567890abcdef      0t0  TCP 127.0.0.1:3000 (LISTEN)
node    12345  alice   24u  IPv6 0xfedcba0987654321      0t0  TCP *:8080 (LISTEN)
sshd      999   root    3u  IPv4 0xaaaaaaaaaaaaaaaa      0t0  TCP *:22 (LISTEN)
Python  54321    bob    5u  IPv4 0xbbbbbbbbbbbbbbbb      0t0  TCP 0.0.0.0:9000 (LISTEN)
";

    const SS_SAMPLE: &str = "\
State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:((\"sshd\",pid=999,fd=3))
LISTEN  0       128     127.0.0.1:3000      0.0.0.0:*          users:((\"node\",pid=12345,fd=23))
LISTEN  0       128     [::]:8080           [::]:*             users:((\"node\",pid=12345,fd=24))
LISTEN  0       4096    0.0.0.0:9000        0.0.0.0:*
";

    fn http(nom: &str, url: &str) -> ServeurMcpDeclare {
        ServeurMcpDeclare {
            nom: nom.to_string(),
            transport: "http".to_string(),
            commande: None,
            args: vec![],
            env_keys: vec![],
            url: Some(url.to_string()),
            disabled: false,
            scope: ScopeServeur::default(),
        }
    }

    #[test]
    fn parse_lsof_extrait_les_sockets() {
        let socks = parser_lsof(LSOF_SAMPLE);
        assert_eq!(socks.len(), 4);
        let s3000 = socks.iter().find(|s| s.port == 3000).unwrap();
        assert_eq!(s3000.adresse, "127.0.0.1");
        assert!(!s3000.bind_toutes_interfaces);
        assert_eq!(s3000.processus.as_deref(), Some("node"));
        assert_eq!(s3000.pid, Some(12345));

        let s8080 = socks.iter().find(|s| s.port == 8080).unwrap();
        assert_eq!(s8080.protocole, "tcp6");
        assert!(s8080.bind_toutes_interfaces, "*:8080 = bind-all");
    }

    #[test]
    fn parse_ss_extrait_les_sockets() {
        let socks = parser_ss(SS_SAMPLE);
        assert_eq!(socks.len(), 4);
        let s8080 = socks.iter().find(|s| s.port == 8080).unwrap();
        assert_eq!(s8080.adresse, "::");
        assert!(s8080.bind_toutes_interfaces);
        assert_eq!(s8080.processus.as_deref(), Some("node"));

        // Ligne sans champ process (privilèges manquants) → pid/proc None,
        // mais le socket reste énuméré.
        let s9000 = socks.iter().find(|s| s.port == 9000).unwrap();
        assert!(s9000.pid.is_none());
        assert!(s9000.processus.is_none());
        assert!(s9000.bind_toutes_interfaces);
    }

    #[test]
    fn separe_hote_port_ipv6() {
        assert_eq!(separer_hote_port("[::]:8080"), Some(("::".to_string(), 8080)));
        assert_eq!(separer_hote_port("[::1]:25"), Some(("::1".to_string(), 25)));
        assert_eq!(
            separer_hote_port("127.0.0.1:3000"),
            Some(("127.0.0.1".to_string(), 3000))
        );
        assert_eq!(separer_hote_port("*:111"), Some(("*".to_string(), 111)));
        assert_eq!(separer_hote_port("pas-de-port"), None);
    }

    #[test]
    fn correlation_signale_bind_all_inconnu() {
        let socks = parser_lsof(LSOF_SAMPLE);
        // Inventaire : un serveur MCP HTTP sur le port 8080 (donc connu).
        let connus = vec![http("local-mcp", "http://0.0.0.0:8080/mcp")];
        let constats = correler_avec_inventaire(&socks, &connus);
        // Attendu : seul 9000 (bind-all, >=1024, inconnu) est signalé.
        //  - 3000 : loopback → ignoré ;
        //  - 8080 : bind-all mais connu → ignoré ;
        //  - 22   : port privilégié → ignoré.
        assert_eq!(constats.len(), 1, "vu : {:?}", constats.iter().map(|c| &c.titre).collect::<Vec<_>>());
        assert!(constats[0].titre.contains("9000"));
        assert_eq!(constats[0].type_constat, TypeConstat::ShadowMcp);
    }

    #[test]
    fn correlation_dedoublonne_dual_stack_ipv4_ipv6() {
        // Régression : un process qui écoute en IPv4 ET IPv6 sur le même port
        // (dual-stack) est énuméré deux fois (`tcp` 0.0.0.0 + `tcp6` ::). C'est
        // UN listener logique → un seul constat, pas deux cartes identiques.
        let sock = |proto: &str, adresse: &str| SocketEnEcoute {
            protocole: proto.to_string(),
            bind_toutes_interfaces: true,
            adresse: adresse.to_string(),
            port: 7000,
            pid: Some(635),
            processus: Some("ControlCe".to_string()),
        };
        let socks = vec![sock("tcp", "0.0.0.0"), sock("tcp6", "::")];
        let constats = correler_avec_inventaire(&socks, &[]);
        assert_eq!(
            constats.len(),
            1,
            "le listener dual-stack (même port/pid) ne doit donner qu'un seul constat",
        );
        assert!(constats[0].titre.contains("7000"));
        // Deux ports distincts restent deux constats (pas de sur-collapse).
        let multi = vec![sock("tcp", "0.0.0.0"), {
            let mut s = sock("tcp6", "::");
            s.port = 5000;
            s.pid = Some(652);
            s
        }];
        assert_eq!(correler_avec_inventaire(&multi, &[]).len(), 2);
    }

    #[test]
    fn correlation_aucun_inconnu_aucun_constat() {
        // Faux positif proscrit : tous les bind-all hauts sont dans l'inventaire.
        let socks = parser_lsof(LSOF_SAMPLE);
        let connus = vec![
            http("a", "http://0.0.0.0:8080/mcp"),
            http("b", "http://0.0.0.0:9000/mcp"),
        ];
        assert!(correler_avec_inventaire(&socks, &connus).is_empty());
    }

    #[test]
    fn parsers_ne_paniquent_pas_sur_sortie_malformee() {
        // La sortie de `lsof`/`ss` est une commande externe non fiable : aucune
        // entrée (ports hors plage u16, UTF-8 multioctet, crochets non fermés,
        // pid non numérique, ligne géante) ne doit provoquer de panic.
        let garbage = [
            "",
            "\n\n\n",
            "(LISTEN)",
            "COMMAND PID",
            "node 1 u IPv4 x x x [::1]:99999 (LISTEN)", // port hors u16
            "node 1 u IPv4 x x x : (LISTEN)",
            "node 1 u IPv4 x x x [ (LISTEN)",
            "héllo wörld 😀 TCP [::]:8080 (LISTEN)",
            "LISTEN 0 128",
            "LISTEN 0 128 [::1]:abc x users:((\"x\",pid=notanum,fd=1))",
            "LISTEN 0 128 0.0.0.0:99999 0.0.0.0:* users:((\"é😀\",pid=99999999999999999,fd=1))",
            &"A".repeat(100_000),
        ];
        for g in garbage {
            let _ = parser_lsof(g);
            let _ = parser_ss(g);
            let _ = separer_hote_port(g);
        }
        // Un port hors plage u16 doit être ignoré silencieusement, pas tronqué.
        assert!(parser_lsof("node 1 u IPv4 x x x [::1]:99999 (LISTEN)").is_empty());
    }

    #[test]
    fn ports_connus_gere_defaut_et_explicite() {
        let serveurs = vec![
            http("https-default", "https://api.example.com/mcp"), // 443
            http("explicite", "http://10.0.0.5:7100/mcp"),        // 7100
        ];
        let ports = ports_connus(&serveurs);
        assert!(ports.contains(&443));
        assert!(ports.contains(&7100));
    }
}
