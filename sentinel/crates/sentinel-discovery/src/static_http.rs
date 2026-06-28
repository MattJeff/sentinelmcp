//! D14 — Contrôles **statiques** OAuth / SSRF pour les serveurs MCP HTTP.
//!
//! Sur chaque [`ServeurMcpDeclare`] de transport HTTP, ce module émet des
//! [`Constat`] sans **aucun accès réseau** : on n'analyse que ce qui est
//! déclaré dans la config (l'`url` et les noms de variables d'environnement).
//!
//! Contrôles implémentés :
//!
//!   * **SSRF** — l'endpoint pointe vers une IP loopback / privée / lien-local
//!     (incl. l'IP de métadonnées cloud `169.254.169.254`) ou non spécifiée
//!     (`0.0.0.0` / `::`). Un serveur MCP distant qui parle à ces adresses est
//!     un pivot SSRF classique (CWE-918).
//!   * **Confused deputy (RFC 8707)** — l'URL embarque un `client_id` OAuth
//!     sans paramètre `resource`/`audience` : le serveur d'autorisation ne peut
//!     pas restreindre l'audience du jeton (CWE-441).
//!   * **client_id statique** — un `client_id` figé en clair dans l'URL.
//!   * **Token passthrough suspect** — un secret/jeton est embarqué dans la
//!     query string de l'URL, ou une variable d'environnement nommée pour
//!     **relayer** un jeton client vers l'amont (CWE-522).
//!   * **Transport en clair** — endpoint `http://` vers un hôte public.
//!
//! ## Faux positifs maîtrisés
//!
//!   * un endpoint HTTPS public **sans** query suspecte n'émet **rien** ;
//!   * une variable d'env « métier » (`API_KEY`, `GITHUB_TOKEN`, …) n'est PAS
//!     traitée comme un passthrough : un serveur a légitimement besoin de ses
//!     propres identifiants. Seuls les noms qui signalent un **relais** de
//!     jeton (`AUTHORIZATION`, `BEARER_TOKEN`, `PASSTHROUGH_TOKEN`, …) sont
//!     remontés ;
//!   * une URL illisible n'émet **rien** (pas de panic, pas de constat hasardeux).

use std::net::{IpAddr, Ipv6Addr};

use chrono::Utc;
use reqwest::Url;
use sentinel_protocol::{Constat, EtatConstat, Severite, TypeConstat};
use uuid::Uuid;

use crate::config_baseline::id_serveur_stable;
use crate::model::ServeurMcpDeclare;

/// Analyse statique d'un lot de serveurs : ne retient que les serveurs HTTP.
pub fn analyser_serveurs_http(serveurs: &[ServeurMcpDeclare]) -> Vec<Constat> {
    serveurs.iter().flat_map(analyser_serveur_http).collect()
}

/// Analyse statique d'un seul serveur. Retourne un `Vec` vide si le serveur
/// n'est pas HTTP, ou si rien de suspect n'est trouvé.
pub fn analyser_serveur_http(serveur: &ServeurMcpDeclare) -> Vec<Constat> {
    if !est_http(serveur) {
        return Vec::new();
    }
    let mut constats = Vec::new();

    // 1. Variables d'environnement de relais de jeton (indépendant de l'URL).
    if let Some(c) = constat_passthrough_env(serveur) {
        constats.push(c);
    }

    // 2. Contrôles dérivés de l'URL (si elle est lisible).
    let Some(url) = serveur.url.as_deref().and_then(|u| Url::parse(u).ok()) else {
        return constats;
    };

    if let Some(c) = constat_ssrf(serveur, &url) {
        constats.push(c);
    }
    if let Some(c) = constat_secret_dans_url(serveur, &url) {
        constats.push(c);
    }
    if let Some(c) = constat_oauth(serveur, &url) {
        constats.push(c);
    }
    if let Some(c) = constat_cleartext(serveur, &url) {
        constats.push(c);
    }

    constats
}

/// Un serveur est « HTTP » s'il le déclare explicitement ou s'il porte une URL
/// sans commande stdio.
fn est_http(serveur: &ServeurMcpDeclare) -> bool {
    let t = serveur.transport.to_ascii_lowercase();
    t == "http" || t == "sse" || (serveur.url.is_some() && serveur.commande.is_none())
}

// ───────────────────────── SSRF ─────────────────────────

/// Classe de risque réseau d'un hôte d'endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RisqueReseau {
    Loopback,
    ReseauPrive,
    LienLocal,
    MetadataCloud,
    NonSpecifie,
}

impl RisqueReseau {
    fn severite(self) -> Severite {
        match self {
            // L'IP de métadonnées cloud et le bind-all sont les plus dangereux.
            RisqueReseau::MetadataCloud | RisqueReseau::NonSpecifie | RisqueReseau::LienLocal => {
                Severite::Haute
            }
            RisqueReseau::Loopback | RisqueReseau::ReseauPrive => Severite::Moyenne,
        }
    }

    fn libelle(self) -> &'static str {
        match self {
            RisqueReseau::Loopback => "loopback",
            RisqueReseau::ReseauPrive => "réseau privé (RFC 1918 / ULA)",
            RisqueReseau::LienLocal => "lien-local",
            RisqueReseau::MetadataCloud => "métadonnées cloud (169.254.169.254)",
            RisqueReseau::NonSpecifie => "adresse non spécifiée (bind-all)",
        }
    }
}

/// Noms d'hôtes de métadonnées cloud bien connus (résolvent vers
/// `169.254.169.254` / équivalents). On les reconnaît par nom — sans aucune
/// résolution DNS — car ce sont des cibles SSRF sans aucun usage légitime côté
/// serveur MCP.
const HOTES_METADATA: &[&str] = &["metadata.google.internal", "metadata.goog"];

/// Classe l'hôte d'une URL. `None` pour un hôte public ordinaire.
fn classer_hote(url: &Url) -> Option<RisqueReseau> {
    let host = url.host_str()?;
    // url renvoie les IPv6 entre crochets : on les retire pour le parsing.
    let host_nu = host.trim_start_matches('[').trim_end_matches(']');

    // Noms réservés / LAN.
    let host_min = host_nu.to_ascii_lowercase();
    if host_min == "localhost" || host_min.ends_with(".localhost") {
        return Some(RisqueReseau::Loopback);
    }
    if HOTES_METADATA.contains(&host_min.as_str()) {
        // Endpoint de métadonnées cloud désigné par son nom DNS interne.
        return Some(RisqueReseau::MetadataCloud);
    }
    if host_min.ends_with(".local") {
        // mDNS / Bonjour : hôte de réseau local.
        return Some(RisqueReseau::ReseauPrive);
    }

    match host_nu.parse::<IpAddr>() {
        Ok(ip) => classer_ip(ip),
        Err(_) => None, // nom de domaine public — pas d'analyse SSRF statique.
    }
}

/// Classe une IP littérale. Implémentation manuelle pour les plages IPv6
/// (ULA / lien-local) dont les helpers `std` sont encore instables.
fn classer_ip(ip: IpAddr) -> Option<RisqueReseau> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o == [169, 254, 169, 254] {
                return Some(RisqueReseau::MetadataCloud);
            }
            if v4.is_unspecified() {
                return Some(RisqueReseau::NonSpecifie);
            }
            if v4.is_loopback() {
                return Some(RisqueReseau::Loopback);
            }
            if v4.is_link_local() {
                return Some(RisqueReseau::LienLocal);
            }
            if v4.is_private() {
                return Some(RisqueReseau::ReseauPrive);
            }
            None
        }
        IpAddr::V6(v6) => classer_ipv6(v6),
    }
}

fn classer_ipv6(v6: Ipv6Addr) -> Option<RisqueReseau> {
    // Adresse IPv4 « mappée » `::ffff:a.b.c.d` : contournement SSRF classique
    // (`http://[::ffff:127.0.0.1]/`, `…[::ffff:169.254.169.254]/`). On reclasse
    // via la logique IPv4, sinon ces formes échappaient à toute détection.
    if let Some(v4) = v6.to_ipv4_mapped() {
        return classer_ip(IpAddr::V4(v4));
    }
    if v6.is_unspecified() {
        return Some(RisqueReseau::NonSpecifie);
    }
    if v6.is_loopback() {
        return Some(RisqueReseau::Loopback);
    }
    let premier = v6.segments()[0];
    // fe80::/10 — lien-local.
    if premier & 0xffc0 == 0xfe80 {
        return Some(RisqueReseau::LienLocal);
    }
    // fc00::/7 — unique-local (équivalent ULA des plages privées).
    if premier & 0xfe00 == 0xfc00 {
        return Some(RisqueReseau::ReseauPrive);
    }
    None
}

fn constat_ssrf(serveur: &ServeurMcpDeclare, url: &Url) -> Option<Constat> {
    let risque = classer_hote(url)?;
    let mut refs = vec![
        "OWASP MCP".to_string(),
        "SSRF".to_string(),
        "CWE-918".to_string(),
    ];
    if risque == RisqueReseau::MetadataCloud {
        refs.push("cloud-metadata".to_string());
    }
    Some(Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&serveur.nom),
        outil_nom: None,
        type_constat: TypeConstat::Autre,
        severite: risque.severite(),
        titre: format!(
            "Serveur HTTP « {} » pointe vers une adresse interne ({})",
            serveur.nom,
            risque.libelle()
        ),
        detail: format!(
            "L'endpoint déclaré « {} » résout vers un hôte {} : un serveur MCP qui contacte cette \
             adresse peut être détourné pour atteindre des services internes (SSRF, CWE-918). \
             Vérifier que cet endpoint est intentionnel et restreindre les destinations réseau.",
            serveur.url.as_deref().unwrap_or(""),
            risque.libelle()
        ),
        diff: None,
        references_conformite: refs,
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    })
}

// ───────────────────────── OAuth / RFC 8707 ─────────────────────────

fn constat_oauth(serveur: &ServeurMcpDeclare, url: &Url) -> Option<Constat> {
    let mut a_client_id = false;
    let mut a_resource = false;
    let mut a_audience = false;
    for (k, v) in url.query_pairs() {
        match k.as_ref().to_ascii_lowercase().as_str() {
            "client_id" if !v.is_empty() => a_client_id = true,
            "resource" if !v.is_empty() => a_resource = true,
            "audience" | "aud" if !v.is_empty() => a_audience = true,
            _ => {}
        }
    }
    if !a_client_id {
        return None;
    }

    let manque_audience = !a_resource && !a_audience;
    let mut refs = vec!["OWASP MCP".to_string(), "OAuth".to_string()];
    let (severite, titre, detail);
    if manque_audience {
        refs.push("RFC 8707".to_string());
        refs.push("confused-deputy".to_string());
        refs.push("CWE-441".to_string());
        severite = Severite::Moyenne;
        titre = format!(
            "Serveur HTTP « {} » : client_id OAuth sans audience/resource (confused deputy)",
            serveur.nom
        );
        detail = format!(
            "L'URL OAuth de « {}» embarque un `client_id` statique mais aucun paramètre \
             `resource`/`audience` (RFC 8707). Sans audience, le serveur d'autorisation émet un \
             jeton non restreint : un serveur intermédiaire peut le rejouer vers une autre API \
             (confused deputy, CWE-441). Ajouter le paramètre `resource` pointant l'API cible.",
            serveur.nom
        );
    } else {
        refs.push("client_id-statique".to_string());
        severite = Severite::Moyenne;
        titre = format!(
            "Serveur HTTP « {} » : client_id OAuth statique en clair dans l'URL",
            serveur.nom
        );
        detail = format!(
            "L'URL de « {} » fige un `client_id` OAuth en clair. Un identifiant client statique \
             partagé facilite l'usurpation ; préférer un enregistrement client dynamique ou un \
             secret hors configuration.",
            serveur.nom
        );
    }

    Some(Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&serveur.nom),
        outil_nom: None,
        type_constat: TypeConstat::Autre,
        severite,
        titre,
        detail,
        diff: None,
        references_conformite: refs,
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    })
}

// ───────────────────────── Secret / token dans l'URL ─────────────────────────

/// Paramètres de query qui trahissent un secret embarqué dans l'URL.
const PARAMS_SECRET: &[&str] = &[
    "token",
    "access_token",
    "api_key",
    "apikey",
    "bearer",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "auth",
];

/// Valeurs qui désignent un **schéma / mode** d'authentification — donc PAS un
/// secret. Un paramètre ambigu comme `auth=bearer` ou `auth=none` sélectionne
/// une méthode d'auth ; le traiter comme un secret en clair est un faux positif
/// (un vrai secret est une chaîne aléatoire, jamais l'un de ces mots-clés). On
/// ne supprime donc l'alerte que lorsque la **valeur entière** est l'un d'eux.
const VALEURS_SCHEMA_AUTH: &[&str] = &[
    "bearer",
    "basic",
    "digest",
    "negotiate",
    "ntlm",
    "none",
    "oauth",
    "oauth2",
    "openid",
    "apikey",
    "api_key",
    "token",
    "jwt",
    "hmac",
    "mac",
    "true",
    "false",
];

/// `true` si la valeur d'un paramètre est un simple sélecteur de schéma d'auth
/// (et non un secret). Comparaison insensible à la casse sur la valeur entière.
fn valeur_est_schema_auth(valeur: &str) -> bool {
    let v = valeur.trim().to_ascii_lowercase();
    VALEURS_SCHEMA_AUTH.contains(&v.as_str())
}

fn constat_secret_dans_url(serveur: &ServeurMcpDeclare, url: &Url) -> Option<Constat> {
    let trouve: Vec<String> = url
        .query_pairs()
        .filter(|(k, v)| {
            !v.is_empty()
                && PARAMS_SECRET.contains(&k.as_ref().to_ascii_lowercase().as_str())
                // Faux positif proscrit : `auth=bearer`, `auth=none`… sélectionne
                // un schéma d'auth, ce n'est pas un secret fuité.
                && !valeur_est_schema_auth(v.as_ref())
        })
        .map(|(k, _)| k.to_string())
        .collect();
    if trouve.is_empty() {
        return None;
    }
    Some(Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&serveur.nom),
        outil_nom: None,
        type_constat: TypeConstat::Autre,
        severite: Severite::Haute,
        titre: format!(
            "Serveur HTTP « {} » : secret embarqué dans l'URL ({})",
            serveur.nom,
            trouve.join(", ")
        ),
        detail: format!(
            "L'URL de « {} » embarque un ou plusieurs secrets en clair dans sa query string \
             ({}). Un jeton dans l'URL fuite via les logs/proxies et peut être relayé vers \
             l'amont (token passthrough, CWE-522). Déplacer ces secrets hors de l'URL.",
            serveur.nom,
            trouve.join(", ")
        ),
        diff: None,
        references_conformite: vec![
            "OWASP MCP".to_string(),
            "token-passthrough".to_string(),
            "CWE-522".to_string(),
        ],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    })
}

// ───────────────────────── Token passthrough (env) ─────────────────────────

/// Noms de variables d'environnement qui signalent le **relais** d'un jeton
/// client vers l'amont (et non un identifiant propre au serveur).
const ENV_PASSTHROUGH: &[&str] = &[
    "authorization",
    "bearer",
    "bearer_token",
    "passthrough_token",
    "forward_token",
    "upstream_token",
    "mcp_proxy_token",
    "proxy_authorization",
];

fn constat_passthrough_env(serveur: &ServeurMcpDeclare) -> Option<Constat> {
    let trouve: Vec<String> = serveur
        .env_keys
        .iter()
        .filter(|k| ENV_PASSTHROUGH.contains(&k.to_ascii_lowercase().as_str()))
        .cloned()
        .collect();
    if trouve.is_empty() {
        return None;
    }
    Some(Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&serveur.nom),
        outil_nom: None,
        type_constat: TypeConstat::Autre,
        severite: Severite::Moyenne,
        titre: format!(
            "Serveur HTTP « {} » : variable de relais de jeton ({})",
            serveur.nom,
            trouve.join(", ")
        ),
        detail: format!(
            "Le serveur « {} » déclare la/les variable(s) d'environnement {} qui dénote(nt) le \
             relais d'un jeton client vers l'amont (token passthrough). Un serveur MCP ne doit pas \
             réutiliser le jeton du client pour appeler d'autres API (confused deputy, CWE-522) : \
             utiliser des identifiants propres au serveur avec une audience restreinte.",
            serveur.nom,
            trouve.join(", ")
        ),
        diff: None,
        references_conformite: vec![
            "OWASP MCP".to_string(),
            "token-passthrough".to_string(),
            "CWE-522".to_string(),
        ],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    })
}

// ───────────────────────── Transport en clair ─────────────────────────

fn constat_cleartext(serveur: &ServeurMcpDeclare, url: &Url) -> Option<Constat> {
    if url.scheme() != "http" {
        return None;
    }
    // On ne double pas l'alerte pour le loopback/LAN (déjà couvert par SSRF) :
    // le risque « transport en clair » vise un endpoint *public* atteint sans TLS.
    if classer_hote(url).is_some() {
        return None;
    }
    Some(Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&serveur.nom),
        outil_nom: None,
        type_constat: TypeConstat::Autre,
        severite: Severite::Moyenne,
        titre: format!(
            "Serveur HTTP « {} » : endpoint public en clair (http://)",
            serveur.nom
        ),
        detail: format!(
            "L'endpoint « {} » est contacté en HTTP non chiffré vers un hôte public : le trafic MCP \
             (jetons, appels d'outils) est interceptable et modifiable (CWE-319). Utiliser HTTPS.",
            serveur.url.as_deref().unwrap_or("")
        ),
        diff: None,
        references_conformite: vec![
            "OWASP MCP".to_string(),
            "cleartext-transport".to_string(),
            "CWE-319".to_string(),
        ],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::ScopeServeur;

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

    fn types(constats: &[Constat]) -> Vec<&str> {
        constats.iter().map(|c| c.titre.as_str()).collect()
    }

    #[test]
    fn endpoint_https_public_propre_est_silencieux() {
        // Faux positif proscrit : un serveur HTTPS public ordinaire.
        let s = http("api", "https://api.example.com/mcp");
        let c = analyser_serveur_http(&s);
        assert!(c.is_empty(), "ne doit rien flagger, vu : {:?}", types(&c));
    }

    #[test]
    fn serveur_stdio_ignore() {
        let s = ServeurMcpDeclare {
            nom: "fs".to_string(),
            transport: "stdio".to_string(),
            commande: Some("npx".to_string()),
            args: vec!["-y".to_string(), "@mcp/fs".to_string()],
            env_keys: vec!["API_KEY".to_string()],
            url: None,
            disabled: false,
            scope: ScopeServeur::default(),
        };
        assert!(analyser_serveur_http(&s).is_empty());
    }

    #[test]
    fn env_metier_non_traite_comme_passthrough() {
        // Faux positif proscrit : API_KEY / GITHUB_TOKEN sont des creds propres.
        let mut s = http("github", "https://api.githubcopilot.com/mcp/");
        s.env_keys = vec!["API_KEY".to_string(), "GITHUB_TOKEN".to_string()];
        assert!(analyser_serveur_http(&s).is_empty());
    }

    #[test]
    fn loopback_flague_ssrf() {
        let s = http("local", "http://127.0.0.1:8080/mcp");
        let c = analyser_serveur_http(&s);
        assert!(c.iter().any(|c| c.titre.contains("adresse interne")));
        assert!(c.iter().any(|c| c.references_conformite.iter().any(|r| r == "CWE-918")));
    }

    #[test]
    fn metadata_cloud_est_haute() {
        let s = http("meta", "http://169.254.169.254/latest/meta-data/");
        let c = analyser_serveur_http(&s);
        let ssrf = c.iter().find(|c| c.titre.contains("adresse interne")).expect("ssrf");
        assert_eq!(ssrf.severite, Severite::Haute);
        assert!(ssrf.references_conformite.iter().any(|r| r == "cloud-metadata"));
    }

    #[test]
    fn ipv6_loopback_et_ula() {
        assert_eq!(classer_ip("::1".parse().unwrap()), Some(RisqueReseau::Loopback));
        assert_eq!(classer_ip("fd00::1".parse().unwrap()), Some(RisqueReseau::ReseauPrive));
        assert_eq!(classer_ip("fe80::1".parse().unwrap()), Some(RisqueReseau::LienLocal));
        assert_eq!(classer_ip("2606:4700:4700::1111".parse().unwrap()), None);
    }

    #[test]
    fn bind_all_non_specifie() {
        assert_eq!(classer_ip("0.0.0.0".parse().unwrap()), Some(RisqueReseau::NonSpecifie));
    }

    #[test]
    fn ipv4_mappe_en_ipv6_ne_contourne_pas_le_ssrf() {
        // Contournement classique : encoder une cible interne en IPv4-mapped
        // IPv6. Avant durcissement, `::ffff:127.0.0.1` échappait à toute
        // classification (ni loopback, ni lien-local, ni ULA) → FAUX NÉGATIF.
        assert_eq!(
            classer_ip("::ffff:127.0.0.1".parse().unwrap()),
            Some(RisqueReseau::Loopback)
        );
        assert_eq!(
            classer_ip("::ffff:169.254.169.254".parse().unwrap()),
            Some(RisqueReseau::MetadataCloud)
        );
        assert_eq!(
            classer_ip("::ffff:10.0.0.1".parse().unwrap()),
            Some(RisqueReseau::ReseauPrive)
        );
        // Une IPv4 publique mappée reste publique (pas de faux positif).
        assert_eq!(classer_ip("::ffff:8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn metadata_via_url_ipv4_mappe_est_haute() {
        // Bout en bout : un endpoint déclaré avec l'IP mappée doit lever SSRF.
        let s = http("meta6", "http://[::ffff:169.254.169.254]/latest/meta-data/");
        let c = analyser_serveur_http(&s);
        let ssrf = c
            .iter()
            .find(|c| c.titre.contains("adresse interne"))
            .expect("ssrf attendu sur ::ffff:169.254.169.254");
        assert_eq!(ssrf.severite, Severite::Haute);
        assert!(ssrf.references_conformite.iter().any(|r| r == "cloud-metadata"));
    }

    #[test]
    fn hote_metadata_par_nom_est_flague() {
        // `metadata.google.internal` n'est pas une IP : sans cette reconnaissance
        // par nom, le pivot SSRF vers les métadonnées GCP passait inaperçu.
        let s = http("gcp", "http://metadata.google.internal/computeMetadata/v1/");
        let c = analyser_serveur_http(&s);
        let ssrf = c
            .iter()
            .find(|c| c.titre.contains("adresse interne"))
            .expect("ssrf attendu sur metadata.google.internal");
        assert_eq!(ssrf.severite, Severite::Haute);
        assert!(ssrf.references_conformite.iter().any(|r| r == "cloud-metadata"));
    }

    #[test]
    fn endpoint_https_public_avec_query_anodine_reste_silencieux() {
        // Faux positif proscrit : query métier sans secret ni client_id OAuth.
        let s = http("api", "https://api.example.com/mcp?version=2&format=json");
        let c = analyser_serveur_http(&s);
        assert!(c.is_empty(), "ne doit rien flagger, vu : {:?}", types(&c));
    }

    #[test]
    fn client_id_sans_resource_est_confused_deputy() {
        let s = http("oauth", "https://auth.example.com/authorize?client_id=abc123&response_type=code");
        let c = analyser_serveur_http(&s);
        let oauth = c.iter().find(|c| c.titre.contains("confused deputy")).expect("confused deputy");
        assert!(oauth.references_conformite.iter().any(|r| r == "RFC 8707"));
    }

    #[test]
    fn client_id_avec_resource_pas_de_confused_deputy() {
        // Faux positif proscrit : présence de `resource` → pas de confused deputy.
        let s = http(
            "oauth",
            "https://auth.example.com/authorize?client_id=abc123&resource=https://api.example.com",
        );
        let c = analyser_serveur_http(&s);
        assert!(
            !c.iter().any(|c| c.titre.contains("confused deputy")),
            "resource présent → pas de confused deputy"
        );
        // Mais le client_id statique reste signalé.
        assert!(c.iter().any(|c| c.titre.contains("client_id OAuth statique")));
    }

    #[test]
    fn secret_dans_url_est_haute() {
        let s = http("leak", "https://api.example.com/mcp?access_token=ghp_secret");
        let c = analyser_serveur_http(&s);
        let leak = c.iter().find(|c| c.titre.contains("secret embarqué")).expect("secret");
        assert_eq!(leak.severite, Severite::Haute);
    }

    #[test]
    fn env_passthrough_detecte() {
        let mut s = http("proxy", "https://api.example.com/mcp");
        s.env_keys = vec!["AUTHORIZATION".to_string()];
        let c = analyser_serveur_http(&s);
        assert!(c.iter().any(|c| c.titre.contains("relais de jeton")));
    }

    #[test]
    fn http_public_en_clair_flague_cleartext() {
        let s = http("clair", "http://api.example.com/mcp");
        let c = analyser_serveur_http(&s);
        assert!(c.iter().any(|c| c.titre.contains("en clair")));
    }

    #[test]
    fn url_illisible_ne_panique_pas() {
        let s = http("casse", "ht!tp://[not-a-url");
        // Ne doit pas paniquer ; au pire aucun constat URL.
        let _ = analyser_serveur_http(&s);
    }

    #[test]
    fn auth_scheme_dans_query_n_est_pas_un_secret() {
        // Faux positif proscrit : `auth=bearer` / `auth=none` sélectionne un
        // schéma d'auth, pas un secret en clair. Ne doit PAS lever « secret
        // embarqué ».
        for url in [
            "https://api.example.com/mcp?auth=bearer",
            "https://api.example.com/mcp?auth=none",
            "https://api.example.com/mcp?auth=oauth2",
            "https://api.example.com/sse?token=none",
        ] {
            let s = http("api", url);
            let c = analyser_serveur_http(&s);
            assert!(
                !c.iter().any(|c| c.titre.contains("secret embarqué")),
                "{url} ne doit pas être flaggé comme secret, vu : {:?}",
                types(&c)
            );
        }
    }

    #[test]
    fn vrai_secret_avec_param_auth_reste_flague() {
        // Régression inverse : un vrai secret sous la clé `auth` reste détecté.
        let s = http("leak", "https://api.example.com/mcp?auth=ghp_R3alSecretValue123");
        let c = analyser_serveur_http(&s);
        assert!(
            c.iter().any(|c| c.titre.contains("secret embarqué")),
            "un secret réel sous `auth` doit rester détecté, vu : {:?}",
            types(&c)
        );
    }

    #[test]
    fn ip_encodee_ne_contourne_pas_le_ssrf() {
        // Contournement SSRF classique : encoder la cible interne en décimal /
        // hexadécimal / octal. Le parseur d'URL doit normaliser, donc la
        // classification SSRF doit tenir (pas de faux négatif).
        let cas = [
            ("http://2130706433/", RisqueReseau::Loopback),       // 127.0.0.1 décimal
            ("http://0x7f000001/", RisqueReseau::Loopback),       // 127.0.0.1 hex
            ("http://017700000001/", RisqueReseau::Loopback),     // 127.0.0.1 octal
            ("http://2852039166/", RisqueReseau::MetadataCloud),  // 169.254.169.254 décimal
            ("http://0xa9fea9fe/", RisqueReseau::MetadataCloud),  // 169.254.169.254 hex
        ];
        for (url, attendu) in cas {
            let u = Url::parse(url).expect("url parse");
            assert_eq!(classer_hote(&u), Some(attendu), "classification de {url}");
            let s = http("enc", url);
            assert!(
                analyser_serveur_http(&s)
                    .iter()
                    .any(|c| c.titre.contains("adresse interne")),
                "{url} doit lever un SSRF"
            );
        }
    }
}
