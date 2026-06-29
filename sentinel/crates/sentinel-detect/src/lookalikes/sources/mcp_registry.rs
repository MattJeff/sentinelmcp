//! Implémentation HTTP du connecteur « registre officiel MCP ».
//!
//! Le registre officiel vit dans le dépôt GitHub
//! `modelcontextprotocol/servers`. À ce jour deux formes coexistent :
//!
//!   1. Un fichier `registry.json` à la racine — JSON tabulé, facile à parser.
//!   2. Le `README.md` du dépôt — liste à puces Markdown énumérant les
//!      serveurs sous la forme `- [nom](url) - description`.
//!
//! Stratégie :
//!   - tenter d'abord (1) via l'URL « raw » GitHub ;
//!   - si elle renvoie 404 (le fichier n'existe pas encore dans `main`),
//!     basculer vers (2) en interrogeant l'API GitHub
//!     `repos/{owner}/{repo}/contents/README.md`, qui renvoie un payload
//!     JSON contenant le contenu encodé en base64.
//!
//! Comme pour les autres connecteurs, toute défaillance (réseau, statut
//! non-2xx, payload illisible) doit produire un `Vec` vide accompagné
//! d'un log d'avertissement : la collecte multi-registres ne doit jamais
//! être bloquée par l'indisponibilité d'un registre.

use std::time::Duration;

use base64_decode::decode_standard;
use serde_json::Value;
use tracing::warn;

use crate::lookalikes::{EntreeRegistre, SignatureOutil};

/// URL par défaut de l'API REST du registre **officiel** MCP
/// (`registry.modelcontextprotocol.io`). C'est la source faisant désormais
/// autorité : elle renvoie un objet `{ "servers": [...] }` directement
/// exploitable par [`parser_registry_json`]. Tentée en premier par
/// [`lister_serveurs`] ; en cas d'échec (réseau, statut non-2xx, JSON
/// invalide ou liste vide) on retombe sur le dépôt GitHub historique.
pub const MCP_REGISTRY_OFFICIAL_API_URL: &str =
    "https://registry.modelcontextprotocol.io/v0/servers?limit=100";

/// URL « raw » par défaut du fichier `registry.json` (étape 1).
pub const MCP_REGISTRY_RAW_URL: &str =
    "https://raw.githubusercontent.com/modelcontextprotocol/servers/main/registry.json";

/// URL par défaut de l'API GitHub renvoyant le `README.md` (étape 2 / repli).
pub const MCP_REGISTRY_README_API_URL: &str =
    "https://api.github.com/repos/modelcontextprotocol/servers/contents/README.md";

/// Timeout HTTP appliqué à chaque requête (spec : 8 s).
const TIMEOUT_REQUETE: Duration = Duration::from_secs(8);

/// User-Agent envoyé aux endpoints GitHub (l'API en exige un explicite).
const USER_AGENT: &str = "sentinel-detect/0.1 (+https://github.com/sentinel-mcp)";

/// Récupère la liste des serveurs du registre officiel MCP.
///
/// Stratégie en deux temps :
///   1. l'API REST faisant autorité (`registry.modelcontextprotocol.io`) ;
///   2. à défaut (échec ou liste vide), repli sur le dépôt GitHub
///      `modelcontextprotocol/servers` (raw `registry.json` puis README).
pub async fn lister_serveurs() -> Vec<EntreeRegistre> {
    let officiel = lister_serveurs_depuis_api(MCP_REGISTRY_OFFICIAL_API_URL).await;
    if !officiel.is_empty() {
        return officiel;
    }
    lister_serveurs_depuis(MCP_REGISTRY_RAW_URL, MCP_REGISTRY_README_API_URL).await
}

/// Interroge l'API REST du registre officiel MCP et parse le corps avec
/// [`parser_registry_json`] (qui reconnaît la forme `{ "servers": [...] }`).
///
/// Variante paramétrable utilisée par `lister_serveurs` et par les tests
/// d'intégration (wiremock). Toute défaillance (réseau, statut non-2xx,
/// corps illisible ou JSON invalide) produit un Vec vide — jamais de
/// panique, jamais de propagation d'erreur.
pub async fn lister_serveurs_depuis_api(url: &str) -> Vec<EntreeRegistre> {
    let client = match reqwest::Client::builder()
        .timeout(TIMEOUT_REQUETE)
        .user_agent(USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : client HTTP (API officielle) impossible");
            return Vec::new();
        }
    };

    let reponse = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url, "mcp-registry : échec requête API officielle");
            return Vec::new();
        }
    };

    if !reponse.status().is_success() {
        warn!(statut = %reponse.status(), url = %url, "mcp-registry : statut HTTP non-2xx sur l'API officielle");
        return Vec::new();
    }

    let texte = match reponse.text().await {
        Ok(t) => t,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : lecture du corps de l'API officielle impossible");
            return Vec::new();
        }
    };

    parser_registry_json(&texte)
}

/// Variante paramétrable de `lister_serveurs` — utilisée par les tests
/// d'intégration pour pointer vers un serveur wiremock.
///
/// `url_registry_json` est tentée en premier ; un statut 404 déclenche
/// le repli vers `url_readme_api`. Tout autre statut non-2xx ou erreur
/// de parsing renvoie un Vec vide sans tenter le repli (on évite ainsi
/// de marteler GitHub en cas d'erreur transitoire).
pub async fn lister_serveurs_depuis(
    url_registry_json: &str,
    url_readme_api: &str,
) -> Vec<EntreeRegistre> {
    let client = match reqwest::Client::builder()
        .timeout(TIMEOUT_REQUETE)
        .user_agent(USER_AGENT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : impossible de construire le client HTTP");
            return Vec::new();
        }
    };

    // Étape 1 : tentative `registry.json` brut.
    match client.get(url_registry_json).send().await {
        Ok(reponse) => {
            let statut = reponse.status();
            if statut.is_success() {
                let texte = match reponse.text().await {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(erreur = %e, "mcp-registry : lecture du corps registry.json impossible");
                        return Vec::new();
                    }
                };
                return parser_registry_json(&texte);
            } else if statut.as_u16() == 404 {
                // 404 attendu : on bascule vers le README via l'API.
            } else {
                warn!(statut = %statut, url = %url_registry_json, "mcp-registry : statut HTTP non-2xx sur registry.json");
                return Vec::new();
            }
        }
        Err(e) => {
            warn!(erreur = %e, url = %url_registry_json, "mcp-registry : échec de la requête registry.json");
            return Vec::new();
        }
    }

    // Étape 2 : repli sur l'API GitHub contents du README.
    let reponse = match client.get(url_readme_api).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url_readme_api, "mcp-registry : échec de la requête README");
            return Vec::new();
        }
    };

    if !reponse.status().is_success() {
        warn!(statut = %reponse.status(), url = %url_readme_api, "mcp-registry : statut HTTP non-2xx sur README");
        return Vec::new();
    }

    let payload: Value = match reponse.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : payload JSON README invalide");
            return Vec::new();
        }
    };

    let contenu_b64 = match payload.get("content").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            warn!("mcp-registry : champ `content` absent dans la réponse README");
            return Vec::new();
        }
    };

    // GitHub renvoie le contenu base64 entrecoupé de `\n` (longueurs de ligne
    // 60 ou 76). On supprime ces blancs avant de décoder.
    let nettoye: String = contenu_b64
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let octets = match decode_standard(&nettoye) {
        Ok(o) => o,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : base64 README invalide");
            return Vec::new();
        }
    };

    let markdown = match String::from_utf8(octets) {
        Ok(s) => s,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : README non-UTF8");
            return Vec::new();
        }
    };

    parser_readme_markdown(&markdown)
}

/// Parse le contenu textuel d'un `registry.json`.
///
/// Deux formes sont tolérées :
///   - un tableau JSON direct `[ {..}, {..} ]` ;
///   - un objet avec un champ `servers` (ou `packages`) contenant un tableau.
///
/// Chaque entrée doit exposer un champ texte `name` (ou `id`).
fn parser_registry_json(texte: &str) -> Vec<EntreeRegistre> {
    let racine: Value = match serde_json::from_str(texte) {
        Ok(v) => v,
        Err(e) => {
            warn!(erreur = %e, "mcp-registry : registry.json non parsable");
            return Vec::new();
        }
    };

    let tableau = if let Some(arr) = racine.as_array() {
        arr.clone()
    } else if let Some(arr) = racine.get("servers").and_then(|v| v.as_array()) {
        arr.clone()
    } else if let Some(arr) = racine.get("packages").and_then(|v| v.as_array()) {
        arr.clone()
    } else {
        warn!("mcp-registry : registry.json ne contient ni tableau direct ni `servers`/`packages`");
        return Vec::new();
    };

    tableau.iter().filter_map(extraire_entree_json).collect()
}

/// Extrait une `EntreeRegistre` à partir d'un nœud JSON `registry.json`.
fn extraire_entree_json(node: &Value) -> Option<EntreeRegistre> {
    let nom = node
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| node.get("id").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();
    if nom.is_empty() {
        return None;
    }

    let description = node
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let url = node
        .get("url")
        .or_else(|| node.get("homepage"))
        .or_else(|| node.get("repository"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let auteur = node
        .get("publisher")
        .or_else(|| node.get("author"))
        .or_else(|| node.get("owner"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(EntreeRegistre {
        registre: "mcp-registry".to_string(),
        nom,
        description,
        auteur,
        url,
        outils: None,
    })
}

/// Parse les lignes Markdown du README listant les serveurs.
///
/// Format reconnu (tolérant aux décorations comme `**`) :
///
/// ```text
/// - [Nom](https://exemple) - Description du serveur.
/// - **[Nom](url)** — description
/// ```
///
/// Les lignes ne respectant pas le motif sont ignorées silencieusement.
///
/// En complément, après l'extraction d'une entrée serveur, on scanne les
/// lignes suivantes (jusqu'à la prochaine entrée de serveur ou à un
/// en-tête de section) à la recherche de noms d'outils délimités par des
/// backticks (`` `read_file` ``, `` `write_file` ``…). Tout identifiant
/// `snake_case` rencontré est promu en `SignatureOutil` minimale.
fn parser_readme_markdown(markdown: &str) -> Vec<EntreeRegistre> {
    let mut entrees: Vec<EntreeRegistre> = Vec::new();
    // Index dans `entrees` de la dernière entrée serveur extraite ; sert à
    // accrocher les outils trouvés sur les lignes qui suivent.
    let mut courant: Option<usize> = None;
    // Accumulateur d'outils pour l'entrée courante (préserve l'ordre
    // d'apparition tout en évitant les doublons).
    let mut outils_courant: Vec<String> = Vec::new();

    let lignes: Vec<&str> = markdown.lines().collect();
    for ligne in &lignes {
        let nettoye = ligne.trim_start();

        // Un en-tête Markdown (`#`, `##`, …) ferme la section courante.
        if nettoye.starts_with('#') {
            attacher_outils(&mut entrees, courant.take(), &mut outils_courant);
            continue;
        }

        if nettoye.starts_with("- ") || nettoye.starts_with("* ") {
            let reste = &nettoye[2..];

            if let Some((nom, description)) = extraire_lien_markdown(reste) {
                if nom.is_empty() {
                    continue;
                }
                // Le bullet décrit une nouvelle entrée serveur → on ferme
                // la précédente puis on en ouvre une nouvelle.
                attacher_outils(&mut entrees, courant.take(), &mut outils_courant);
                entrees.push(EntreeRegistre {
                    registre: "mcp-registry".to_string(),
                    nom,
                    description: if description.is_empty() {
                        None
                    } else {
                        Some(description)
                    },
                    auteur: None,
                    url: None,
                    outils: None,
                });
                courant = Some(entrees.len() - 1);
                continue;
            }

            // Bullet sans lien Markdown : potentiellement un sous-bullet
            // énumérant un outil → on scanne les backticks.
            if courant.is_some() {
                collecter_outils_backticks(reste, &mut outils_courant);
            }
            continue;
        }

        // Toute autre ligne (paragraphe, ligne vide…) : on extrait
        // également les backticks éventuels, qui sont parfois utilisés en
        // prose pour énumérer les outils d'un serveur (`tool_a`, `tool_b`).
        if courant.is_some() {
            collecter_outils_backticks(nettoye, &mut outils_courant);
        }
    }

    // Fin de fichier : ne pas oublier la dernière entrée.
    attacher_outils(&mut entrees, courant.take(), &mut outils_courant);

    entrees
}

/// Accroche le buffer d'outils accumulé à l'entrée d'index `idx` puis vide
/// le buffer. Si aucun outil n'a été collecté, l'entrée garde `outils =
/// None` (la consigne demande explicitement de ne pas créer de `Some(vec
/// [])`).
fn attacher_outils(
    entrees: &mut [EntreeRegistre],
    idx: Option<usize>,
    buffer: &mut Vec<String>,
) {
    if let Some(i) = idx {
        if !buffer.is_empty() {
            let signatures = buffer
                .iter()
                .map(|nom| SignatureOutil {
                    nom: nom.clone(),
                    enums_tries: Vec::new(),
                    description_empreinte: String::new(),
                })
                .collect();
            entrees[i].outils = Some(signatures);
        }
    }
    buffer.clear();
}

/// Repère tous les snippets `` `xxx` `` dans `texte` et conserve ceux qui
/// ressemblent à un identifiant `snake_case` ASCII (lettres minuscules,
/// chiffres, underscore, longueur ≥ 2 et au moins une lettre).
fn collecter_outils_backticks(texte: &str, accumulateur: &mut Vec<String>) {
    let octets = texte.as_bytes();
    let mut i = 0;
    while i < octets.len() {
        if octets[i] == b'`' {
            // Ne pas confondre avec une délimitation de bloc ``` … ```.
            if i + 2 < octets.len() && octets[i + 1] == b'`' && octets[i + 2] == b'`' {
                i += 3;
                continue;
            }
            let debut = i + 1;
            let mut fin = debut;
            while fin < octets.len() && octets[fin] != b'`' {
                fin += 1;
            }
            if fin >= octets.len() {
                break;
            }
            let candidat = &texte[debut..fin];
            if est_identifiant_outil(candidat)
                && !accumulateur.iter().any(|n| n == candidat)
            {
                accumulateur.push(candidat.to_string());
            }
            i = fin + 1;
        } else {
            i += 1;
        }
    }
}

/// `true` si `s` ressemble à un identifiant d'outil snake_case raisonnable.
fn est_identifiant_outil(s: &str) -> bool {
    if s.len() < 2 {
        return false;
    }
    let mut contient_lettre = false;
    for c in s.chars() {
        match c {
            'a'..='z' => contient_lettre = true,
            '0'..='9' | '_' => {}
            _ => return false,
        }
    }
    contient_lettre
}

/// Extrait `(nom, description)` d'une portion du type
/// `**[nom](url)** - description` ou `[nom](url) — description`.
fn extraire_lien_markdown(reste: &str) -> Option<(String, String)> {
    // On localise le `[` qui ouvre le lien.
    let debut = reste.find('[')?;
    let fin_nom_rel = reste[debut + 1..].find(']')?;
    let nom = reste[debut + 1..debut + 1 + fin_nom_rel].trim();

    // Après le `]`, on doit trouver immédiatement `(` qui ouvre l'URL.
    let apres_crochet = &reste[debut + 1 + fin_nom_rel + 1..];
    if !apres_crochet.starts_with('(') {
        return None;
    }
    let fin_url_rel = apres_crochet[1..].find(')')?;
    let apres_url = &apres_crochet[1 + fin_url_rel + 1..];

    // La description suit, séparée par `-`, `—` ou `–`, éventuellement
    // après `**` de fermeture.
    let mut desc = apres_url.trim_start_matches('*').trim();
    for sep in ['-', '—', '–', ':'] {
        if let Some(rest) = desc.strip_prefix(sep) {
            desc = rest.trim();
            break;
        }
    }
    // On retire un `**` de fermeture éventuel dans la description.
    let description = desc.trim_end_matches('*').trim().to_string();

    let nom_propre = nom.trim_matches('*').trim().to_string();
    Some((nom_propre, description))
}

// ---------------------------------------------------------------------------
// Décodage base64 minimal — évite d'ajouter une crate.
// ---------------------------------------------------------------------------

/// Module privé : implémentation locale du décodage base64 standard
/// (alphabet `A-Za-z0-9+/`, padding `=`). On évite ainsi une nouvelle
/// dépendance pour une seule fonction.
mod base64_decode {
    /// Décode une chaîne base64 standard.
    pub fn decode_standard(entree: &str) -> Result<Vec<u8>, &'static str> {
        let octets = entree.as_bytes();
        if octets.len() % 4 != 0 {
            return Err("longueur non multiple de 4");
        }

        let mut sortie = Vec::with_capacity(octets.len() / 4 * 3);
        let mut buf: u32 = 0;
        let mut comptes: u32 = 0;
        let mut paddings: usize = 0;

        for &c in octets {
            if c == b'=' {
                paddings += 1;
                buf <<= 6;
                comptes += 6;
                if comptes >= 8 {
                    comptes -= 8;
                }
                continue;
            }
            if paddings > 0 {
                return Err("caractère après padding");
            }
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => return Err("caractère base64 invalide"),
            };
            buf = (buf << 6) | u32::from(v);
            comptes += 6;
            if comptes >= 8 {
                comptes -= 8;
                sortie.push(((buf >> comptes) & 0xFF) as u8);
            }
        }

        Ok(sortie)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decode_chaine_simple() {
            assert_eq!(decode_standard("aGVsbG8=").unwrap(), b"hello");
            assert_eq!(decode_standard("Zm9vYmFy").unwrap(), b"foobar");
            assert_eq!(decode_standard("").unwrap(), b"");
        }
    }
}

#[cfg(test)]
mod tests_fixtures {
    use super::*;

    /// Échantillon réaliste de `GET /v0/servers` du registre officiel
    /// (`registry.modelcontextprotocol.io`) : objet `{ "servers": [...] }` où
    /// chaque entrée porte un `name` (identifiant inversé) + `description`, le
    /// dépôt étant niché dans `repository` (donc pas de `url` au niveau
    /// racine — `url` reste `None`, ce qui est attendu).
    const FIXTURE_OFFICIEL: &str = r#"{
      "servers": [
        {
          "id": "0f9c0000-0000-0000-0000-000000000000",
          "name": "io.github.modelcontextprotocol/server-filesystem",
          "description": "Secure file operations with configurable access controls.",
          "repository": { "url": "https://github.com/modelcontextprotocol/servers", "source": "github" },
          "version_detail": { "version": "1.0.0", "is_latest": true }
        },
        {
          "name": "io.github.example/postgres-mcp",
          "description": "Read-only Postgres access for LLMs.",
          "repository": { "url": "https://github.com/example/postgres-mcp", "source": "github" }
        }
      ],
      "metadata": { "next_cursor": "abc", "count": 2 }
    }"#;

    #[test]
    fn parse_api_officielle() {
        let entrees = parser_registry_json(FIXTURE_OFFICIEL);
        assert_eq!(entrees.len(), 2);
        assert_eq!(entrees[0].registre, "mcp-registry");
        assert_eq!(
            entrees[0].nom,
            "io.github.modelcontextprotocol/server-filesystem"
        );
        assert_eq!(
            entrees[0].description.as_deref(),
            Some("Secure file operations with configurable access controls.")
        );
        assert_eq!(entrees[1].nom, "io.github.example/postgres-mcp");
    }

    /// Échantillon réaliste du README du dépôt `modelcontextprotocol/servers`
    /// (liste à puces Markdown ; les outils sont énumérés sur la ligne de
    /// prose suivant l'entrée du serveur).
    const FIXTURE_README: &str = r#"
## 🌟 Reference Servers

- **[Filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)** - Secure file operations.
  Exposes `read_file`, `write_file` and `list_directory`.
- **[Git](https://github.com/modelcontextprotocol/servers/tree/main/src/git)** — Tools to read and search Git repos.

## 🤝 Third-Party Servers

- [Brave Search](https://example.com/brave) - Web and local search via Brave.
"#;

    #[test]
    fn parse_readme_markdown_fixture() {
        let entrees = parser_readme_markdown(FIXTURE_README);
        let noms: Vec<&str> = entrees.iter().map(|e| e.nom.as_str()).collect();
        assert_eq!(noms, vec!["Filesystem", "Git", "Brave Search"]);

        // Les outils énumérés sous Filesystem sont rattachés à cette entrée,
        // dans l'ordre d'apparition.
        let outils: Vec<&str> = entrees[0]
            .outils
            .as_ref()
            .expect("Filesystem doit porter des outils")
            .iter()
            .map(|o| o.nom.as_str())
            .collect();
        assert_eq!(outils, vec!["read_file", "write_file", "list_directory"]);

        // Git n'énumère aucun outil → `outils: None`.
        assert!(entrees[1].outils.is_none());
    }

    #[test]
    fn json_invalide_renvoie_vide() {
        assert!(parser_registry_json("pas du json").is_empty());
        assert!(parser_registry_json("{\"autre\": 1}").is_empty());
    }
}
