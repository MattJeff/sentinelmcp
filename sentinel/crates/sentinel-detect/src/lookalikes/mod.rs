//! Détection de sosies (mode C registres) — agents 3.8 (lead) et 3.9 (similarité/SBOM).
//!
//! Architecture mode C :
//!   ConnecteurRegistres agrège N sources (trait SourceRegistre).
//!   Chaque source est interrogeable individuellement ou en bloc (interroger_tous).
//!   Les 4 sources prédéfinies sont des stubs v1 — les vraies requêtes HTTP arrivent en v2.
//!   SourceStatique permet l'injection de données de test sans réseau.

pub mod intra_inventory;
pub mod similarity;
pub mod sources;

/// Liste statique des scopes / paquets « officiellement reconnus » pour le
/// détecteur de sosies. Deux serveurs **tous les deux** dans cette
/// liste ne peuvent pas être un sosie l'un de l'autre — ce sont par
/// définition deux paquets officiels distincts.
///
/// Conservateur volontairement : on commence par les scopes et noms
/// vraiment publiés par les éditeurs reconnus du protocole MCP. Élargir
/// est trivial (ajouter un préfixe) ; rétrécir une fois déployé l'est
/// beaucoup moins. La règle : si l'éditeur peut signer cryptographiquement
/// la release et la publie sur npm sous un nom stable, c'est officiel.
const PREFIXES_SCOPES_OFFICIELS: &[&str] =
    &["@modelcontextprotocol/", "@anthropic-ai/"];

/// Noms exacts (hors scope) ajoutés à la main quand l'éditeur ne pousse
/// pas sous un scope npm — typiquement les utilitaires single-name
/// largement adoptés.
const PAQUETS_OFFICIELS_EXACTS: &[&str] = &["chrome-devtools-mcp"];

/// Renvoie `true` si `package_id` correspond à un paquet officiel
/// reconnu — utilisé par le détecteur de sosies pour court-circuiter la
/// comparaison entre deux entrées « officielles » qui partagent forcément
/// nom et description par construction (même paquet npm, même
/// `tools/list`).
///
/// `package_id` est l'identifiant canonique au sens de
/// `sentinel_protocol::extraire_package_id` (`@scope/pkg`, `pkg`,
/// `host:port`). On ne tolère pas de variation orthographique : matcher
/// `@modelcontextprotocoll/server-fetch` (typo-squat avec un l de trop)
/// **doit** retomber dans le détecteur, sinon on perdrait le signal qui
/// fait justement le cœur de la fonction.
pub fn est_paquet_officiel(package_id: &str) -> bool {
    if PAQUETS_OFFICIELS_EXACTS.contains(&package_id) {
        return true;
    }
    PREFIXES_SCOPES_OFFICIELS
        .iter()
        .any(|prefixe| package_id.starts_with(prefixe))
}

#[cfg(test)]
mod tests_allowlist {
    use super::est_paquet_officiel;

    #[test]
    fn scopes_officiels_reconnus() {
        assert!(est_paquet_officiel("@modelcontextprotocol/server-postgres"));
        assert!(est_paquet_officiel("@modelcontextprotocol/server-fetch"));
        assert!(est_paquet_officiel("@anthropic-ai/mcp"));
        assert!(est_paquet_officiel("chrome-devtools-mcp"));
    }

    #[test]
    fn typosquats_non_reconnus_comme_officiels() {
        // C'est précisément le cas que la fonction NE doit PAS valider :
        // un nom proche d'un officiel mais avec une typo ou un suffixe
        // hostile doit pouvoir continuer à matcher comme sosie.
        assert!(!est_paquet_officiel("filesystm-mcp"));
        assert!(!est_paquet_officiel("mcp-postgres-helper"));
        assert!(!est_paquet_officiel("mcp-brave-search-pro"));
        assert!(!est_paquet_officiel(
            "@modelcontextprotocoll/server-fetch"
        ));
        assert!(!est_paquet_officiel("@anthropic-ai-fake/mcp"));
    }
}

use std::sync::Arc;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Modèle de données
// ---------------------------------------------------------------------------

/// Signature compacte d'un outil exposé par un serveur MCP, utilisée pour
/// renforcer la détection de sosies lorsque le registre source publie le
/// schéma des outils. Permet de distinguer deux serveurs au nom proche en
/// comparant leurs signatures d'outils plutôt que la seule description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SignatureOutil {
    /// Nom de l'outil tel qu'exposé par le serveur MCP.
    pub nom: String,
    /// Valeurs `enum` rassemblées récursivement depuis l'`inputSchema` de
    /// l'outil, triées par ordre lexicographique et dédupliquées.
    pub enums_tries: Vec<String>,
    /// SHA-256 de la description de l'outil, tronqué aux 16 premiers
    /// caractères hexadécimaux. Chaîne vide si la description est absente.
    pub description_empreinte: String,
}

/// Entrée canonique issue d'un registre public MCP.
///
/// Le champ `outils` reste optionnel : les registres publics ne publient
/// généralement que `nom` + `description`. Quand le registre expose le
/// schéma des outils (ex. mcp-registry enrichi), le connecteur peut
/// remplir `outils` pour activer la corrélation par signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntreeRegistre {
    /// Identifiant court du registre source (ex. "pulsemcp", "smithery").
    pub registre: String,
    /// Nom du serveur tel qu'annoncé dans le registre.
    pub nom: String,
    /// Description courte du serveur, si publiée par le registre.
    pub description: Option<String>,
    /// Organisation ou individu ayant publié le serveur, si connu.
    pub auteur: Option<String>,
    /// URL de déploiement, page de registre ou dépôt du serveur.
    pub url: Option<String>,
    /// Signatures d'outils si le registre les expose. `None` si le
    /// registre ne porte que nom + description (cas le plus fréquent).
    pub outils: Option<Vec<SignatureOutil>>,
}

impl EntreeRegistre {
    /// Constructeur minimal pour les sources qui ne disposent que d'un
    /// nom et d'une description. Les autres champs sont initialisés à
    /// `None`. Garde les implémentations de `SourceRegistre` concises.
    pub fn depuis_nom_description(
        registre: impl Into<String>,
        nom: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            registre: registre.into(),
            nom: nom.into(),
            description: Some(description.into()),
            auteur: None,
            url: None,
            outils: None,
        }
    }
}

/// Construit une `SignatureOutil` à partir des champs publiés par un
/// serveur MCP pour un outil donné :
///
/// - parcours récursif de `input_schema` à la recherche de toutes les
///   listes `"enum": [...]` (les valeurs non-`String` sont ignorées),
/// - tri lexicographique + déduplication des valeurs collectées,
/// - SHA-256 de la description, tronqué aux 16 premiers caractères hex
///   (chaîne vide si la description est absente ou vide).
pub fn signature_outil_depuis_outil(
    nom: &str,
    description: Option<&str>,
    input_schema: &serde_json::Value,
) -> SignatureOutil {
    let mut enums = Vec::new();
    collecter_enums(input_schema, &mut enums);
    enums.sort();
    enums.dedup();

    let description_empreinte = match description {
        Some(desc) if !desc.is_empty() => {
            let mut hasher = Sha256::new();
            hasher.update(desc.as_bytes());
            let hex = hex::encode(hasher.finalize());
            hex[..16].to_string()
        }
        _ => String::new(),
    };

    SignatureOutil {
        nom: nom.to_string(),
        enums_tries: enums,
        description_empreinte,
    }
}

/// Parcourt récursivement un nœud JSON et ajoute à `sortie` toutes les
/// valeurs `String` rencontrées sous une clé `"enum"` portant un tableau.
fn collecter_enums(noeud: &serde_json::Value, sortie: &mut Vec<String>) {
    match noeud {
        serde_json::Value::Object(map) => {
            for (cle, valeur) in map {
                if cle == "enum" {
                    if let Some(tableau) = valeur.as_array() {
                        for element in tableau {
                            if let Some(s) = element.as_str() {
                                sortie.push(s.to_string());
                            }
                        }
                    }
                }
                // Continue la descente même sous la clé "enum" pour
                // capturer d'éventuels schémas imbriqués (rare mais
                // toléré par JSON Schema).
                collecter_enums(valeur, sortie);
            }
        }
        serde_json::Value::Array(tableau) => {
            for element in tableau {
                collecter_enums(element, sortie);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Trait source
// ---------------------------------------------------------------------------

/// Contrat qu'implémente chaque connecteur de registre public.
pub trait SourceRegistre: Send + Sync {
    /// Renvoie la liste de toutes les entrées exposées par ce registre.
    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>>;

    /// Nom court du registre (pour audit et corrélation).
    fn nom(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Connecteur principal
// ---------------------------------------------------------------------------

/// Agrège plusieurs sources de registres et les interroge en parallèle ou par nom.
pub struct ConnecteurRegistres {
    pub sources: Vec<Arc<dyn SourceRegistre>>,
}

impl ConnecteurRegistres {
    /// Crée un connecteur vide — ajouter des sources via `ajouter`.
    pub fn nouveau() -> Self {
        Self { sources: Vec::new() }
    }

    /// Ajoute une source au connecteur.
    pub fn ajouter(&mut self, source: Arc<dyn SourceRegistre>) {
        self.sources.push(source);
    }

    /// Interroge une seule source identifiée par son nom court.
    /// Retourne une erreur si aucune source ne correspond au nom fourni.
    pub async fn interroger(&self, nom_registre: &str) -> anyhow::Result<Vec<EntreeRegistre>> {
        for source in &self.sources {
            if source.nom() == nom_registre {
                return source.lister().await;
            }
        }
        anyhow::bail!("registre inconnu : {}", nom_registre)
    }

    /// Interroge toutes les sources en parallèle et retourne leurs résultats
    /// (même en cas d'erreur partielle).
    ///
    /// Fan-out borné par un timeout global de 30 secondes : si l'ensemble
    /// dépasse ce délai, on retourne les résultats déjà collectés (Vec, jamais
    /// de panique). Les 4 sources étant peu nombreuses, on utilise
    /// `futures::future::join_all` plutôt qu'un `buffer_unordered` (pas de
    /// gain de streaming attendu). Le plafond de concurrence par source
    /// (5 détails en parallèle) est imposé en aval par L3/L4.
    pub async fn interroger_tous(&self) -> Vec<(String, anyhow::Result<Vec<EntreeRegistre>>)> {
        use std::sync::Mutex as StdMutex;
        use std::time::Duration;

        // Collecteur partagé : chaque future y pousse son résultat dès qu'elle
        // termine. En cas d'expiration du timeout global, on récupère ce qui a
        // déjà été produit sans rien perdre.
        let collecteur: Arc<StdMutex<Vec<(String, anyhow::Result<Vec<EntreeRegistre>>)>>> =
            Arc::new(StdMutex::new(Vec::with_capacity(self.sources.len())));

        let futures_iter = self.sources.iter().map(|source| {
            let nom = source.nom().to_string();
            let collecteur = Arc::clone(&collecteur);
            let fut = source.lister();
            async move {
                let res = fut.await;
                if let Ok(mut guard) = collecteur.lock() {
                    guard.push((nom, res));
                }
            }
        });

        let fanout = futures::future::join_all(futures_iter);
        // On ignore volontairement le résultat de `timeout` : qu'on termine
        // dans le délai ou non, on récupère le contenu du collecteur partagé.
        let _ = tokio::time::timeout(Duration::from_secs(30), fanout).await;

        // Mutex potentiellement empoisonné si une tâche de fan-out a paniqué :
        // on récupère malgré tout les données déjà collectées plutôt que de propager le panic.
        let mut guard = collecteur.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *guard)
    }
}

// ---------------------------------------------------------------------------
// Sources prédéfinies (stubs v1 — appels HTTP en v2)
// ---------------------------------------------------------------------------

/// Connecteur vers PulseMCP (https://pulsemcp.com/api).
/// V1 : stub sans appel réseau. V2 : GET /api/servers avec pagination.
pub struct SourcePulseMCP;

impl SourcePulseMCP {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourcePulseMCP {
    fn nom(&self) -> &'static str {
        "pulsemcp"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move { Ok(sources::pulsemcp::lister_serveurs().await) })
    }
}

/// Connecteur vers le registre officiel MCP (https://github.com/modelcontextprotocol/servers).
///
/// Implémentation : tente d'abord le fichier `registry.json` à la racine
/// du dépôt (URL « raw »), puis bascule sur l'API GitHub renvoyant le
/// `README.md` (parsing Markdown des entrées de liste) si le premier
/// renvoie 404. Toute autre défaillance produit un Vec vide pour ne pas
/// bloquer la collecte multi-registres (cf. `sources::mcp_registry`).
pub struct SourceMcpRegistry;

impl SourceMcpRegistry {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourceMcpRegistry {
    fn nom(&self) -> &'static str {
        "mcp-registry"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move { Ok(sources::mcp_registry::lister_serveurs().await) })
    }
}

/// Connecteur vers Smithery (https://smithery.ai).
/// Délègue à `sources::smithery::lister_serveurs` qui interroge
/// `https://registry.smithery.ai/servers?page_size=100` et retourne un
/// Vec vide en cas d'erreur réseau ou de payload inattendu.
pub struct SourceSmithery;

impl SourceSmithery {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourceSmithery {
    fn nom(&self) -> &'static str {
        "smithery"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move { Ok(sources::smithery::lister_serveurs().await) })
    }
}

/// Connecteur vers mcp.so (https://mcp.so).
/// Délègue à `sources::mcpso::lister_serveurs` qui interroge
/// `https://mcp.so/api/servers?limit=100` et retourne un Vec vide en
/// cas d'erreur réseau ou de payload inattendu.
pub struct SourceMcpSo;

impl SourceMcpSo {
    pub fn nouveau() -> Arc<dyn SourceRegistre> {
        Arc::new(Self)
    }
}

impl SourceRegistre for SourceMcpSo {
    fn nom(&self) -> &'static str {
        "mcp.so"
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        Box::pin(async move { Ok(sources::mcpso::lister_serveurs().await) })
    }
}

// ---------------------------------------------------------------------------
// Source statique — injection de test
// ---------------------------------------------------------------------------

/// Source de test injectable : retourne des entrées fixées à la construction.
/// Permet de tester ConnecteurRegistres sans réseau.
pub struct SourceStatique {
    pub nom: &'static str,
    pub entrees: Vec<EntreeRegistre>,
}

impl SourceStatique {
    pub fn nouveau(nom: &'static str, entrees: Vec<EntreeRegistre>) -> Arc<dyn SourceRegistre> {
        Arc::new(Self { nom, entrees })
    }
}

impl SourceRegistre for SourceStatique {
    fn nom(&self) -> &'static str {
        self.nom
    }

    fn lister(&self) -> BoxFuture<'_, anyhow::Result<Vec<EntreeRegistre>>> {
        let entrees = self.entrees.clone();
        Box::pin(async move { Ok(entrees) })
    }
}

// ---------------------------------------------------------------------------
// Tests internes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn depuis_nom_description_remplit_les_optionnels_a_none() {
        let entree = EntreeRegistre::depuis_nom_description(
            "pulsemcp",
            "filesystem-server",
            "accès au système de fichiers",
        );
        assert_eq!(entree.registre, "pulsemcp");
        assert_eq!(entree.nom, "filesystem-server");
        assert_eq!(
            entree.description.as_deref(),
            Some("accès au système de fichiers")
        );
        assert!(entree.auteur.is_none());
        assert!(entree.url.is_none());
        assert!(entree.outils.is_none());
    }

    #[test]
    fn signature_outil_collecte_et_trie_les_enums() {
        let schema = json!({
            "type": "object",
            "properties": {
                "mode": { "type": "string", "enum": ["read", "write", "append"] },
                "format": { "type": "string", "enum": ["json", "yaml", "json"] }
            }
        });
        let sig = signature_outil_depuis_outil("fs.open", Some("ouvre un fichier"), &schema);
        assert_eq!(sig.nom, "fs.open");
        // Tri lexicographique et déduplication ("json" deux fois → une seule entrée)
        assert_eq!(
            sig.enums_tries,
            vec![
                "append".to_string(),
                "json".to_string(),
                "read".to_string(),
                "write".to_string(),
                "yaml".to_string(),
            ]
        );
        // SHA-256 attendu (16 premiers caractères hex)
        let mut hasher = Sha256::new();
        hasher.update(b"ouvre un fichier");
        let attendu = hex::encode(hasher.finalize());
        assert_eq!(sig.description_empreinte, attendu[..16]);
    }

    #[test]
    fn signature_outil_descend_dans_les_sous_schemas() {
        let schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": { "enum": ["alpha", "beta"] }
                        }
                    }
                }
            }
        });
        let sig = signature_outil_depuis_outil("nested", None, &schema);
        assert_eq!(sig.enums_tries, vec!["alpha".to_string(), "beta".to_string()]);
        // Description absente → empreinte vide
        assert_eq!(sig.description_empreinte, "");
    }

    #[test]
    fn signature_outil_ignore_les_enums_non_string() {
        let schema = json!({
            "properties": {
                "level": { "enum": [1, 2, 3, "high"] }
            }
        });
        let sig = signature_outil_depuis_outil("mix", Some(""), &schema);
        // Seules les chaînes sont conservées
        assert_eq!(sig.enums_tries, vec!["high".to_string()]);
        // Description vide → empreinte vide
        assert_eq!(sig.description_empreinte, "");
    }

    #[test]
    fn entree_registre_serialise_en_json() {
        let entree = EntreeRegistre {
            registre: "mcp-registry".to_string(),
            nom: "demo".to_string(),
            description: Some("demo server".to_string()),
            auteur: Some("anthropic".to_string()),
            url: Some("https://example.invalid/demo".to_string()),
            outils: Some(vec![SignatureOutil {
                nom: "echo".to_string(),
                enums_tries: vec!["a".to_string(), "b".to_string()],
                description_empreinte: "0123456789abcdef".to_string(),
            }]),
        };
        let json = serde_json::to_value(&entree).expect("sérialisation ok");
        assert_eq!(json["registre"], "mcp-registry");
        assert_eq!(json["outils"][0]["nom"], "echo");
        // Aller-retour serde
        let retour: EntreeRegistre = serde_json::from_value(json).expect("désérialisation ok");
        assert_eq!(retour, entree);
    }
}
