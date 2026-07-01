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
// Connecteur par défaut, agrégation multi-registres et cache disque
// ---------------------------------------------------------------------------

use sentinel_store::registry_cache::CacheRegistres;
use tracing::warn;

/// TTL par défaut du cache disque des registres : 24 heures. Au-delà, une
/// entrée est considérée périmée et déclenche une nouvelle interrogation
/// réseau (le cache périmé reste néanmoins servi en mode hors-ligne si le
/// réseau est indisponible — cf. [`interroger_source_avec_cache`]).
pub const TTL_CACHE_REGISTRES_SECS: i64 = 24 * 3600;

/// Construit un [`ConnecteurRegistres`] peuplé des sources publiques **vivantes** :
/// le registre officiel MCP (`registry.modelcontextprotocol.io`) et Smithery
/// (`registry.smithery.ai`). C'est le point d'entrée standard pour alimenter le
/// benchmark de sosies.
///
/// PulseMCP et mcp.so sont volontairement EXCLUS : leurs APIs publiques ne sont
/// plus disponibles (PulseMCP `/v0*` → 404/410 Gone ; mcp.so `/api/servers` ne
/// renvoie plus de JSON). Les interroger ne produisait que des `Vec` vides et du
/// bruit de log à chaque scan, en plus de ~6 s de timeout réseau gaspillées. Les
/// connecteurs [`SourcePulseMCP`]/[`SourceMcpSo`] restent disponibles pour un
/// usage explicite si ces registres réexposent une API.
pub fn connecteur_par_defaut() -> ConnecteurRegistres {
    let mut connecteur = ConnecteurRegistres::nouveau();
    connecteur.ajouter(SourceMcpRegistry::nouveau());
    connecteur.ajouter(SourceSmithery::nouveau());
    connecteur
}

/// Agrège les registres publics vivants (registre officiel MCP + Smithery) en
/// une liste **dédupliquée** d'`EntreeRegistre`, interrogés en parallèle
/// (fan-out borné par le timeout global de [`ConnecteurRegistres::interroger_tous`]).
///
/// Robustesse : tout registre en échec contribue zéro entrée (jamais de
/// panique, jamais d'erreur propagée) — la liste agrège simplement ce qui a
/// pu être collecté. Sans réseau, renvoie un Vec vide.
pub async fn lister_tous_les_serveurs() -> Vec<EntreeRegistre> {
    let connecteur = connecteur_par_defaut();
    let resultats = connecteur.interroger_tous().await;
    let toutes: Vec<EntreeRegistre> = resultats
        .into_iter()
        .flat_map(|(_, res)| res.unwrap_or_default())
        .collect();
    dedupliquer(toutes)
}

/// Variante **cache-aware** de [`lister_tous_les_serveurs`] : chaque registre
/// est servi depuis le cache disque `cache` s'il est frais (âge < `ttl_secs`),
/// sinon interrogé sur le réseau puis remis en cache. En cas d'échec réseau,
/// un cache périmé (s'il existe) est servi en dégradé — permettant un mode
/// hors-ligne. Le résultat agrégé est dédupliqué.
///
/// `ttl_secs` recommandé : [`TTL_CACHE_REGISTRES_SECS`].
pub async fn lister_tous_les_serveurs_avec_cache(
    cache: &CacheRegistres,
    ttl_secs: i64,
) -> Vec<EntreeRegistre> {
    let connecteur = connecteur_par_defaut();
    let mut toutes = Vec::new();
    for source in &connecteur.sources {
        let entrees = interroger_source_avec_cache(cache, source, ttl_secs).await;
        toutes.extend(entrees);
    }
    dedupliquer(toutes)
}

/// Interroge une source unique en passant par le cache disque, avec garantie
/// de non-panique :
///
/// 1. cache frais (< `ttl_secs`) → désérialisé et renvoyé **sans réseau** ;
/// 2. sinon la source est interrogée ; un résultat non vide est remis en
///    cache (écriture best-effort, jamais fatale) puis renvoyé ;
/// 3. si la source échoue (Vec vide), un cache périmé éventuel est servi en
///    dégradé (mode hors-ligne) ; à défaut, Vec vide.
///
/// Le payload est stocké en JSON sérialisé (`Vec<EntreeRegistre>`). Exposé
/// pour permettre des tests hors-ligne du comportement de cache via une
/// [`SourceStatique`] et un cache `:memory:`.
pub async fn interroger_source_avec_cache(
    cache: &CacheRegistres,
    source: &Arc<dyn SourceRegistre>,
    ttl_secs: i64,
) -> Vec<EntreeRegistre> {
    let nom = source.nom();

    // 1. Cache frais → service direct, sans toucher au réseau.
    if cache.est_frais(nom, ttl_secs).unwrap_or(false) {
        if let Ok(Some((payload, _))) = cache.lire(nom) {
            if let Ok(entrees) = serde_json::from_slice::<Vec<EntreeRegistre>>(&payload) {
                return entrees;
            }
        }
    }

    // 2. Interrogation de la source (réseau, ou données injectées en test).
    let entrees = source.lister().await.unwrap_or_default();
    if !entrees.is_empty() {
        match serde_json::to_vec(&entrees) {
            Ok(bytes) => {
                if let Err(e) = cache.ecrire(nom, &bytes) {
                    warn!(registre = nom, erreur = %e, "registres : écriture du cache impossible");
                }
            }
            Err(e) => {
                warn!(registre = nom, erreur = %e, "registres : sérialisation pour le cache impossible")
            }
        }
        return entrees;
    }

    // 3. Échec → service d'un cache périmé si présent (mode hors-ligne dégradé).
    if let Ok(Some((payload, _))) = cache.lire(nom) {
        if let Ok(entrees) = serde_json::from_slice::<Vec<EntreeRegistre>>(&payload) {
            warn!(
                registre = nom,
                "registres : interrogation infructueuse, service du cache périmé"
            );
            return entrees;
        }
    }

    Vec::new()
}

/// Déduplique une liste d'`EntreeRegistre` agrégée depuis plusieurs registres.
///
/// Clé de déduplication : le **nom normalisé** (minuscules, espaces de bord
/// rognés). Un même serveur publié sur plusieurs registres (donc au nom
/// identique) est fusionné en une seule entrée ; on conserve la plus riche
/// (présence d'outils prioritaire, puis d'une description non vide). L'ordre
/// de première apparition des clés est préservé pour un résultat
/// déterministe. Les entrées au nom vide sont ignorées.
///
/// Choix volontairement conservateur : on ne fusionne que les noms
/// **exactement** identiques (après normalisation). Les variantes proches
/// (typosquats) restent distinctes — c'est précisément le signal que le
/// benchmark de sosies cherche à exploiter.
fn dedupliquer(entrees: Vec<EntreeRegistre>) -> Vec<EntreeRegistre> {
    use std::collections::HashMap;

    let mut ordre: Vec<String> = Vec::new();
    let mut par_cle: HashMap<String, EntreeRegistre> = HashMap::new();

    for entree in entrees {
        let cle = entree.nom.trim().to_lowercase();
        if cle.is_empty() {
            continue;
        }
        match par_cle.get_mut(&cle) {
            Some(existante) => {
                if richesse(&entree) > richesse(existante) {
                    *existante = entree;
                }
            }
            None => {
                ordre.push(cle.clone());
                par_cle.insert(cle, entree);
            }
        }
    }

    ordre
        .into_iter()
        .filter_map(|cle| par_cle.remove(&cle))
        .collect()
}

/// Score d'information d'une entrée : +2 si elle porte des outils non vides,
/// +1 si elle porte une description non vide. Sert d'arbitre lors de la
/// déduplication de deux entrées au même nom.
fn richesse(entree: &EntreeRegistre) -> u8 {
    let mut score = 0;
    if entree.outils.as_ref().is_some_and(|o| !o.is_empty()) {
        score += 2;
    }
    if entree.description.as_ref().is_some_and(|d| !d.is_empty()) {
        score += 1;
    }
    score
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

    // -----------------------------------------------------------------------
    // Déduplication et cache (entièrement hors-ligne)
    // -----------------------------------------------------------------------

    use std::path::PathBuf;

    /// Fabrique une entrée de test concise.
    fn entree(
        nom: &str,
        registre: &str,
        desc: Option<&str>,
        avec_outils: bool,
    ) -> EntreeRegistre {
        EntreeRegistre {
            registre: registre.to_string(),
            nom: nom.to_string(),
            description: desc.map(|s| s.to_string()),
            auteur: None,
            url: None,
            outils: if avec_outils {
                Some(vec![SignatureOutil {
                    nom: "t".to_string(),
                    enums_tries: vec![],
                    description_empreinte: String::new(),
                }])
            } else {
                None
            },
        }
    }

    #[test]
    fn dedup_fusionne_les_noms_identiques_en_gardant_le_plus_riche() {
        let toutes = vec![
            entree("github-mcp", "pulsemcp", None, false),
            // Même nom (à la casse près), entrée plus riche : doit l'emporter.
            entree("Github-MCP", "smithery", Some("desc"), true),
            entree("filesystem", "mcp.so", Some("fs"), false),
        ];
        let dedup = dedupliquer(toutes);
        assert_eq!(dedup.len(), 2);

        let gh = dedup
            .iter()
            .find(|e| e.nom.eq_ignore_ascii_case("github-mcp"))
            .unwrap();
        assert_eq!(gh.registre, "smithery");
        assert!(gh.outils.is_some());

        // Ordre de première apparition des clés préservé.
        assert!(dedup[0].nom.eq_ignore_ascii_case("github-mcp"));
        assert_eq!(dedup[1].nom, "filesystem");
    }

    #[test]
    fn dedup_ignore_les_noms_vides() {
        let toutes = vec![
            entree("   ", "x", None, false),
            entree("ok", "x", None, false),
        ];
        assert_eq!(dedupliquer(toutes).len(), 1);
    }

    #[test]
    fn dedup_conserve_les_variantes_proches() {
        // Un typosquat ne doit PAS être fusionné avec l'original.
        let toutes = vec![
            entree("github-mcp", "pulsemcp", None, false),
            entree("github-mcpp", "mcp.so", None, false),
        ];
        assert_eq!(dedupliquer(toutes).len(), 2);
    }

    #[tokio::test]
    async fn cache_sert_le_frais_sans_reinterroger_la_source() {
        let cache = CacheRegistres::nouveau(PathBuf::from(":memory:")).unwrap();
        let source_pleine =
            SourceStatique::nouveau("reg", vec![entree("a", "reg", Some("d"), false)]);

        // 1er appel : miss → interrogation de la source → mise en cache.
        let r1 = interroger_source_avec_cache(&cache, &source_pleine, 3600).await;
        assert_eq!(r1.len(), 1);

        // 2e appel avec une source VIDE (simulant un réseau ko) mais cache
        // frais → on sert le cache sans interroger la source.
        let source_vide = SourceStatique::nouveau("reg", vec![]);
        let r2 = interroger_source_avec_cache(&cache, &source_vide, 3600).await;
        assert_eq!(r2.len(), 1);
        assert_eq!(r2[0].nom, "a");
    }

    #[tokio::test]
    async fn cache_perime_servi_en_mode_hors_ligne() {
        let cache = CacheRegistres::nouveau(PathBuf::from(":memory:")).unwrap();
        let source_pleine =
            SourceStatique::nouveau("reg", vec![entree("a", "reg", Some("d"), false)]);

        // Remplit le cache.
        let _ = interroger_source_avec_cache(&cache, &source_pleine, 3600).await;

        // ttl = 0 → jamais frais ; source vide (réseau ko) → repli sur le
        // cache périmé.
        let source_vide = SourceStatique::nouveau("reg", vec![]);
        let r = interroger_source_avec_cache(&cache, &source_vide, 0).await;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].nom, "a");
    }

    #[tokio::test]
    async fn aucun_cache_et_source_vide_renvoie_vide() {
        let cache = CacheRegistres::nouveau(PathBuf::from(":memory:")).unwrap();
        let source_vide = SourceStatique::nouveau("reg", vec![]);
        let r = interroger_source_avec_cache(&cache, &source_vide, 3600).await;
        assert!(r.is_empty());
    }
}
