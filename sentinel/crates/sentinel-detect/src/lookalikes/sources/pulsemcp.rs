//! Implémentation HTTP du connecteur PulseMCP.
//!
//! Interroge l'API publique `https://api.pulsemcp.com/v0/servers?count_per_page=100`
//! et convertit chaque entrée en `EntreeRegistre`. Pour chaque entrée
//! disposant d'un `slug` (ou à défaut d'un `id`), un appel de détail
//! `{base}/v0/servers/{slug}` est tenté afin d'enrichir l'entrée avec sa
//! liste d'outils (`tools` ou `tools_supported`). Les appels de détail
//! sont concurrents avec un parallélisme maximal de 5 et un budget total
//! de 30 secondes (listing + enrichissement). Toute erreur réseau,
//! statut non-2xx ou payload invalide est silencieusement absorbée :
//! l'entrée garde alors `outils: None`.
//!
//! En cas d'erreur sur la requête de liste, retourne un Vec vide avec un
//! log d'avertissement (pas de propagation d'erreur — la collecte
//! multi-registres ne doit pas être bloquée par la défaillance d'un
//! registre).

use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::Deserialize;
use tracing::warn;

use crate::lookalikes::{EntreeRegistre, SignatureOutil};

/// URL par défaut de l'API publique PulseMCP.
pub const PULSEMCP_DEFAULT_URL: &str = "https://api.pulsemcp.com/v0/servers?count_per_page=100";

/// Timeout HTTP appliqué à la requête de liste (cf. spec : 6 s).
const TIMEOUT_REQUETE: Duration = Duration::from_secs(6);

/// Timeout HTTP appliqué à chaque requête de détail (spec : 3 s).
const TIMEOUT_DETAIL: Duration = Duration::from_secs(3);

/// Budget total pour la phase liste + enrichissement (spec : 30 s).
const BUDGET_GLOBAL: Duration = Duration::from_secs(30);

/// Parallélisme maximal pour les appels de détail.
const PARALLELISME_DETAIL: usize = 5;

/// Représentation brute d'un serveur PulseMCP.
/// On lit uniquement les champs utiles à `EntreeRegistre` ; les inconnus
/// sont ignorés (serde ne signale pas d'erreur sur champs supplémentaires).
#[derive(Debug, Deserialize)]
struct ServeurPulse {
    #[serde(default)]
    name: String,
    #[serde(default)]
    short_description: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    id: Option<String>,
}

/// Enveloppe de la réponse PulseMCP.
#[derive(Debug, Deserialize)]
struct ReponsePulse {
    #[serde(default)]
    servers: Vec<ServeurPulse>,
}

/// Payload minimal renvoyé par l'endpoint de détail. On lit les deux
/// noms de champ rencontrés en pratique (`tools` et `tools_supported`).
#[derive(Debug, Deserialize)]
struct DetailPulse {
    #[serde(default)]
    tools: Option<Vec<OutilDetail>>,
    #[serde(default)]
    tools_supported: Option<Vec<OutilDetail>>,
}

/// Représentation tolérante d'un outil : la valeur peut être une simple
/// chaîne (`"foo"`) ou un objet contenant un champ `name`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OutilDetail {
    Nom(String),
    Objet {
        #[serde(default)]
        name: Option<String>,
    },
}

impl OutilDetail {
    fn nom(self) -> Option<String> {
        match self {
            OutilDetail::Nom(s) if !s.is_empty() => Some(s),
            OutilDetail::Objet { name: Some(n) } if !n.is_empty() => Some(n),
            _ => None,
        }
    }
}

/// Récupère la liste des serveurs PulseMCP depuis l'URL par défaut.
pub async fn lister_serveurs() -> Vec<EntreeRegistre> {
    lister_serveurs_depuis(PULSEMCP_DEFAULT_URL).await
}

/// Variante paramétrable de `lister_serveurs` — utilisée par les tests
/// d'intégration pour pointer vers un serveur wiremock.
pub async fn lister_serveurs_depuis(url: &str) -> Vec<EntreeRegistre> {
    match tokio::time::timeout(BUDGET_GLOBAL, lister_et_enrichir(url)).await {
        Ok(entrees) => entrees,
        Err(_) => {
            warn!(url = %url, "pulsemcp : budget global dépassé");
            Vec::new()
        }
    }
}

/// Boucle interne : liste puis enrichit, sous le budget global.
async fn lister_et_enrichir(url: &str) -> Vec<EntreeRegistre> {
    let client_liste = match reqwest::Client::builder().timeout(TIMEOUT_REQUETE).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "pulsemcp : impossible de construire le client HTTP");
            return Vec::new();
        }
    };

    let reponse = match client_liste.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(erreur = %e, url = %url, "pulsemcp : échec de la requête HTTP");
            return Vec::new();
        }
    };

    if !reponse.status().is_success() {
        warn!(statut = %reponse.status(), url = %url, "pulsemcp : statut HTTP non-2xx");
        return Vec::new();
    }

    let corps: ReponsePulse = match reponse.json().await {
        Ok(c) => c,
        Err(e) => {
            warn!(erreur = %e, "pulsemcp : payload JSON invalide");
            return Vec::new();
        }
    };

    let base = base_depuis_url(url);

    // Client dédié aux requêtes de détail, avec son propre timeout.
    let client_detail = reqwest::Client::builder()
        .timeout(TIMEOUT_DETAIL)
        .build()
        .ok();

    // Prépare les entrées de base puis enrichit en parallèle.
    let entrees: Vec<(EntreeRegistre, Option<String>)> = corps
        .servers
        .into_iter()
        .map(|s| {
            let slug = s.slug.clone().or_else(|| s.id.clone());
            let entree = EntreeRegistre {
                registre: "pulsemcp".to_string(),
                nom: s.name,
                description: s.short_description,
                auteur: None,
                url: None,
                outils: None,
            };
            (entree, slug)
        })
        .collect();

    // Sans base ni client de détail, on renvoie tel quel.
    let (base, client_detail) = match (base, client_detail) {
        (Some(b), Some(c)) => (b, c),
        _ => return entrees.into_iter().map(|(e, _)| e).collect(),
    };

    let resultats: Vec<EntreeRegistre> = stream::iter(entrees.into_iter())
        .map(|(mut entree, slug)| {
            let base = base.clone();
            let client = client_detail.clone();
            async move {
                if let Some(slug) = slug {
                    if let Some(outils) = recuperer_outils(&client, &base, &slug).await {
                        entree.outils = Some(outils);
                    }
                }
                entree
            }
        })
        .buffer_unordered(PARALLELISME_DETAIL)
        .collect()
        .await;

    resultats
}

/// Extrait la base d'URL (`https://host[:port]`) à partir d'une URL
/// pointant vers `/v0/servers...`. Renvoie `None` si l'URL ne contient
/// pas le segment attendu — auquel cas l'enrichissement est sauté.
fn base_depuis_url(url: &str) -> Option<String> {
    let (base, _) = url.split_once("/v0/")?;
    Some(base.to_string())
}

/// Appelle l'endpoint de détail et extrait la liste d'outils. Toute
/// erreur (réseau, statut non-2xx, JSON invalide, liste vide) est
/// silencieusement absorbée → renvoie `None`.
async fn recuperer_outils(
    client: &reqwest::Client,
    base: &str,
    slug: &str,
) -> Option<Vec<SignatureOutil>> {
    let url = format!("{base}/v0/servers/{slug}");
    let reponse = client.get(&url).send().await.ok()?;
    if !reponse.status().is_success() {
        return None;
    }
    let detail: DetailPulse = reponse.json().await.ok()?;

    let bruts = detail.tools.or(detail.tools_supported)?;
    let outils: Vec<SignatureOutil> = bruts
        .into_iter()
        .filter_map(OutilDetail::nom)
        .map(|nom| SignatureOutil {
            nom,
            enums_tries: vec![],
            description_empreinte: String::new(),
        })
        .collect();

    if outils.is_empty() {
        None
    } else {
        Some(outils)
    }
}
