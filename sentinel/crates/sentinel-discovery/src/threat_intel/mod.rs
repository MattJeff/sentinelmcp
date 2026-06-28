//! Threat intelligence feed for Sentinel.
//!
//! This module ships a curated, versioned list of known-bad MCP packages,
//! lookalike / typo-squat names, documented poisoning incidents, rug-pull
//! demos, and maintainer-revoked packages. The feed is bundled at compile
//! time via [`include_str!`] from `data/threat_feed.yaml`, so the desktop
//! binary always has an offline baseline even when network feeds are
//! unreachable.
//!
//! The main entry point is [`FluxMenaces::par_defaut`], which loads the
//! bundled YAML. To check a discovered MCP server, call
//! [`FluxMenaces::correspondances`]; it returns every matching threat
//! entry, allowing the UI to surface a red badge next to the offending
//! server.
//!
//! Matching today is performed by **exact package-name match** against
//! either the declared server name or any token that looks like a package
//! identifier inside the command-line arguments (e.g. the
//! `@modelcontextprotocol/server-filesystem` argument passed to `npx -y`).
//! This keeps false positives low while still catching the typical
//! `npx -y <package>` invocation pattern used by virtually every MCP
//! client.
//!
//! The feed format is intentionally simple YAML so non-Rust contributors
//! (security researchers) can edit it directly via a pull request.
//!
//! ## Refresh from a remote URL (V0.3)
//!
//! The bundled YAML remains the source of truth for the cold-boot,
//! offline-first fallback. On top of that, [`refresh`] provides an
//! optional cascade:
//!
//!   1. HTTP GET an operator-configured URL, validate the YAML, and write
//!      it to `<app-data>/threat_feed_cache.yaml` with a sibling
//!      `threat_feed_cache.meta.json` metadata file.
//!   2. If the network fetch fails, fall back to the on-disk cache when
//!      it is present.
//!   3. If the cache is missing or corrupt, fall back to the bundled
//!      [`FluxMenaces::par_defaut`].
//!
//! See [`refresh::charger_feed`] and [`refresh::rafraichir_feed`] for the
//! full contract.

use crate::model::ServeurMcpDeclare;
use serde::{Deserialize, Serialize};

pub mod refresh;

/// Bundled YAML feed. Updated by editing `data/threat_feed.yaml`.
const FEED_YAML: &str = include_str!("../../data/threat_feed.yaml");

/// One entry in the threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntreeMenace {
    /// Stable Sentinel identifier, e.g. `"MCP-2026-001"`.
    pub identifiant: String,
    /// Exact package name we will match against discovered MCP servers.
    pub package_name: String,
    /// Short, human-readable reason this package is flagged.
    pub raison: String,
    /// Severity: `"critical"`, `"high"`, or `"medium"`.
    pub severite: String,
    /// External references (SAFE-T1001, GHSA-…, "lookalike", etc.).
    #[serde(default)]
    pub references: Vec<String>,
    /// Date this entry was added to the feed.
    pub publie_a: chrono::NaiveDate,
}

/// Internal on-disk representation of the YAML file. `pub(crate)` so the
/// [`refresh`] submodule can reuse it when validating remote payloads.
#[derive(Debug, Deserialize)]
pub(crate) struct FluxYaml {
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) entries: Vec<EntreeMenace>,
}

/// Full threat intelligence feed, ready for lookups.
#[derive(Debug, Clone)]
pub struct FluxMenaces {
    pub entrees: Vec<EntreeMenace>,
    pub version_feed: String,
}

impl FluxMenaces {
    /// Loads the bundled YAML at compile time via [`include_str!`].
    ///
    /// Panics if the bundled feed is malformed — this is a build-time
    /// guarantee, since the YAML is shipped inside the binary.
    pub fn par_defaut() -> Self {
        let parsed: FluxYaml = serde_yaml::from_str(FEED_YAML)
            .expect("bundled threat_feed.yaml must parse cleanly");
        Self {
            entrees: parsed.entries,
            version_feed: parsed.version,
        }
    }

    /// Parse a raw YAML payload using the same shape as the bundled feed.
    ///
    /// Used by [`refresh::rafraichir_feed`] to validate remote responses
    /// and by [`refresh::charger_feed`] to rehydrate the on-disk cache.
    /// Returns an `Err` when the YAML is malformed or fails the
    /// non-empty/version invariants that the bundled feed satisfies.
    pub fn depuis_yaml(yaml: &str) -> Result<Self, refresh::ThreatFeedError> {
        let parsed: FluxYaml = serde_yaml::from_str(yaml)
            .map_err(|e| refresh::ThreatFeedError::Parse(e.to_string()))?;
        if parsed.version.trim().is_empty() {
            return Err(refresh::ThreatFeedError::Parse(
                "missing or empty `version` field".to_string(),
            ));
        }
        Ok(Self {
            entrees: parsed.entries,
            version_feed: parsed.version,
        })
    }

    /// Returns every threat entry that matches the supplied declared MCP
    /// server.
    ///
    /// A match is recorded when the package name appears either as the
    /// server's declared `nom`, or as a token inside its CLI arguments
    /// (typical for `npx -y <pkg>` / `uvx <pkg>` invocations).
    pub fn correspondances(&self, serveur: &ServeurMcpDeclare) -> Vec<&EntreeMenace> {
        // Build the set of candidate identifiers from the server.
        // We compare with exact equality only — no fuzzy matching here, to
        // keep the feed authoritative.
        let mut candidates: Vec<&str> = Vec::with_capacity(1 + serveur.args.len());
        candidates.push(serveur.nom.as_str());
        for a in &serveur.args {
            candidates.push(a.as_str());
        }

        self.entrees
            .iter()
            .filter(|entry| {
                candidates
                    .iter()
                    .any(|c| *c == entry.package_name.as_str())
            })
            .collect()
    }

    /// Variante **floue** de [`correspondances`](Self::correspondances)
    /// (D16) : rattrape les variantes de casse (`@ModelContextProtocol/…` vs
    /// `@modelcontextprotocol/…`) et les typos proches (distance de Levenshtein
    /// ≤ 2) d'un nom connu-mauvais, sans exploser les faux positifs.
    ///
    /// Trois paliers, du plus fort au plus faible :
    ///   1. **exact** (sensible à la casse) — `distance = 0`, `exact_casse` ;
    ///   2. **exact insensible à la casse** — `distance = 0` ;
    ///   3. **proche** — Levenshtein ≤ 2 sur les noms minusculisés.
    ///
    /// ## Faux positifs maîtrisés
    ///
    ///   * le palier flou (3) exige une **longueur minimale** ([`SEUIL_LONGUEUR_FLOU`])
    ///     pour ne pas matcher des labels courts (`fs`, `db`…) ;
    ///   * un paquet sous le **scope officiel** `@modelcontextprotocol/`
    ///     (orthographe et bornes exactes) est **exempté du palier flou** : le
    ///     paquet légitime `@modelcontextprotocol/server-filesystem` ne doit pas
    ///     être confondu avec le typo-squat `…/server-filesystem-1` (distance 2).
    ///     Il reste sujet aux paliers exacts si jamais le feed le listait ;
    ///   * au plus **une** correspondance par entrée du feed (la plus forte).
    pub fn correspondances_floues(
        &self,
        serveur: &ServeurMcpDeclare,
    ) -> Vec<CorrespondanceFloue<'_>> {
        let mut candidates: Vec<&str> = Vec::with_capacity(1 + serveur.args.len());
        candidates.push(serveur.nom.as_str());
        for a in &serveur.args {
            candidates.push(a.as_str());
        }

        let mut resultats: Vec<CorrespondanceFloue> = Vec::new();
        for entry in &self.entrees {
            let pkg = entry.package_name.as_str();
            let pkg_min = pkg.to_lowercase();

            // Meilleure correspondance trouvée pour cette entrée : (candidat,
            // distance, exact_casse). On préfère la plus petite distance et,
            // à égalité, le match sensible à la casse.
            let mut meilleur: Option<(String, u8, bool)> = None;

            for cand in &candidates {
                let c = *cand;

                // Palier 1 : exact sensible à la casse — imbattable.
                if c == pkg {
                    meilleur = Some((c.to_string(), 0, true));
                    break;
                }

                let c_min = c.to_lowercase();

                // Palier 2 : exact insensible à la casse.
                if c_min == pkg_min {
                    if meilleur.as_ref().map_or(true, |(_, d, _)| *d > 0) {
                        meilleur = Some((c.to_string(), 0, false));
                    }
                    continue;
                }

                // Palier 3 : proche (Levenshtein ≤ 2), avec garde-fous.
                if est_officiel_legitime(&c_min) {
                    continue;
                }
                let min_len = c_min.chars().count().min(pkg_min.chars().count());
                if min_len < SEUIL_LONGUEUR_FLOU {
                    continue;
                }
                let d = distance_levenshtein(&c_min, &pkg_min, 2);
                if (1..=2).contains(&d) {
                    let d = d as u8;
                    if meilleur.as_ref().map_or(true, |(_, bd, _)| d < *bd) {
                        meilleur = Some((c.to_string(), d, false));
                    }
                }
            }

            if let Some((candidat, distance, exact_casse)) = meilleur {
                resultats.push(CorrespondanceFloue {
                    entree: entry,
                    candidat,
                    distance,
                    exact_casse,
                });
            }
        }
        resultats
    }
}

/// Longueur minimale (en caractères) requise des deux côtés pour autoriser un
/// match flou (Levenshtein). En-dessous, le risque de faux positif est trop
/// élevé pour des libellés courts.
pub const SEUIL_LONGUEUR_FLOU: usize = 6;

/// Une correspondance floue entre un serveur déclaré et une entrée du feed.
#[derive(Debug, Clone)]
pub struct CorrespondanceFloue<'a> {
    /// L'entrée du feed qui a matché.
    pub entree: &'a EntreeMenace,
    /// Le token du serveur (nom ou argument) qui a déclenché le match.
    pub candidat: String,
    /// Distance de Levenshtein (0 = exact / casse seule).
    pub distance: u8,
    /// `true` si le match est exact **et** sensible à la casse.
    pub exact_casse: bool,
}

/// `true` si le candidat appartient au scope officiel `@modelcontextprotocol/`
/// (orthographe exacte). Sert d'allowlist structurelle pour exempter les
/// paquets officiels du matching flou (un typo-squat du scope ne passe pas).
fn est_officiel_legitime(candidat_min: &str) -> bool {
    candidat_min.starts_with("@modelcontextprotocol/")
}

/// Distance de Levenshtein bornée : retourne `plafond + 1` dès que la distance
/// dépasse `plafond` (sortie anticipée — on n'a pas besoin de la valeur exacte
/// au-delà du seuil). Opère sur les `char` (sûr en UTF-8).
fn distance_levenshtein(a: &str, b: &str, plafond: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    // |len(a) - len(b)| est un minorant de la distance.
    if n.abs_diff(m) > plafond {
        return plafond + 1;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut cur = vec![0usize; m + 1];
    for i in 1..=n {
        cur[0] = i;
        let mut min_ligne = cur[0];
        for j in 1..=m {
            let cout = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cout);
            min_ligne = min_ligne.min(cur[j]);
        }
        // Toute la ligne dépasse déjà le plafond → inutile de continuer.
        if min_ligne > plafond {
            return plafond + 1;
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[m]
}

impl Default for FluxMenaces {
    fn default() -> Self {
        Self::par_defaut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ServeurMcpDeclare;
    use sentinel_protocol::ScopeServeur;

    fn srv(nom: &str, args: &[&str]) -> ServeurMcpDeclare {
        ServeurMcpDeclare {
            nom: nom.to_string(),
            transport: "stdio".to_string(),
            commande: Some("npx".to_string()),
            args: args.iter().map(|s| s.to_string()).collect(),
            env_keys: vec![],
            url: None,
            disabled: false,
            scope: ScopeServeur::default(),
        }
    }

    #[test]
    fn floue_pas_de_faux_positif_sur_noms_legitimes_realistes() {
        // Faux positif proscrit : des noms de paquets MCP légitimes, proches en
        // longueur des entrées du feed, ne doivent PAS fuzzy-matcher.
        let flux = FluxMenaces::par_defaut();
        let legit = [
            "mcp-server-fetch",
            "mcp-server-git",
            "mcp-server-time",
            "mcp-server-sqlite",
            "mcp-server-postgres",
            "mcp-pdf-reader",
            "mcp-csv-writer",
            "mcp-time-tracker",
            "mcp-prompt-manager",
            "mcp-do-everywhere",
        ];
        for n in legit {
            let hits = flux.correspondances_floues(&srv(n, &[]));
            assert!(
                hits.is_empty(),
                "{n} ne doit pas fuzzy-matcher, vu : {:?}",
                hits.iter()
                    .map(|h| (h.entree.package_name.clone(), h.distance))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn distance_levenshtein_bornee_et_utf8() {
        // Déterminisme + sûreté UTF-8 + court-circuit du plafond.
        assert_eq!(distance_levenshtein("abc", "abc", 2), 0);
        assert_eq!(distance_levenshtein("abc", "abd", 2), 1);
        assert_eq!(distance_levenshtein("kitten", "sitting", 2), 3); // > plafond → plafond+1
        assert_eq!(distance_levenshtein("café", "cafe", 2), 1); // multibyte, pas de panic
        assert_eq!(distance_levenshtein("😀😀", "😀x", 2), 1);
    }
}
