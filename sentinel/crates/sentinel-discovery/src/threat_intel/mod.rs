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
}

impl Default for FluxMenaces {
    fn default() -> Self {
        Self::par_defaut()
    }
}
