//! Supply-chain attestation for declared MCP servers.
//!
//! For each [`ServeurMcpDeclare`], we try to pin down *what* will actually be
//! executed on the user's machine. The main case we cover today is npm
//! packages launched via `npx`: we resolve the package name (handling
//! `-y`/`--yes`/`--package` flags and the `@scope/name@version` syntax),
//! then talk to the public npm registry to verify the package exists, read
//! the published tarball integrity (a SHA-512 published by npm), the
//! current maintainers, the publish date, and weekly download count.
//!
//! The output is an [`AttestationSupplyChain`] which the UI/CLI can present
//! next to each server so the operator knows whether the dependency they
//! pulled is reputable, fresh, and pinned.
//!
//! Non-npm commands (Python `uvx`, absolute local binaries, git URLs…)
//! return [`EtatAttestation::NonNpm`] with a note — extending coverage to
//! those ecosystems is left to future versions.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::ServeurMcpDeclare;

/// The verdict we publish for one MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSupplyChain {
    /// `ServeurMcpDeclare::nom` — kept so callers can join the result back.
    pub serveur_nom: String,
    /// Resolved npm package name (e.g. `"@modelcontextprotocol/server-filesystem"`).
    pub package_name: Option<String>,
    /// Version requested by the config (after the `@` in `pkg@1.2.3`).
    pub version_requise: Option<String>,
    /// `dist-tags.latest` published on the registry.
    pub version_disponible: Option<String>,
    /// `versions[<latest>].dist.integrity` — npm publishes SHA-512.
    pub tarball_sha512: Option<String>,
    /// Maintainer names as published by npm.
    pub maintainers: Vec<String>,
    /// `time[<latest>]` — when `version_disponible` was published.
    pub publie_a: Option<DateTime<Utc>>,
    /// Downloads in the last week, via the npm downloads API.
    pub downloads_weekly: Option<u64>,
    /// Overall verdict.
    pub etat: EtatAttestation,
    /// Free-form notes (used for "non-npm-python", network errors, …).
    pub notes: Vec<String>,
}

/// Possible verdicts for an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtatAttestation {
    /// Package was found on npm and metadata fully resolved.
    Verifie,
    /// Registry replied 403/401 — the package is private (rare on public npm).
    PackagePrive,
    /// Registry replied 404 — typosquat candidate or unpublished package.
    PackageInconnu,
    /// Command does not resolve to an npm package (uvx, git, local binary…).
    NonNpm,
    /// Network/registry error (timeout, 5xx).
    ErreurReseau,
}

/// Async client for npm attestation.
#[derive(Debug, Clone)]
pub struct VerifierSupplyChain {
    pub client: reqwest::Client,
    pub timeout: Duration,
}

impl Default for VerifierSupplyChain {
    fn default() -> Self {
        Self::par_defaut()
    }
}

impl VerifierSupplyChain {
    /// Build with sensible defaults: 8 s timeout, a sentinel user-agent.
    pub fn par_defaut() -> Self {
        let timeout = Duration::from_secs(8);
        let client = reqwest::Client::builder()
            .user_agent("sentinel-mcp-supply-chain/0.1")
            .timeout(timeout)
            .build()
            .expect("reqwest client build");
        Self { client, timeout }
    }

    /// Same as [`par_defaut`] but lets callers point at a mock registry by
    /// supplying alternative base URLs (used by the test suite).
    pub fn avec_base_urls(client: reqwest::Client, timeout: Duration) -> Self {
        Self { client, timeout }
    }

    /// Run a supply-chain check on a single declared server.
    pub async fn attester(&self, serveur: &ServeurMcpDeclare) -> AttestationSupplyChain {
        self.attester_avec_endpoints(
            serveur,
            "https://registry.npmjs.org",
            "https://api.npmjs.org",
        )
        .await
    }

    /// Same as [`attester`] but takes explicit registry/downloads base URLs.
    /// This is the unit-testable entry point: tests pass a `wiremock` server URL.
    pub async fn attester_avec_endpoints(
        &self,
        serveur: &ServeurMcpDeclare,
        registry_base: &str,
        downloads_base: &str,
    ) -> AttestationSupplyChain {
        let mut att = AttestationSupplyChain {
            serveur_nom: serveur.nom.clone(),
            package_name: None,
            version_requise: None,
            version_disponible: None,
            tarball_sha512: None,
            maintainers: vec![],
            publie_a: None,
            downloads_weekly: None,
            etat: EtatAttestation::NonNpm,
            notes: vec![],
        };

        let Some(commande) = serveur.commande.as_deref() else {
            att.notes.push("no command on server entry".into());
            return att;
        };

        // 1. Classify the command.
        let kind = classer_commande(commande);
        match kind {
            CommandeKind::Npx => {}
            CommandeKind::Uvx => {
                att.etat = EtatAttestation::NonNpm;
                att.notes.push("non-npm-python".into());
                return att;
            }
            CommandeKind::LocalBinary => {
                att.etat = EtatAttestation::NonNpm;
                att.notes.push("local binary".into());
                return att;
            }
            CommandeKind::Autre => {
                att.etat = EtatAttestation::NonNpm;
                att.notes.push(format!("unsupported command: {commande}"));
                return att;
            }
        }

        // 2. Extract the npm package + optional pinned version from args.
        let Some((paquet, version_requise)) = extraire_paquet_npm(&serveur.args) else {
            att.etat = EtatAttestation::NonNpm;
            att.notes
                .push("could not extract npm package from npx args".into());
            return att;
        };
        att.package_name = Some(paquet.clone());
        att.version_requise = version_requise;

        // 3. Query the registry.
        let url_registry = format!(
            "{}/{}",
            registry_base.trim_end_matches('/'),
            url_encode_paquet(&paquet)
        );

        let resp = match self.client.get(&url_registry).send().await {
            Ok(r) => r,
            Err(e) => {
                att.etat = if e.is_timeout() {
                    EtatAttestation::ErreurReseau
                } else {
                    EtatAttestation::ErreurReseau
                };
                att.notes.push(format!("registry request failed: {e}"));
                return att;
            }
        };

        let status = resp.status();
        if status.as_u16() == 404 {
            att.etat = EtatAttestation::PackageInconnu;
            att.notes.push("registry 404".into());
            return att;
        }
        if status.as_u16() == 401 || status.as_u16() == 403 {
            att.etat = EtatAttestation::PackagePrive;
            att.notes.push(format!("registry refused ({status})"));
            return att;
        }
        if !status.is_success() {
            att.etat = EtatAttestation::ErreurReseau;
            att.notes.push(format!("registry status {status}"));
            return att;
        }

        let registry_json: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                att.etat = EtatAttestation::ErreurReseau;
                att.notes.push(format!("registry body parse: {e}"));
                return att;
            }
        };

        appliquer_metadata_registry(&mut att, &registry_json);

        // 4. Best-effort downloads call — never downgrade overall verdict on failure.
        let url_downloads = format!(
            "{}/downloads/point/last-week/{}",
            downloads_base.trim_end_matches('/'),
            url_encode_paquet(&paquet)
        );
        if let Ok(r) = self.client.get(&url_downloads).send().await {
            if r.status().is_success() {
                if let Ok(v) = r.json::<serde_json::Value>().await {
                    if let Some(n) = v.get("downloads").and_then(|x| x.as_u64()) {
                        att.downloads_weekly = Some(n);
                    }
                }
            }
        }

        att.etat = EtatAttestation::Verifie;
        att
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandeKind {
    Npx,
    Uvx,
    LocalBinary,
    Autre,
}

fn classer_commande(commande: &str) -> CommandeKind {
    let trimmed = commande.trim();
    // Absolute path → local binary.
    if trimmed.starts_with('/') || (trimmed.len() >= 2 && &trimmed[1..2] == ":") {
        return CommandeKind::LocalBinary;
    }
    let basename = std::path::Path::new(trimmed)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(trimmed);
    match basename {
        "npx" => CommandeKind::Npx,
        "uvx" => CommandeKind::Uvx,
        _ => CommandeKind::Autre,
    }
}

/// Walk through `npx` arguments and return the first positional argument that
/// is the package, plus an optional version after `@`. Recognises `-y`,
/// `--yes`, `-p`, `--package`, `--package=<v>`, `--quiet`, `--no-install`,
/// `--prefer-offline`, `--call`, `--workspace` flags.
pub fn extraire_paquet_npm(args: &[String]) -> Option<(String, Option<String>)> {
    let mut iter = args.iter().peekable();
    let value_flags = [
        "-p",
        "--package",
        "--call",
        "-c",
        "--workspace",
        "-w",
        "--node-options",
    ];
    let boolean_flags = [
        "-y",
        "--yes",
        "-n",
        "--no",
        "--quiet",
        "-q",
        "--no-install",
        "--prefer-offline",
        "--prefer-online",
        "--ignore-existing",
        "--shell-auto-fallback",
    ];

    while let Some(a) = iter.next() {
        if a == "--" {
            // Everything after `--` is for the package itself, not npx.
            return iter.next().cloned().map(separer_paquet_version);
        }
        if boolean_flags.contains(&a.as_str()) {
            continue;
        }
        if value_flags.contains(&a.as_str()) {
            // Consume the value too.
            iter.next();
            continue;
        }
        if a.starts_with("--") && a.contains('=') {
            // `--package=foo` → ignore as flag, but if the explicit `--package=<v>`
            // is set we treat it as the package candidate, otherwise skip.
            if let Some(rest) = a.strip_prefix("--package=") {
                return Some(separer_paquet_version(rest.to_string()));
            }
            continue;
        }
        if a.starts_with('-') {
            // Unknown flag — skip.
            continue;
        }
        // First positional wins.
        return Some(separer_paquet_version(a.clone()));
    }
    None
}

/// Splits `"@scope/name@1.2.3"` into `("@scope/name", Some("1.2.3"))`,
/// `"pkg@latest"` into `("pkg", Some("latest"))`, `"pkg"` into `("pkg", None)`.
fn separer_paquet_version(spec: String) -> (String, Option<String>) {
    // Scoped: starts with @ then has a `/`, then optional `@version`.
    if let Some(rest) = spec.strip_prefix('@') {
        // rest = "scope/name[@version]"
        if let Some(slash) = rest.find('/') {
            let after_slash = &rest[slash + 1..];
            if let Some(at) = after_slash.find('@') {
                let name = format!("@{}/{}", &rest[..slash], &after_slash[..at]);
                let version = after_slash[at + 1..].to_string();
                return (name, Some(version));
            }
            return (format!("@{rest}"), None);
        }
        // Bare "@something" — treat as name without version.
        return (format!("@{rest}"), None);
    }
    // Unscoped: split at first `@`.
    if let Some(at) = spec.find('@') {
        let (name, ver) = spec.split_at(at);
        return (name.to_string(), Some(ver[1..].to_string()));
    }
    (spec, None)
}

/// Percent-encodes the `/` in `@scope/name` to `%2F`, leaves the `@` alone
/// (npm registry accepts both, but `%2F` is the canonical form).
fn url_encode_paquet(p: &str) -> String {
    p.replace('/', "%2F")
}

fn appliquer_metadata_registry(att: &mut AttestationSupplyChain, body: &serde_json::Value) {
    let latest = body
        .pointer("/dist-tags/latest")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    if let Some(ref l) = latest {
        att.version_disponible = Some(l.clone());

        let version_path = format!("/versions/{}", l);
        if let Some(version_obj) = body.pointer(&version_path) {
            // dist.integrity (sha512-…). Some old packages only have dist.shasum (sha1).
            if let Some(int) = version_obj
                .pointer("/dist/integrity")
                .and_then(|v| v.as_str())
            {
                att.tarball_sha512 = Some(int.to_string());
            } else if let Some(shasum) = version_obj
                .pointer("/dist/shasum")
                .and_then(|v| v.as_str())
            {
                att.tarball_sha512 = Some(format!("sha1-{shasum}"));
            }
        }

        if let Some(t) = body.pointer(&format!("/time/{}", l)).and_then(|v| v.as_str()) {
            if let Ok(parsed) = DateTime::parse_from_rfc3339(t) {
                att.publie_a = Some(parsed.with_timezone(&Utc));
            }
        }
    }

    if let Some(arr) = body.get("maintainers").and_then(|v| v.as_array()) {
        att.maintainers = arr
            .iter()
            .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .collect();
    }
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic — no network).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn separe_scoped_avec_version() {
        let (n, v) = separer_paquet_version("@scope/pkg@1.2.3".to_string());
        assert_eq!(n, "@scope/pkg");
        assert_eq!(v.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn separe_unscoped_sans_version() {
        let (n, v) = separer_paquet_version("plain-pkg".to_string());
        assert_eq!(n, "plain-pkg");
        assert!(v.is_none());
    }

    #[test]
    fn extrait_paquet_avec_flags() {
        let args = vec![
            "-y".to_string(),
            "--prefer-offline".to_string(),
            "@scope/pkg@1.2.3".to_string(),
            "--server-arg".to_string(),
        ];
        let (n, v) = extraire_paquet_npm(&args).unwrap();
        assert_eq!(n, "@scope/pkg");
        assert_eq!(v.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn classifie_chemin_absolu_comme_local_binary() {
        assert_eq!(
            classer_commande("/usr/local/bin/my-mcp"),
            CommandeKind::LocalBinary
        );
        assert_eq!(classer_commande("npx"), CommandeKind::Npx);
        assert_eq!(classer_commande("uvx"), CommandeKind::Uvx);
        assert_eq!(classer_commande("docker"), CommandeKind::Autre);
    }
}
