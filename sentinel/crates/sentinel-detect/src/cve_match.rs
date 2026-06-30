//! Matching CVE/OSV hors-ligne pour serveurs MCP (D8).
//!
//! Une petite base EMBARQUÉE (`data/cve_mcp.json`, incluse via `include_str!`)
//! de vulnérabilités MCP connues, indexée par paquet + plage de versions. La
//! recherche est purement locale (zéro appel réseau) : c'est un filet de
//! sécurité « known-vulnerable package » exécutable hors-ligne.
//!
//! Comparaison de versions : semver simplifié `MAJOR.MINOR.PATCH` (préfixe `v`
//! et pré-release/build tolérés). Une version non interprétable n'est JAMAIS
//! signalée — on préfère un faux négatif à un faux positif sur un produit de
//! sécurité.

use chrono::Utc;
use once_cell::sync::Lazy;
use sentinel_protocol::{Constat, EtatConstat, ServeurId, Severite, TypeConstat};
use serde::Deserialize;
#[cfg(test)]
use uuid::Uuid;

/// Base JSON embarquée (source de vérité versionnée avec le crate).
const BASE_CVE_JSON: &str = include_str!("data/cve_mcp.json");

// ---------------------------------------------------------------------------
// Modèle de la base embarquée
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct EntreeCve {
    cve_id: String,
    /// Identités de paquet couvertes (telles que retournées par
    /// `extraire_package_id`). Plusieurs alias possibles.
    packages: Vec<String>,
    /// Borne basse incluse de la plage affectée (défaut `0.0.0`).
    #[serde(default)]
    introduced: Option<String>,
    /// Première version CORRIGÉE (borne haute exclue). `None` = toujours affecté.
    #[serde(default)]
    fixed: Option<String>,
    cvss: f64,
    resume: String,
    #[serde(default)]
    references: Vec<String>,
}

/// Base parsée une seule fois. Un JSON embarqué invalide est un bug de build :
/// on échoue bruyamment en debug, et on retombe sur une base vide en release
/// (jamais de panic en production sur une donnée pourtant interne).
static BASE: Lazy<Vec<EntreeCve>> = Lazy::new(|| match serde_json::from_str(BASE_CVE_JSON) {
    Ok(v) => v,
    Err(e) => {
        debug_assert!(false, "base CVE embarquée invalide : {e}");
        Vec::new()
    }
});

// ---------------------------------------------------------------------------
// Constat public
// ---------------------------------------------------------------------------

/// Constat de correspondance CVE (paquet vulnérable détecté à une version
/// affectée).
#[derive(Debug, Clone, PartialEq)]
pub struct ConstatCve {
    /// Identifiant CVE (ex. `CVE-2025-6514`).
    pub cve_id: String,
    /// Identité de paquet ayant matché.
    pub package: String,
    /// Version détectée sur l'hôte.
    pub version_detectee: String,
    /// Plage affectée, lisible (ex. `>=0.0.5, <0.1.16`).
    pub plage_affectee: String,
    /// Score CVSS (base score).
    pub cvss: f64,
    /// Sévérité dérivée du CVSS.
    pub severite: Severite,
    /// Résumé lisible.
    pub resume: String,
    /// Références (URLs NVD/GHSA).
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Comparaison de versions (semver simplifié)
// ---------------------------------------------------------------------------

/// Parse une version `MAJOR.MINOR.PATCH` en triplet numérique.
///
/// Tolère un préfixe `v`/`V`, les métadonnées de build (`+…`) et le suffixe de
/// pré-release (`-rc1`), qui sont ignorés. Les composants manquants valent 0
/// (`1.2` → `1.2.0`). Renvoie `None` si un composant n'est pas numérique :
/// l'appelant traite alors la version comme NON comparable (pas de signalement).
fn parser_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim();
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    // Retire build (+) puis pré-release (-).
    let v = v.split('+').next().unwrap_or(v);
    let v = v.split('-').next().unwrap_or(v);
    if v.is_empty() {
        return None;
    }
    let mut it = v.split('.');
    let major = it.next().unwrap_or("0").parse::<u64>().ok()?;
    let minor = match it.next() {
        Some(s) => s.parse::<u64>().ok()?,
        None => 0,
    };
    let patch = match it.next() {
        Some(s) => s.parse::<u64>().ok()?,
        None => 0,
    };
    Some((major, minor, patch))
}

/// `true` si `version` ∈ [introduced, fixed) (borne basse incluse, borne haute
/// exclue). `introduced` absent ⇒ `0.0.0` ; `fixed` absent ⇒ borne haute infinie.
/// Toute version non interprétable renvoie `false` (anti-faux-positif).
fn version_affectee(version: &str, introduced: Option<&str>, fixed: Option<&str>) -> bool {
    let v = match parser_version(version) {
        Some(v) => v,
        None => return false,
    };
    let bas = introduced
        .and_then(parser_version)
        .unwrap_or((0, 0, 0));
    if v < bas {
        return false;
    }
    match fixed.and_then(parser_version) {
        Some(haut) => v < haut,
        None => true,
    }
}

// ---------------------------------------------------------------------------
// API publique
// ---------------------------------------------------------------------------

/// Dérive une sévérité Sentinel d'un score CVSS (échelle qualitative NVD).
pub fn severite_depuis_cvss(cvss: f64) -> Severite {
    if cvss >= 9.0 {
        Severite::Critique
    } else if cvss >= 7.0 {
        Severite::Haute
    } else if cvss >= 4.0 {
        Severite::Moyenne
    } else {
        Severite::Info
    }
}

/// Recherche les CVE connues affectant `package_id` à la version `version`.
///
/// `package_id` est l'identité canonique du paquet (cf.
/// `sentinel_protocol::extraire_package_id`) ; `version` est la version
/// installée. Comparaison insensible à la casse sur le nom de paquet. Une
/// `version` vide ou non interprétable ne produit AUCUN constat.
pub fn rechercher_cve(package_id: &str, version: &str) -> Vec<ConstatCve> {
    let pkg = package_id.trim().to_lowercase();
    if pkg.is_empty() {
        return Vec::new();
    }
    let mut constats = Vec::new();
    for entree in BASE.iter() {
        let concerne = entree
            .packages
            .iter()
            .any(|p| p.to_lowercase() == pkg);
        if !concerne {
            continue;
        }
        if !version_affectee(version, entree.introduced.as_deref(), entree.fixed.as_deref()) {
            continue;
        }
        let plage = format!(
            ">={}{}",
            entree.introduced.as_deref().unwrap_or("0.0.0"),
            match &entree.fixed {
                Some(f) => format!(", <{f}"),
                None => String::new(),
            }
        );
        constats.push(ConstatCve {
            cve_id: entree.cve_id.clone(),
            package: package_id.to_string(),
            version_detectee: version.to_string(),
            plage_affectee: plage,
            cvss: entree.cvss,
            severite: severite_depuis_cvss(entree.cvss),
            resume: entree.resume.clone(),
            references: entree.references.clone(),
        });
    }
    // Ordre déterministe : CVSS décroissant puis identifiant CVE.
    constats.sort_by(|a, b| {
        b.cvss
            .total_cmp(&a.cvss)
            .then_with(|| a.cve_id.cmp(&b.cve_id))
    });
    constats
}

/// Convertit un `ConstatCve` en `Constat` formel pour le store.
pub fn vers_constat(c: &ConstatCve, serveur_id: ServeurId) -> Constat {
    let mut references = vec![c.cve_id.clone()];
    references.extend(c.references.iter().cloned());
    Constat {
        id: crate::id_constat(&[
            "cve",
            &serveur_id.to_string(),
            &c.cve_id,
            &c.package,
        ]),
        serveur_id,
        outil_nom: None,
        type_constat: TypeConstat::Autre,
        severite: c.severite,
        titre: format!(
            "{} — package \"{}\" {} vulnerable (CVSS {:.1})",
            c.cve_id, c.package, c.version_detectee, c.cvss
        ),
        detail: format!(
            "{} Affected range: {}.",
            c.resume, c.plage_affectee
        ),
        diff: None,
        references_conformite: references,
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_embarquee_se_charge() {
        assert!(!BASE.is_empty(), "la base CVE embarquée doit se parser");
        // Cohérence : chaque entrée a au moins un paquet et un CVSS plausible.
        for e in BASE.iter() {
            assert!(!e.packages.is_empty(), "{} sans paquet", e.cve_id);
            assert!((0.0..=10.0).contains(&e.cvss), "{} CVSS hors échelle", e.cve_id);
        }
    }

    #[test]
    fn base_bornes_versions_toutes_parsables() {
        // Garde-fou anti-faux-positif : une borne `fixed` non parsable serait
        // silencieusement traitée comme « borne haute infinie » → TOUTES les
        // versions du paquet seraient signalées vulnérables. On exige que chaque
        // `introduced`/`fixed` de la base embarquée se parse réellement.
        for e in BASE.iter() {
            if let Some(i) = &e.introduced {
                assert!(
                    parser_version(i).is_some(),
                    "{} : borne `introduced` non parsable « {i} »",
                    e.cve_id
                );
            }
            if let Some(f) = &e.fixed {
                assert!(
                    parser_version(f).is_some(),
                    "{} : borne `fixed` non parsable « {f} » (élargirait la plage à l'infini)",
                    e.cve_id
                );
            }
        }
    }

    #[test]
    fn parser_version_tolere_v_et_prerelease() {
        assert_eq!(parser_version("0.1.15"), Some((0, 1, 15)));
        assert_eq!(parser_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parser_version("1.9.4-rc1"), Some((1, 9, 4)));
        assert_eq!(parser_version("2025.7.1"), Some((2025, 7, 1)));
        assert_eq!(parser_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parser_version("latest"), None);
        assert_eq!(parser_version(""), None);
    }

    #[test]
    fn mcp_remote_version_vulnerable_detectee() {
        let r = rechercher_cve("mcp-remote", "0.1.15");
        assert_eq!(r.len(), 1, "0.1.15 doit matcher CVE-2025-6514 : {r:?}");
        assert_eq!(r[0].cve_id, "CVE-2025-6514");
        assert_eq!(r[0].severite, Severite::Critique);
    }

    #[test]
    fn mcp_remote_version_corrigee_non_signalee() {
        // 0.1.16 est la version corrigée → aucun constat (anti-faux-positif).
        let r = rechercher_cve("mcp-remote", "0.1.16");
        assert!(r.is_empty(), "la version corrigée ne doit pas matcher : {r:?}");
        let r2 = rechercher_cve("mcp-remote", "1.0.0");
        assert!(r2.is_empty(), "une version postérieure ne doit pas matcher : {r2:?}");
    }

    #[test]
    fn filesystem_scheme_calendaire_compare_correctement() {
        // Schéma calendaire 2025.7.x : 0.6.2 < 2025.7.1 → affecté.
        let r = rechercher_cve("@modelcontextprotocol/server-filesystem", "0.6.2");
        assert_eq!(r.len(), 2, "deux CVE EscapeRoute attendues : {r:?}");
        // Corrigé.
        let r2 = rechercher_cve("@modelcontextprotocol/server-filesystem", "2025.7.1");
        assert!(r2.is_empty(), "la version corrigée calendaire ne doit pas matcher : {r2:?}");
    }

    #[test]
    fn paquet_inconnu_aucun_constat() {
        let r = rechercher_cve("@scope/un-paquet-totalement-benin", "1.0.0");
        assert!(r.is_empty(), "un paquet hors base ne doit jamais matcher : {r:?}");
    }

    #[test]
    fn version_non_interpretable_ne_signale_pas() {
        // « latest » / version vide : on ne signale pas (faux positif proscrit).
        assert!(rechercher_cve("mcp-remote", "latest").is_empty());
        assert!(rechercher_cve("mcp-remote", "").is_empty());
    }

    #[test]
    fn nom_paquet_insensible_a_la_casse() {
        let r = rechercher_cve("MCP-Remote", "0.1.0");
        assert_eq!(r.len(), 1, "la casse du paquet ne doit pas empêcher le match : {r:?}");
    }

    #[test]
    fn vers_constat_porte_le_cve_et_la_severite() {
        let r = rechercher_cve("@modelcontextprotocol/inspector", "0.10.0");
        assert_eq!(r.len(), 1);
        let id = Uuid::new_v4();
        let constat = vers_constat(&r[0], id);
        assert_eq!(constat.serveur_id, id);
        assert_eq!(constat.severite, Severite::Critique);
        assert!(constat.references_conformite.contains(&"CVE-2025-49596".to_string()));
    }
}
