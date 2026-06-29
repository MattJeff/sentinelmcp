//! Helpers de sortie partagés : code de sortie, impression respectant
//! `--quiet` et rendu de tables texte simples.

use sentinel_detect::{ConfigDetection, ConfigJugeLlm};
use sentinel_protocol::{Severite, TypeConstat};

/// Code de sortie sémantique du CLI.
///
/// 0 = aucun constat, 1 = constats haute/critique. Les erreurs
/// d'exécution (code 2) passent par `anyhow::Error` dans `main`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeSortie {
    Aucun,
    ConstatsCritiques,
}

/// Dérive le code de sortie d'une liste de sévérités.
pub fn code_depuis_severites<'a, I>(severites: I) -> CodeSortie
where
    I: IntoIterator<Item = &'a Severite>,
{
    if severites
        .into_iter()
        .any(|s| matches!(s, Severite::Haute | Severite::Critique))
    {
        CodeSortie::ConstatsCritiques
    } else {
        CodeSortie::Aucun
    }
}

/// Libellé texte stable d'une sévérité (aligné sur le wire format serde).
pub fn libelle_severite(s: &Severite) -> &'static str {
    match s {
        Severite::Info => "info",
        Severite::Moyenne => "moyenne",
        Severite::Haute => "haute",
        Severite::Critique => "critique",
    }
}

/// Libellé texte stable d'un type de constat (aligné sur le wire format serde
/// `snake_case`). Utilisé pour rendre les `Constat` formels (issus du pipeline
/// hybride patterns/YARA/LLM) dans les sorties table et JSON du CLI.
pub fn libelle_type(t: &TypeConstat) -> &'static str {
    match t {
        TypeConstat::NouveauServeur => "nouveau_serveur",
        TypeConstat::ShadowMcp => "shadow_mcp",
        TypeConstat::RugPull => "rug_pull",
        TypeConstat::Poisoning => "poisoning",
        TypeConstat::Sosie => "sosie",
        TypeConstat::Exfiltration => "exfiltration",
        TypeConstat::SansAuthentification => "sans_authentification",
        TypeConstat::DeriveInterSession => "derive_inter_session",
        TypeConstat::AbusSampling => "abus_sampling",
        TypeConstat::ElicitationSensible => "elicitation_sensible",
        TypeConstat::Autre => "autre",
    }
}

/// Construit la configuration du pipeline de détection hybride
/// (`sentinel_detect::ConfigDetection`) à partir des flags CLI.
///
/// Garde le zéro-cloud par défaut : YARA local activé selon `yara`, juge LLM
/// désactivé sauf si `llm` est explicitement demandé (`--llm`). Quand le juge
/// est activé, il pointe sur l'URL Ollama locale `llm_url` (défaut
/// `http://localhost:11434`) — aucune URL distante n'est jamais utilisée.
pub fn config_detection(yara: bool, llm: bool, llm_url: &str) -> ConfigDetection {
    let llm = if llm {
        Some(ConfigJugeLlm {
            active: true,
            url_base: llm_url.to_string(),
            ..ConfigJugeLlm::default()
        })
    } else {
        None
    };
    ConfigDetection { yara, llm }
}

/// Imprime sur stdout sauf si `--quiet`.
pub fn imprimer(quiet: bool, texte: &str) {
    if !quiet {
        println!("{texte}");
    }
}

/// Rendu d'une table texte à colonnes alignées (en-tête + séparateur).
pub fn rendre_table(entetes: &[&str], lignes: &[Vec<String>]) -> String {
    let nb_cols = entetes.len();
    let mut largeurs: Vec<usize> = entetes.iter().map(|e| e.chars().count()).collect();
    for ligne in lignes {
        for (i, cellule) in ligne.iter().take(nb_cols).enumerate() {
            largeurs[i] = largeurs[i].max(cellule.chars().count());
        }
    }

    let formater = |cellules: &[String]| -> String {
        let mut out = String::new();
        for (i, c) in cellules.iter().take(nb_cols).enumerate() {
            let pad = largeurs[i].saturating_sub(c.chars().count());
            out.push_str(c);
            if i + 1 < nb_cols {
                out.push_str(&" ".repeat(pad + 2));
            }
        }
        out
    };

    let mut rendu = String::new();
    let entetes_owned: Vec<String> = entetes.iter().map(|e| e.to_string()).collect();
    rendu.push_str(&formater(&entetes_owned));
    rendu.push('\n');
    // `saturating_sub` évite un sous-débordement de `usize` quand il n'y a
    // aucune colonne (nb_cols == 0) : 2 * (0 - 1) paniquerait sinon.
    rendu.push_str(&"-".repeat(largeurs.iter().sum::<usize>() + 2 * nb_cols.saturating_sub(1)));
    for ligne in lignes {
        rendu.push('\n');
        rendu.push_str(&formater(ligne));
    }
    rendu
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_sortie_critique_si_haute_ou_critique() {
        assert_eq!(
            code_depuis_severites(&[Severite::Info, Severite::Moyenne]),
            CodeSortie::Aucun
        );
        assert_eq!(
            code_depuis_severites(&[Severite::Moyenne, Severite::Haute]),
            CodeSortie::ConstatsCritiques
        );
        assert_eq!(
            code_depuis_severites(&[Severite::Critique]),
            CodeSortie::ConstatsCritiques
        );
        assert_eq!(code_depuis_severites(&[]), CodeSortie::Aucun);
    }

    #[test]
    fn table_aligne_les_colonnes() {
        let rendu = rendre_table(
            &["NOM", "TRANSPORT"],
            &[
                vec!["fs".into(), "stdio".into()],
                vec!["serveur-long".into(), "http".into()],
            ],
        );
        let lignes: Vec<&str> = rendu.lines().collect();
        assert_eq!(lignes.len(), 4);
        assert!(lignes[0].starts_with("NOM"));
        assert!(lignes[0].contains("TRANSPORT"));
        assert!(lignes[3].starts_with("serveur-long"));
    }

    #[test]
    fn libelle_type_aligne_sur_le_wire_format() {
        assert_eq!(libelle_type(&TypeConstat::Poisoning), "poisoning");
        assert_eq!(libelle_type(&TypeConstat::Exfiltration), "exfiltration");
        assert_eq!(libelle_type(&TypeConstat::Sosie), "sosie");
    }

    #[test]
    fn config_detection_zero_cloud_par_defaut() {
        // Sans --llm : juge LLM désactivé (aucun appel réseau possible).
        let cfg = config_detection(true, false, "http://localhost:11434");
        assert!(cfg.yara);
        assert!(cfg.llm.is_none(), "le juge LLM doit rester désactivé par défaut");

        // --no-yara : YARA désactivé.
        let cfg = config_detection(false, false, "http://localhost:11434");
        assert!(!cfg.yara);
    }

    #[test]
    fn config_detection_active_le_juge_llm_sur_demande() {
        let cfg = config_detection(true, true, "http://127.0.0.1:1234");
        let llm = cfg.llm.expect("--llm doit activer le juge");
        assert!(llm.active);
        assert_eq!(llm.url_base, "http://127.0.0.1:1234");
    }

    #[test]
    fn table_sans_colonne_ne_panique_pas() {
        // Régression : avec zéro colonne, le calcul de la largeur du
        // séparateur faisait 2 * (0 - 1) et sous-débordait usize (panic).
        let rendu = rendre_table(&[], &[]);
        // En-tête vide + séparateur vide : aucune panique, sortie cohérente.
        assert_eq!(rendu, "\n");
    }
}
