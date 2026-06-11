//! Helpers de sortie partagés : code de sortie, impression respectant
//! `--quiet` et rendu de tables texte simples.

use sentinel_protocol::Severite;

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
    rendu.push_str(&"-".repeat(largeurs.iter().sum::<usize>() + 2 * (nb_cols - 1)));
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
}
