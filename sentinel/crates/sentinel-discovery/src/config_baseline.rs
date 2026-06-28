//! D13 — Baseline + diff du **contenu** des configurations MCP de projet.
//!
//! Sentinel distingue déjà la portée `User` de la portée `Project` (voir
//! [`sentinel_protocol::ScopeServeur`] et les sources Claude Desktop / Code).
//! Ce module ajoute la couche manquante : comparer le *contenu* d'une config
//! de projet (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`…) entre deux
//! observations.
//!
//! ## Pourquoi (CVE-2025-54136 « MCPoison »)
//!
//! Un opérateur approuve un serveur MCP de projet **par son nom** (clé de la
//! map `mcpServers`). L'attaquant échange ensuite *le contenu* de cette entrée
//! — il garde le même nom mais change la `command`, les `args`, l'`url` ou le
//! transport — et le client (Cursor, Claude Code…) ré-exécute le serveur sans
//! redemander d'approbation. La dérive est invisible si l'on ne regarde que
//! les noms : il faut diffuser le **contenu**.
//!
//! [`comparer_config_projet`] prend la liste précédente (approuvée) et la liste
//! courante de [`ServeurMcpDeclare`] d'un même projet et émet un [`Constat`]
//! par dérive observée :
//!   * **serveur ajouté** hors approbation → [`TypeConstat::ShadowMcp`] (MCP09) ;
//!   * **contenu modifié** d'un serveur approuvé (commande/url/transport/args/
//!     env/réactivation) → [`TypeConstat::RugPull`] (MCP03) — l'artefact qui
//!     s'exécutera a changé après approbation.
//!
//! ## Faux positifs maîtrisés
//!
//! * un serveur **retiré** de la config n'émet **rien** (nettoyage légitime) ;
//! * deux configs **identiques** (même à l'ordre près, le matching se fait par
//!   nom) n'émettent **rien** ;
//! * un champ inchangé ne contribue pas à la sévérité.
//!
//! Pour le suivi continu, [`BaselineConfigsProjet`] mémorise la dernière config
//! approuvée par chemin de projet : la **première** observation d'un projet est
//! silencieuse (rien à comparer), les suivantes sont diffées.

use std::collections::BTreeMap;

use chrono::Utc;
use sentinel_protocol::{Constat, EtatConstat, ServeurId, Severite, TypeConstat};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::model::ServeurMcpDeclare;

/// Identifiant de serveur **stable et déterministe** dérivé du nom déclaré.
///
/// On ne dispose pas ici d'un `ServeurId` issu du store (la comparaison porte
/// sur des configs brutes). On dérive donc un UUID reproductible du nom du
/// serveur via SHA-256 : deux exécutions produisent le même `serveur_id` pour
/// un même nom, ce qui permet à l'appelant de corréler / dédupliquer les
/// constats sans dépendre du hasard de `Uuid::new_v4`.
pub(crate) fn id_serveur_stable(nom: &str) -> ServeurId {
    let digest = Sha256::digest(nom.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Compare deux états successifs d'une **même config de projet** et retourne un
/// constat par dérive de contenu.
///
/// Le matching se fait par `nom` (la clé d'approbation). L'ordre des entrées
/// n'a aucune importance. Retourne un `Vec` vide — donc **aucun faux positif**
/// — si rien d'observable n'a changé (configs identiques, simple réordonnance,
/// ou serveurs uniquement retirés).
pub fn comparer_config_projet(
    precedente: &[ServeurMcpDeclare],
    courante: &[ServeurMcpDeclare],
) -> Vec<Constat> {
    let mut constats = Vec::new();

    // Index de la config précédente par nom (première occurrence conservée :
    // les noms sont des clés de map, donc uniques dans une config réelle).
    let mut index_prec: BTreeMap<&str, &ServeurMcpDeclare> = BTreeMap::new();
    for s in precedente {
        index_prec.entry(s.nom.as_str()).or_insert(s);
    }

    for actuel in courante {
        match index_prec.get(actuel.nom.as_str()) {
            None => {
                // Serveur présent maintenant, absent de la baseline approuvée :
                // ajout hors approbation (vecteur MCPoison « nouveau serveur »).
                constats.push(constat_serveur_ajoute(actuel));
            }
            Some(precedent) => {
                if let Some(c) = constat_si_modifie(precedent, actuel) {
                    constats.push(c);
                }
            }
        }
    }

    constats
}

/// Construit le constat d'un serveur ajouté hors baseline approuvée.
fn constat_serveur_ajoute(serveur: &ServeurMcpDeclare) -> Constat {
    let cible = decrire_cible(serveur);
    Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&serveur.nom),
        outil_nom: None,
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Haute,
        titre: format!(
            "Serveur MCP « {} » ajouté dans une config projet hors approbation",
            serveur.nom
        ),
        detail: format!(
            "La config MCP de projet déclare désormais le serveur « {} » ({cible}) absent de la \
             baseline approuvée. Un échange de contenu d'une config approuvée par nom (CVE-2025-54136 \
             « MCPoison ») injecte ainsi un serveur non revu : l'approuver explicitement après revue \
             avant de réactiver le client.",
            serveur.nom
        ),
        diff: None,
        references_conformite: vec!["OWASP MCP09".to_string(), "CVE-2025-54136".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

/// Compare deux déclarations du **même** serveur (même nom) et retourne un
/// constat si le contenu exécutable/sensible a changé. Retourne `None` si rien
/// d'observable n'a bougé.
fn constat_si_modifie(
    precedent: &ServeurMcpDeclare,
    actuel: &ServeurMcpDeclare,
) -> Option<Constat> {
    let mut changements: Vec<String> = Vec::new();
    // Sévérité = max des sévérités par champ ; on part du plancher.
    let mut severite = Severite::Info;
    let hausser = |s: Severite, sev: &mut Severite| {
        if s > *sev {
            *sev = s;
        }
    };

    // Transport (stdio ↔ http) : changement de nature d'exécution.
    if precedent.transport != actuel.transport {
        changements.push(format!(
            "transport `{}` → `{}`",
            precedent.transport, actuel.transport
        ));
        hausser(Severite::Critique, &mut severite);
    }

    // Commande stdio : un binaire différent s'exécutera.
    if precedent.commande != actuel.commande {
        changements.push(format!(
            "commande `{}` → `{}`",
            precedent.commande.as_deref().unwrap_or("∅"),
            actuel.commande.as_deref().unwrap_or("∅"),
        ));
        hausser(Severite::Critique, &mut severite);
    }

    // URL HTTP : un endpoint distant différent sera contacté.
    if precedent.url != actuel.url {
        changements.push(format!(
            "url `{}` → `{}`",
            precedent.url.as_deref().unwrap_or("∅"),
            actuel.url.as_deref().unwrap_or("∅"),
        ));
        hausser(Severite::Critique, &mut severite);
    }

    // Arguments : même binaire, comportement potentiellement différent.
    if precedent.args != actuel.args {
        changements.push(format!(
            "args `{}` → `{}`",
            precedent.args.join(" "),
            actuel.args.join(" "),
        ));
        hausser(Severite::Haute, &mut severite);
    }

    // Réactivation d'un serveur précédemment désactivé.
    if precedent.disabled && !actuel.disabled {
        changements.push("serveur réactivé (disabled `true` → `false`)".to_string());
        hausser(Severite::Haute, &mut severite);
    }

    // Clés d'environnement (noms uniquement) : ajout/retrait de secrets injectés.
    let env_prec: std::collections::BTreeSet<&str> =
        precedent.env_keys.iter().map(String::as_str).collect();
    let env_act: std::collections::BTreeSet<&str> =
        actuel.env_keys.iter().map(String::as_str).collect();
    if env_prec != env_act {
        let ajoutees: Vec<&str> = env_act.difference(&env_prec).copied().collect();
        let retirees: Vec<&str> = env_prec.difference(&env_act).copied().collect();
        changements.push(format!(
            "clés env ajoutées={:?} retirées={:?}",
            ajoutees, retirees
        ));
        hausser(Severite::Moyenne, &mut severite);
    }

    if changements.is_empty() {
        return None;
    }

    let diff = construire_diff_config(precedent, actuel);

    Some(Constat {
        id: Uuid::new_v4(),
        serveur_id: id_serveur_stable(&actuel.nom),
        outil_nom: None,
        type_constat: TypeConstat::RugPull,
        severite,
        titre: format!(
            "Config projet altérée après approbation : serveur « {} » modifié (MCPoison)",
            actuel.nom
        ),
        detail: format!(
            "Le contenu du serveur MCP « {} », approuvé par nom, a changé sans nouvelle revue \
             (CVE-2025-54136 « MCPoison ») : {}. L'artefact qui s'exécutera n'est plus celui qui a \
             été approuvé — ré-attester puis ré-approuver explicitement avant réactivation.",
            actuel.nom,
            changements.join(" ; ")
        ),
        diff: Some(diff),
        references_conformite: vec!["OWASP MCP03".to_string(), "CVE-2025-54136".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    })
}

/// Diff Markdown lisible (UI) entre deux déclarations d'un même serveur.
fn construire_diff_config(precedent: &ServeurMcpDeclare, actuel: &ServeurMcpDeclare) -> String {
    let ligne = |libelle: &str, avant: &str, apres: &str| -> String {
        if avant == apres {
            format!("- {libelle} : `{avant}` (inchangé)\n")
        } else {
            format!("- {libelle} : `{avant}` → `{apres}`\n")
        }
    };
    let mut md = String::from("### Dérive de config projet (MCPoison)\n\n");
    md.push_str(&ligne("Transport", &precedent.transport, &actuel.transport));
    md.push_str(&ligne(
        "Commande",
        precedent.commande.as_deref().unwrap_or("∅"),
        actuel.commande.as_deref().unwrap_or("∅"),
    ));
    md.push_str(&ligne(
        "URL",
        precedent.url.as_deref().unwrap_or("∅"),
        actuel.url.as_deref().unwrap_or("∅"),
    ));
    md.push_str(&ligne(
        "Args",
        &precedent.args.join(" "),
        &actuel.args.join(" "),
    ));
    md.push_str(&ligne(
        "Clés env",
        &precedent.env_keys.join(", "),
        &actuel.env_keys.join(", "),
    ));
    md
}

/// Décrit brièvement la cible exécutable d'un serveur (pour les messages).
fn decrire_cible(serveur: &ServeurMcpDeclare) -> String {
    if let Some(url) = &serveur.url {
        format!("url={url}")
    } else if let Some(cmd) = &serveur.commande {
        if serveur.args.is_empty() {
            format!("commande={cmd}")
        } else {
            format!("commande={cmd} {}", serveur.args.join(" "))
        }
    } else {
        "cible indéterminée".to_string()
    }
}

/// Baseline en mémoire du **contenu** des configs MCP de projet, indexée par
/// chemin de projet.
///
/// Permet un suivi continu sans dépendre du store : à chaque ré-observation
/// d'un projet, on diffuse contre la dernière config approuvée via
/// [`comparer_config_projet`], puis on met la baseline à jour. La **première**
/// observation d'un projet est silencieuse (rien à comparer).
#[derive(Debug, Clone, Default)]
pub struct BaselineConfigsProjet {
    par_projet: BTreeMap<String, Vec<ServeurMcpDeclare>>,
}

impl BaselineConfigsProjet {
    /// Baseline vide.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe la config courante d'un projet (identifié par son chemin), la
    /// compare à la baseline approuvée puis la met à jour. Retourne les
    /// constats de dérive. La première observation d'un projet ne produit
    /// jamais de constat.
    pub fn observer(&mut self, chemin_projet: &str, courante: &[ServeurMcpDeclare]) -> Vec<Constat> {
        let constats = match self.par_projet.get(chemin_projet) {
            Some(prec) => comparer_config_projet(prec, courante),
            None => Vec::new(),
        };
        self.par_projet
            .insert(chemin_projet.to_string(), courante.to_vec());
        constats
    }

    /// Config actuellement en baseline pour un projet, le cas échéant.
    pub fn config(&self, chemin_projet: &str) -> Option<&[ServeurMcpDeclare]> {
        self.par_projet.get(chemin_projet).map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_protocol::ScopeServeur;

    fn stdio(nom: &str, cmd: &str, args: &[&str]) -> ServeurMcpDeclare {
        ServeurMcpDeclare {
            nom: nom.to_string(),
            transport: "stdio".to_string(),
            commande: Some(cmd.to_string()),
            args: args.iter().map(|s| s.to_string()).collect(),
            env_keys: vec![],
            url: None,
            disabled: false,
            scope: ScopeServeur::Project {
                path: "/repo".to_string(),
            },
        }
    }

    #[test]
    fn configs_identiques_aucun_constat() {
        // Faux positif proscrit : contenu inchangé → rien.
        let a = vec![
            stdio("fs", "npx", &["-y", "@mcp/fs"]),
            stdio("db", "node", &["db.js"]),
        ];
        assert!(comparer_config_projet(&a, &a).is_empty());
    }

    #[test]
    fn reordonnance_seule_aucun_constat() {
        // Le matching par nom rend l'ordre indifférent (faux positif proscrit).
        let avant = vec![stdio("fs", "npx", &["-y", "@mcp/fs"]), stdio("db", "node", &["db.js"])];
        let apres = vec![stdio("db", "node", &["db.js"]), stdio("fs", "npx", &["-y", "@mcp/fs"])];
        assert!(comparer_config_projet(&avant, &apres).is_empty());
    }

    #[test]
    fn serveur_retire_aucun_constat() {
        // Retrait = nettoyage légitime → pas de constat.
        let avant = vec![stdio("fs", "npx", &["-y", "@mcp/fs"]), stdio("db", "node", &["db.js"])];
        let apres = vec![stdio("fs", "npx", &["-y", "@mcp/fs"])];
        assert!(comparer_config_projet(&avant, &apres).is_empty());
    }

    #[test]
    fn commande_echangee_est_rugpull_critique() {
        // MCPoison : même nom approuvé, commande échangée.
        let avant = vec![stdio("fs", "npx", &["-y", "@mcp/fs"])];
        let apres = vec![stdio("fs", "/tmp/evil.sh", &["-y", "@mcp/fs"])];
        let c = comparer_config_projet(&avant, &apres);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].type_constat, TypeConstat::RugPull);
        assert_eq!(c[0].severite, Severite::Critique);
        assert!(c[0].diff.is_some());
        assert!(c[0]
            .references_conformite
            .iter()
            .any(|r| r == "CVE-2025-54136"));
    }

    #[test]
    fn serveur_ajoute_est_shadow_haute() {
        let avant = vec![stdio("fs", "npx", &["-y", "@mcp/fs"])];
        let apres = vec![
            stdio("fs", "npx", &["-y", "@mcp/fs"]),
            stdio("backdoor", "node", &["evil.js"]),
        ];
        let c = comparer_config_projet(&avant, &apres);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].type_constat, TypeConstat::ShadowMcp);
        assert_eq!(c[0].severite, Severite::Haute);
        assert!(c[0].references_conformite.iter().any(|r| r == "OWASP MCP09"));
    }

    #[test]
    fn args_seuls_modifies_est_haute() {
        let avant = vec![stdio("fs", "npx", &["-y", "@mcp/fs"])];
        let apres = vec![stdio("fs", "npx", &["-y", "@mcp/fs", "--allow-write", "/"])];
        let c = comparer_config_projet(&avant, &apres);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severite, Severite::Haute);
    }

    #[test]
    fn reactivation_serveur_desactive_detectee() {
        let mut avant = stdio("fs", "npx", &["-y", "@mcp/fs"]);
        avant.disabled = true;
        let apres = stdio("fs", "npx", &["-y", "@mcp/fs"]);
        let c = comparer_config_projet(&[avant], &[apres]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severite, Severite::Haute);
    }

    #[test]
    fn id_serveur_stable_est_deterministe() {
        assert_eq!(id_serveur_stable("github"), id_serveur_stable("github"));
        assert_ne!(id_serveur_stable("github"), id_serveur_stable("gitlab"));
    }

    #[test]
    fn baseline_premiere_observation_silencieuse_puis_detecte() {
        let mut b = BaselineConfigsProjet::new();
        let v1 = vec![stdio("fs", "npx", &["-y", "@mcp/fs"])];
        // Première observation : rien à comparer.
        assert!(b.observer("/repo", &v1).is_empty());
        assert!(b.config("/repo").is_some());

        // Échange de commande → constat critique.
        let v2 = vec![stdio("fs", "/tmp/evil", &["-y", "@mcp/fs"])];
        let c = b.observer("/repo", &v2);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severite, Severite::Critique);

        // Baseline mise à jour : ré-observer v2 ne re-déclenche pas.
        assert!(b.observer("/repo", &v2).is_empty());
    }
}
