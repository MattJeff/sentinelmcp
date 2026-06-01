//! Détecteur de portée — Agent 1.7.
//!
//! Infère la portée fonctionnelle d'un serveur MCP à partir des noms et
//! descriptions de ses outils. La portée sert ensuite de signal d'entrée au
//! classificateur de risque (module 3) pour passer une carte orange en rouge.
//!
//! # Heuristiques documentées
//!
//! Chaque paire `(motif_regex, Portee)` est évaluée sur `nom` et `description`
//! de chaque outil (matching insensible à la casse). Plusieurs portées peuvent
//! être déclenchées par le même outil ; le résultat final est dédupliqué et
//! trié par valeur discriminante.
//!
//! ## Filesystem
//! Motifs : `read_file`, `write_file`, `list_dir`, `glob`, `path`,
//! `directory`, `~/\.ssh`, `/etc/`, `\.env`
//!
//! ## BaseDonnees
//! Motifs : `query`, `sql`, `database`, `db_`, `select `, `insert `,
//! `update `, `delete from`
//!
//! ## ApiExterne
//! Motifs : `http`, `fetch`, `request`, `webhook`, `api_call`, `curl`, `url`
//!
//! ## Secrets
//! Motifs : `secret`, `credential`, `token`, `api_key`, `password`, `ssh`,
//! `keychain`, `vault`
//!
//! ## Reseau
//! Motifs : `tcp`, `udp`, `socket`, `port`, `listen`, `bind`
//!
//! ## Lecture
//! Motifs : `read_`, `get_`, `list_`, `query_`, `show_`, `view_`
//!
//! ## Ecriture
//! Motifs : `write_`, `set_`, `create_`, `delete_`, `update_`, `post_`,
//! `send_`

use once_cell::sync::Lazy;
use regex::Regex;
use sentinel_protocol::{Outil, Portee};

/// Un règle heuristique associe un pattern regex précompilé à une portée.
struct Regle {
    motif: Regex,
    portee: Portee,
}

/// Table de règles précompilée (initialisée une seule fois au premier appel).
static REGLES: Lazy<Vec<Regle>> = Lazy::new(|| {
    // Chaque entrée : (pattern regex, portée cible).
    // L'ordre n'a pas d'importance fonctionnelle : toutes les règles sont
    // évaluées indépendamment.
    let definitions: &[(&str, Portee)] = &[
        // --- Filesystem ---
        (r"read_file",    Portee::Filesystem),
        (r"write_file",   Portee::Filesystem),
        (r"list_dir",     Portee::Filesystem),
        (r"glob",         Portee::Filesystem),
        (r"path",         Portee::Filesystem),
        (r"directory",    Portee::Filesystem),
        (r"~/\.ssh",      Portee::Filesystem),
        (r"/etc/",        Portee::Filesystem),
        (r"\.env",        Portee::Filesystem),
        // --- BaseDonnees ---
        (r"query",        Portee::BaseDonnees),
        (r"sql",          Portee::BaseDonnees),
        (r"database",     Portee::BaseDonnees),
        (r"db_",          Portee::BaseDonnees),
        (r"select ",      Portee::BaseDonnees),
        (r"insert ",      Portee::BaseDonnees),
        (r"update ",      Portee::BaseDonnees),
        (r"delete from",  Portee::BaseDonnees),
        // --- ApiExterne ---
        (r"http",         Portee::ApiExterne),
        (r"fetch",        Portee::ApiExterne),
        (r"request",      Portee::ApiExterne),
        (r"webhook",      Portee::ApiExterne),
        (r"api_call",     Portee::ApiExterne),
        (r"curl",         Portee::ApiExterne),
        (r"url",          Portee::ApiExterne),
        // --- Secrets ---
        (r"secret",       Portee::Secrets),
        (r"credential",   Portee::Secrets),
        (r"token",        Portee::Secrets),
        (r"api_key",      Portee::Secrets),
        (r"password",     Portee::Secrets),
        (r"ssh",          Portee::Secrets),
        (r"keychain",     Portee::Secrets),
        (r"vault",        Portee::Secrets),
        // --- Reseau ---
        (r"tcp",          Portee::Reseau),
        (r"udp",          Portee::Reseau),
        (r"socket",       Portee::Reseau),
        (r"port",         Portee::Reseau),
        (r"listen",       Portee::Reseau),
        (r"bind",         Portee::Reseau),
        // --- Lecture ---
        (r"read_",        Portee::Lecture),
        (r"get_",         Portee::Lecture),
        (r"list_",        Portee::Lecture),
        (r"query_",       Portee::Lecture),
        (r"show_",        Portee::Lecture),
        (r"view_",        Portee::Lecture),
        // --- Ecriture ---
        (r"write_",       Portee::Ecriture),
        (r"set_",         Portee::Ecriture),
        (r"create_",      Portee::Ecriture),
        (r"delete_",      Portee::Ecriture),
        (r"update_",      Portee::Ecriture),
        (r"post_",        Portee::Ecriture),
        (r"send_",        Portee::Ecriture),
    ];

    definitions
        .iter()
        .map(|(motif, portee)| Regle {
            motif: Regex::new(&format!("(?i){motif}")).expect("regex valide"),
            portee: *portee,
        })
        .collect()
});

/// Renvoie l'ensemble des portées inférées pour un jeu d'outils, triées et
/// dédupliquées.
///
/// Si aucune heuristique ne correspond, renvoie `[Portee::Inconnu]`.
pub fn inferer_portee(outils: &[Outil]) -> Vec<Portee> {
    use std::collections::HashSet;

    let mut trouvees: HashSet<Portee> = HashSet::new();

    for outil in outils {
        let cibles = std::iter::once(outil.nom.as_str()).chain(
            outil.description.as_deref().into_iter(),
        );
        for texte in cibles {
            for regle in REGLES.iter() {
                if regle.motif.is_match(texte) {
                    trouvees.insert(regle.portee);
                }
            }
        }
    }

    if trouvees.is_empty() {
        return vec![Portee::Inconnu];
    }

    // Tri stable par valeur discriminante (ordre défini dans l'enum).
    let mut resultat: Vec<Portee> = trouvees.into_iter().collect();
    resultat.sort_by_key(portee_ordre);
    resultat
}

/// Renvoie la table brute des heuristiques `(motif, portée)` utilisée en
/// interne. Utile pour l'agent 1.8 (mesure du taux de faux positifs).
pub fn jeu_heuristiques() -> Vec<(&'static str, Portee)> {
    vec![
        // Filesystem
        ("read_file",   Portee::Filesystem),
        ("write_file",  Portee::Filesystem),
        ("list_dir",    Portee::Filesystem),
        ("glob",        Portee::Filesystem),
        ("path",        Portee::Filesystem),
        ("directory",   Portee::Filesystem),
        ("~/\\.ssh",    Portee::Filesystem),
        ("/etc/",       Portee::Filesystem),
        ("\\.env",      Portee::Filesystem),
        // BaseDonnees
        ("query",       Portee::BaseDonnees),
        ("sql",         Portee::BaseDonnees),
        ("database",    Portee::BaseDonnees),
        ("db_",         Portee::BaseDonnees),
        ("select ",     Portee::BaseDonnees),
        ("insert ",     Portee::BaseDonnees),
        ("update ",     Portee::BaseDonnees),
        ("delete from", Portee::BaseDonnees),
        // ApiExterne
        ("http",        Portee::ApiExterne),
        ("fetch",       Portee::ApiExterne),
        ("request",     Portee::ApiExterne),
        ("webhook",     Portee::ApiExterne),
        ("api_call",    Portee::ApiExterne),
        ("curl",        Portee::ApiExterne),
        ("url",         Portee::ApiExterne),
        // Secrets
        ("secret",      Portee::Secrets),
        ("credential",  Portee::Secrets),
        ("token",       Portee::Secrets),
        ("api_key",     Portee::Secrets),
        ("password",    Portee::Secrets),
        ("ssh",         Portee::Secrets),
        ("keychain",    Portee::Secrets),
        ("vault",       Portee::Secrets),
        // Reseau
        ("tcp",         Portee::Reseau),
        ("udp",         Portee::Reseau),
        ("socket",      Portee::Reseau),
        ("port",        Portee::Reseau),
        ("listen",      Portee::Reseau),
        ("bind",        Portee::Reseau),
        // Lecture
        ("read_",       Portee::Lecture),
        ("get_",        Portee::Lecture),
        ("list_",       Portee::Lecture),
        ("query_",      Portee::Lecture),
        ("show_",       Portee::Lecture),
        ("view_",       Portee::Lecture),
        // Ecriture
        ("write_",      Portee::Ecriture),
        ("set_",        Portee::Ecriture),
        ("create_",     Portee::Ecriture),
        ("delete_",     Portee::Ecriture),
        ("update_",     Portee::Ecriture),
        ("post_",       Portee::Ecriture),
        ("send_",       Portee::Ecriture),
    ]
}

/// Ordre de tri déterministe pour `Portee` (par valeur discriminante déclarée
/// dans l'enum).
fn portee_ordre(p: &Portee) -> u8 {
    match p {
        Portee::Filesystem   => 0,
        Portee::BaseDonnees  => 1,
        Portee::ApiExterne   => 2,
        Portee::Secrets      => 3,
        Portee::Reseau       => 4,
        Portee::Lecture      => 5,
        Portee::Ecriture     => 6,
        Portee::Inconnu      => 7,
    }
}
