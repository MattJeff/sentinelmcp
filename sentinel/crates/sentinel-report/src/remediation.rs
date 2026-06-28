//! Plan de remédiation — agent 5.10.
//!
//! Pour chaque serveur non conforme, produit une `ActionRemediation` priorisée
//! avec justification issue des références de conformité du constat le plus grave.

use sentinel_protocol::{Constat, Couleur, Serveur, Severite, StatutServeur};

/// Une action recommandée pour un serveur donné.
#[derive(Debug, Clone)]
pub struct ActionRemediation {
    /// Endpoint du serveur concerné.
    pub serveur_endpoint: String,
    /// Couleur de criticité du serveur.
    pub couleur: Couleur,
    /// Action recommandée : "Approuver", "Investiguer" ou "Bloquer".
    pub action: String,
    /// Justification incluant les références de conformité si disponibles.
    pub justification: String,
    /// Priorité : 1 = haute, 2 = moyenne, 3 = basse.
    pub priorite: u8,
}

/// Générateur du plan de remédiation.
pub struct PlanRemediation;

impl PlanRemediation {
    /// Construit la liste des actions de remédiation à partir de l'inventaire
    /// et des constats ouverts.
    ///
    /// Règles :
    /// - Serveur Rouge → "Bloquer", priorité 1.
    /// - Serveur Orange ou Suspect (non rouge) → "Investiguer", priorité 2.
    /// - Serveur Vert non Approuvé → "Approuver", priorité 3.
    /// - Serveur Vert Approuvé → pas d'action.
    pub fn construire(serveurs: &[Serveur], constats: &[Constat]) -> Vec<ActionRemediation> {
        let mut actions = Vec::new();

        for serveur in serveurs {
            let action_opt = Self::action_pour_serveur(serveur, constats);
            if let Some(action) = action_opt {
                actions.push(action);
            }
        }

        // Tri par priorité croissante (1 en tête), puis par endpoint pour la stabilité.
        actions.sort_by(|a, b| a.priorite.cmp(&b.priorite).then(a.serveur_endpoint.cmp(&b.serveur_endpoint)));

        actions
    }

    /// Conseil de remédiation ciblé selon la nature « Vague D » du constat le
    /// plus grave (CVE, OAuth/SSRF, cross-server shadowing, trifecta, socket
    /// fantôme). Reconnu via les marqueurs de `references_conformite`. Texte sans
    /// caractère `|` pour rester sûr dans une cellule de tableau Markdown.
    fn conseil_vague_d(constat: &Constat) -> Option<String> {
        let marque =
            |aiguille: &str| constat.references_conformite.iter().any(|r| r.contains(aiguille));
        if marque("CVE-") {
            Some(
                "Mettre à jour le paquet vers une version non affectée (CVE connue, supply-chain)."
                    .to_string(),
            )
        } else if marque("confused-deputy") || marque("RFC 8707") {
            Some(
                "Restreindre l'audience du jeton OAuth (paramètre resource, RFC 8707) pour clore le confused deputy."
                    .to_string(),
            )
        } else if marque("SSRF") || marque("CWE-918") {
            Some(
                "Interdire les destinations loopback / privées / métadonnées cloud (pivot SSRF, CWE-918)."
                    .to_string(),
            )
        } else if marque("SAFE-T1102") {
            Some(
                "Isoler le serveur : un outil instruit le client à propos d'un autre serveur (cross-server shadowing)."
                    .to_string(),
            )
        } else if marque("ATT&CK T1567") {
            Some(
                "Couper l'écriture externe : trifecta létale (entrée non fiable + lecture secret + exfiltration)."
                    .to_string(),
            )
        } else if marque("shadow-mcp") {
            Some(
                "Tracer le processus du socket en écoute non attribué (shadow MCP)."
                    .to_string(),
            )
        } else {
            None
        }
    }

    fn action_pour_serveur(serveur: &Serveur, constats: &[Constat]) -> Option<ActionRemediation> {
        // Trouver le constat le plus grave associé à ce serveur.
        let constat_grave = constats
            .iter()
            .filter(|c| c.serveur_id == serveur.id)
            .max_by_key(|c| &c.severite);

        let refs_conformite = constat_grave
            .map(|c| c.references_conformite.join(", "))
            .unwrap_or_default();

        // Conseil ciblé pour les détections avancées (Vague D), le cas échéant.
        let conseil = constat_grave
            .and_then(Self::conseil_vague_d)
            .map(|c| format!(" {c}"))
            .unwrap_or_default();

        match serveur.couleur {
            Couleur::Rouge => {
                let justification = if refs_conformite.is_empty() {
                    format!(
                        "Serveur rouge (statut : {:?}) — risque immédiat détecté.{}",
                        serveur.statut, conseil
                    )
                } else {
                    format!(
                        "Serveur rouge (statut : {:?}) — références : {}.{}",
                        serveur.statut, refs_conformite, conseil
                    )
                };
                Some(ActionRemediation {
                    serveur_endpoint: serveur.endpoint.clone(),
                    couleur: Couleur::Rouge,
                    action: "Bloquer".into(),
                    justification,
                    priorite: 1,
                })
            }
            Couleur::Orange => {
                let justification = if refs_conformite.is_empty() {
                    format!(
                        "Serveur orange (statut : {:?}) — investigation requise.{}",
                        serveur.statut, conseil
                    )
                } else {
                    format!(
                        "Serveur orange (statut : {:?}) — références : {}.{}",
                        serveur.statut, refs_conformite, conseil
                    )
                };
                Some(ActionRemediation {
                    serveur_endpoint: serveur.endpoint.clone(),
                    couleur: Couleur::Orange,
                    action: "Investiguer".into(),
                    justification,
                    priorite: 2,
                })
            }
            Couleur::Vert => {
                if serveur.statut == StatutServeur::Approuve {
                    // Serveur vert approuvé : aucune action.
                    None
                } else {
                    // Serveur vert non approuvé (Inconnu, Suspect, etc.) : à approuver.
                    let justification = format!(
                        "Serveur vert non approuvé (statut : {:?}) — validation formelle requise.",
                        serveur.statut
                    );
                    Some(ActionRemediation {
                        serveur_endpoint: serveur.endpoint.clone(),
                        couleur: Couleur::Vert,
                        action: "Approuver".into(),
                        justification,
                        priorite: 3,
                    })
                }
            }
        }
    }

    /// Sérialise la liste des actions en Markdown pour inclusion dans le bundle.
    pub fn vers_markdown(actions: &[ActionRemediation]) -> String {
        let mut md = String::new();
        md.push_str("# Plan de remédiation\n\n");

        if actions.is_empty() {
            md.push_str("Aucune action requise — tous les serveurs sont conformes.\n");
            return md;
        }

        md.push_str("| Priorité | Endpoint | Couleur | Action | Justification |\n");
        md.push_str("|---|---|---|---|---|\n");

        for a in actions {
            let couleur_str = match a.couleur {
                Couleur::Rouge => "Rouge",
                Couleur::Orange => "Orange",
                Couleur::Vert => "Vert",
            };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                a.priorite, a.serveur_endpoint, couleur_str, a.action, a.justification
            ));
        }

        md.push('\n');
        md
    }
}

// Vérifie la sévérité pour le tri des constats (ordre : Info < Moyenne < Haute < Critique).
fn _severite_ordre(s: &Severite) -> u8 {
    match s {
        Severite::Info => 0,
        Severite::Moyenne => 1,
        Severite::Haute => 2,
        Severite::Critique => 3,
    }
}
