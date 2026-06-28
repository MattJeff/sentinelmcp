//! Moteur de mapping de conformité — agent 5.4.
//!
//! Mapping constat → référentiels : OWASP MCP, SAFE-MCP, SOC 2, ISO 27001.
//! Version de la table : 2026-beta-1.
//!
//! ATTENTION : un mapping faux est pire que pas de rapport.
//! Toute modification doit être validée par relecture experte OWASP.

use sentinel_protocol::{Constat, Severite, TypeConstat};

/// Version de la table de mapping. Incrémenter à chaque modification.
pub const VERSION_TABLE: &str = "2026-beta-2";

/// Référence vers un contrôle d'un référentiel de conformité.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// Nom court du cadre : "OWASP MCP", "SAFE-MCP", "SOC 2", "ISO 27001".
    pub cadre: &'static str,
    /// Identifiant du contrôle dans le cadre (ex. "MCP09", "SAFE-T1001", "CC6.1").
    pub identifiant: &'static str,
    /// Titre humain du contrôle.
    pub titre: &'static str,
    /// URL canonique vers la spécification (None si le contrôle n'est pas encore publié).
    pub url: Option<&'static str>,
}

/// Niveau de couverture d'une catégorie de référentiel par Sentinel.
///
/// Honnêteté assumée pour un auditeur / RSSI : Sentinel est un EDR de serveurs
/// MCP, pas un moteur d'introspection du raisonnement de l'agent. Certaines
/// catégories agentiques (mémoire persistante, hallucinations en cascade…)
/// sont des angles morts revendiqués.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NiveauCouverture {
    /// Catégorie couverte par un détecteur Sentinel dédié.
    Oui,
    /// Couverture heuristique, indirecte ou partielle (faux négatifs possibles).
    Partiel,
    /// Hors périmètre de l'EDR — angle mort assumé.
    Non,
}

impl NiveauCouverture {
    /// Étiquette lisible pour le rendu Markdown / JSON.
    pub fn etiquette(self) -> &'static str {
        match self {
            NiveauCouverture::Oui => "Oui",
            NiveauCouverture::Partiel => "Partiel",
            NiveauCouverture::Non => "Non",
        }
    }
}

/// Ligne de la matrice de couverture : une catégorie d'un référentiel et le
/// niveau de couverture revendiqué par Sentinel, justifié pour l'auditeur.
#[derive(Debug, Clone, PartialEq)]
pub struct CouvertureCategorie {
    /// Cadre : "OWASP MCP" ou "OWASP ASI".
    pub cadre: &'static str,
    /// Identifiant de la catégorie (ex. "MCP03", "ASI06").
    pub identifiant: &'static str,
    /// Intitulé humain de la catégorie (table Sentinel).
    pub titre: &'static str,
    /// Niveau de couverture revendiqué.
    pub niveau: NiveauCouverture,
    /// Justification courte (détecteur concerné ou raison de l'angle mort).
    pub justification: &'static str,
}

// ---------------------------------------------------------------------------
// Constantes — une seule définition par référence, évite les divergences.
// ---------------------------------------------------------------------------

const OWASP_MCP09: Reference = Reference {
    cadre: "OWASP MCP",
    identifiant: "MCP09",
    titre: "Shadow MCP Server",
    url: Some("https://owasp.org/www-project-mcp-top-10/"),
};

const OWASP_MCP03: Reference = Reference {
    cadre: "OWASP MCP",
    identifiant: "MCP03",
    titre: "Tool Poisoning",
    url: Some("https://owasp.org/www-project-mcp-top-10/"),
};

const OWASP_A07: Reference = Reference {
    cadre: "OWASP",
    identifiant: "A07",
    titre: "Identification and Authentication Failures",
    url: Some("https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
};

const SAFE_T1001: Reference = Reference {
    cadre: "SAFE-MCP",
    identifiant: "SAFE-T1001",
    titre: "Tool Description Poisoning",
    url: Some("https://safemcp.io/techniques/T1001"),
};

const SAFE_T1201: Reference = Reference {
    cadre: "SAFE-MCP",
    identifiant: "SAFE-T1201",
    titre: "Rug Pull — Tool Behavior Change",
    url: Some("https://safemcp.io/techniques/T1201"),
};

const OWASP_ASI06: Reference = Reference {
    cadre: "OWASP ASI",
    identifiant: "ASI06",
    titre: "Memory & Context Poisoning",
    url: None,
};

const MCP_SPEC_ELICITATION: Reference = Reference {
    cadre: "MCP Spec",
    identifiant: "Elicitation",
    titre: "Servers MUST NOT request sensitive information via elicitation",
    url: Some("https://modelcontextprotocol.io/specification"),
};

const SOC2_CC6_1: Reference = Reference {
    cadre: "SOC 2",
    identifiant: "CC6.1",
    titre: "Logical and Physical Access Controls",
    url: None,
};

const SOC2_CC7_1: Reference = Reference {
    cadre: "SOC 2",
    identifiant: "CC7.1",
    titre: "System Operations — Change Management",
    url: None,
};

const SOC2_CC7_2: Reference = Reference {
    cadre: "SOC 2",
    identifiant: "CC7.2",
    titre: "System Operations — Anomaly Detection",
    url: None,
};

const ISO_A12_4_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.12.4.1",
    titre: "Event Logging",
    url: None,
};

const ISO_A14_2_2: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.14.2.2",
    titre: "System Change Control Procedures",
    url: None,
};

const ISO_A12_6_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.12.6.1",
    titre: "Management of Technical Vulnerabilities",
    url: None,
};

const ISO_A8_1_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.8.1.1",
    titre: "Inventory of Assets",
    url: None,
};

const ISO_A13_1_1: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.13.1.1",
    titre: "Network Controls",
    url: None,
};

const ISO_A12_4_3: Reference = Reference {
    cadre: "ISO 27001",
    identifiant: "A.12.4.3",
    titre: "Administrator and Operator Logs",
    url: None,
};

// ---------------------------------------------------------------------------
// Moteur
// ---------------------------------------------------------------------------

pub struct MoteurConformite;

impl MoteurConformite {
    /// Retourne la liste de références applicables à un type de constat.
    ///
    /// L'ordre est significatif : les références les plus spécifiques au risque
    /// MCP apparaissent en premier (OWASP MCP puis SAFE-MCP), suivies des
    /// contrôles opérationnels généraux (SOC 2, ISO 27001).
    pub fn references_pour(t: &TypeConstat) -> Vec<Reference> {
        match t {
            // Serveur inconnu observé pour la première fois — Shadow MCP.
            TypeConstat::NouveauServeur | TypeConstat::ShadowMcp => vec![
                OWASP_MCP09.clone(),
                SOC2_CC6_1.clone(),
                ISO_A12_4_1.clone(),
            ],
            // Changement de comportement entre deux observations d'un serveur approuvé.
            TypeConstat::RugPull => vec![
                OWASP_MCP03.clone(),
                SAFE_T1201.clone(),
                SOC2_CC7_1.clone(),
                ISO_A14_2_2.clone(),
            ],
            // Instruction cachée dans la description ou le schéma d'un outil.
            TypeConstat::Poisoning => vec![
                OWASP_MCP03.clone(),
                SAFE_T1001.clone(),
                SOC2_CC7_2.clone(),
                ISO_A12_6_1.clone(),
            ],
            // Serveur qui usurpe le nom ou l'empreinte d'un serveur légitime.
            TypeConstat::Sosie => vec![
                OWASP_MCP09.clone(),
                ISO_A8_1_1.clone(),
            ],
            // Paramètre d'appel acheminant des données vers une destination externe.
            TypeConstat::Exfiltration => vec![
                SAFE_T1201.clone(),
                OWASP_MCP03.clone(),
                ISO_A13_1_1.clone(),
            ],
            // Serveur accessible sans mécanisme d'authentification.
            TypeConstat::SansAuthentification => vec![
                OWASP_A07.clone(),
                SOC2_CC6_1.clone(),
            ],
            // Divergence de comportement observée entre deux sessions distinctes.
            TypeConstat::DeriveInterSession => vec![
                SAFE_T1201.clone(),
                ISO_A12_4_3.clone(),
            ],
            // Abus de la primitive sampling (drain de quota, injection persistante).
            TypeConstat::AbusSampling => vec![
                OWASP_ASI06.clone(),
                SOC2_CC7_2.clone(),
                ISO_A12_4_1.clone(),
            ],
            // Elicitation demandant des informations sensibles (interdit par la spec MCP).
            TypeConstat::ElicitationSensible => vec![
                MCP_SPEC_ELICITATION.clone(),
                SOC2_CC6_1.clone(),
            ],
            // Constat non catégorisé — aucune référence applicable.
            TypeConstat::Autre => vec![],
        }
    }

    /// Retourne les références applicables en fonction de la sévérité seule.
    ///
    /// Usage : enrichir un constat lorsque son type fin n'est pas disponible
    /// (ex. agrégation de métriques globales). Ne pas utiliser à la place de
    /// `references_pour` quand le `TypeConstat` est connu.
    pub fn references_par_severite(s: &Severite) -> Vec<Reference> {
        match s {
            Severite::Critique | Severite::Haute => vec![
                OWASP_MCP03.clone(),
                OWASP_MCP09.clone(),
            ],
            Severite::Moyenne => vec![
                OWASP_MCP09.clone(),
            ],
            Severite::Info => vec![],
        }
    }

    /// Tableau complet : tous les types de constats et leurs références.
    ///
    /// Utilisé par l'agent 5.6 (PDF) et 5.7 (JSON) pour générer l'annexe
    /// de couverture de conformité du rapport.
    pub fn tableau_complet() -> Vec<(TypeConstat, Vec<Reference>)> {
        let types = [
            TypeConstat::NouveauServeur,
            TypeConstat::ShadowMcp,
            TypeConstat::RugPull,
            TypeConstat::Poisoning,
            TypeConstat::Sosie,
            TypeConstat::Exfiltration,
            TypeConstat::SansAuthentification,
            TypeConstat::DeriveInterSession,
            TypeConstat::AbusSampling,
            TypeConstat::ElicitationSensible,
            TypeConstat::Autre,
        ];
        types
            .into_iter()
            .map(|t| {
                let refs = Self::references_pour(&t);
                (t, refs)
            })
            .collect()
    }

    /// Génère la section conformité d'un rapport Markdown.
    ///
    /// Produit un tableau : `| Constat | Cadre | Identifiant | Titre |`
    /// Un constat sans référence n'est pas listé (pas de ligne vide trompeuse).
    pub fn markdown_section(constats: &[Constat]) -> String {
        let mut lignes: Vec<String> = Vec::new();

        lignes.push(format!(
            "## Conformité (table v{})\n",
            VERSION_TABLE
        ));
        lignes.push(
            "| Constat | Cadre | Identifiant | Titre |".to_string(),
        );
        lignes.push("|---------|-------|-------------|-------|".to_string());

        for constat in constats {
            let refs = Self::references_pour(&constat.type_constat);
            for r in &refs {
                let identifiant = match r.url {
                    Some(url) => format!("[{}]({})", r.identifiant, url),
                    None => r.identifiant.to_string(),
                };
                lignes.push(format!(
                    "| {} | {} | {} | {} |",
                    constat.titre, r.cadre, identifiant, r.titre
                ));
            }
        }

        lignes.join("\n")
    }

    // -----------------------------------------------------------------------
    // D10 — estampillage multi-référentiels
    // -----------------------------------------------------------------------

    /// Table de correspondance documentée : pour un type de constat, retourne
    /// l'ensemble des identifiants de référentiels applicables, tous cadres
    /// confondus (OWASP MCP Top 10, SAFE-MCP, OWASP Agentic Security Initiative
    /// et MITRE ATT&CK / ATLAS quand une technique est clairement applicable).
    ///
    /// Le résultat est un estampillage « à plat » destiné à enrichir le champ
    /// `references_conformite` des constats et la section conformité du rapport.
    /// Pour les références détaillées (cadre, titre, URL, SOC 2 / ISO 27001),
    /// voir [`Self::references_pour`].
    ///
    /// Chaque correspondance MITRE est une technique réelle et stable :
    /// - ATT&CK T1195 — Supply Chain Compromise (serveur fantôme, rug-pull) ;
    /// - ATT&CK T1036 — Masquerading (sosie / typosquatting) ;
    /// - ATT&CK T1567 — Exfiltration Over Web Service (exfiltration) ;
    /// - ATT&CK T1598 — Phishing for Information (elicitation de secrets) ;
    /// - ATLAS AML.T0051 — LLM Prompt Injection (poisoning, injection persistante).
    pub fn references_frameworks(t: &TypeConstat) -> Vec<&'static str> {
        match t {
            // Serveur fantôme : OWASP MCP09 + introduction d'un composant non
            // approuvé dans la chaîne d'approvisionnement.
            TypeConstat::NouveauServeur | TypeConstat::ShadowMcp => {
                vec!["MCP09", "ATT&CK T1195"]
            }
            // Rug-pull : changement de comportement d'un outil approuvé →
            // compromission de dépendance logicielle.
            TypeConstat::RugPull => vec!["MCP03", "SAFE-T1201", "ATT&CK T1195"],
            // Tool poisoning : instruction cachée dans la description/le schéma
            // = injection d'invite au sens ATLAS.
            TypeConstat::Poisoning => vec!["MCP03", "SAFE-T1001", "ATLAS AML.T0051"],
            // Sosie / lookalike : usurpation de l'empreinte d'un serveur légitime.
            TypeConstat::Sosie => vec!["MCP09", "ATT&CK T1036"],
            // Exfiltration : acheminement de données vers une destination externe.
            TypeConstat::Exfiltration => vec!["MCP03", "SAFE-T1201", "ATT&CK T1567"],
            // Absence d'authentification : défaut d'identification/authentification.
            TypeConstat::SansAuthentification => vec!["A07"],
            // Dérive inter-session : variante de changement de comportement.
            TypeConstat::DeriveInterSession => vec!["SAFE-T1201"],
            // Abus de sampling : injection persistante dans le contexte / mémoire.
            TypeConstat::AbusSampling => vec!["ASI06", "ATLAS AML.T0051"],
            // Elicitation sensible : extraction de secrets auprès de l'utilisateur.
            TypeConstat::ElicitationSensible => vec!["ATT&CK T1598"],
            // Constat non catégorisé.
            TypeConstat::Autre => vec![],
        }
    }

    /// Section Markdown récapitulant l'estampillage multi-référentiels par type
    /// de constat présent. Un constat dont le type n'a aucune correspondance
    /// n'est pas listé. Les types sont dédupliqués (un seul affichage par type).
    pub fn frameworks_markdown(constats: &[Constat]) -> String {
        let mut lignes: Vec<String> = Vec::new();
        lignes.push(format!(
            "## Correspondances multi-référentiels (table v{})\n",
            VERSION_TABLE
        ));
        lignes.push("| Type de constat | Référentiels (SAFE-MCP / OWASP MCP / ASI / MITRE) |".to_string());
        lignes.push("|-----------------|----------------------------------------------------|".to_string());

        let mut vus: Vec<&TypeConstat> = Vec::new();
        for constat in constats {
            // Déduplication par type : on n'affiche chaque type qu'une fois.
            if vus.contains(&&constat.type_constat) {
                continue;
            }
            let ids = Self::references_frameworks(&constat.type_constat);
            if ids.is_empty() {
                continue;
            }
            vus.push(&constat.type_constat);
            lignes.push(format!(
                "| {:?} | {} |",
                constat.type_constat,
                ids.join(", ")
            ));
        }

        lignes.join("\n")
    }

    // -----------------------------------------------------------------------
    // P3 — matrice de couverture
    // -----------------------------------------------------------------------

    /// Matrice de couverture honnête : pour chaque catégorie d'OWASP MCP Top 10
    /// et d'OWASP Agentic Security Initiative, indique si Sentinel la couvre
    /// (Oui / Partiel / Non) avec une justification.
    ///
    /// La numérotation est alignée au mieux sur les référentiels publics ; les
    /// intitulés et les niveaux de couverture relèvent de la table Sentinel
    /// (version [`VERSION_TABLE`]). ASI06 (mémoire & contexte persistants) est
    /// un angle mort explicitement revendiqué.
    pub fn matrice_couverture() -> Vec<CouvertureCategorie> {
        use NiveauCouverture::*;
        vec![
            // ---- OWASP MCP Top 10 ------------------------------------------
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP01",
                titre: "Injection d'invite / d'outil",
                niveau: Partiel,
                justification: "Heuristiques de poisoning sur descriptions et schémas ; pas d'inspection de tout le trafic.",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP02",
                titre: "Authentification et autorisation défaillantes",
                niveau: Oui,
                justification: "Détecteur SansAuthentification (endpoint exposé sans mécanisme d'auth).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP03",
                titre: "Empoisonnement d'outil (Tool Poisoning)",
                niveau: Oui,
                justification: "Détecteur Poisoning (instructions cachées dans la description/le schéma).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP04",
                titre: "Exfiltration de données via paramètres",
                niveau: Oui,
                justification: "Détecteur Exfiltration (paramètres acheminés vers une destination externe).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP05",
                titre: "Élévation de privilèges / confused deputy",
                niveau: Non,
                justification: "Hors périmètre EDR : l'analyse des chaînes de privilèges de l'agent n'est pas instrumentée.",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP06",
                titre: "Exécution de code non maîtrisée",
                niveau: Partiel,
                justification: "Surveillance comportementale du serveur ; pas d'analyse statique de son code.",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP07",
                titre: "Détournement de consentement (elicitation)",
                niveau: Oui,
                justification: "Détecteur ElicitationSensible (demande d'informations sensibles, interdite par la spec).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP08",
                titre: "Manque de journalisation et de traçabilité",
                niveau: Oui,
                justification: "Sentinel produit le journal d'évidence signé (inventaire, constats, horodatage).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP09",
                titre: "Serveur MCP fantôme (Shadow MCP Server)",
                niveau: Oui,
                justification: "Détecteur NouveauServeur / ShadowMcp (serveur non approuvé observé).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP10",
                titre: "Compromission de la chaîne d'approvisionnement / rug-pull",
                niveau: Oui,
                justification: "Détecteurs RugPull et Sosie (changement de comportement, usurpation d'empreinte).",
            },
            // ---- OWASP Agentic Security Initiative -------------------------
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI01",
                titre: "Détournement d'objectif / manipulation d'intention",
                niveau: Non,
                justification: "Hors périmètre : le raisonnement interne de l'agent n'est pas observé.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI02",
                titre: "Abus d'outil (Tool Misuse)",
                niveau: Partiel,
                justification: "Couvert indirectement via Poisoning et Exfiltration sur la surface MCP.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI03",
                titre: "Compromission de privilèges",
                niveau: Non,
                justification: "Hors périmètre : pas d'instrumentation des autorisations effectives de l'agent.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI04",
                titre: "Surcharge de ressources (Resource Overload)",
                niveau: Partiel,
                justification: "Détecteur AbusSampling (drain de quota) ; pas de quotas applicatifs complets.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI05",
                titre: "Hallucinations en cascade",
                niveau: Non,
                justification: "Hors périmètre : Sentinel n'évalue pas le contenu généré par le modèle.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI06",
                titre: "Empoisonnement mémoire & contexte (persistant)",
                niveau: Non,
                justification: "Angle mort assumé : la mémoire persistante de l'agent n'est pas inspectée par l'EDR.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI07",
                titre: "Comportements trompeurs / désalignés",
                niveau: Non,
                justification: "Hors périmètre : l'alignement comportemental du modèle n'est pas évalué.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI08",
                titre: "Répudiation & non-traçabilité",
                niveau: Oui,
                justification: "Évidence signée Ed25519, inventaire et journal horodatés.",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI09",
                titre: "Usurpation d'identité & imitation",
                niveau: Oui,
                justification: "Détecteur Sosie / lookalike (usurpation de nom ou d'empreinte).",
            },
            CouvertureCategorie {
                cadre: "OWASP ASI",
                identifiant: "ASI10",
                titre: "Débordement du humain-dans-la-boucle",
                niveau: Partiel,
                justification: "Élicitation abusive détectée ; pas de mesure de la charge décisionnelle globale.",
            },
        ]
    }

    /// Rend la matrice de couverture sous forme de tableau Markdown lisible
    /// pour un RSSI / auditeur, précédé d'une légende explicite des niveaux.
    pub fn matrice_couverture_markdown() -> String {
        let mut lignes: Vec<String> = Vec::new();
        lignes.push(format!(
            "## Matrice de couverture (table v{})\n",
            VERSION_TABLE
        ));
        lignes.push(
            "Lecture : « Oui » = catégorie couverte par un détecteur dédié ; \
             « Partiel » = couverture heuristique ou indirecte (faux négatifs \
             possibles) ; « Non » = hors périmètre EDR (angle mort assumé). \
             Numérotation alignée au mieux sur OWASP MCP Top 10 et OWASP Agentic \
             Security Initiative ; les intitulés relèvent de la table Sentinel.\n"
                .to_string(),
        );
        lignes.push("| Cadre | ID | Catégorie | Couverture | Justification |".to_string());
        lignes.push("|-------|----|-----------|------------|---------------|".to_string());

        for c in Self::matrice_couverture() {
            lignes.push(format!(
                "| {} | {} | {} | {} | {} |",
                c.cadre,
                c.identifiant,
                c.titre,
                c.niveau.etiquette(),
                c.justification
            ));
        }

        lignes.join("\n")
    }

    /// Rend la matrice de couverture sous forme de tableau JSON (liste d'objets)
    /// pour intégration dans le bundle d'export.
    pub fn matrice_couverture_json() -> serde_json::Value {
        let categories: Vec<serde_json::Value> = Self::matrice_couverture()
            .into_iter()
            .map(|c| {
                serde_json::json!({
                    "cadre": c.cadre,
                    "identifiant": c.identifiant,
                    "titre": c.titre,
                    "couverture": c.niveau.etiquette(),
                    "justification": c.justification,
                })
            })
            .collect();
        serde_json::json!({
            "version_table": VERSION_TABLE,
            "categories": categories,
        })
    }
}

// ---------------------------------------------------------------------------
// Implémentation de Clone pour Reference (nécessaire pour les .clone() ci-dessus).
// ---------------------------------------------------------------------------
// Reference dérive Clone, donc les constantes peuvent être clonées directement.

#[cfg(test)]
mod tests_internes {
    use super::*;

    #[test]
    fn version_table_non_vide() {
        assert!(!VERSION_TABLE.is_empty());
    }

    #[test]
    fn autre_vide() {
        assert!(MoteurConformite::references_pour(&TypeConstat::Autre).is_empty());
    }

    #[test]
    fn frameworks_autre_vide() {
        assert!(MoteurConformite::references_frameworks(&TypeConstat::Autre).is_empty());
    }

    #[test]
    fn matrice_couverture_non_vide_et_complete() {
        // 10 catégories OWASP MCP + 10 OWASP ASI.
        assert_eq!(MoteurConformite::matrice_couverture().len(), 20);
    }

    #[test]
    fn etiquette_niveaux() {
        assert_eq!(NiveauCouverture::Oui.etiquette(), "Oui");
        assert_eq!(NiveauCouverture::Partiel.etiquette(), "Partiel");
        assert_eq!(NiveauCouverture::Non.etiquette(), "Non");
    }
}
