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

// --- Vague D — référentiels des nouvelles natures de constats --------------

/// Cross-server tool shadowing (un serveur instruit le client à propos d'un
/// autre serveur, ou collisionne son nom d'outil).
const SAFE_T1102: Reference = Reference {
    cadre: "SAFE-MCP",
    identifiant: "SAFE-T1102",
    titre: "Cross-Server Tool Shadowing",
    url: Some("https://safemcp.io/techniques/T1102"),
};

/// Confused deputy / élévation de privilèges sur la surface MCP HTTP
/// (OAuth sans audience, SSRF). Aligné sur l'intitulé de la matrice MCP05.
const OWASP_MCP05: Reference = Reference {
    cadre: "OWASP MCP",
    identifiant: "MCP05",
    titre: "Confused Deputy / Privilege Escalation",
    url: Some("https://owasp.org/www-project-mcp-top-10/"),
};

/// Compromission de la chaîne d'approvisionnement (rug-pull, paquet vulnérable
/// avec CVE connue). Aligné sur l'intitulé de la matrice MCP10.
const OWASP_MCP10: Reference = Reference {
    cadre: "OWASP MCP",
    identifiant: "MCP10",
    titre: "Supply Chain Compromise",
    url: Some("https://owasp.org/www-project-mcp-top-10/"),
};

/// Composant tiers vulnérable et non à jour (CVE connue) — OWASP Top 10 2021.
const OWASP_A06: Reference = Reference {
    cadre: "OWASP",
    identifiant: "A06",
    titre: "Vulnerable and Outdated Components",
    url: Some("https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
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

    // -----------------------------------------------------------------------
    // Vague D — estampillage affiné par la NATURE du constat
    // -----------------------------------------------------------------------

    /// Pousse un identifiant de référentiel s'il n'est pas déjà présent.
    fn pousser_id_unique(ids: &mut Vec<&'static str>, valeur: &'static str) {
        if !ids.contains(&valeur) {
            ids.push(valeur);
        }
    }

    /// Pousse une référence détaillée si son couple (cadre, identifiant) est absent.
    fn pousser_ref_unique(refs: &mut Vec<Reference>, r: Reference) {
        if !refs
            .iter()
            .any(|x| x.cadre == r.cadre && x.identifiant == r.identifiant)
        {
            refs.push(r);
        }
    }

    /// Estampillage multi-référentiels **affiné par la nature** d'un constat.
    ///
    /// [`Self::references_frameworks`] ne dispatche que sur le `TypeConstat`. Or
    /// plusieurs détections Vague D partagent un même type sans s'y réduire : la
    /// vulnérabilité CVE et les contrôles OAuth/SSRF statiques retombent sur
    /// `Autre`, le cross-server shadowing sur `Poisoning`, la trifecta létale sur
    /// `Exfiltration`. Ces natures ne se distinguent que par les marqueurs déjà
    /// déposés par les détecteurs dans `references_conformite`. On lit donc ces
    /// marqueurs pour produire l'estampillage exact — sans introduire de nouveau
    /// variant d'enum (changement strictement additif).
    pub fn references_frameworks_constat(c: &Constat) -> Vec<&'static str> {
        let mut ids = Self::references_frameworks(&c.type_constat);
        let contient =
            |aiguille: &str| c.references_conformite.iter().any(|r| r.contains(aiguille));

        // Cross-server tool shadowing : SAFE-T1102 + tool poisoning inter-serveurs.
        if contient("SAFE-T1102") {
            Self::pousser_id_unique(&mut ids, "SAFE-T1102");
            Self::pousser_id_unique(&mut ids, "MCP03");
        }
        // Vulnérabilité CVE connue : composant vulnérable → chaîne d'appro.
        if contient("CVE-") {
            Self::pousser_id_unique(&mut ids, "A06");
            Self::pousser_id_unique(&mut ids, "MCP10");
            Self::pousser_id_unique(&mut ids, "ATT&CK T1195");
        }
        // OAuth confused deputy (RFC 8707) : délégation d'autorité abusable.
        if contient("confused-deputy") || contient("RFC 8707") {
            Self::pousser_id_unique(&mut ids, "MCP05");
        }
        // SSRF (CWE-918) : pivot réseau vers services internes / métadonnées cloud.
        if contient("SSRF") || contient("CWE-918") {
            Self::pousser_id_unique(&mut ids, "MCP05");
            Self::pousser_id_unique(&mut ids, "CWE-918");
        }
        // Trifecta létale : exfiltration runtime → exfil over web service + shadow.
        if contient("ATT&CK T1567") {
            Self::pousser_id_unique(&mut ids, "ATT&CK T1567");
            Self::pousser_id_unique(&mut ids, "MCP09");
        }
        ids
    }

    /// Références de conformité détaillées **affinées par la nature** d'un
    /// constat. Complète [`Self::references_pour`] (qui ne voit que le type) avec
    /// les référentiels propres aux détections Vague D, identifiées par les
    /// marqueurs déposés dans `references_conformite`.
    pub fn references_pour_constat(c: &Constat) -> Vec<Reference> {
        let mut refs = Self::references_pour(&c.type_constat);
        let contient =
            |aiguille: &str| c.references_conformite.iter().any(|r| r.contains(aiguille));

        if contient("SAFE-T1102") {
            Self::pousser_ref_unique(&mut refs, SAFE_T1102.clone());
            Self::pousser_ref_unique(&mut refs, OWASP_MCP03.clone());
        }
        if contient("CVE-") {
            Self::pousser_ref_unique(&mut refs, OWASP_A06.clone());
            Self::pousser_ref_unique(&mut refs, OWASP_MCP10.clone());
            Self::pousser_ref_unique(&mut refs, ISO_A12_6_1.clone());
        }
        if contient("confused-deputy")
            || contient("RFC 8707")
            || contient("SSRF")
            || contient("CWE-918")
        {
            Self::pousser_ref_unique(&mut refs, OWASP_MCP05.clone());
        }
        if contient("ATT&CK T1567") {
            Self::pousser_ref_unique(&mut refs, OWASP_MCP09.clone());
        }
        refs
    }

    /// Libellé humain de la nature d'un constat pour l'estampillage, en
    /// distinguant les détections Vague D qui partagent un même `TypeConstat`.
    fn nature_vague_d(c: &Constat) -> String {
        let contient =
            |aiguille: &str| c.references_conformite.iter().any(|r| r.contains(aiguille));
        if contient("CVE-") {
            "Vulnérabilité CVE connue".to_string()
        } else if contient("confused-deputy") || contient("RFC 8707") {
            "OAuth confused deputy".to_string()
        } else if contient("SSRF") || contient("CWE-918") {
            "SSRF (pivot réseau)".to_string()
        } else if contient("SAFE-T1102") {
            "Cross-server shadowing".to_string()
        } else if contient("shadow-mcp") {
            "Socket fantôme (shadow MCP)".to_string()
        } else if contient("ATT&CK T1567") {
            "Trifecta létale (exfiltration runtime)".to_string()
        } else {
            format!("{:?}", c.type_constat)
        }
    }

    /// Variante constat-aware de [`Self::frameworks_markdown`] : estampille
    /// chaque constat selon sa nature fine (détections Vague D incluses) plutôt
    /// que son seul type. Les lignes au libellé + référentiels identiques sont
    /// dédupliquées. C'est cette variante qu'utilise le rapport, afin que les
    /// CVE / OAuth-SSRF / cross-server shadowing / trifecta apparaissent.
    pub fn frameworks_markdown_constats(constats: &[Constat]) -> String {
        let mut lignes: Vec<String> = Vec::new();
        lignes.push(format!(
            "## Correspondances multi-référentiels (table v{})\n",
            VERSION_TABLE
        ));
        lignes.push(
            "| Nature du constat | Référentiels (SAFE-MCP / OWASP MCP / ASI / MITRE / CWE) |"
                .to_string(),
        );
        lignes.push(
            "|-------------------|----------------------------------------------------------|"
                .to_string(),
        );

        let mut vues: Vec<String> = Vec::new();
        for c in constats {
            let ids = Self::references_frameworks_constat(c);
            if ids.is_empty() {
                continue;
            }
            let libelle = Self::nature_vague_d(c);
            // Déduplication par (libellé, estampillage) : une nature donnée
            // n'apparaît qu'une fois.
            let cle = format!("{}|{}", libelle, ids.join(","));
            if vues.contains(&cle) {
                continue;
            }
            vues.push(cle);
            lignes.push(format!("| {} | {} |", libelle, ids.join(", ")));
        }

        lignes.join("\n")
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
                justification: "Détecteur Exfiltration (paramètres vers une destination externe) renforcé par la trifecta létale runtime (entrée non fiable + lecture secret + écriture externe, ATT&CK T1567).",
            },
            CouvertureCategorie {
                cadre: "OWASP MCP",
                identifiant: "MCP05",
                titre: "Élévation de privilèges / confused deputy",
                niveau: Partiel,
                justification: "Contrôles statiques OAuth/SSRF sur les serveurs HTTP (confused deputy RFC 8707, SSRF CWE-918) ; les chaînes de privilèges effectives de l'agent restent hors périmètre.",
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
                justification: "Détecteurs RugPull et Sosie (changement de comportement, usurpation d'empreinte) et appariement de CVE connues sur les paquets (composants vulnérables, OWASP A06).",
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
                justification: "Couvert indirectement via Poisoning, cross-server shadowing (SAFE-T1102) et Exfiltration sur la surface MCP.",
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

    // --- Vague D — estampillage affiné par la nature -----------------------

    fn constat_avec_refs(t: TypeConstat, refs: &[&str]) -> Constat {
        Constat {
            id: uuid::Uuid::new_v4(),
            serveur_id: uuid::Uuid::new_v4(),
            outil_nom: None,
            type_constat: t,
            severite: Severite::Haute,
            titre: "test".to_string(),
            detail: String::new(),
            diff: None,
            references_conformite: refs.iter().map(|s| s.to_string()).collect(),
            horodatage: chrono::Utc::now(),
            etat: sentinel_protocol::EtatConstat::Ouvert,
        }
    }

    #[test]
    fn frameworks_constat_cve_supply_chain() {
        // Une CVE (TypeConstat::Autre) est mappée vers la chaîne d'appro.
        let c = constat_avec_refs(TypeConstat::Autre, &["CVE-2025-49596", "GHSA-xxxx"]);
        let ids = MoteurConformite::references_frameworks_constat(&c);
        assert!(ids.contains(&"A06"), "CVE → OWASP A06, obtenu : {:?}", ids);
        assert!(ids.contains(&"MCP10"), "CVE → MCP10, obtenu : {:?}", ids);
        assert!(ids.contains(&"ATT&CK T1195"), "CVE → T1195, obtenu : {:?}", ids);
    }

    #[test]
    fn frameworks_constat_cross_server_shadowing() {
        let c = constat_avec_refs(
            TypeConstat::Poisoning,
            &["SAFE-T1102", "SAFE-T1001", "OWASP MCP03"],
        );
        let ids = MoteurConformite::references_frameworks_constat(&c);
        assert!(ids.contains(&"SAFE-T1102"), "→ SAFE-T1102, obtenu : {:?}", ids);
        assert!(ids.contains(&"MCP03"), "→ MCP03, obtenu : {:?}", ids);
    }

    #[test]
    fn frameworks_constat_oauth_ssrf_confused_deputy() {
        let oauth = constat_avec_refs(
            TypeConstat::Autre,
            &["OWASP MCP", "OAuth", "confused-deputy", "RFC 8707"],
        );
        assert!(
            MoteurConformite::references_frameworks_constat(&oauth).contains(&"MCP05"),
            "OAuth confused deputy → MCP05"
        );
        let ssrf = constat_avec_refs(TypeConstat::Autre, &["OWASP MCP", "SSRF", "CWE-918"]);
        let ids = MoteurConformite::references_frameworks_constat(&ssrf);
        assert!(ids.contains(&"MCP05"), "SSRF → MCP05, obtenu : {:?}", ids);
        assert!(ids.contains(&"CWE-918"), "SSRF → CWE-918, obtenu : {:?}", ids);
    }

    #[test]
    fn frameworks_constat_trifecta_letale() {
        let c = constat_avec_refs(
            TypeConstat::Exfiltration,
            &["SAFE-T1201", "OWASP MCP09", "ATT&CK T1567"],
        );
        let ids = MoteurConformite::references_frameworks_constat(&c);
        assert!(ids.contains(&"ATT&CK T1567"), "→ T1567, obtenu : {:?}", ids);
        assert!(ids.contains(&"MCP09"), "trifecta → MCP09, obtenu : {:?}", ids);
    }

    #[test]
    fn frameworks_constat_socket_fantome_via_type() {
        // Le socket fantôme est un ShadowMcp : déjà couvert par le type seul.
        let c = constat_avec_refs(TypeConstat::ShadowMcp, &["OWASP MCP09", "shadow-mcp"]);
        let ids = MoteurConformite::references_frameworks_constat(&c);
        assert!(ids.contains(&"MCP09"), "socket fantôme → MCP09, obtenu : {:?}", ids);
        assert_eq!(
            MoteurConformite::nature_vague_d(&c),
            "Socket fantôme (shadow MCP)"
        );
    }

    #[test]
    fn references_pour_constat_cve_porte_a06_et_mcp10() {
        let c = constat_avec_refs(TypeConstat::Autre, &["CVE-2025-49596"]);
        let refs = MoteurConformite::references_pour_constat(&c);
        let ids: Vec<&str> = refs.iter().map(|r| r.identifiant).collect();
        assert!(ids.contains(&"A06"), "obtenu : {:?}", ids);
        assert!(ids.contains(&"MCP10"), "obtenu : {:?}", ids);
    }

    #[test]
    fn frameworks_markdown_constats_distingue_les_natures_autre() {
        // Deux constats Autre de natures différentes ne doivent pas être
        // collapsés (contrairement à la dédup par type).
        let cve = constat_avec_refs(TypeConstat::Autre, &["CVE-2025-49596"]);
        let ssrf = constat_avec_refs(TypeConstat::Autre, &["SSRF", "CWE-918"]);
        let md = MoteurConformite::frameworks_markdown_constats(&[cve, ssrf]);
        assert!(md.contains("Vulnérabilité CVE connue"), "md :\n{}", md);
        assert!(md.contains("SSRF (pivot réseau)"), "md :\n{}", md);
    }
}
