//! Moteur de règles YARA — détection hybride locale (gap n°4, docs/COMPARISON.md).
//!
//! S'appuie sur la crate `yara-x` (réimplémentation Rust officielle de
//! VirusTotal — aucune dépendance à la libyara C). Les règles sont appliquées
//! à la surface textuelle de chaque outil MCP : `description` + `inputSchema`
//! sérialisé (les descriptions imbriquées, enums, defaults et noms de
//! propriétés sont donc couverts).
//!
//! Sources de règles :
//!   - 3 règles d'exemple embarquées (poisoning pseudo-système, références à
//!     des fichiers de secrets, directive d'exfiltration réseau) ;
//!   - un répertoire configurable (`*.yar` / `*.yara`), chaque fichier compilé
//!     dans son propre namespace — un fichier invalide est ignoré avec un
//!     log d'avertissement, il ne bloque jamais le chargement des autres.
//!
//! Métadonnées de règle reconnues (toutes optionnelles) :
//!   - `description` : libellé humain repris dans le constat ;
//!   - `categorie`   : catégorie libre (defaut : `yara`) ;
//!   - `severite`    : `info|moyenne|haute|critique` (ou `low|medium|high|critical`),
//!                     défaut : `Critique`.
//!
//! Sortie : `ConstatYara` (détail local) convertible en `Constat` formel
//! (`TypeConstat::Poisoning`) via `vers_constat`, comme `InspecteurPoisoning`.

use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use sentinel_protocol::{Constat, EtatConstat, Outil, ServeurId, Severite, TypeConstat};
use tracing::warn;

/// Namespace des règles embarquées.
const NAMESPACE_EMBARQUE: &str = "sentinel-embarque";

/// Timeout appliqué à chaque scan (les textes sont courts — un timeout
/// court protège contre les règles pathologiques importées).
const TIMEOUT_SCAN: Duration = Duration::from_secs(2);

/// Règles d'exemple embarquées : poisoning + exfiltration.
const REGLES_EMBARQUEES: &str = r#"
rule MCP_Poisoning_PseudoSysteme {
    meta:
        description = "Pseudo-system tags or hidden directives in a tool's description"
        categorie = "balises_pseudo_systeme"
        severite = "critique"
        reference = "SAFE-T1001"
    strings:
        $sys1 = "[SYSTEM]" nocase
        $sys2 = "<system>" nocase
        $sys3 = "<IMPORTANT>" nocase
        $hid1 = /do not (tell|inform|mention|reveal)[^.]{0,60}(user|anyone)/ nocase
        $hid2 = /(ignore|disregard) (all |any )?(previous|prior|earlier) instructions/ nocase
    condition:
        any of them
}

rule MCP_Poisoning_FichiersSecrets {
    meta:
        description = "Reference to secret files in a tool's surface"
        categorie = "exfiltration_secrets"
        severite = "critique"
        reference = "SAFE-T1001"
    strings:
        $p1 = "~/.ssh"
        $p2 = "id_rsa"
        $p3 = /\.env\b/
        $p4 = "credentials.json"
        $p5 = "/etc/passwd"
    condition:
        any of them
}

rule MCP_Exfiltration_Reseau {
    meta:
        description = "Directive to send data to an external URL"
        categorie = "exfiltration_reseau"
        severite = "haute"
        reference = "SAFE-T1201"
    strings:
        $u1 = /(send|post|upload|forward)[^.]{0,60}https?:\/\// nocase
        $u2 = "webhook.site" nocase
        $u3 = /base64[^.]{0,40}(encode|exfiltrat)/ nocase
    condition:
        any of them
}
"#;

// ---------------------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------------------

/// Constat YARA local (avant conversion en `Constat` formel du store).
#[derive(Debug, Clone)]
pub struct ConstatYara {
    /// Nom de l'outil concerné.
    pub outil: String,
    /// Identifiant de la règle YARA déclenchée.
    pub regle: String,
    /// Namespace de la règle (`sentinel-embarque` ou nom du fichier importé).
    pub namespace: String,
    /// Catégorie (méta `categorie` de la règle, défaut : `yara`).
    pub categorie: String,
    /// Description humaine (méta `description` de la règle).
    pub description: String,
    /// Sévérité (méta `severite` de la règle, défaut : Critique).
    pub severite: Severite,
}

/// Moteur YARA : règles compilées une fois, scannées à la demande.
pub struct MoteurYara {
    rules: yara_x::Rules,
    /// Nombre de sources compilées avec succès (embarquées = 1).
    nb_sources: usize,
}

impl MoteurYara {
    /// Construit le moteur avec uniquement les règles d'exemple embarquées.
    pub fn embarque() -> anyhow::Result<Self> {
        Self::construire(None)
    }

    /// Construit le moteur avec les règles embarquées + toutes les règles
    /// `*.yar` / `*.yara` du répertoire donné. Un répertoire absent ou un
    /// fichier invalide est ignoré avec un avertissement.
    pub fn avec_repertoire(repertoire: &Path) -> anyhow::Result<Self> {
        Self::construire(Some(repertoire))
    }

    /// Nombre de sources de règles compilées (1 = embarquées seules).
    pub fn nb_sources(&self) -> usize {
        self.nb_sources
    }

    fn construire(repertoire: Option<&Path>) -> anyhow::Result<Self> {
        let mut compiler = yara_x::Compiler::new();
        let mut nb_sources = 0usize;

        // 1. Règles embarquées — leur échec est un bug, on propage.
        compiler.new_namespace(NAMESPACE_EMBARQUE);
        compiler
            .add_source(REGLES_EMBARQUEES)
            .map_err(|e| anyhow::anyhow!("règles YARA embarquées invalides : {e}"))?;
        nb_sources += 1;

        // 2. Règles importées — best-effort, chaque fichier dans son namespace.
        if let Some(dir) = repertoire {
            match std::fs::read_dir(dir) {
                Ok(entrees) => {
                    let mut chemins: Vec<_> = entrees
                        .filter_map(|e| e.ok().map(|e| e.path()))
                        .filter(|p| {
                            matches!(
                                p.extension().and_then(|e| e.to_str()),
                                Some("yar") | Some("yara")
                            )
                        })
                        .collect();
                    chemins.sort();
                    for chemin in chemins {
                        let source = match std::fs::read_to_string(&chemin) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(chemin = %chemin.display(), erreur = %e,
                                      "yara : fichier de règles illisible, ignoré");
                                continue;
                            }
                        };
                        let ns = chemin
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("import")
                            .to_string();
                        compiler.new_namespace(&ns);
                        match compiler.add_source(source.as_str()) {
                            Ok(_) => nb_sources += 1,
                            Err(e) => {
                                warn!(chemin = %chemin.display(), erreur = %e,
                                      "yara : règle invalide, fichier ignoré");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(repertoire = %dir.display(), erreur = %e,
                          "yara : répertoire de règles inaccessible, règles embarquées seules");
                }
            }
        }

        Ok(Self {
            rules: compiler.build(),
            nb_sources,
        })
    }

    /// Inspecte un ensemble d'outils : pour chaque outil, scanne la
    /// concaténation `description + inputSchema` (JSON sérialisé) et retourne
    /// un constat par règle déclenchée.
    pub fn inspecter(&self, outils: &[Outil]) -> Vec<ConstatYara> {
        let mut constats = Vec::new();
        for outil in outils {
            let texte = Self::surface_outil(outil);
            for c in self.inspecter_texte(&texte) {
                constats.push(ConstatYara {
                    outil: outil.nom.clone(),
                    ..c
                });
            }
        }
        constats
    }

    /// Scanne un texte arbitraire. Le champ `outil` des constats est vide —
    /// rempli par `inspecter`.
    pub fn inspecter_texte(&self, texte: &str) -> Vec<ConstatYara> {
        let mut scanner = yara_x::Scanner::new(&self.rules);
        scanner.set_timeout(TIMEOUT_SCAN);
        let resultats = match scanner.scan(texte.as_bytes()) {
            Ok(r) => r,
            Err(e) => {
                warn!(erreur = %e, "yara : échec du scan");
                return Vec::new();
            }
        };
        resultats
            .matching_rules()
            .map(|regle| {
                let mut categorie = "yara".to_string();
                let mut description = String::new();
                let mut severite = Severite::Critique;
                for (clef, valeur) in regle.metadata() {
                    let valeur_str = match valeur {
                        yara_x::MetaValue::String(s) => s.to_string(),
                        yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).to_string(),
                        autre => format!("{autre:?}"),
                    };
                    match clef {
                        "categorie" | "category" => categorie = valeur_str,
                        "description" => description = valeur_str,
                        "severite" | "severity" => severite = parser_severite(&valeur_str),
                        _ => {}
                    }
                }
                ConstatYara {
                    outil: String::new(),
                    regle: regle.identifier().to_string(),
                    namespace: regle.namespace().to_string(),
                    categorie,
                    description,
                    severite,
                }
            })
            .collect()
    }

    /// Convertit un `ConstatYara` en `Constat` formel pour le store.
    pub fn vers_constat(c: &ConstatYara, serveur_id: ServeurId) -> Constat {
        Constat {
            id: crate::id_constat(&[
                "yara",
                &serveur_id.to_string(),
                &c.outil,
                &c.regle,
                &c.namespace,
                &c.categorie,
            ]),
            serveur_id,
            outil_nom: Some(c.outil.clone()),
            type_constat: TypeConstat::Poisoning,
            severite: c.severite,
            titre: format!(
                "YARA rule \"{}\" triggered — tool \"{}\" [{}]",
                c.regle, c.outil, c.categorie
            ),
            detail: format!(
                "YARA rule \"{}\" (namespace: {}, category: {}) triggered on the tool's \
                 description / inputSchema. {}",
                c.regle,
                c.namespace,
                c.categorie,
                if c.description.is_empty() {
                    "No rule description.".to_string()
                } else {
                    c.description.clone()
                }
            ),
            diff: None,
            references_conformite: vec!["SAFE-T1001".to_string(), "OWASP MCP03".to_string()],
            horodatage: Utc::now(),
            etat: EtatConstat::Ouvert,
        }
    }

    /// Surface textuelle scannée pour un outil : description + inputSchema.
    fn surface_outil(outil: &Outil) -> String {
        let mut texte = String::new();
        if let Some(desc) = &outil.description {
            texte.push_str(desc);
            texte.push('\n');
        }
        if let Ok(schema) = serde_json::to_string(&outil.input_schema) {
            texte.push_str(&schema);
        }
        texte
    }
}

/// Mappe la méta `severite` d'une règle vers `Severite` (défaut : Critique).
fn parser_severite(s: &str) -> Severite {
    match s.to_ascii_lowercase().as_str() {
        "info" | "low" | "basse" => Severite::Info,
        "moyenne" | "medium" => Severite::Moyenne,
        "haute" | "high" => Severite::Haute,
        _ => Severite::Critique,
    }
}
