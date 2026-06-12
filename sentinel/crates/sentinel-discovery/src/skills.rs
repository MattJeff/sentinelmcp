//! Découverte des **skills** et **agents** (sub-agents) installés sur la
//! machine — gap n°2 de `docs/COMPARISON.md` (couverture skills/agents,
//! la surface d'attaque qui croît le plus vite).
//!
//! Surface couverte :
//!   * **scope utilisateur** :
//!       - `~/.claude/skills/<skill>/SKILL.md`   (Claude Code / Claude Desktop)
//!       - `~/.claude/agents/*.md`               (sub-agents Claude Code)
//!       - `~/.agents/skills/<skill>/SKILL.md`   (convention multi-agents)
//!       - `~/.codex/skills/<skill>/SKILL.md`    (OpenAI Codex CLI)
//!   * **scope projet** — racines découvertes via les clés
//!     `projects.<chemin>` de `~/.claude.json` (la liste des projets connus
//!     de Claude Code) plus les dossiers à un niveau sous le home :
//!       - `<projet>/.claude/skills/<skill>/SKILL.md`
//!       - `<projet>/.claude/agents/*.md`
//!       - `<projet>/.agents/skills/<skill>/SKILL.md`
//!   * **scope extension** (plugins Claude Code) :
//!       - `~/.claude/plugins/**/skills/<skill>/SKILL.md`
//!       - `~/.claude/plugins/**/agents/*.md`
//!
//! Chaque artefact est parsé (frontmatter YAML + corps Markdown), puis son
//! contenu **intégral** (frontmatter compris) passe dans
//! [`InspecteurPoisoning::inspecter_texte`] (crate `sentinel-detect`) pour
//! détecter le poisoning de skills : instructions cachées, exfiltration de
//! secrets, caractères invisibles, …
//!
//! La sortie ([`SkillDecouvert`]) est rattachée au modèle de découverte
//! existant : chaque skill porte le [`ClientKind`] auquel il appartient et
//! [`rattacher_aux_clients`] les agrège dans `ClientDecouvert.skills`
//! (champ `#[serde(default)]`, rétrocompatible côté UI).

use crate::model::{ClientDecouvert, ClientKind};
use crate::sources::os_paths::ContexteOs;
use sentinel_detect::InspecteurPoisoning;
use sentinel_protocol::Severite;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Modèle
// ---------------------------------------------------------------------------

/// Nature de l'artefact découvert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeArtefactSkill {
    /// Un skill : dossier contenant un `SKILL.md` (frontmatter + instructions).
    Skill,
    /// Un agent / sub-agent : fichier `.md` autonome (frontmatter + prompt système).
    Agent,
}

/// Portée de déclaration d'un skill ou agent.
///
/// Miroir de `ScopeServeur` (sentinel-protocol) étendu du variant
/// `Extension` — défini localement pour ne pas toucher aux autres crates.
/// Même pattern serde `tag = "kind"` pour une wire representation
/// cohérente côté UI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ScopeSkill {
    /// Scope utilisateur (`~/.claude/skills`, `~/.agents/skills`, …).
    User,
    /// Scope projet (`<projet>/.claude/skills`, `<projet>/.agents/skills`, …).
    Project { path: String },
    /// Scope extension / plugin (`~/.claude/plugins/**`).
    Extension { plugin: String },
}

impl Default for ScopeSkill {
    fn default() -> Self {
        ScopeSkill::User
    }
}

/// Constat de poisoning sur le texte d'un skill/agent (forme sérialisable
/// du tuple retourné par `InspecteurPoisoning::inspecter_texte`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstatSkillTexte {
    /// Nom du pattern déclenché.
    pub pattern: String,
    /// Catégorie du pattern (injection-prompt, exfiltration-secrets, …).
    pub categorie: String,
    /// Extrait contextuel du texte ayant déclenché la correspondance.
    pub extrait: String,
    /// Sévérité héritée du pattern.
    pub severite: Severite,
}

/// Un skill ou agent découvert sur disque.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDecouvert {
    /// Nom de l'artefact (frontmatter `name`, sinon nom du dossier/fichier).
    pub nom: String,
    /// Description issue du frontmatter, si présente.
    pub description: Option<String>,
    /// Skill ou agent.
    pub type_artefact: TypeArtefactSkill,
    /// Portée de déclaration (user / project / extension).
    pub scope: ScopeSkill,
    /// Chemin absolu du fichier `SKILL.md` ou `.md` d'agent.
    pub chemin: PathBuf,
    /// Client AI auquel l'artefact appartient.
    pub client: ClientKind,
    /// Frontmatter YAML aplati (valeurs stringifiées) — affichage UI sélectif.
    #[serde(default)]
    pub frontmatter: BTreeMap<String, String>,
    /// Constats de poisoning détectés dans le contenu intégral.
    #[serde(default)]
    pub constats_poisoning: Vec<ConstatSkillTexte>,
    /// Notes brutes pour l'UI ("frontmatter non parseable", …).
    #[serde(default)]
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Chemins candidats (fonctions pures, testables sur tous les OS)
// ---------------------------------------------------------------------------

/// Dossiers de skills au scope utilisateur : `(dossier, client propriétaire)`.
pub fn dossiers_skills_utilisateur(ctx: &ContexteOs) -> Vec<(PathBuf, ClientKind)> {
    vec![
        (ctx.home.join(".claude").join("skills"), ClientKind::ClaudeCodeCli),
        (ctx.home.join(".agents").join("skills"), ClientKind::Autre),
        (ctx.home.join(".codex").join("skills"), ClientKind::Codex),
    ]
}

/// Dossiers d'agents au scope utilisateur : `(dossier, client propriétaire)`.
pub fn dossiers_agents_utilisateur(ctx: &ContexteOs) -> Vec<(PathBuf, ClientKind)> {
    vec![(ctx.home.join(".claude").join("agents"), ClientKind::ClaudeCodeCli)]
}

/// Dossier des plugins Claude Code (scope extension).
pub fn dossier_plugins(ctx: &ContexteOs) -> PathBuf {
    ctx.home.join(".claude").join("plugins")
}

/// Racines de projets à inspecter pour les scopes projet.
///
/// Deux sources, dédupliquées :
///   1. les clés `projects.<chemin>` de `~/.claude.json` (liste des projets
///      réellement ouverts dans Claude Code) ;
///   2. les dossiers à un niveau sous le home qui contiennent `.claude/` ou
///      `.agents/` (même heuristique que le scan `.mcp.json` de la source
///      claude-code-cli). Les dossiers cachés (`.claude`, `.codex`, …) sont
///      exclus pour ne pas re-traiter les scopes utilisateur comme projets.
pub fn racines_projets(home: &Path) -> Vec<PathBuf> {
    let mut vues: BTreeSet<PathBuf> = BTreeSet::new();
    let mut out: Vec<PathBuf> = Vec::new();

    // 1. Clés `projects` de ~/.claude.json.
    let claude_json = home.join(".claude.json");
    if let Ok(raw) = std::fs::read_to_string(&claude_json) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(projects) = value.get("projects").and_then(|v| v.as_object()) {
                for chemin in projects.keys() {
                    let p = PathBuf::from(chemin);
                    if p.is_dir() && vues.insert(p.clone()) {
                        out.push(p);
                    }
                }
            }
        }
    }

    // 2. Dossiers visibles à un niveau sous le home.
    if let Ok(rd) = std::fs::read_dir(home) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let nom = entry.file_name().to_string_lossy().to_string();
            if nom.starts_with('.') {
                continue;
            }
            let interessant = p.join(".claude").is_dir() || p.join(".agents").is_dir();
            if interessant && vues.insert(p.clone()) {
                out.push(p);
            }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Frontmatter YAML
// ---------------------------------------------------------------------------

/// Sépare le frontmatter YAML (`--- … ---` en tête de fichier) du corps
/// Markdown et l'aplatit en `clé → valeur stringifiée`.
///
/// Retourne `(frontmatter, corps, erreur_de_parse)`. Un fichier sans
/// frontmatter (ou avec un frontmatter non parseable) n'est jamais rejeté :
/// le corps complet est conservé et l'erreur éventuelle remontée en note.
pub fn parser_frontmatter(contenu: &str) -> (BTreeMap<String, String>, String, Option<String>) {
    let mut fm = BTreeMap::new();

    let reste = match contenu.strip_prefix("---") {
        Some(r) if r.starts_with('\n') || r.starts_with("\r\n") => r,
        _ => return (fm, contenu.to_string(), None),
    };

    // Chercher la ligne de fermeture `---`.
    let mut fin_yaml: Option<(usize, usize)> = None; // (début du corps, fin du yaml)
    let mut offset = 0usize;
    for ligne in reste.split_inclusive('\n') {
        if ligne.trim_end() == "---" && offset > 0 {
            fin_yaml = Some((offset + ligne.len(), offset));
            break;
        }
        offset += ligne.len();
    }
    let (debut_corps, fin) = match fin_yaml {
        Some(t) => t,
        None => return (fm, contenu.to_string(), Some("frontmatter non fermé".to_string())),
    };

    let yaml = &reste[..fin];
    let corps = reste[debut_corps..].to_string();

    match serde_yaml::from_str::<serde_yaml::Value>(yaml) {
        Ok(serde_yaml::Value::Mapping(map)) => {
            for (k, v) in map {
                let clef = match k.as_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                let valeur = match &v {
                    serde_yaml::Value::String(s) => s.clone(),
                    serde_yaml::Value::Bool(b) => b.to_string(),
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::Null => String::new(),
                    autre => serde_json::to_string(autre).unwrap_or_default(),
                };
                fm.insert(clef, valeur);
            }
            (fm, corps, None)
        }
        Ok(_) => (fm, corps, Some("frontmatter YAML inattendu (pas un mapping)".to_string())),
        Err(e) => (fm, corps, Some(format!("frontmatter non parseable: {e}"))),
    }
}

// ---------------------------------------------------------------------------
// Découvreur
// ---------------------------------------------------------------------------

/// Découvreur de skills/agents. Sans état — pattern aligné sur les autres
/// briques de la crate (`ProbeurActif`, `InspecteurRuntime`, …).
#[derive(Default)]
pub struct DecouvreurSkills;

impl DecouvreurSkills {
    /// Découverte sur la machine courante (home réel).
    pub fn decouvrir(&self) -> Vec<SkillDecouvert> {
        match ContexteOs::courant() {
            Some(ctx) => self.decouvrir_avec_contexte(&ctx),
            None => vec![],
        }
    }

    /// Variante paramétrée par le contexte OS — testable avec un home
    /// synthétique.
    pub fn decouvrir_avec_contexte(&self, ctx: &ContexteOs) -> Vec<SkillDecouvert> {
        let mut out: Vec<SkillDecouvert> = Vec::new();
        let mut vus: BTreeSet<PathBuf> = BTreeSet::new();

        // ── 1. Scope utilisateur ────────────────────────────────────────────
        for (dossier, client) in dossiers_skills_utilisateur(ctx) {
            scanner_dossier_skills(&dossier, ScopeSkill::User, client, &mut out, &mut vus);
        }
        for (dossier, client) in dossiers_agents_utilisateur(ctx) {
            scanner_dossier_agents(&dossier, ScopeSkill::User, client, &mut out, &mut vus);
        }

        // ── 2. Scope projet ─────────────────────────────────────────────────
        for racine in racines_projets(&ctx.home) {
            let scope = ScopeSkill::Project {
                path: racine.to_string_lossy().to_string(),
            };
            scanner_dossier_skills(
                &racine.join(".claude").join("skills"),
                scope.clone(),
                ClientKind::ClaudeCodeCli,
                &mut out,
                &mut vus,
            );
            scanner_dossier_agents(
                &racine.join(".claude").join("agents"),
                scope.clone(),
                ClientKind::ClaudeCodeCli,
                &mut out,
                &mut vus,
            );
            scanner_dossier_skills(
                &racine.join(".agents").join("skills"),
                scope,
                ClientKind::Autre,
                &mut out,
                &mut vus,
            );
        }

        // ── 3. Scope extension (plugins Claude Code) ────────────────────────
        scanner_plugins(&dossier_plugins(ctx), &mut out, &mut vus);

        out
    }
}

/// Rattache les skills découverts au modèle de découverte existant : chaque
/// skill rejoint le `ClientDecouvert` de son [`ClientKind`] ; si aucun client
/// de ce kind n'a été détecté par les sources, un client « porteur » est créé
/// (un skill installé sans config MCP reste une surface d'attaque à montrer).
pub fn rattacher_aux_clients(clients: &mut Vec<ClientDecouvert>, skills: Vec<SkillDecouvert>) {
    for skill in skills {
        let kind = skill.client;
        match clients.iter_mut().find(|c| c.kind == kind) {
            Some(client) => client.skills.push(skill),
            None => {
                let mut client = ClientDecouvert::nouveau(kind);
                client
                    .notes
                    .push("skills/agents détectés sans configuration MCP".to_string());
                client.skills.push(skill);
                clients.push(client);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Privé — scan des dossiers
// ---------------------------------------------------------------------------

/// Scanne un dossier de skills : chaque sous-dossier contenant un `SKILL.md`
/// est un skill.
fn scanner_dossier_skills(
    dossier: &Path,
    scope: ScopeSkill,
    client: ClientKind,
    out: &mut Vec<SkillDecouvert>,
    vus: &mut BTreeSet<PathBuf>,
) {
    let rd = match std::fs::read_dir(dossier) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let skill_md = p.join("SKILL.md");
        if skill_md.is_file() && vus.insert(skill_md.clone()) {
            if let Some(s) =
                analyser_artefact(&skill_md, TypeArtefactSkill::Skill, scope.clone(), client)
            {
                out.push(s);
            }
        }
    }
}

/// Scanne un dossier d'agents : fichiers `.md` directs + un niveau de
/// sous-dossiers (Claude Code autorise l'organisation en sous-dossiers).
fn scanner_dossier_agents(
    dossier: &Path,
    scope: ScopeSkill,
    client: ClientKind,
    out: &mut Vec<SkillDecouvert>,
    vus: &mut BTreeSet<PathBuf>,
) {
    if !dossier.is_dir() {
        return;
    }
    for entry in WalkDir::new(dossier)
        .max_depth(2)
        .into_iter()
        .filter_map(Result::ok)
    {
        let p = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if p.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let chemin = p.to_path_buf();
        if vus.insert(chemin.clone()) {
            if let Some(s) =
                analyser_artefact(&chemin, TypeArtefactSkill::Agent, scope.clone(), client)
            {
                out.push(s);
            }
        }
    }
}

/// Scanne `~/.claude/plugins` (scope extension) : tout `SKILL.md` sous un
/// composant `skills/`, tout `.md` sous un composant `agents/`. Le nom du
/// plugin est dérivé du chemin relatif (composants avant `skills`/`agents`).
fn scanner_plugins(dossier: &Path, out: &mut Vec<SkillDecouvert>, vus: &mut BTreeSet<PathBuf>) {
    if !dossier.is_dir() {
        return;
    }
    for entry in WalkDir::new(dossier)
        .max_depth(8)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let rel = match p.strip_prefix(dossier) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let composants: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();

        let nom_fichier = match composants.last() {
            Some(n) => n.as_str(),
            None => continue,
        };

        let type_artefact = if nom_fichier == "SKILL.md"
            && composants.iter().any(|c| c == "skills")
        {
            TypeArtefactSkill::Skill
        } else if nom_fichier.ends_with(".md")
            && composants.len() >= 2
            && composants[composants.len() - 2] == "agents"
        {
            TypeArtefactSkill::Agent
        } else {
            continue;
        };

        // Plugin = composants du chemin relatif avant `skills`/`agents`.
        let pivot = composants
            .iter()
            .position(|c| c == "skills" || c == "agents")
            .unwrap_or(0);
        let plugin = if pivot == 0 {
            "plugin-inconnu".to_string()
        } else {
            composants[..pivot].join("/")
        };

        let chemin = p.to_path_buf();
        if vus.insert(chemin.clone()) {
            if let Some(s) = analyser_artefact(
                &chemin,
                type_artefact,
                ScopeSkill::Extension { plugin },
                ClientKind::ClaudeCodeCli,
            ) {
                out.push(s);
            }
        }
    }
}

/// Parse un fichier de skill/agent et applique l'inspection de poisoning sur
/// son contenu intégral (frontmatter compris : un `allowed-tools` ou une
/// `description` empoisonnés doivent aussi déclencher).
fn analyser_artefact(
    chemin: &Path,
    type_artefact: TypeArtefactSkill,
    scope: ScopeSkill,
    client: ClientKind,
) -> Option<SkillDecouvert> {
    let contenu = std::fs::read_to_string(chemin).ok()?;
    let (frontmatter, _corps, erreur_fm) = parser_frontmatter(&contenu);

    // Nom : frontmatter `name`, sinon dossier (skill) ou nom de fichier (agent).
    let nom_defaut = match type_artefact {
        TypeArtefactSkill::Skill => chemin
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string()),
        TypeArtefactSkill::Agent => chemin
            .file_stem()
            .map(|n| n.to_string_lossy().to_string()),
    };
    let nom = frontmatter
        .get("name")
        .cloned()
        .filter(|s| !s.trim().is_empty())
        .or(nom_defaut)
        .unwrap_or_else(|| "inconnu".to_string());

    let description = frontmatter
        .get("description")
        .cloned()
        .filter(|s| !s.trim().is_empty());

    let constats_poisoning = InspecteurPoisoning::inspecter_texte(&contenu)
        .into_iter()
        .map(|(pattern, categorie, extrait, severite)| ConstatSkillTexte {
            pattern,
            categorie,
            extrait,
            severite,
        })
        .collect();

    let mut notes = Vec::new();
    if let Some(e) = erreur_fm {
        notes.push(e);
    }

    Some(SkillDecouvert {
        nom,
        description,
        type_artefact,
        scope,
        chemin: chemin.to_path_buf(),
        client,
        frontmatter,
        constats_poisoning,
        notes,
    })
}

// ---------------------------------------------------------------------------
// Tests unitaires (chemins + frontmatter — les scans avec fixtures vivent
// dans tests/skills.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::os_paths::OsCible;

    #[test]
    fn chemins_utilisateur_macos() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/alice");
        let skills = dossiers_skills_utilisateur(&ctx);
        assert_eq!(skills[0].0, PathBuf::from("/Users/alice/.claude/skills"));
        assert_eq!(skills[0].1, ClientKind::ClaudeCodeCli);
        assert_eq!(skills[1].0, PathBuf::from("/Users/alice/.agents/skills"));
        assert_eq!(skills[2].0, PathBuf::from("/Users/alice/.codex/skills"));
        assert_eq!(skills[2].1, ClientKind::Codex);
        let agents = dossiers_agents_utilisateur(&ctx);
        assert_eq!(agents[0].0, PathBuf::from("/Users/alice/.claude/agents"));
    }

    #[test]
    fn chemins_utilisateur_windows() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        let skills = dossiers_skills_utilisateur(&ctx);
        assert_eq!(skills[0].0, PathBuf::from("C:/Users/alice/.claude/skills"));
        assert_eq!(
            dossier_plugins(&ctx),
            PathBuf::from("C:/Users/alice/.claude/plugins")
        );
    }

    #[test]
    fn frontmatter_nominal() {
        let contenu = "---\nname: revue-code\ndescription: Relit le code\nallowed-tools: [Read, Grep]\n---\n# Corps\n";
        let (fm, corps, err) = parser_frontmatter(contenu);
        assert!(err.is_none());
        assert_eq!(fm.get("name").unwrap(), "revue-code");
        assert_eq!(fm.get("description").unwrap(), "Relit le code");
        assert_eq!(fm.get("allowed-tools").unwrap(), r#"["Read","Grep"]"#);
        assert_eq!(corps, "# Corps\n");
    }

    #[test]
    fn frontmatter_absent() {
        let contenu = "# Juste du markdown\n";
        let (fm, corps, err) = parser_frontmatter(contenu);
        assert!(fm.is_empty());
        assert_eq!(corps, contenu);
        assert!(err.is_none());
    }

    #[test]
    fn frontmatter_non_ferme() {
        let contenu = "---\nname: cassé\n# pas de fermeture\n";
        let (fm, corps, err) = parser_frontmatter(contenu);
        assert!(fm.is_empty());
        assert_eq!(corps, contenu);
        assert!(err.is_some());
    }

    #[test]
    fn frontmatter_yaml_invalide() {
        let contenu = "---\n: [pas: du yaml: valide\n---\ncorps\n";
        let (_fm, corps, err) = parser_frontmatter(contenu);
        assert_eq!(corps, "corps\n");
        assert!(err.is_some());
    }
}
