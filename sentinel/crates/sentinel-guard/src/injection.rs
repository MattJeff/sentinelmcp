//! Injection / éjection de sentinel-guard dans une config client MCP.
//!
//! `inject_config` réécrit chaque entrée stdio (`command` + `args`)
//! d'un fichier de config client (clé `mcpServers`, top-level et
//! `projects.<chemin>.mcpServers`) pour faire passer le serveur par le
//! binaire sentinel-guard :
//!
//! ```text
//! command → chemin du binaire sentinel-guard
//! args    → ["--", command, ...args]
//! ```
//!
//! Une sauvegarde `<fichier>.sentinel.bak` est créée au premier passage
//! (jamais écrasée). Les deux opérations sont idempotentes : ré-injecter
//! une config déjà injectée (ou ré-éjecter une config propre) ne change
//! rien. Les entrées sans `command` (serveurs HTTP/SSE) sont ignorées.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::Value;

/// Suffixe du fichier de sauvegarde posé avant la première réécriture.
pub const SUFFIXE_BACKUP: &str = ".sentinel.bak";

const NOM_BINAIRE: &str = "sentinel-guard";

/// Chemin du fichier de sauvegarde associé à une config.
pub fn chemin_backup(config: &Path) -> PathBuf {
    PathBuf::from(format!("{}{}", config.display(), SUFFIXE_BACKUP))
}

/// `true` si la commande pointe déjà sur un binaire sentinel-guard.
/// Découpe manuellement sur `/` et `\` pour reconnaître aussi les
/// chemins Windows quel que soit l'OS hôte.
fn est_commande_guard(command: &str) -> bool {
    let nom = command.rsplit(['/', '\\']).next().unwrap_or(command);
    nom == NOM_BINAIRE || nom == "sentinel-guard.exe"
}

/// Applique `f` à chaque bloc `mcpServers` du document : top-level puis
/// `projects.<chemin>.mcpServers` (convention `.claude.json`).
fn pour_chaque_bloc<F>(racine: &mut Value, mut f: F)
where
    F: FnMut(&mut serde_json::Map<String, Value>),
{
    if let Some(bloc) = racine.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        f(bloc);
    }
    if let Some(projets) = racine.get_mut("projects").and_then(|v| v.as_object_mut()) {
        for (_chemin, projet) in projets.iter_mut() {
            if let Some(bloc) = projet.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
                f(bloc);
            }
        }
    }
}

fn lire_config(path: &Path) -> Result<Value> {
    let contenu = fs::read_to_string(path)
        .with_context(|| format!("lecture de la config {path:?}"))?;
    serde_json::from_str(&contenu).with_context(|| format!("parsing JSON de {path:?}"))
}

fn ecrire_config(path: &Path, racine: &Value) -> Result<()> {
    let contenu = serde_json::to_string_pretty(racine)?;
    fs::write(path, contenu).with_context(|| format!("écriture de la config {path:?}"))
}

/// Réécrit la config pour faire passer chaque serveur stdio par
/// `chemin_guard`. Retourne le nombre d'entrées modifiées (0 si la
/// config était déjà entièrement injectée — idempotence). La sauvegarde
/// `.sentinel.bak` n'est créée que si quelque chose change, et n'est
/// jamais écrasée.
pub fn inject_config(path: impl AsRef<Path>, chemin_guard: &str) -> Result<usize> {
    let path = path.as_ref();
    let mut racine = lire_config(path)?;
    let mut modifies = 0usize;

    pour_chaque_bloc(&mut racine, |bloc| {
        for (_nom, entree) in bloc.iter_mut() {
            let Some(obj) = entree.as_object_mut() else { continue };
            let Some(command) = obj
                .get("command")
                .and_then(|c| c.as_str())
                .map(str::to_string)
            else {
                continue;
            };
            if command.is_empty() || est_commande_guard(&command) {
                continue;
            }
            let anciens_args = obj
                .get("args")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            let mut nouveaux_args = vec![Value::String("--".into()), Value::String(command)];
            nouveaux_args.extend(anciens_args);
            obj.insert("command".into(), Value::String(chemin_guard.to_string()));
            obj.insert("args".into(), Value::Array(nouveaux_args));
            modifies += 1;
        }
    });

    if modifies > 0 {
        let backup = chemin_backup(path);
        if !backup.exists() {
            fs::copy(path, &backup)
                .with_context(|| format!("création de la sauvegarde {backup:?}"))?;
        }
        ecrire_config(path, &racine)?;
    }
    Ok(modifies)
}

/// Opération inverse : restaure `command`/`args` d'origine pour chaque
/// entrée passant par sentinel-guard, en relisant la commande réelle
/// après le séparateur `--`. Retourne le nombre d'entrées restaurées
/// (0 si rien à faire — idempotence). La sauvegarde `.sentinel.bak`
/// est laissée en place (ceinture et bretelles).
pub fn eject_config(path: impl AsRef<Path>) -> Result<usize> {
    let path = path.as_ref();
    let mut racine = lire_config(path)?;
    let mut modifies = 0usize;

    pour_chaque_bloc(&mut racine, |bloc| {
        for (_nom, entree) in bloc.iter_mut() {
            let Some(obj) = entree.as_object_mut() else { continue };
            let Some(command) = obj.get("command").and_then(|c| c.as_str()) else {
                continue;
            };
            if !est_commande_guard(command) {
                continue;
            }
            let args = obj
                .get("args")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            // La vraie commande est le premier token après `--` (les
            // tokens avant sont des flags du garde : --db, --block, …).
            let Some(pos) = args.iter().position(|a| a.as_str() == Some("--")) else {
                continue;
            };
            let Some(commande_reelle) = args.get(pos + 1).and_then(|a| a.as_str()) else {
                continue;
            };
            let args_reels: Vec<Value> = args[pos + 2..].to_vec();
            obj.insert("command".into(), Value::String(commande_reelle.to_string()));
            obj.insert("args".into(), Value::Array(args_reels));
            modifies += 1;
        }
    });

    if modifies > 0 {
        ecrire_config(path, &racine)?;
    }
    Ok(modifies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ecrire_fichier(dir: &Path, nom: &str, v: &Value) -> PathBuf {
        let p = dir.join(nom);
        fs::write(&p, serde_json::to_string_pretty(v).unwrap()).unwrap();
        p
    }

    fn config_exemple() -> Value {
        json!({
            "mcpServers": {
                "fichiers": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "distant": { "url": "https://mcp.example.com/sse" }
            },
            "projects": {
                "/Users/x/projet": {
                    "mcpServers": {
                        "temps": { "command": "uvx", "args": ["mcp-server-time"] }
                    }
                }
            },
            "autreCle": true
        })
    }

    #[test]
    fn inject_reecrit_command_et_args_avec_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ecrire_fichier(tmp.path(), "config.json", &config_exemple());

        let n = inject_config(&cfg, "/opt/sentinel/sentinel-guard").unwrap();
        assert_eq!(n, 2, "deux entrées stdio (user + projet)");

        let racine: Value = serde_json::from_str(&fs::read_to_string(&cfg).unwrap()).unwrap();
        let fichiers = &racine["mcpServers"]["fichiers"];
        assert_eq!(fichiers["command"], json!("/opt/sentinel/sentinel-guard"));
        assert_eq!(
            fichiers["args"],
            json!(["--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"])
        );
        let temps = &racine["projects"]["/Users/x/projet"]["mcpServers"]["temps"];
        assert_eq!(temps["command"], json!("/opt/sentinel/sentinel-guard"));
        assert_eq!(temps["args"], json!(["--", "uvx", "mcp-server-time"]));
        // L'entrée HTTP n'est pas touchée, les autres clés non plus.
        assert_eq!(racine["mcpServers"]["distant"], json!({"url": "https://mcp.example.com/sse"}));
        assert_eq!(racine["autreCle"], json!(true));
        // Backup créé et identique à l'original.
        let backup = chemin_backup(&cfg);
        assert!(backup.exists());
        let sauve: Value = serde_json::from_str(&fs::read_to_string(&backup).unwrap()).unwrap();
        assert_eq!(sauve, config_exemple());
    }

    #[test]
    fn inject_est_idempotent_et_ne_touche_pas_le_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ecrire_fichier(tmp.path(), "config.json", &config_exemple());

        assert_eq!(inject_config(&cfg, "/opt/sentinel-guard").unwrap(), 2);
        let apres_premier = fs::read_to_string(&cfg).unwrap();
        let backup_avant = fs::read_to_string(chemin_backup(&cfg)).unwrap();

        assert_eq!(inject_config(&cfg, "/opt/sentinel-guard").unwrap(), 0);
        assert_eq!(fs::read_to_string(&cfg).unwrap(), apres_premier);
        assert_eq!(fs::read_to_string(chemin_backup(&cfg)).unwrap(), backup_avant);
    }

    #[test]
    fn eject_restaure_la_config_d_origine() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ecrire_fichier(tmp.path(), "config.json", &config_exemple());

        inject_config(&cfg, "/opt/sentinel-guard").unwrap();
        assert_eq!(eject_config(&cfg).unwrap(), 2);

        let racine: Value = serde_json::from_str(&fs::read_to_string(&cfg).unwrap()).unwrap();
        assert_eq!(racine, config_exemple());
    }

    #[test]
    fn eject_est_idempotent_sur_config_propre() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ecrire_fichier(tmp.path(), "config.json", &config_exemple());
        assert_eq!(eject_config(&cfg).unwrap(), 0);
        let racine: Value = serde_json::from_str(&fs::read_to_string(&cfg).unwrap()).unwrap();
        assert_eq!(racine, config_exemple());
    }

    #[test]
    fn eject_gere_les_flags_du_garde_avant_le_separateur() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ecrire_fichier(
            tmp.path(),
            "config.json",
            &json!({
                "mcpServers": {
                    "s": {
                        "command": "/opt/sentinel-guard",
                        "args": ["--db", "/tmp/x.db", "--block", "--", "npx", "-y", "pkg"]
                    }
                }
            }),
        );
        assert_eq!(eject_config(&cfg).unwrap(), 1);
        let racine: Value = serde_json::from_str(&fs::read_to_string(&cfg).unwrap()).unwrap();
        assert_eq!(racine["mcpServers"]["s"]["command"], json!("npx"));
        assert_eq!(racine["mcpServers"]["s"]["args"], json!(["-y", "pkg"]));
    }

    #[test]
    fn est_commande_guard_reconnait_chemins_et_exe() {
        assert!(est_commande_guard("/usr/local/bin/sentinel-guard"));
        assert!(est_commande_guard("sentinel-guard"));
        assert!(est_commande_guard("C:\\Sentinel\\sentinel-guard.exe"));
        assert!(!est_commande_guard("npx"));
        assert!(!est_commande_guard("/usr/bin/python3"));
    }
}
