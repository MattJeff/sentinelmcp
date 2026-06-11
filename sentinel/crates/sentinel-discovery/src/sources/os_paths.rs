//! Résolution des chemins de configuration par OS pour les sources de
//! discovery.
//!
//! Chaque source expose une fonction pure `chemins_*_candidats(&ContexteOs)`
//! qui retourne ses chemins candidats **sans** dépendre de `cfg!` — l'OS est
//! un paramètre explicite ([`OsCible`]) et le home dir est injecté. Cela rend
//! les chemins Windows/Linux testables depuis n'importe quelle machine.
//!
//! La sélection de l'OS réel se fait en un seul endroit :
//! [`OsCible::courant`] (via `cfg!(target_os = …)`), utilisé par les
//! implémentations `SourceClient::detecter`.

use std::path::PathBuf;

/// OS cible pour la résolution des chemins de config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsCible {
    MacOs,
    Windows,
    Linux,
}

impl OsCible {
    /// OS de la machine courante (seul point d'usage de `cfg!`).
    pub fn courant() -> Self {
        if cfg!(target_os = "windows") {
            OsCible::Windows
        } else if cfg!(target_os = "macos") {
            OsCible::MacOs
        } else {
            OsCible::Linux
        }
    }

    /// Les trois OS supportés — pratique pour les tests exhaustifs.
    pub const TOUS: [OsCible; 3] = [OsCible::MacOs, OsCible::Windows, OsCible::Linux];
}

/// Contexte d'environnement injectable : home dir + overrides des variables
/// d'environnement pertinentes (`XDG_CONFIG_HOME`, `%APPDATA%`,
/// `%LOCALAPPDATA%`). Les valeurs absentes retombent sur les défauts
/// standards dérivés du home.
#[derive(Debug, Clone)]
pub struct ContexteOs {
    pub os: OsCible,
    pub home: PathBuf,
    /// Override de `$XDG_CONFIG_HOME` (Linux). Défaut : `<home>/.config`.
    pub xdg_config_home: Option<PathBuf>,
    /// Override de `%APPDATA%` (Windows). Défaut : `<home>/AppData/Roaming`.
    pub appdata: Option<PathBuf>,
    /// Override de `%LOCALAPPDATA%` (Windows). Défaut : `<home>/AppData/Local`.
    pub local_appdata: Option<PathBuf>,
}

impl ContexteOs {
    /// Contexte « pur » : OS + home injectés, défauts standards pour le reste.
    pub fn nouveau(os: OsCible, home: impl Into<PathBuf>) -> Self {
        Self {
            os,
            home: home.into(),
            xdg_config_home: None,
            appdata: None,
            local_appdata: None,
        }
    }

    /// Contexte réel de la machine courante : OS via `cfg!`, home via `dirs`,
    /// et variables d'environnement honorées quand elles sont définies.
    pub fn courant() -> Option<Self> {
        let mut ctx = Self::nouveau(OsCible::courant(), dirs::home_dir()?);
        ctx.xdg_config_home = env_path("XDG_CONFIG_HOME");
        ctx.appdata = env_path("APPDATA");
        ctx.local_appdata = env_path("LOCALAPPDATA");
        Some(ctx)
    }

    pub fn avec_xdg_config_home(mut self, p: impl Into<PathBuf>) -> Self {
        self.xdg_config_home = Some(p.into());
        self
    }

    pub fn avec_appdata(mut self, p: impl Into<PathBuf>) -> Self {
        self.appdata = Some(p.into());
        self
    }

    pub fn avec_local_appdata(mut self, p: impl Into<PathBuf>) -> Self {
        self.local_appdata = Some(p.into());
        self
    }

    /// `%APPDATA%` (Roaming) effectif.
    pub fn dossier_appdata(&self) -> PathBuf {
        self.appdata
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Roaming"))
    }

    /// `%LOCALAPPDATA%` effectif.
    pub fn dossier_local_appdata(&self) -> PathBuf {
        self.local_appdata
            .clone()
            .unwrap_or_else(|| self.home.join("AppData").join("Local"))
    }

    /// `$XDG_CONFIG_HOME` effectif (défaut `~/.config`).
    pub fn dossier_xdg_config(&self) -> PathBuf {
        self.xdg_config_home
            .clone()
            .unwrap_or_else(|| self.home.join(".config"))
    }

    /// Racine des configs applicatives selon l'OS :
    /// * macOS   → `~/Library/Application Support`
    /// * Windows → `%APPDATA%`
    /// * Linux   → `$XDG_CONFIG_HOME` (défaut `~/.config`)
    pub fn dossier_config_apps(&self) -> PathBuf {
        match self.os {
            OsCible::MacOs => self.home.join("Library").join("Application Support"),
            OsCible::Windows => self.dossier_appdata(),
            OsCible::Linux => self.dossier_xdg_config(),
        }
    }

    /// Racine des données applicatives selon l'OS :
    /// * macOS   → `~/Library/Application Support`
    /// * Windows → `%LOCALAPPDATA%`
    /// * Linux   → `~/.local/share`
    pub fn dossier_data_apps(&self) -> PathBuf {
        match self.os {
            OsCible::MacOs => self.home.join("Library").join("Application Support"),
            OsCible::Windows => self.dossier_local_appdata(),
            OsCible::Linux => self.home.join(".local").join("share"),
        }
    }

    /// Variantes Linux du dossier de config : `$XDG_CONFIG_HOME` puis
    /// `~/.config` si différent (dédupliqué).
    pub fn dossiers_config_linux(&self) -> Vec<PathBuf> {
        let mut out = vec![self.dossier_xdg_config()];
        pousser_unique(&mut out, self.home.join(".config"));
        out
    }
}

/// Ajoute `p` à `v` seulement s'il n'y est pas déjà.
pub fn pousser_unique(v: &mut Vec<PathBuf>, p: PathBuf) {
    if !v.contains(&p) {
        v.push(p);
    }
}

fn env_path(var: &str) -> Option<PathBuf> {
    match std::env::var(var) {
        Ok(s) if !s.trim().is_empty() => Some(PathBuf::from(s)),
        _ => None,
    }
}

/// Premier candidat existant, sinon le premier de la liste (pour garder un
/// chemin "attendu" à afficher dans les notes quand rien n'existe).
pub fn premier_existant_ou_premier(candidats: &[PathBuf]) -> Option<PathBuf> {
    candidats
        .iter()
        .find(|p| p.exists())
        .or_else(|| candidats.first())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defauts_windows_derives_du_home() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice");
        assert_eq!(
            ctx.dossier_appdata(),
            PathBuf::from("C:/Users/alice/AppData/Roaming")
        );
        assert_eq!(
            ctx.dossier_local_appdata(),
            PathBuf::from("C:/Users/alice/AppData/Local")
        );
        assert_eq!(
            ctx.dossier_config_apps(),
            PathBuf::from("C:/Users/alice/AppData/Roaming")
        );
    }

    #[test]
    fn overrides_env_windows() {
        let ctx = ContexteOs::nouveau(OsCible::Windows, "C:/Users/alice")
            .avec_appdata("D:/Roaming")
            .avec_local_appdata("D:/Local");
        assert_eq!(ctx.dossier_appdata(), PathBuf::from("D:/Roaming"));
        assert_eq!(ctx.dossier_local_appdata(), PathBuf::from("D:/Local"));
    }

    #[test]
    fn defauts_linux_xdg() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob");
        assert_eq!(
            ctx.dossier_config_apps(),
            PathBuf::from("/home/bob/.config")
        );
        assert_eq!(
            ctx.dossier_data_apps(),
            PathBuf::from("/home/bob/.local/share")
        );
        // XDG défini : il prime, mais ~/.config reste en fallback dédupliqué.
        let ctx = ctx.avec_xdg_config_home("/home/bob/xdg");
        assert_eq!(
            ctx.dossiers_config_linux(),
            vec![
                PathBuf::from("/home/bob/xdg"),
                PathBuf::from("/home/bob/.config")
            ]
        );
    }

    #[test]
    fn linux_xdg_egal_config_deduplique() {
        let ctx = ContexteOs::nouveau(OsCible::Linux, "/home/bob")
            .avec_xdg_config_home("/home/bob/.config");
        assert_eq!(
            ctx.dossiers_config_linux(),
            vec![PathBuf::from("/home/bob/.config")]
        );
    }

    #[test]
    fn defauts_macos() {
        let ctx = ContexteOs::nouveau(OsCible::MacOs, "/Users/carol");
        assert_eq!(
            ctx.dossier_config_apps(),
            PathBuf::from("/Users/carol/Library/Application Support")
        );
    }

    #[test]
    fn os_courant_est_un_des_trois() {
        assert!(OsCible::TOUS.contains(&OsCible::courant()));
    }
}
