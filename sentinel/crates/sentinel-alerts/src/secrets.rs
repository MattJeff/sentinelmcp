//! Coffre de secrets — trousseau OS via le crate `keyring` v3.
//!
//! Les secrets (mot de passe SMTP, token Splunk HEC, mot de passe Elastic,
//! credentials TAXII) ne doivent jamais être persistés en clair dans les
//! fichiers de config (`siem.json`, `taxii.json`, `settings.toml`).
//!
//! Convention de stockage :
//!   * service keyring : [`SERVICE_KEYRING`] (`"sentinel-mcp"`) ;
//!   * clé = nom logique du secret (ex. `"smtp_password"`,
//!     `"splunk_hec_token"`, `"elastic_password"`, `"taxii_password"`) ;
//!   * dans le fichier de config, la valeur est remplacée par la référence
//!     `"keyring:<nom>"` ([`PREFIXE_REFERENCE`]).
//!
//! Opt-out (CI / headless) : `SENTINEL_NO_KEYRING=1` désactive le trousseau
//! et conserve le comportement fichier historique (valeurs en clair).
//!
//! Le trait [`CoffreSecrets`] abstrait le backend : [`CoffreKeyring`] parle
//! au trousseau OS (Keychain macOS / Credential Manager Windows / Secret
//! Service Linux), [`CoffreMemoire`] est un backend en mémoire pour les tests.

use std::collections::HashMap;
use std::sync::Mutex;

/// Nom de service utilisé pour toutes les entrées du trousseau OS.
pub const SERVICE_KEYRING: &str = "sentinel-mcp";

/// Préfixe marquant une référence vers le trousseau dans un fichier de config.
pub const PREFIXE_REFERENCE: &str = "keyring:";

/// Variable d'environnement d'opt-out (CI / headless) : `=1` désactive le trousseau.
pub const ENV_DESACTIVATION: &str = "SENTINEL_NO_KEYRING";

/// Valeur sentinelle renvoyée au frontend à la place d'un secret existant.
/// Le backend ne renvoie **jamais** le secret en clair à l'UI ; à la
/// sauvegarde, recevoir cette sentinelle inchangée signifie « conserver le
/// secret existant ».
pub const VALEUR_MASQUEE: &str = "********";

/// `true` si la valeur est la sentinelle [`VALEUR_MASQUEE`] (secret inchangé).
pub fn est_masque(valeur: &str) -> bool {
    valeur == VALEUR_MASQUEE
}

// ─── Trait d'abstraction ─────────────────────────────────────────────────────

/// Backend de stockage des secrets.
pub trait CoffreSecrets: Send + Sync {
    /// Lit le secret `nom`. `Ok(None)` si l'entrée n'existe pas.
    fn lire(&self, nom: &str) -> anyhow::Result<Option<String>>;
    /// Écrit (crée ou remplace) le secret `nom`.
    fn ecrire(&self, nom: &str, valeur: &str) -> anyhow::Result<()>;
    /// Supprime le secret `nom`. Idempotent : une entrée absente est un `Ok`.
    fn supprimer(&self, nom: &str) -> anyhow::Result<()>;
}

// ─── Backend trousseau OS ────────────────────────────────────────────────────

/// Backend réel : trousseau de l'OS via `keyring` v3.
pub struct CoffreKeyring;

impl CoffreSecrets for CoffreKeyring {
    fn lire(&self, nom: &str) -> anyhow::Result<Option<String>> {
        let entree = keyring::Entry::new(SERVICE_KEYRING, nom)
            .map_err(|e| anyhow::anyhow!("trousseau inaccessible pour '{}': {}", nom, e))?;
        match entree.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("lecture trousseau '{}' échouée: {}", nom, e)),
        }
    }

    fn ecrire(&self, nom: &str, valeur: &str) -> anyhow::Result<()> {
        let entree = keyring::Entry::new(SERVICE_KEYRING, nom)
            .map_err(|e| anyhow::anyhow!("trousseau inaccessible pour '{}': {}", nom, e))?;
        entree
            .set_password(valeur)
            .map_err(|e| anyhow::anyhow!("écriture trousseau '{}' échouée: {}", nom, e))
    }

    fn supprimer(&self, nom: &str) -> anyhow::Result<()> {
        let entree = keyring::Entry::new(SERVICE_KEYRING, nom)
            .map_err(|e| anyhow::anyhow!("trousseau inaccessible pour '{}': {}", nom, e))?;
        match entree.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow::anyhow!(
                "suppression trousseau '{}' échouée: {}",
                nom,
                e
            )),
        }
    }
}

// ─── Backend mémoire (tests) ─────────────────────────────────────────────────

/// Backend en mémoire — destiné aux tests (pas de trousseau OS requis).
#[derive(Default)]
pub struct CoffreMemoire {
    entrees: Mutex<HashMap<String, String>>,
}

impl CoffreMemoire {
    pub fn nouveau() -> Self {
        Self::default()
    }
}

impl CoffreSecrets for CoffreMemoire {
    fn lire(&self, nom: &str) -> anyhow::Result<Option<String>> {
        Ok(self.entrees.lock().unwrap().get(nom).cloned())
    }

    fn ecrire(&self, nom: &str, valeur: &str) -> anyhow::Result<()> {
        self.entrees
            .lock()
            .unwrap()
            .insert(nom.to_string(), valeur.to_string());
        Ok(())
    }

    fn supprimer(&self, nom: &str) -> anyhow::Result<()> {
        self.entrees.lock().unwrap().remove(nom);
        Ok(())
    }
}

// ─── Activation / opt-out ────────────────────────────────────────────────────

/// Logique pure d'activation : `Some("1")` désactive, tout le reste active.
fn actif_selon(valeur_env: Option<&str>) -> bool {
    valeur_env.map(str::trim) != Some("1")
}

/// `true` sauf si `SENTINEL_NO_KEYRING=1` est posé dans l'environnement.
pub fn keyring_actif() -> bool {
    actif_selon(std::env::var(ENV_DESACTIVATION).ok().as_deref())
}

/// Retourne le coffre OS si le trousseau est actif, `None` sinon (opt-out).
pub fn coffre_actif() -> Option<Box<dyn CoffreSecrets>> {
    if keyring_actif() {
        Some(Box::new(CoffreKeyring))
    } else {
        None
    }
}

// ─── Références "keyring:<nom>" ──────────────────────────────────────────────

/// Construit la référence `"keyring:<nom>"`.
pub fn reference(nom: &str) -> String {
    format!("{}{}", PREFIXE_REFERENCE, nom)
}

/// Extrait le nom logique d'une référence, ou `None` si la valeur est en clair.
pub fn nom_depuis_reference(valeur: &str) -> Option<&str> {
    valeur.strip_prefix(PREFIXE_REFERENCE)
}

/// `true` si la valeur est une référence vers le trousseau.
pub fn est_reference(valeur: &str) -> bool {
    valeur.starts_with(PREFIXE_REFERENCE)
}

// ─── Protection / résolution ─────────────────────────────────────────────────

/// Pousse la valeur en clair dans le coffre et la remplace **en place** par la
/// référence `"keyring:<nom>"`. Retourne `true` si la valeur a changé.
///
/// Valeur vide ou déjà sous forme de référence : aucun changement.
pub fn proteger_champ(
    coffre: &dyn CoffreSecrets,
    nom: &str,
    valeur: &mut String,
) -> anyhow::Result<bool> {
    if valeur.is_empty() || est_reference(valeur) {
        return Ok(false);
    }
    coffre.ecrire(nom, valeur)?;
    *valeur = reference(nom);
    Ok(true)
}

/// Variante [`proteger_champ`] pour un champ optionnel.
pub fn proteger_option(
    coffre: &dyn CoffreSecrets,
    nom: &str,
    valeur: &mut Option<String>,
) -> anyhow::Result<bool> {
    match valeur {
        Some(v) => proteger_champ(coffre, nom, v),
        None => Ok(false),
    }
}

/// Résout **en place** une référence `"keyring:<nom>"` vers la valeur du
/// trousseau. Une valeur en clair est laissée telle quelle. Une référence
/// absente du trousseau est une erreur (le secret a été perdu).
pub fn resoudre_champ(coffre: &dyn CoffreSecrets, valeur: &mut String) -> anyhow::Result<()> {
    if let Some(nom) = nom_depuis_reference(valeur) {
        let secret = coffre.lire(nom)?.ok_or_else(|| {
            anyhow::anyhow!("secret '{}' introuvable dans le trousseau", nom)
        })?;
        *valeur = secret;
    }
    Ok(())
}

/// Variante [`resoudre_champ`] pour un champ optionnel.
pub fn resoudre_option(
    coffre: &dyn CoffreSecrets,
    valeur: &mut Option<String>,
) -> anyhow::Result<()> {
    match valeur {
        Some(v) => resoudre_champ(coffre, v),
        None => Ok(()),
    }
}

/// Variante tolérante de [`resoudre_champ`] : si la référence ne peut pas
/// être résolue (entrée supprimée du trousseau, trousseau inaccessible), le
/// champ est vidé et un avertissement est retourné au lieu d'une erreur.
/// La config reste chargeable — jamais d'échec total côté UI.
pub fn resoudre_champ_souple(coffre: &dyn CoffreSecrets, valeur: &mut String) -> Option<String> {
    let Some(nom) = nom_depuis_reference(valeur) else {
        return None;
    };
    match coffre.lire(nom) {
        Ok(Some(secret)) => {
            *valeur = secret;
            None
        }
        Ok(None) => {
            let avert = format!(
                "secret '{}' introuvable dans le trousseau — champ chargé vide, \
                 ressaisissez la valeur dans Settings",
                nom
            );
            valeur.clear();
            Some(avert)
        }
        Err(e) => {
            let avert = format!(
                "lecture trousseau '{}' échouée ({}) — champ chargé vide",
                nom, e
            );
            valeur.clear();
            Some(avert)
        }
    }
}

/// Variante [`resoudre_champ_souple`] pour un champ optionnel.
pub fn resoudre_option_souple(
    coffre: &dyn CoffreSecrets,
    valeur: &mut Option<String>,
) -> Option<String> {
    match valeur {
        Some(v) => resoudre_champ_souple(coffre, v),
        None => None,
    }
}

// ─── Purge des secrets orphelins ─────────────────────────────────────────────

/// Supprime l'entrée `nom` du trousseau lorsque la valeur associée a été
/// vidée côté config (changement de mode d'auth, mot de passe effacé).
/// Retourne `true` si une purge a été demandée. Idempotent.
pub fn purger_si_vide(
    coffre: &dyn CoffreSecrets,
    nom: &str,
    valeur: Option<&str>,
) -> anyhow::Result<bool> {
    if valeur.map_or(true, str::is_empty) {
        coffre.supprimer(nom)?;
        return Ok(true);
    }
    Ok(false)
}

// ─── Écriture vérifiée (migration sans backup en clair) ─────────────────────

/// Écrit `contenu` dans `path` de façon atomique et vérifiée : le contenu
/// passe par un fichier temporaire, est relu et comparé, puis renommé sur la
/// destination. Aucune copie `.bak` n'est créée — le contrat « jamais de
/// clair persistant sur disque » interdit de conserver une sauvegarde en
/// clair du fichier d'origine après migration vers le trousseau.
pub fn ecrire_fichier_verifie(path: &std::path::Path, contenu: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contenu)
        .map_err(|e| anyhow::anyhow!("écriture {:?} échouée: {}", tmp, e))?;
    let relu = std::fs::read_to_string(&tmp)
        .map_err(|e| anyhow::anyhow!("relecture {:?} échouée: {}", tmp, e))?;
    if relu != contenu {
        std::fs::remove_file(&tmp).ok();
        anyhow::bail!("vérification de {:?} échouée: contenu relu différent", tmp);
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow::anyhow!("renommage {:?} -> {:?} échoué: {}", tmp, path, e))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proteger_puis_resoudre_roundtrip() {
        let coffre = CoffreMemoire::nouveau();
        let mut valeur = "hec-token-secret".to_string();

        let change = proteger_champ(&coffre, "splunk_hec_token", &mut valeur).unwrap();
        assert!(change);
        assert_eq!(valeur, "keyring:splunk_hec_token");
        assert_eq!(
            coffre.lire("splunk_hec_token").unwrap().as_deref(),
            Some("hec-token-secret")
        );

        resoudre_champ(&coffre, &mut valeur).unwrap();
        assert_eq!(valeur, "hec-token-secret");
    }

    #[test]
    fn proteger_ignore_valeur_vide() {
        let coffre = CoffreMemoire::nouveau();
        let mut valeur = String::new();
        assert!(!proteger_champ(&coffre, "smtp_password", &mut valeur).unwrap());
        assert_eq!(valeur, "");
        assert!(coffre.lire("smtp_password").unwrap().is_none());
    }

    #[test]
    fn proteger_ignore_reference_existante() {
        let coffre = CoffreMemoire::nouveau();
        coffre.ecrire("taxii_password", "original").unwrap();
        let mut valeur = "keyring:taxii_password".to_string();
        assert!(!proteger_champ(&coffre, "taxii_password", &mut valeur).unwrap());
        // Le secret du trousseau n'a pas été écrasé par la référence.
        assert_eq!(
            coffre.lire("taxii_password").unwrap().as_deref(),
            Some("original")
        );
    }

    #[test]
    fn resoudre_laisse_valeur_claire_intacte() {
        let coffre = CoffreMemoire::nouveau();
        let mut valeur = "pas-une-reference".to_string();
        resoudre_champ(&coffre, &mut valeur).unwrap();
        assert_eq!(valeur, "pas-une-reference");
    }

    #[test]
    fn resoudre_echoue_si_secret_absent() {
        let coffre = CoffreMemoire::nouveau();
        let mut valeur = "keyring:fantome".to_string();
        let err = resoudre_champ(&coffre, &mut valeur).unwrap_err();
        assert!(err.to_string().contains("fantome"));
    }

    #[test]
    fn options_protegees_et_resolues() {
        let coffre = CoffreMemoire::nouveau();
        let mut absent: Option<String> = None;
        assert!(!proteger_option(&coffre, "elastic_password", &mut absent).unwrap());
        resoudre_option(&coffre, &mut absent).unwrap();
        assert!(absent.is_none());

        let mut present = Some("s3cret".to_string());
        assert!(proteger_option(&coffre, "elastic_password", &mut present).unwrap());
        assert_eq!(present.as_deref(), Some("keyring:elastic_password"));
        resoudre_option(&coffre, &mut present).unwrap();
        assert_eq!(present.as_deref(), Some("s3cret"));
    }

    #[test]
    fn resoudre_souple_vide_le_champ_si_secret_perdu() {
        let coffre = CoffreMemoire::nouveau();
        let mut valeur = "keyring:fantome".to_string();
        let avert = resoudre_champ_souple(&coffre, &mut valeur);
        assert!(avert.is_some(), "un avertissement doit être retourné");
        assert!(avert.unwrap().contains("fantome"));
        assert_eq!(valeur, "", "le champ doit être vidé, pas en erreur");

        // Valeur en clair : intacte, pas d'avertissement.
        let mut clair = "pas-une-reference".to_string();
        assert!(resoudre_champ_souple(&coffre, &mut clair).is_none());
        assert_eq!(clair, "pas-une-reference");

        // Référence résoluble : comportement nominal.
        coffre.ecrire("present", "s3cret").unwrap();
        let mut reference = "keyring:present".to_string();
        assert!(resoudre_champ_souple(&coffre, &mut reference).is_none());
        assert_eq!(reference, "s3cret");
    }

    #[test]
    fn supprimer_est_idempotent() {
        let coffre = CoffreMemoire::nouveau();
        coffre.ecrire("smtp_password", "x").unwrap();
        coffre.supprimer("smtp_password").unwrap();
        assert!(coffre.lire("smtp_password").unwrap().is_none());
        // Une seconde suppression ne doit pas échouer.
        coffre.supprimer("smtp_password").unwrap();
    }

    #[test]
    fn purger_si_vide_supprime_les_orphelins() {
        let coffre = CoffreMemoire::nouveau();
        coffre.ecrire("taxii_token", "tok").unwrap();

        // Valeur encore présente : pas de purge.
        assert!(!purger_si_vide(&coffre, "taxii_token", Some("tok")).unwrap());
        assert!(coffre.lire("taxii_token").unwrap().is_some());

        // Valeur vidée : purge.
        assert!(purger_si_vide(&coffre, "taxii_token", Some("")).unwrap());
        assert!(coffre.lire("taxii_token").unwrap().is_none());

        // Champ absent (changement de mode) : purge aussi, idempotente.
        assert!(purger_si_vide(&coffre, "taxii_token", None).unwrap());
    }

    #[test]
    fn sentinelle_masquage() {
        assert!(est_masque(VALEUR_MASQUEE));
        assert!(!est_masque(""));
        assert!(!est_masque("mot-de-passe"));
    }

    #[test]
    fn ecriture_verifiee_remplace_sans_backup() {
        let dir = std::env::temp_dir().join(format!(
            "sentinel-secrets-ecriture-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, "ancien-contenu-en-clair").unwrap();

        ecrire_fichier_verifie(&path, "{ \"pass\": \"keyring:x\" }").unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{ \"pass\": \"keyring:x\" }"
        );
        // Ni .bak ni .tmp ne doivent subsister.
        assert!(!dir.join("config.json.bak").exists());
        assert!(!dir.join("config.tmp").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn opt_out_env_desactive_le_trousseau() {
        assert!(actif_selon(None));
        assert!(actif_selon(Some("0")));
        assert!(actif_selon(Some("")));
        assert!(!actif_selon(Some("1")));
        assert!(!actif_selon(Some(" 1 ")));
    }
}
