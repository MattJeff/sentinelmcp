//! Sinks SIEM externes (Splunk HEC, Elastic, Syslog, etc.).
//!
//! Modules : `splunk` (V17), `elastic` (V18), `syslog` (V18).

pub mod splunk;
pub mod elastic;
pub mod syslog;

pub use splunk::{ClientSplunkHec, SinkError};

/// Résout une éventuelle référence trousseau `keyring:<nom>` vers le secret en
/// clair via le coffre fourni. Une valeur déjà en clair est renvoyée telle
/// quelle (le coffre n'est alors jamais sollicité).
///
/// Défense en profondeur : un secret (token Splunk HEC, mot de passe Elastic)
/// resté sous forme de référence ne doit jamais partir en clair sur le réseau.
/// Si la valeur est une référence mais qu'aucun coffre n'est disponible
/// (trousseau désactivé), on refuse (erreur) plutôt que d'émettre la référence.
pub(crate) fn resoudre_secret(
    valeur: &str,
    coffre: Option<&dyn crate::secrets::CoffreSecrets>,
) -> Result<String, String> {
    use crate::secrets;
    if !secrets::est_reference(valeur) {
        return Ok(valeur.to_string());
    }
    let coffre = coffre.ok_or_else(|| {
        "secret sous forme de référence 'keyring:' mais trousseau indisponible".to_string()
    })?;
    let mut v = valeur.to_string();
    secrets::resoudre_champ(coffre, &mut v).map_err(|e| e.to_string())?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::resoudre_secret;
    use crate::secrets::{reference, CoffreMemoire, CoffreSecrets};

    #[test]
    fn resout_reference_keyring() {
        let coffre = CoffreMemoire::nouveau();
        coffre.ecrire("splunk_hec_token", "vrai-secret").unwrap();
        let r = resoudre_secret(&reference("splunk_hec_token"), Some(&coffre)).unwrap();
        assert_eq!(r, "vrai-secret");
    }

    #[test]
    fn laisse_valeur_claire_intacte_sans_coffre() {
        let r = resoudre_secret("token-en-clair", None).unwrap();
        assert_eq!(r, "token-en-clair");
    }

    #[test]
    fn refuse_reference_sans_coffre() {
        let r = resoudre_secret(&reference("absent"), None);
        assert!(r.is_err(), "une référence sans coffre doit être refusée");
    }
}
