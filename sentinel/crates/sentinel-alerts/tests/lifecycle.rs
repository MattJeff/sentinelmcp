//! Tests du cycle de vie des alertes — agent 4.8.

use sentinel_alerts::lifecycle::{EtatAlerteMachine, transiter};
use sentinel_protocol::EtatConstat;

// --- Transitions valides ---

#[test]
fn ouvert_vers_investigue() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Ouvert, EtatConstat::Investigue);
    assert_eq!(resultat.unwrap(), EtatConstat::Investigue);
}

#[test]
fn ouvert_vers_ignore() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Ouvert, EtatConstat::Ignore);
    assert_eq!(resultat.unwrap(), EtatConstat::Ignore);
}

#[test]
fn investigue_vers_resolu() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Investigue, EtatConstat::Resolu);
    assert_eq!(resultat.unwrap(), EtatConstat::Resolu);
}

#[test]
fn investigue_vers_ignore() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Investigue, EtatConstat::Ignore);
    assert_eq!(resultat.unwrap(), EtatConstat::Ignore);
}

#[test]
fn resolu_vers_ouvert_reouverture() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Resolu, EtatConstat::Ouvert);
    assert_eq!(resultat.unwrap(), EtatConstat::Ouvert);
}

#[test]
fn ignore_vers_ouvert() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Ignore, EtatConstat::Ouvert);
    assert_eq!(resultat.unwrap(), EtatConstat::Ouvert);
}

// --- Transitions invalides ---

#[test]
fn ouvert_vers_resolu_invalide() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Ouvert, EtatConstat::Resolu);
    assert!(resultat.is_err());
    let err = resultat.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalide"), "message d'erreur inattendu : {}", msg);
}

#[test]
fn resolu_vers_resolu_invalide() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Resolu, EtatConstat::Resolu);
    assert!(resultat.is_err());
}

#[test]
fn investigue_vers_ouvert_invalide() {
    let resultat = EtatAlerteMachine::transiter(EtatConstat::Investigue, EtatConstat::Ouvert);
    assert!(resultat.is_err());
}

// --- etats_suivants ---

#[test]
fn etats_suivants_ouvert() {
    let suivants = EtatAlerteMachine::etats_suivants(EtatConstat::Ouvert);
    assert_eq!(suivants, vec![EtatConstat::Investigue, EtatConstat::Ignore]);
}

#[test]
fn etats_suivants_investigue() {
    let suivants = EtatAlerteMachine::etats_suivants(EtatConstat::Investigue);
    assert_eq!(suivants, vec![EtatConstat::Resolu, EtatConstat::Ignore]);
}

#[test]
fn etats_suivants_resolu() {
    let suivants = EtatAlerteMachine::etats_suivants(EtatConstat::Resolu);
    assert_eq!(suivants, vec![EtatConstat::Ouvert]);
}

#[test]
fn etats_suivants_ignore() {
    let suivants = EtatAlerteMachine::etats_suivants(EtatConstat::Ignore);
    assert_eq!(suivants, vec![EtatConstat::Ouvert]);
}

// --- Wrap anyhow (compatibilité ancienne API) ---

#[test]
fn wrap_anyhow_ok() {
    let resultat: anyhow::Result<EtatConstat> =
        transiter(EtatConstat::Ouvert, EtatConstat::Investigue);
    assert_eq!(resultat.unwrap(), EtatConstat::Investigue);
}

#[test]
fn wrap_anyhow_erreur() {
    let resultat: anyhow::Result<EtatConstat> =
        transiter(EtatConstat::Ouvert, EtatConstat::Resolu);
    assert!(resultat.is_err());
    let msg = format!("{}", resultat.unwrap_err());
    assert!(msg.contains("invalide"), "message anyhow inattendu : {}", msg);
}
