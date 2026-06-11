//! Tests d'intégration — DetecteurDeriveLente (fenêtre glissante).
//!
//! Scénario clé : un serveur qui change « un petit peu à chaque session »
//! (1 outil par session sur 5 sessions) reste sous le radar du diff
//! simple mais doit déclencher un constat de dérive lente avec le cumul.

use chrono::Utc;
use sentinel_monitor::derive_lente::{
    DetecteurDeriveLente, ParametresDeriveLente, SessionEmpreintes,
};
use sentinel_protocol::{
    Couleur, Empreinte, ScopeServeur, Serveur, ServeurId, StatutServeur, Transport, TypeConstat,
};
use sentinel_store::Store;
use std::collections::BTreeMap;
use uuid::Uuid;

fn empreintes(paires: &[(&str, &str)]) -> BTreeMap<String, Empreinte> {
    paires
        .iter()
        .map(|(nom, emp)| (nom.to_string(), Empreinte::new(*emp)))
        .collect()
}

fn session(paires: &[(&str, &str)]) -> SessionEmpreintes {
    SessionEmpreintes {
        session_id: Uuid::new_v4().to_string(),
        horodatage: Utc::now(),
        empreintes_outils: empreintes(paires),
    }
}

fn inserer_serveur(store: &Store) -> ServeurId {
    let id = Uuid::new_v4();
    let s = Serveur {
        id,
        endpoint: format!("http://serveur-{}.test/", id),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Approuve,
        couleur: Couleur::Vert,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: ScopeServeur::default(),
    };
    store.upsert_serveur(&s).expect("upsert serveur");
    id
}

// Test 1 : dérive lente sur 5 sessions simulées — un outil change à chaque
// session, chaque pas est petit, le cumul dépasse le seuil → détection
// avec le cumul des changements.
#[test]
fn derive_lente_sur_cinq_sessions_simulees() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0"), ("d", "d0")]);
    // Session 1 : a muté. Session 2 : b muté. Session 3 : c muté.
    // Session 4 : outil e ajouté. Session 5 : d supprimé.
    let sessions = vec![
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0"), ("d", "d0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c0"), ("d", "d0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1"), ("d", "d0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1"), ("d", "d0"), ("e", "e0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1"), ("e", "e0")]),
    ];

    let detecteur = DetecteurDeriveLente::nouveau();
    let bilan = detecteur
        .evaluer(&baseline, &sessions)
        .expect("la dérive lente doit être détectée");

    assert_eq!(bilan.sessions_examinees, 5);
    assert_eq!(bilan.outils_modifies, vec!["a", "b", "c"]);
    assert_eq!(bilan.outils_ajoutes, vec!["e"]);
    assert_eq!(bilan.outils_supprimes, vec!["d"]);
    assert_eq!(bilan.cumul(), 5);
    // Chaque pas est resté petit (1 changement par session).
    assert_eq!(bilan.changements_par_session, vec![1, 1, 1, 1, 1]);
}

// Test 2 : aucune dérive — toutes les sessions conformes à la baseline.
#[test]
fn aucune_derive_quand_sessions_conformes() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0")]);
    let sessions = vec![
        session(&[("a", "a0"), ("b", "b0")]),
        session(&[("a", "a0"), ("b", "b0")]),
        session(&[("a", "a0"), ("b", "b0")]),
        session(&[("a", "a0"), ("b", "b0")]),
        session(&[("a", "a0"), ("b", "b0")]),
    ];
    let detecteur = DetecteurDeriveLente::nouveau();
    assert!(detecteur.evaluer(&baseline, &sessions).is_none());
}

// Test 3 : rupture franche (un pas qui dépasse le seuil) — hors périmètre
// de la dérive lente (le diff simple/rug-pull la voit déjà).
#[test]
fn rupture_franche_non_qualifiee_de_derive_lente() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0"), ("d", "d0")]);
    // Une seule session change 4 outils d'un coup.
    let sessions = vec![
        session(&[("a", "a0"), ("b", "b0"), ("c", "c0"), ("d", "d0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1"), ("d", "d1")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1"), ("d", "d1")]),
    ];
    let detecteur = DetecteurDeriveLente::nouveau();
    assert!(detecteur.evaluer(&baseline, &sessions).is_none());
}

// Test 4 : changement isolé sur une seule session (un seul pas actif)
// → pas de dérive progressive.
#[test]
fn changement_isole_non_qualifie() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0")]);
    let sessions = vec![
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
    ];
    let detecteur = DetecteurDeriveLente::nouveau();
    assert!(detecteur.evaluer(&baseline, &sessions).is_none());
}

// Test 5 : cumul sous le seuil → pas de constat.
#[test]
fn cumul_sous_le_seuil_non_qualifie() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0")]);
    let sessions = vec![
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c0")]),
    ];
    // Cumul = 2 (a et b), seuil par défaut = 3.
    let detecteur = DetecteurDeriveLente::nouveau();
    assert!(detecteur.evaluer(&baseline, &sessions).is_none());
}

// Test 6 : la fenêtre glissante ne regarde que les N dernières sessions —
// une dérive ancienne hors fenêtre, stabilisée depuis, ne déclenche pas.
#[test]
fn fenetre_glissante_ignore_les_sessions_anciennes() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0")]);
    // Dérive lente sur les sessions 1-3, puis 5 sessions stables.
    let mut sessions = vec![
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1")]),
    ];
    for _ in 0..5 {
        sessions.push(session(&[("a", "a1"), ("b", "b1"), ("c", "c1")]));
    }
    let detecteur = DetecteurDeriveLente::avec_parametres(ParametresDeriveLente {
        fenetre: 5,
        seuil_pas: 2,
        seuil_cumul: 3,
        min_sessions: 3,
    });
    // Dans la fenêtre des 5 dernières sessions, le premier pas
    // (baseline → début de fenêtre) porte les 3 changements accumulés :
    // c'est une divergence franche que le diff simple voit déjà — pas
    // une dérive lente en cours.
    assert!(detecteur.evaluer(&baseline, &sessions).is_none());
}

// Test 6 bis : le minimum de sessions est configurable — avec
// `min_sessions: 2`, le détecteur peut se prononcer dès 2 sessions
// (impossible avec l'ancien minimum codé en dur à 3).
#[test]
fn min_sessions_configurable_permet_detection_precoce() {
    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0"), ("d", "d0")]);
    let sessions = vec![
        session(&[("a", "a1"), ("b", "b1"), ("c", "c0"), ("d", "d0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1"), ("d", "d1")]),
    ];

    let parametres = ParametresDeriveLente {
        fenetre: 3,
        seuil_pas: 2,
        seuil_cumul: 3,
        min_sessions: 2,
    };
    let bilan = DetecteurDeriveLente::avec_parametres(parametres.clone())
        .evaluer(&baseline, &sessions)
        .expect("avec min_sessions = 2, la dérive doit être détectée");
    assert_eq!(bilan.cumul(), 4);
    assert_eq!(bilan.changements_par_session, vec![2, 2]);

    // Avec le minimum par défaut (3), le même historique est trop court.
    let parametres_defaut = ParametresDeriveLente {
        min_sessions: 3,
        ..parametres
    };
    assert!(DetecteurDeriveLente::avec_parametres(parametres_defaut)
        .evaluer(&baseline, &sessions)
        .is_none());
}

// Test 7 : le constat est construit et persisté avec le cumul des
// changements dans le détail et le diff.
#[test]
fn constat_persiste_avec_cumul_des_changements() {
    let store = Store::in_memory().unwrap();
    let serveur_id = inserer_serveur(&store);

    let baseline = empreintes(&[("a", "a0"), ("b", "b0"), ("c", "c0")]);
    let sessions = vec![
        session(&[("a", "a1"), ("b", "b0"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c0")]),
        session(&[("a", "a1"), ("b", "b1"), ("c", "c1")]),
    ];

    let detecteur = DetecteurDeriveLente::nouveau();
    let constat = detecteur
        .detecter_et_enregistrer(&store, serveur_id, &baseline, &sessions)
        .expect("détection")
        .expect("constat attendu");

    assert_eq!(constat.type_constat, TypeConstat::DeriveInterSession);
    assert!(constat.titre.contains("Dérive lente"));
    assert!(constat.detail.contains("3 changement(s) cumulé(s)"));
    assert!(constat.detail.contains("a, b, c"));
    let diff = constat.diff.as_deref().expect("diff attendu");
    assert!(diff.contains("~ `a`"));
    assert!(diff.contains("~ `c`"));

    // Persisté dans le store.
    let ouverts = store.lister_constats_ouverts().unwrap();
    assert_eq!(ouverts.len(), 1);
    assert_eq!(ouverts[0].id, constat.id);
    assert_eq!(ouverts[0].serveur_id, serveur_id);
}
