//! Tests d'intégration — historique versionné des baselines (V5).

use sentinel_protocol::{
    Baseline, Couleur, Empreinte, Outil, ScopeServeur, Serveur, ServeurId, StatutServeur,
    Transport,
};
use sentinel_store::{Store, GC_HISTORIQUE_BASELINES_DEFAUT};
use std::collections::BTreeMap;
use uuid::Uuid;

fn inserer_serveur(store: &Store) -> ServeurId {
    let id = Uuid::new_v4();
    let s = Serveur {
        id,
        endpoint: format!("http://serveur-{}.test/", id),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Approuve,
        couleur: Couleur::Vert,
        premiere_vue: chrono::Utc::now(),
        derniere_vue: chrono::Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: ScopeServeur::default(),
    };
    store.upsert_serveur(&s).expect("upsert serveur");
    id
}

fn baseline(serveur_id: ServeurId, empreinte: &str, par: &str) -> Baseline {
    let mut empreintes_outils = BTreeMap::new();
    empreintes_outils.insert("outil_a".to_string(), Empreinte::new(format!("{empreinte}_a")));
    Baseline {
        id: Uuid::new_v4(),
        serveur_id,
        empreinte_serveur: Empreinte::new(empreinte),
        empreintes_outils,
        outils: vec![Outil {
            nom: "outil_a".to_string(),
            description: Some("Outil A".to_string()),
            input_schema: serde_json::json!({"type": "object"}),
            meta: Default::default(),
        }],
        date_approbation: chrono::Utc::now(),
        approuve_par: par.to_string(),
    }
}

// Test 1 : chaque enregistrement archive une version monotone (1, 2, 3…)
// au lieu d'écraser la précédente.
#[test]
fn enregistrement_archive_versions_monotones() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);

    let v1 = store
        .enregistrer_baseline_versionnee(&baseline(sid, "emp1", "alice"), "approbation initiale")
        .unwrap();
    let v2 = store
        .enregistrer_baseline_versionnee(&baseline(sid, "emp2", "bob"), "ré-approbation")
        .unwrap();
    let v3 = store
        .enregistrer_baseline_versionnee(&baseline(sid, "emp3", "carol"), "")
        .unwrap();

    assert_eq!((v1, v2, v3), (1, 2, 3));

    let historique = store.lister_historique_baselines(sid).unwrap();
    assert_eq!(historique.len(), 3);
    // Tri du plus récent au plus ancien.
    assert_eq!(historique[0].version, 3);
    assert_eq!(historique[0].empreinte_serveur, Empreinte::new("emp3"));
    assert_eq!(historique[2].version, 1);
    assert_eq!(historique[2].empreinte_serveur, Empreinte::new("emp1"));
    assert_eq!(historique[2].approbateur, "alice");
    assert_eq!(historique[2].raison, "approbation initiale");
    // Les outils sont archivés avec la version.
    assert_eq!(historique[0].outils.len(), 1);
    assert!(historique[0].empreintes_outils.contains_key("outil_a"));
}

// Test 2 : `enregistrer_baseline` (sans raison) alimente aussi l'historique
// — rétrocompat avec tous les appelants existants.
#[test]
fn enregistrer_baseline_alimente_historique() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);

    store.enregistrer_baseline(&baseline(sid, "emp1", "alice")).unwrap();

    let historique = store.lister_historique_baselines(sid).unwrap();
    assert_eq!(historique.len(), 1);
    assert_eq!(historique[0].version, 1);
    assert_eq!(historique[0].raison, "");
}

// Test 3 : les versions sont indépendantes par serveur.
#[test]
fn versions_independantes_par_serveur() {
    let store = Store::in_memory().unwrap();
    let sid_a = inserer_serveur(&store);
    let sid_b = inserer_serveur(&store);

    store.enregistrer_baseline(&baseline(sid_a, "a1", "alice")).unwrap();
    store.enregistrer_baseline(&baseline(sid_a, "a2", "alice")).unwrap();
    let v = store
        .enregistrer_baseline_versionnee(&baseline(sid_b, "b1", "bob"), "")
        .unwrap();

    assert_eq!(v, 1, "le serveur B démarre à la version 1");
    assert_eq!(store.lister_historique_baselines(sid_a).unwrap().len(), 2);
    assert_eq!(store.lister_historique_baselines(sid_b).unwrap().len(), 1);
}

// Test 4 : rollback restaure une version antérieure comme baseline courante,
// sans détruire l'historique (qui gagne une ligne « rollback vers version N »).
#[test]
fn rollback_restaure_version_anterieure() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);

    store.enregistrer_baseline(&baseline(sid, "emp_v1", "alice")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    store.enregistrer_baseline(&baseline(sid, "emp_v2", "bob")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));

    let restauree = store.rollback_baseline(sid, 1, "carol").unwrap();
    assert_eq!(restauree.empreinte_serveur, Empreinte::new("emp_v1"));
    assert_eq!(restauree.approuve_par, "carol");

    // La baseline courante est désormais celle de la version 1.
    let courante = store.derniere_baseline(sid).unwrap().unwrap();
    assert_eq!(courante.empreinte_serveur, Empreinte::new("emp_v1"));
    assert_eq!(courante.approuve_par, "carol");

    // L'historique compte 3 versions, la dernière trace le rollback.
    let historique = store.lister_historique_baselines(sid).unwrap();
    assert_eq!(historique.len(), 3);
    assert_eq!(historique[0].version, 3);
    assert_eq!(historique[0].raison, "rollback vers version 1");
    assert_eq!(historique[0].approbateur, "carol");
}

// Test 5 : rollback vers une version inexistante échoue proprement.
#[test]
fn rollback_version_inexistante_echoue() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);
    store.enregistrer_baseline(&baseline(sid, "emp1", "alice")).unwrap();

    let resultat = store.rollback_baseline(sid, 42, "carol");
    assert!(resultat.is_err());
}

// Test 5 bis : une ligne d'historique au JSON corrompu fait échouer la
// lecture (erreur explicite) au lieu de retourner une version vide par
// défaut — et le rollback vers cette version échoue au lieu de restaurer
// silencieusement une baseline à 0 outil.
#[test]
fn historique_corrompu_echoue_au_lieu_de_valeurs_par_defaut() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);
    store.enregistrer_baseline(&baseline(sid, "emp1", "alice")).unwrap();
    store.enregistrer_baseline(&baseline(sid, "emp2", "bob")).unwrap();

    // Corruption de la version 1 : JSON d'outils illisible.
    let n = store
        .executer_sql_pour_tests_seulement(
            "UPDATE historique_baselines SET outils = '{pas du json' WHERE version = 1",
        )
        .unwrap();
    assert_eq!(n, 1, "la ligne version 1 doit avoir été corrompue");

    let err = store
        .lister_historique_baselines(sid)
        .expect_err("une ligne corrompue doit faire échouer la lecture");
    assert!(err.to_string().contains("outils JSON corrompu"));
    assert!(err.to_string().contains("version 1"));

    // Le rollback vers la version corrompue échoue proprement — il ne
    // restaure pas une baseline vide comme baseline courante.
    assert!(store.rollback_baseline(sid, 1, "carol").is_err());
    let courante = store.derniere_baseline(sid).unwrap().unwrap();
    assert_eq!(courante.empreinte_serveur, Empreinte::new("emp2"));
}

// Test 5 ter : empreintes_outils corrompu et horodatage invalide sont
// également des erreurs dures.
#[test]
fn empreintes_ou_horodatage_corrompus_echouent() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);
    store.enregistrer_baseline(&baseline(sid, "emp1", "alice")).unwrap();

    store
        .executer_sql_pour_tests_seulement(
            "UPDATE historique_baselines SET empreintes_outils = 'nope' WHERE version = 1",
        )
        .unwrap();
    let err = store.lister_historique_baselines(sid).unwrap_err();
    assert!(err.to_string().contains("empreintes_outils JSON corrompu"));

    // Répare le JSON, casse l'horodatage.
    store
        .executer_sql_pour_tests_seulement(
            "UPDATE historique_baselines SET empreintes_outils = '{}', \
             horodatage = 'hier soir' WHERE version = 1",
        )
        .unwrap();
    let err = store.lister_historique_baselines(sid).unwrap_err();
    assert!(err.to_string().contains("horodatage invalide"));
}

// Test 6 : le GC conserve les N versions les plus récentes par serveur.
#[test]
fn gc_conserve_les_n_versions_les_plus_recentes() {
    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);
    let autre = inserer_serveur(&store);

    for i in 1..=6 {
        store
            .enregistrer_baseline(&baseline(sid, &format!("emp{i}"), "alice"))
            .unwrap();
    }
    store.enregistrer_baseline(&baseline(autre, "x1", "bob")).unwrap();

    let supprimees = store.gc_historique_baselines(3).unwrap();
    assert_eq!(supprimees, 3, "6 versions - 3 gardées = 3 supprimées");

    let historique = store.lister_historique_baselines(sid).unwrap();
    let versions: Vec<i64> = historique.iter().map(|v| v.version).collect();
    assert_eq!(versions, vec![6, 5, 4]);

    // Le serveur sous la rétention n'est pas touché.
    assert_eq!(store.lister_historique_baselines(autre).unwrap().len(), 1);
}

// Test 7 : rétention par défaut = 50 versions ; rien n'est supprimé en deçà.
#[test]
fn gc_defaut_garde_cinquante_versions() {
    assert_eq!(GC_HISTORIQUE_BASELINES_DEFAUT, 50);

    let store = Store::in_memory().unwrap();
    let sid = inserer_serveur(&store);
    for i in 1..=10 {
        store
            .enregistrer_baseline(&baseline(sid, &format!("emp{i}"), "alice"))
            .unwrap();
    }
    let supprimees = store.gc_historique_baselines_defaut().unwrap();
    assert_eq!(supprimees, 0);
    assert_eq!(store.lister_historique_baselines(sid).unwrap().len(), 10);
}
