//! Tests d'intégration — GestionnaireBaselines (agent 2.2).

use sentinel_monitor::GestionnaireBaselines;
use sentinel_protocol::{
    Couleur, Empreinte, Outil, Serveur, ServeurId, StatutServeur, Transport,
};
use sentinel_store::Store;
use uuid::Uuid;

fn store_memoire() -> Store {
    Store::in_memory().expect("store en mémoire")
}

/// Insère un serveur fantoche dans le store pour satisfaire la FK de `baselines`.
fn inserer_serveur(store: &Store, id: ServeurId) {
    let s = Serveur {
        id,
        endpoint: format!("http://test/{}", id),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Approuve,
        couleur: Couleur::Vert,
        premiere_vue: chrono::Utc::now(),
        derniere_vue: chrono::Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    };
    store.upsert_serveur(&s).expect("upsert serveur");
}

fn outil(nom: &str) -> Outil {
    Outil {
        nom: nom.to_string(),
        description: Some(format!("Outil {}", nom)),
        input_schema: serde_json::json!({"type": "object", "properties": {}}),
        meta: Default::default(),
    }
}

fn empreinte(valeur: &str) -> Empreinte {
    Empreinte::new(valeur)
}

// Test 1 : approbation crée une baseline en base.
#[test]
fn approbation_cree_baseline_en_base() {
    let store = store_memoire();
    let serveur_id = Uuid::new_v4();
    inserer_serveur(&store, serveur_id);

    let gestionnaire = GestionnaireBaselines::nouveau(store);
    let outils = vec![outil("lire_fichier"), outil("ecrire_fichier")];

    let baseline = gestionnaire
        .approuver(serveur_id, outils.clone(), empreinte("abc123"), "alice")
        .expect("approbation doit réussir");

    assert_eq!(baseline.serveur_id, serveur_id);
    assert_eq!(baseline.approuve_par, "alice");
    assert_eq!(baseline.empreinte_serveur, empreinte("abc123"));
    assert_eq!(baseline.outils.len(), 2);
    // Les empreintes outils doivent être calculées pour chaque outil.
    assert!(baseline.empreintes_outils.contains_key("lire_fichier"));
    assert!(baseline.empreintes_outils.contains_key("ecrire_fichier"));
}

// Test 2 : derniere_baseline renvoie la plus récente.
#[test]
fn derniere_baseline_renvoie_la_plus_recente() {
    let store = store_memoire();
    let serveur_id = Uuid::new_v4();
    inserer_serveur(&store, serveur_id);

    let gestionnaire = GestionnaireBaselines::nouveau(store);

    gestionnaire
        .approuver(serveur_id, vec![outil("a")], empreinte("v1"), "alice")
        .expect("première approbation");

    // Petite pause pour s'assurer que les horodatages diffèrent.
    std::thread::sleep(std::time::Duration::from_millis(5));

    gestionnaire
        .approuver(serveur_id, vec![outil("a"), outil("b")], empreinte("v2"), "bob")
        .expect("deuxième approbation");

    let derniere = gestionnaire
        .derniere_baseline(serveur_id)
        .expect("lecture doit réussir")
        .expect("une baseline doit exister");

    assert_eq!(derniere.empreinte_serveur, empreinte("v2"));
    assert_eq!(derniere.approuve_par, "bob");
    assert_eq!(derniere.outils.len(), 2);
}

// Test 3 : empreinte_diverge est faux quand identique, vrai quand différent.
#[test]
fn empreinte_diverge_detection_correcte() {
    let store = store_memoire();
    let serveur_id = Uuid::new_v4();
    inserer_serveur(&store, serveur_id);

    let gestionnaire = GestionnaireBaselines::nouveau(store);

    gestionnaire
        .approuver(serveur_id, vec![outil("x")], empreinte("hash_approuve"), "charlie")
        .expect("approbation");

    // Empreinte identique à la baseline → pas de divergence.
    let meme = gestionnaire
        .empreinte_diverge(serveur_id, &empreinte("hash_approuve"))
        .expect("vérification divergence");
    assert!(!meme, "même empreinte ne doit pas diverger");

    // Empreinte différente → divergence détectée.
    let different = gestionnaire
        .empreinte_diverge(serveur_id, &empreinte("hash_modifie"))
        .expect("vérification divergence");
    assert!(different, "empreinte modifiée doit diverger");
}

// Test 4 : deux baselines successives conservent les deux (historique complet).
#[test]
fn deux_baselines_successives_conservent_historique() {
    let store = store_memoire();
    let serveur_id = Uuid::new_v4();
    inserer_serveur(&store, serveur_id);

    let gestionnaire = GestionnaireBaselines::nouveau(store);

    let b1 = gestionnaire
        .approuver(serveur_id, vec![outil("outil1")], empreinte("emp1"), "alice")
        .expect("première baseline");

    std::thread::sleep(std::time::Duration::from_millis(5));

    let b2 = gestionnaire
        .approuver(serveur_id, vec![outil("outil2")], empreinte("emp2"), "bob")
        .expect("deuxième baseline");

    // Les deux baselines ont des identifiants distincts.
    assert_ne!(b1.id, b2.id);

    // La dernière baseline retournée par l'API est bien b2.
    let derniere = gestionnaire
        .derniere_baseline(serveur_id)
        .expect("lecture")
        .expect("existe");

    assert_eq!(derniere.id, b2.id);
    assert_eq!(derniere.empreinte_serveur, empreinte("emp2"));
    // b1 est conservée en base (ID distinct de la dernière).
    assert_ne!(derniere.id, b1.id);
}
