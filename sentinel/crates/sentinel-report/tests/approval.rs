//! Tests d'intégration du flux d'approbation d'inventaire — agent 5.9.

use chrono::Utc;
use sentinel_detect::empreinte_outil;
use sentinel_protocol::{
    Couleur, Outil, Portee, Serveur, ServeurId, StatutServeur, Transport,
};
use sentinel_report::approval::{DecisionApprobation, FluxApprobation};
use sentinel_store::Store;
use serde_json::json;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

fn creer_store_avec_serveur() -> (Store, ServeurId) {
    let store = Store::in_memory().expect("store en mémoire");
    let id = Uuid::new_v4();
    let serveur = Serveur {
        id,
        endpoint: "http://mcp.example.com".into(),
        transport: Transport::Http,
        portees: vec![Portee::ApiExterne],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
    };
    store.upsert_serveur(&serveur).expect("upsert serveur");
    (store, id)
}

fn inserer_outil(store: &Store, serveur_id: ServeurId, nom: &str) {
    let outil = Outil {
        nom: nom.to_string(),
        description: Some(format!("description de {nom}")),
        input_schema: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
        meta: Default::default(),
    };
    let emp = empreinte_outil(&outil);
    store
        .upsert_outil(serveur_id, &outil, &emp)
        .expect("upsert outil");
}

// ---------------------------------------------------------------------------
// Test 1 : approuver un serveur fige une baseline
// ---------------------------------------------------------------------------

#[test]
fn approuver_fige_une_baseline() {
    let (store, serveur_id) = creer_store_avec_serveur();
    inserer_outil(&store, serveur_id, "lire_fichier");
    inserer_outil(&store, serveur_id, "ecrire_fichier");

    let flux = FluxApprobation::nouveau(store.clone());
    let serveur = flux
        .appliquer(serveur_id, DecisionApprobation::Approuve, "alice")
        .expect("appliquer Approuve");

    // Statut et couleur corrects.
    assert_eq!(serveur.statut, StatutServeur::Approuve);
    assert_eq!(serveur.couleur, Couleur::Vert);

    // La baseline a bien été enregistrée.
    let baseline = store
        .derniere_baseline(serveur_id)
        .expect("derniere_baseline")
        .expect("baseline présente");

    assert_eq!(baseline.serveur_id, serveur_id);
    assert_eq!(baseline.approuve_par, "alice");
    // Deux outils → deux empreintes individuelles.
    assert_eq!(baseline.empreintes_outils.len(), 2);
    assert_eq!(baseline.outils.len(), 2);
    // L'empreinte globale du serveur est une chaîne hex non vide.
    assert_eq!(baseline.empreinte_serveur.as_str().len(), 64);
}

// ---------------------------------------------------------------------------
// Test 2 : bloquer met le statut Bloque et la couleur Rouge
// ---------------------------------------------------------------------------

#[test]
fn bloquer_met_statut_bloque_et_rouge() {
    let (store, serveur_id) = creer_store_avec_serveur();

    let flux = FluxApprobation::nouveau(store.clone());
    let serveur = flux
        .appliquer(serveur_id, DecisionApprobation::Bloque, "bob")
        .expect("appliquer Bloque");

    assert_eq!(serveur.statut, StatutServeur::Bloque);
    assert_eq!(serveur.couleur, Couleur::Rouge);

    // Aucune baseline ne doit exister.
    let baseline = store
        .derniere_baseline(serveur_id)
        .expect("derniere_baseline");
    assert!(baseline.is_none(), "bloquer ne doit pas créer de baseline");
}

// ---------------------------------------------------------------------------
// Test 3 : à investiguer met le statut AInvestiguer, pas de baseline
// ---------------------------------------------------------------------------

#[test]
fn a_investiguer_met_statut_correspondant() {
    let (store, serveur_id) = creer_store_avec_serveur();

    let flux = FluxApprobation::nouveau(store.clone());
    let serveur = flux
        .appliquer(serveur_id, DecisionApprobation::AInvestiguer, "carol")
        .expect("appliquer AInvestiguer");

    assert_eq!(serveur.statut, StatutServeur::AInvestiguer);

    // Aucune baseline ne doit exister.
    let baseline = store
        .derniere_baseline(serveur_id)
        .expect("derniere_baseline");
    assert!(
        baseline.is_none(),
        "à investiguer ne doit pas créer de baseline"
    );
}

// ---------------------------------------------------------------------------
// Test 4 : historique v1 renvoie toujours une liste vide
// ---------------------------------------------------------------------------

#[test]
fn historique_v1_renvoie_liste_vide() {
    let (store, serveur_id) = creer_store_avec_serveur();

    let flux = FluxApprobation::nouveau(store);
    let hist = flux
        .historique(serveur_id)
        .expect("historique");

    assert!(
        hist.is_empty(),
        "l'historique v1 doit être vide (pas de table dédiée)"
    );
}
