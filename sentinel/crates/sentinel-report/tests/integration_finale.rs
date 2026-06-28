//! Tests d'intégration finale — agent 5.10.
//!
//! Valide le pipeline complet (Store → BundleRapport → PlanRemediation)
//! et la métrique de performance (<5 s pour 5 serveurs synthétiques).

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Outil, Portee, Severite, StatutServeur,
    Transport, TypeConstat,
};
use sentinel_report::{remediation::PlanRemediation, GenerateurRapport};
use sentinel_scan::store_contract::{AdaptateurStore, ContratScanStore, EvenementInventaire};
use sentinel_store::Store;
use std::time::Instant;
use uuid::Uuid;

/// Force la clé de signature éphémère : tests hermétiques, sans accès au
/// trousseau OS (cf. convention `SENTINEL_NO_KEYRING`).
fn hermetique() {
    std::env::set_var("SENTINEL_NO_KEYRING", "1");
}

// ------------------------------------------------------------------ //
//  Helpers                                                             //
// ------------------------------------------------------------------ //

fn evenement_inventaire(endpoint: &str, portees: Vec<Portee>) -> EvenementInventaire {
    EvenementInventaire {
        endpoint: endpoint.into(),
        transport: Transport::Http,
        outils: vec![Outil {
            nom: "outil_test".into(),
            description: Some("Outil de test synthétique".into()),
            input_schema: serde_json::json!({"type": "object", "properties": {}}),
            meta: Default::default(),
        }],
        portees,
    }
}

fn forcer_couleur_rouge(store: &Store, endpoint: &str) {
    // Met à jour la couleur du serveur enregistré pour simuler une détection rouge.
    let serveurs = store.lister_serveurs().unwrap();
    if let Some(mut s) = serveurs.into_iter().find(|s| s.endpoint == endpoint) {
        s.couleur = Couleur::Rouge;
        s.statut = StatutServeur::Suspect;
        store.upsert_serveur(&s).unwrap();
    }
}

fn enregistrer_constat_critique(store: &Store, serveur_id: uuid::Uuid) {
    let c = Constat {
        id: Uuid::new_v4(),
        serveur_id,
        outil_nom: Some("outil_test".into()),
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Critique,
        titre: "Serveur MCP fantôme".into(),
        detail: "Endpoint non approuvé détecté.".into(),
        diff: None,
        references_conformite: vec!["OWASP MCP09".into(), "SAFE-T1001".into()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    };
    store.enregistrer_constat(&c).unwrap();
}

// ------------------------------------------------------------------ //
//  Test 1 — Pipeline complet                                          //
//                                                                     //
//  Store → AdaptateurStore.enregistrer_inventaire                     //
//       → GenerateurRapport.generer_bundle (BundleRapport non vide)   //
//       → PlanRemediation.construire (≥1 action si serveur rouge)     //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_pipeline_complet() {
    hermetique();
    // 1. Store en mémoire + adaptateur.
    let store = Store::in_memory().expect("store en mémoire");
    let adaptateur = AdaptateurStore::nouveau(store.clone());

    // 2. Écriture d'un inventaire via AdaptateurStore (contrat scan → store).
    let endpoint_rouge = "http://shadow.internal:8888";
    let endpoint_vert = "http://trusted.internal:443";

    let id_rouge = adaptateur
        .enregistrer_inventaire(evenement_inventaire(endpoint_rouge, vec![Portee::Reseau]))
        .await
        .expect("enregistrement inventaire rouge");

    adaptateur
        .enregistrer_inventaire(evenement_inventaire(endpoint_vert, vec![Portee::Lecture]))
        .await
        .expect("enregistrement inventaire vert");

    // 3. Forcer la couleur rouge sur le premier serveur (simule la détection).
    forcer_couleur_rouge(&store, endpoint_rouge);

    // 4. Enregistrer un constat critique lié au serveur rouge.
    enregistrer_constat_critique(&store, id_rouge);

    // 5. Générer le bundle rapport.
    let generateur = GenerateurRapport::nouveau(store.clone());
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    // Vérification : bundle non vide.
    assert!(
        !bundle.inventaire.is_empty(),
        "L'inventaire du bundle doit contenir au moins un serveur"
    );
    assert!(
        !bundle.resume_exec_md.is_empty(),
        "Le résumé exécutif ne doit pas être vide"
    );

    // 6. Construire le plan de remédiation.
    // On doit lire les serveurs et constats depuis le store pour alimenter le plan.
    let serveurs = store.lister_serveurs().expect("lecture serveurs");
    // Les constats ouverts sont déjà dans bundle.inventaire ; on les relit proprement.
    // Note : lister_constats_ouverts filtre par etat = '"ouvert"' (JSON sérialisé).
    let constats = store.lister_constats_ouverts().unwrap_or_default();

    let actions = PlanRemediation::construire(&serveurs, &constats);

    // Vérification : au moins une action car il y a un serveur rouge.
    assert!(
        !actions.is_empty(),
        "Le plan de remédiation doit produire au moins une action pour un serveur rouge"
    );

    let action_rouge = actions.iter().find(|a| a.action == "Bloquer");
    assert!(
        action_rouge.is_some(),
        "Il doit exister une action 'Bloquer' pour le serveur rouge"
    );

    // Vérification : le Markdown est cohérent.
    let md = PlanRemediation::vers_markdown(&actions);
    assert!(
        md.contains("Bloquer"),
        "Le Markdown doit contenir l'action Bloquer"
    );
}

// ------------------------------------------------------------------ //
//  Test 2 — Validation de la métrique 5 minutes (proxy <5 secondes    //
//  pour 5 serveurs synthétiques)                                       //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_pipeline_complet_sous_5_secondes() {
    hermetique();
    let debut = Instant::now();

    // 1. Store en mémoire + adaptateur.
    let store = Store::in_memory().expect("store en mémoire");
    let adaptateur = AdaptateurStore::nouveau(store.clone());

    // 2. Enregistrer 5 serveurs synthétiques.
    let endpoints = [
        ("http://mcp-alpha.internal:8001", Portee::Filesystem),
        ("http://mcp-beta.internal:8002", Portee::BaseDonnees),
        ("http://mcp-gamma.internal:8003", Portee::ApiExterne),
        ("http://mcp-delta.internal:8004", Portee::Secrets),
        ("http://mcp-epsilon.internal:8005", Portee::Reseau),
    ];

    let mut ids = Vec::new();
    for (ep, portee) in &endpoints {
        let id = adaptateur
            .enregistrer_inventaire(evenement_inventaire(ep, vec![*portee]))
            .await
            .expect("enregistrement inventaire");
        ids.push((*ep, id));
    }

    // 3. Forcer le premier serveur en rouge + constat critique.
    forcer_couleur_rouge(&store, endpoints[0].0);
    enregistrer_constat_critique(&store, ids[0].1);

    // 4. Générer le bundle rapport.
    let generateur = GenerateurRapport::nouveau(store.clone());
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    assert_eq!(
        bundle.inventaire.len(),
        5,
        "L'inventaire doit contenir exactement 5 serveurs"
    );

    // 5. Construire le plan de remédiation.
    let serveurs = store.lister_serveurs().expect("lecture serveurs");
    let constats = store.lister_constats_ouverts().unwrap_or_default();
    let actions = PlanRemediation::construire(&serveurs, &constats);

    assert!(
        !actions.is_empty(),
        "Le plan de remédiation doit produire des actions"
    );

    // 6. Mesure du temps total.
    let duree = debut.elapsed();
    assert!(
        duree.as_secs() < 5,
        "Le pipeline complet pour 5 serveurs doit s'exécuter en moins de 5 secondes, \
         mais a pris {:?}",
        duree
    );
}
