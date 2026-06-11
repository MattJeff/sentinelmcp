//! Tests d'intégration — export/import de golden baselines signées Ed25519.

use sentinel_monitor::golden::{FichierGolden, GoldenBaselines};
use sentinel_monitor::GestionnaireBaselines;
use sentinel_protocol::{
    Couleur, Empreinte, Outil, ScopeServeur, Serveur, ServeurId, StatutServeur, Transport,
};
use sentinel_report::signature::SignataireBundle;
use sentinel_store::Store;
use uuid::Uuid;

fn inserer_serveur(store: &Store, endpoint: &str) -> ServeurId {
    let id = Uuid::new_v4();
    let s = Serveur {
        id,
        endpoint: endpoint.to_string(),
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

fn outil(nom: &str) -> Outil {
    Outil {
        nom: nom.to_string(),
        description: Some(format!("Outil {}", nom)),
        input_schema: serde_json::json!({"type": "object"}),
        meta: Default::default(),
    }
}

// Test 1 : export puis import sur un autre poste — la signature est
// vérifiée, la baseline est rejouée au nom de l'importateur et la
// provenance est tracée dans l'historique versionné.
#[test]
fn export_import_round_trip_signe() {
    // Poste A : approuve une baseline et exporte.
    let store_a = Store::in_memory().unwrap();
    inserer_serveur(&store_a, "http://partage.test/");
    let serveur_a = store_a.lister_serveurs().unwrap()[0].id;
    let gestionnaire = GestionnaireBaselines::nouveau(store_a.clone());
    gestionnaire
        .approuver(
            serveur_a,
            vec![outil("lire"), outil("ecrire")],
            Empreinte::new("emp_golden"),
            "alice",
        )
        .unwrap();

    let signataire = SignataireBundle::generer();
    let golden_a = GoldenBaselines::nouveau(store_a);
    let fichier = golden_a.exporter(&signataire, "alice").unwrap();

    // Poste B : même endpoint, UUID local différent.
    let store_b = Store::in_memory().unwrap();
    let serveur_b = inserer_serveur(&store_b, "http://partage.test/");
    let golden_b = GoldenBaselines::nouveau(store_b.clone());
    let bilan = golden_b
        .importer(&fichier, "bob", &[signataire.cle_publique.clone()])
        .unwrap();

    assert_eq!(bilan.importees, 1);
    assert!(bilan.ignorees.is_empty());

    // La baseline locale porte l'empreinte exportée, approuvée par bob.
    let baseline = store_b.derniere_baseline(serveur_b).unwrap().unwrap();
    assert_eq!(baseline.empreinte_serveur, Empreinte::new("emp_golden"));
    assert_eq!(baseline.approuve_par, "bob");
    assert_eq!(baseline.outils.len(), 2);

    // L'historique trace la provenance de l'import.
    let historique = store_b.lister_historique_baselines(serveur_b).unwrap();
    assert_eq!(historique.len(), 1);
    assert!(historique[0].raison.contains("import golden baseline"));
    assert!(historique[0].raison.contains("alice"));
    assert_eq!(historique[0].approbateur, "bob");
}

// Test 2 : payload altéré après signature → import refusé.
#[test]
fn import_refuse_si_payload_altere() {
    let store = Store::in_memory().unwrap();
    let serveur_id = inserer_serveur(&store, "http://victime.test/");
    let gestionnaire = GestionnaireBaselines::nouveau(store.clone());
    gestionnaire
        .approuver(serveur_id, vec![outil("lire")], Empreinte::new("emp_ok"), "alice")
        .unwrap();

    let signataire = SignataireBundle::generer();
    let golden = GoldenBaselines::nouveau(store.clone());
    let fichier = golden.exporter(&signataire, "alice").unwrap();

    // Altération : un attaquant remplace l'empreinte dans le payload.
    let altere = fichier.replace("emp_ok", "emp_pirate");
    assert_ne!(fichier, altere, "l'altération doit avoir eu lieu");

    let resultat = golden.importer(&altere, "bob", &[signataire.cle_publique.clone()]);
    let err = resultat.expect_err("l'import d'un fichier altéré doit échouer");
    assert!(err.to_string().contains("signature"));

    // Rien n'a été écrit : l'historique ne contient que l'approbation d'alice.
    let historique = store.lister_historique_baselines(serveur_id).unwrap();
    assert_eq!(historique.len(), 1);
    assert_eq!(historique[0].approbateur, "alice");
}

// Test 3 : signature produite par une autre clé que celle annoncée → refus.
#[test]
fn import_refuse_si_signature_etrangere() {
    let store = Store::in_memory().unwrap();
    let serveur_id = inserer_serveur(&store, "http://cible.test/");
    let gestionnaire = GestionnaireBaselines::nouveau(store.clone());
    gestionnaire
        .approuver(serveur_id, vec![outil("lire")], Empreinte::new("emp1"), "alice")
        .unwrap();

    let signataire = SignataireBundle::generer();
    let intrus = SignataireBundle::generer();
    let golden = GoldenBaselines::nouveau(store);
    let fichier = golden.exporter(&signataire, "alice").unwrap();

    // Remplace la signature par celle d'une autre clé sur le même payload.
    let mut parse: FichierGolden = serde_json::from_str(&fichier).unwrap();
    let octets = serde_json::to_vec(&parse.payload).unwrap();
    parse.signature_ed25519_hex = hex::encode(intrus.signer(&octets));
    let falsifie = serde_json::to_string(&parse).unwrap();

    let err = golden
        .importer(&falsifie, "bob", &[signataire.cle_publique.clone()])
        .expect_err("signature étrangère doit être rejetée");
    assert!(err.to_string().contains("signature"));
}

// Test 3 bis : fichier entièrement forgé — l'attaquant génère sa propre
// paire de clés, signe son payload de façon cohérente et embarque SA clé
// publique. La signature est « valide » contre la clé du fichier, mais la
// clé ne figure pas parmi les clés de confiance → rejet, rien n'est écrit.
#[test]
fn import_refuse_un_fichier_forge_auto_signe() {
    let store = Store::in_memory().unwrap();
    let serveur_id = inserer_serveur(&store, "http://cible.test/");
    let gestionnaire = GestionnaireBaselines::nouveau(store.clone());
    gestionnaire
        .approuver(serveur_id, vec![outil("lire")], Empreinte::new("emp_legit"), "alice")
        .unwrap();

    // L'attaquant fabrique un export complet avec sa propre paire :
    // payload forgé + signature cohérente + sa clé publique embarquée.
    let attaquant = SignataireBundle::generer();
    let golden = GoldenBaselines::nouveau(store.clone());
    let fichier_forge = golden.exporter(&attaquant, "alice").unwrap();
    let fichier_forge = fichier_forge.replace("emp_legit", "emp_forge");

    // Auto-cohérent : sans ancre de confiance, le fichier passerait.
    let cle_equipe = SignataireBundle::generer().cle_publique;
    let err = golden
        .importer(&fichier_forge, "bob", &[cle_equipe])
        .expect_err("un fichier auto-signé par une clé inconnue doit être rejeté");
    assert!(err.to_string().contains("clé publique non reconnue"));

    // Rien n'a été écrit : seule l'approbation d'alice subsiste.
    let historique = store.lister_historique_baselines(serveur_id).unwrap();
    assert_eq!(historique.len(), 1);
    assert_eq!(historique[0].approbateur, "alice");
    let courante = store.derniere_baseline(serveur_id).unwrap().unwrap();
    assert_eq!(courante.empreinte_serveur, Empreinte::new("emp_legit"));
}

// Test 3 ter : une liste de clés de confiance vide rejette tout fichier,
// même légitime — sécurité par défaut.
#[test]
fn import_refuse_tout_sans_cle_de_confiance() {
    let store = Store::in_memory().unwrap();
    let serveur_id = inserer_serveur(&store, "http://cible.test/");
    let gestionnaire = GestionnaireBaselines::nouveau(store.clone());
    gestionnaire
        .approuver(serveur_id, vec![outil("lire")], Empreinte::new("emp1"), "alice")
        .unwrap();

    let signataire = SignataireBundle::generer();
    let golden = GoldenBaselines::nouveau(store);
    let fichier = golden.exporter(&signataire, "alice").unwrap();

    let err = golden
        .importer(&fichier, "bob", &[])
        .expect_err("aucune clé de confiance → rejet");
    assert!(err.to_string().contains("clé publique non reconnue"));
}

// Test 4 : les entrées sans serveur local correspondant sont ignorées
// et listées dans le bilan (pas de création sauvage de serveurs).
#[test]
fn import_ignore_les_serveurs_inconnus_localement() {
    let store_a = Store::in_memory().unwrap();
    let serveur_a = inserer_serveur(&store_a, "http://inconnu-ailleurs.test/");
    let gestionnaire = GestionnaireBaselines::nouveau(store_a.clone());
    gestionnaire
        .approuver(serveur_a, vec![outil("lire")], Empreinte::new("emp1"), "alice")
        .unwrap();

    let signataire = SignataireBundle::generer();
    let fichier = GoldenBaselines::nouveau(store_a)
        .exporter(&signataire, "alice")
        .unwrap();

    // Poste B : inventaire vide.
    let store_b = Store::in_memory().unwrap();
    let bilan = GoldenBaselines::nouveau(store_b)
        .importer(&fichier, "bob", &[signataire.cle_publique.clone()])
        .unwrap();

    assert_eq!(bilan.importees, 0);
    assert_eq!(bilan.ignorees, vec!["http://inconnu-ailleurs.test/"]);
}

// Test 5 : verifier_fichier valide un fichier sain sans rien écrire.
#[test]
fn verifier_fichier_accepte_un_export_sain() {
    let store = Store::in_memory().unwrap();
    let serveur_id = inserer_serveur(&store, "http://sain.test/");
    let gestionnaire = GestionnaireBaselines::nouveau(store.clone());
    gestionnaire
        .approuver(serveur_id, vec![outil("lire")], Empreinte::new("emp1"), "alice")
        .unwrap();

    let signataire = SignataireBundle::generer();
    let fichier = GoldenBaselines::nouveau(store)
        .exporter(&signataire, "alice")
        .unwrap();

    let payload =
        GoldenBaselines::verifier_fichier(&fichier, &[signataire.cle_publique.clone()])
            .expect("fichier sain");
    assert_eq!(payload.exporte_par, "alice");
    assert_eq!(payload.baselines.len(), 1);
    assert_eq!(payload.baselines[0].endpoint, "http://sain.test/");
}
