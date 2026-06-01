//! Tests d'intégration du pipeline de génération de rapport — agent 5.1.

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Severite, Serveur, StatutServeur, Transport, TypeConstat,
};
use sentinel_report::GenerateurRapport;
use sentinel_store::Store;
use uuid::Uuid;

// ------------------------------------------------------------------ //
//  Helpers                                                             //
// ------------------------------------------------------------------ //

fn serveur_rouge() -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: "http://suspect.internal:8080".into(),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Suspect,
        couleur: Couleur::Rouge,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
    }
}

fn serveur_vert() -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: "http://trusted.internal:9000".into(),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Approuve,
        couleur: Couleur::Vert,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
    }
}

fn constat_ouvert(serveur_id: uuid::Uuid) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id,
        outil_nom: Some("exec_shell".into()),
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Critique,
        titre: "Serveur MCP fantôme détecté".into(),
        detail: "Endpoint non référencé dans l'inventaire approuvé.".into(),
        diff: None,
        references_conformite: vec!["OWASP MCP09".into(), "SAFE-T1001".into()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

fn store_preremplit() -> Store {
    let store = Store::in_memory().expect("store en mémoire");
    let rouge = serveur_rouge();
    let vert = serveur_vert();
    let constat = constat_ouvert(rouge.id);

    store.upsert_serveur(&rouge).unwrap();
    store.upsert_serveur(&vert).unwrap();
    store.enregistrer_constat(&constat).unwrap();

    store
}

// ------------------------------------------------------------------ //
//  Test 1 — le pipeline produit un BundleRapport avec inventaire       //
//            non vide quand le store est pré-rempli                    //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_inventaire_non_vide() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    assert!(
        !bundle.inventaire.is_empty(),
        "L'inventaire doit contenir au moins un serveur"
    );
    assert_eq!(
        bundle.inventaire.len(),
        2,
        "L'inventaire doit contenir exactement 2 serveurs"
    );
}

// ------------------------------------------------------------------ //
//  Test 2 — le résumé exécutif contient le compte de serveurs          //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_resume_contient_compte_serveurs() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    // Le résumé doit mentionner le nombre total de serveurs (2).
    assert!(
        bundle.resume_exec_md.contains("2"),
        "Le résumé exécutif doit mentionner le compte de serveurs : got:\n{}",
        bundle.resume_exec_md
    );

    // Le résumé doit indiquer qu'il y a au moins un serveur rouge.
    assert!(
        bundle.resume_exec_md.contains("ATTENTION")
            || bundle.resume_exec_md.contains("rouge"),
        "Le résumé doit signaler la présence d'un serveur rouge : got:\n{}",
        bundle.resume_exec_md
    );
}

// ------------------------------------------------------------------ //
//  Test 3 — la signature est optionnelle (None sans clé configurée)   //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_signature_optionnelle() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    // En l'absence de clé configurée, la signature doit être None.
    // Le pipeline ne doit pas paniquer.
    assert!(
        bundle.signature_ed25519.is_none(),
        "Sans clé injectée, la signature doit être None"
    );
    assert!(
        bundle.signature_horodatage.is_none(),
        "Sans signature, l'horodatage de signature doit être None"
    );
}

// ------------------------------------------------------------------ //
//  Test 4 — le mapping conformité couvre OWASP MCP09 et MCP03         //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_mapping_conformite_references_fixes() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    assert!(
        bundle.mapping_conformite_md.contains("MCP09"),
        "Le mapping doit référencer MCP09 : got:\n{}",
        bundle.mapping_conformite_md
    );
    assert!(
        bundle.mapping_conformite_md.contains("MCP03"),
        "Le mapping doit référencer MCP03 : got:\n{}",
        bundle.mapping_conformite_md
    );
}

// ------------------------------------------------------------------ //
//  Test 5 — le JSON export est structuré et contient les statistiques  //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_json_export_structure() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    let stats = &bundle.json_export["statistiques"];
    assert_eq!(
        stats["total_serveurs"].as_u64().unwrap_or(0),
        2,
        "Le JSON doit indiquer 2 serveurs"
    );
    assert_eq!(
        stats["serveurs_rouge"].as_u64().unwrap_or(0),
        1,
        "Le JSON doit indiquer 1 serveur rouge"
    );

    assert_eq!(
        bundle.json_export["schema_version"].as_str().unwrap_or(""),
        "1.0",
        "Le JSON doit indiquer la version de schéma"
    );
}

// ------------------------------------------------------------------ //
//  Test 6 — store vide : le bundle est produit sans panique            //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_store_vide_pas_de_panique() {
    let store = Store::in_memory().expect("store en mémoire");
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer même avec un store vide");

    assert!(
        bundle.inventaire.is_empty(),
        "Inventaire doit être vide si le store est vide"
    );
    assert!(
        bundle.resume_exec_md.contains("0"),
        "Le résumé doit indiquer 0 serveurs : got:\n{}",
        bundle.resume_exec_md
    );
}
