//! Tests d'intégration du pipeline de génération de rapport — agent 5.1.

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Severite, Serveur, StatutServeur, Transport, TypeConstat,
};
use sentinel_report::{GenerateurRapport, SignataireBundle};
use sentinel_store::Store;
use uuid::Uuid;

/// Force la clé de signature éphémère pour rendre les tests hermétiques
/// (aucun accès au trousseau OS, cf. convention `SENTINEL_NO_KEYRING`).
fn hermetique() {
    std::env::set_var("SENTINEL_NO_KEYRING", "1");
}

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
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
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
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
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
    hermetique();
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
//  Test 3 — la signature est désactivable via sans_signature()        //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_signature_optionnelle() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store).sans_signature();
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    // Avec sans_signature(), aucune signature n'est apposée et le pipeline
    // ne doit pas paniquer.
    assert!(
        bundle.signature_ed25519.is_none(),
        "Avec sans_signature(), la signature doit être None"
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
    hermetique();
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

// ------------------------------------------------------------------ //
//  Test 7 — B1/B2 : le bundle est signé par défaut et vérifiable      //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_bundle_signe_et_verifiable() {
    hermetique();
    let store = store_preremplit();
    // Signataire explicite → chemin de signature hermétique (pas de trousseau).
    let generateur =
        GenerateurRapport::nouveau(store).avec_signataire(SignataireBundle::generer());
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    let signature = bundle
        .signature_ed25519
        .as_ref()
        .expect("la signature Ed25519 doit être présente par défaut (B1)");
    let cle_publique = bundle
        .cle_publique
        .as_ref()
        .expect("la clé publique doit accompagner la signature");
    assert!(
        bundle.signature_horodatage.is_some(),
        "l'horodatage de signature doit être renseigné"
    );

    // Reconstruit le payload à partir des champs publics et vérifie la signature
    // a posteriori — exactement le contrat attendu d'un rapport signé.
    let payload = GenerateurRapport::payload_signature(
        &bundle.resume_exec_md,
        &bundle.mapping_conformite_md,
        &bundle.json_export,
    );
    assert!(
        sentinel_report::signature::verifier_signature(cle_publique, &payload, signature),
        "la signature doit être vérifiable a posteriori"
    );

    // Sanity : une signature ne doit pas valider un payload modifié.
    let mut payload_altere = payload.clone();
    payload_altere.push(b'!');
    assert!(
        !sentinel_report::signature::verifier_signature(
            cle_publique,
            &payload_altere,
            signature
        ),
        "un payload altéré ne doit pas être validé"
    );
}

// ------------------------------------------------------------------ //
//  Test 8 — B6 : le PDF est produit sur le disque                     //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_pdf_genere_sur_disque() {
    hermetique();
    let store = store_preremplit();
    let generateur =
        GenerateurRapport::nouveau(store).avec_signataire(SignataireBundle::generer());
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    let pdf = bundle
        .pdf_path
        .as_ref()
        .expect("le chemin du PDF doit être renseigné (B6)");
    assert!(
        pdf.exists(),
        "le fichier PDF doit exister sur le disque : {:?}",
        pdf
    );
    assert!(
        std::fs::metadata(pdf).map(|m| m.len() > 0).unwrap_or(false),
        "le PDF ne doit pas être vide"
    );

    // Nettoyage best-effort du fichier temporaire.
    let _ = std::fs::remove_file(pdf);
}

// ------------------------------------------------------------------ //
//  Test 9 — B2 : pas de collision de payload signé                    //
// ------------------------------------------------------------------ //

#[test]
fn test_payload_signature_non_collision() {
    // Avec une simple concaténation, ("a","bc") et ("ab","c") produisent tous
    // deux "abc" → collision. Le payload structuré doit les distinguer.
    let json = serde_json::json!({});
    let p1 = GenerateurRapport::payload_signature("a", "bc", &json);
    let p2 = GenerateurRapport::payload_signature("ab", "c", &json);
    assert_ne!(
        p1, p2,
        "deux contenus logiquement différents ne doivent pas produire le même payload signé"
    );
}

// ------------------------------------------------------------------ //
//  Test 10 — D10/P3 : la matrice de couverture apparaît dans le       //
//            markdown ET le JSON du bundle                             //
// ------------------------------------------------------------------ //

#[tokio::test]
async fn test_matrice_couverture_dans_le_bundle() {
    let store = store_preremplit();
    let generateur = GenerateurRapport::nouveau(store);
    let bundle = generateur
        .generer_bundle()
        .await
        .expect("generer_bundle ne doit pas échouer");

    // Markdown : la matrice de couverture et l'estampillage frameworks.
    assert!(
        bundle.mapping_conformite_md.contains("Matrice de couverture"),
        "le mapping doit contenir la matrice de couverture : got:\n{}",
        bundle.mapping_conformite_md
    );
    assert!(
        bundle.mapping_conformite_md.contains("ASI06"),
        "la matrice doit mentionner ASI06 (angle mort mémoire persistante)"
    );
    assert!(
        bundle
            .mapping_conformite_md
            .contains("Correspondances multi-référentiels"),
        "le mapping doit contenir l'estampillage multi-référentiels"
    );

    // JSON : la matrice de couverture est exposée et structurée.
    let cats = bundle.json_export["matrice_couverture"]["categories"]
        .as_array()
        .expect("matrice_couverture.categories doit être un tableau JSON");
    assert_eq!(cats.len(), 20, "20 catégories attendues (10 MCP + 10 ASI)");
}
