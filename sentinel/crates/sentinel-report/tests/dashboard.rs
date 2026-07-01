//! Tests agent 5.8 — Tableau de bord d'inventaire.

use chrono::Utc;
use sentinel_protocol::{
    Constat, Couleur, EtatConstat, Outil, Portee, Serveur, Severite, StatutServeur, Transport,
    TypeConstat,
};
use sentinel_report::TableauBord;
use sentinel_store::Store;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serveur_test(endpoint: &str, couleur: Couleur, statut: StatutServeur) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: endpoint.to_string(),
        transport: Transport::Http,
        portees: vec![Portee::ApiExterne],
        statut,
        couleur,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    }
}

fn outil_test(nom: &str) -> Outil {
    Outil {
        nom: nom.to_string(),
        description: Some(format!("Description de {}", nom)),
        input_schema: serde_json::json!({ "type": "object", "properties": {} }),
        meta: Default::default(),
    }
}

fn constat_test(serveur_id: Uuid) -> Constat {
    Constat {
        id: Uuid::new_v4(),
        serveur_id,
        outil_nom: None,
        type_constat: TypeConstat::ShadowMcp,
        severite: Severite::Haute,
        titre: "Constat test".to_string(),
        detail: "Détail du constat.".to_string(),
        diff: None,
        references_conformite: vec!["OWASP MCP09".to_string()],
        horodatage: Utc::now(),
        etat: EtatConstat::Ouvert,
    }
}

fn empreinte_test() -> sentinel_protocol::Empreinte {
    sentinel_protocol::Empreinte::new("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
}

// ---------------------------------------------------------------------------
// Test 1 : cartes retourne 0 sur store vide
// ---------------------------------------------------------------------------

#[test]
fn test_cartes_store_vide() {
    let store = Store::in_memory().expect("Store en mémoire");
    let tb = TableauBord::nouveau(store);

    let cartes = tb.cartes().expect("cartes() ne doit pas échouer");
    assert!(
        cartes.is_empty(),
        "un store vide doit retourner 0 carte, obtenu : {}",
        cartes.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2 : cartes retourne N sur store pré-rempli
// ---------------------------------------------------------------------------

#[test]
fn test_cartes_store_prerempli() {
    let store = Store::in_memory().expect("Store en mémoire");

    let s1 = serveur_test("https://alpha.example.com", Couleur::Vert, StatutServeur::Approuve);
    let s2 = serveur_test("https://beta.example.com", Couleur::Rouge, StatutServeur::Suspect);
    let s3 = serveur_test("https://gamma.example.com", Couleur::Orange, StatutServeur::Inconnu);

    // Insérer outils pour s1 (2 outils)
    store.upsert_serveur(&s1).expect("upsert s1");
    store.upsert_outil(s1.id, &outil_test("recherche"), &empreinte_test()).expect("outil s1-1");
    store.upsert_outil(s1.id, &outil_test("lecture_fichier"), &empreinte_test()).expect("outil s1-2");

    // Insérer s2 (0 outil)
    store.upsert_serveur(&s2).expect("upsert s2");

    // Insérer s3 (1 outil)
    store.upsert_serveur(&s3).expect("upsert s3");
    store.upsert_outil(s3.id, &outil_test("api_externe"), &empreinte_test()).expect("outil s3-1");

    let tb = TableauBord::nouveau(store);
    let cartes = tb.cartes().expect("cartes()");

    assert_eq!(cartes.len(), 3, "3 cartes attendues");

    // Vérifier les compteurs d'outils
    let carte_alpha = cartes.iter().find(|c| c.endpoint == "https://alpha.example.com").unwrap();
    let carte_beta = cartes.iter().find(|c| c.endpoint == "https://beta.example.com").unwrap();
    let carte_gamma = cartes.iter().find(|c| c.endpoint == "https://gamma.example.com").unwrap();

    assert_eq!(carte_alpha.nombre_outils, 2, "alpha doit avoir 2 outils");
    assert_eq!(carte_beta.nombre_outils, 0, "beta doit avoir 0 outil");
    assert_eq!(carte_gamma.nombre_outils, 1, "gamma doit avoir 1 outil");

    // Vérifier les couleurs
    assert_eq!(carte_alpha.couleur, "vert");
    assert_eq!(carte_beta.couleur, "rouge");
    assert_eq!(carte_gamma.couleur, "orange");
}

// ---------------------------------------------------------------------------
// Test 3 : detail retourne l'objet attendu pour un id valide
// ---------------------------------------------------------------------------

#[test]
fn test_detail_id_valide() {
    let store = Store::in_memory().expect("Store en mémoire");

    let s = serveur_test("https://cible.example.com", Couleur::Rouge, StatutServeur::Suspect);
    let id_serveur = s.id;

    store.upsert_serveur(&s).expect("upsert serveur");
    store.upsert_outil(id_serveur, &outil_test("outil_dangereux"), &empreinte_test()).expect("outil");

    // Enregistrer un constat ouvert
    let c = constat_test(id_serveur);
    store.enregistrer_constat(&c).expect("constat");

    let tb = TableauBord::nouveau(store);
    let detail = tb.detail(id_serveur).expect("detail()");

    assert_eq!(detail.serveur.id, id_serveur.to_string(), "id serveur correct");
    assert_eq!(detail.serveur.endpoint, "https://cible.example.com");
    assert_eq!(detail.serveur.couleur, "rouge");
    assert_eq!(detail.serveur.statut, "suspect");
    assert_eq!(detail.serveur.nombre_outils, 1, "1 outil attendu");

    assert_eq!(detail.outils.len(), 1, "1 outil dans le détail");
    assert_eq!(detail.outils[0].nom, "outil_dangereux");

    assert_eq!(detail.constats_ouverts, 1, "1 constat ouvert attendu");
}

// ---------------------------------------------------------------------------
// Test 4 : cartes_par_couleur filtre correctement
// ---------------------------------------------------------------------------

#[test]
fn test_cartes_par_couleur() {
    let store = Store::in_memory().expect("Store en mémoire");

    let s_vert = serveur_test("https://vert.example.com", Couleur::Vert, StatutServeur::Approuve);
    let s_rouge_1 = serveur_test("https://rouge1.example.com", Couleur::Rouge, StatutServeur::Suspect);
    let s_rouge_2 = serveur_test("https://rouge2.example.com", Couleur::Rouge, StatutServeur::AInvestiguer);

    store.upsert_serveur(&s_vert).expect("upsert vert");
    store.upsert_serveur(&s_rouge_1).expect("upsert rouge1");
    store.upsert_serveur(&s_rouge_2).expect("upsert rouge2");

    let tb = TableauBord::nouveau(store);

    let rouges = tb.cartes_par_couleur(Couleur::Rouge).expect("cartes_par_couleur(rouge)");
    assert_eq!(rouges.len(), 2, "2 serveurs rouges attendus");
    assert!(rouges.iter().all(|c| c.couleur == "rouge"), "tous doivent être rouge");

    let verts = tb.cartes_par_couleur(Couleur::Vert).expect("cartes_par_couleur(vert)");
    assert_eq!(verts.len(), 1, "1 serveur vert attendu");
    assert_eq!(verts[0].endpoint, "https://vert.example.com");

    let oranges = tb.cartes_par_couleur(Couleur::Orange).expect("cartes_par_couleur(orange)");
    assert!(oranges.is_empty(), "0 serveur orange attendu");
}

// ---------------------------------------------------------------------------
// Test 5 : detail retourne une erreur pour un id inexistant
// ---------------------------------------------------------------------------

#[test]
fn test_detail_id_invalide() {
    let store = Store::in_memory().expect("Store en mémoire");
    let tb = TableauBord::nouveau(store);
    let id_inexistant = Uuid::new_v4();

    let resultat = tb.detail(id_inexistant);
    assert!(
        resultat.is_err(),
        "detail() doit échouer pour un id inexistant"
    );
    let msg = resultat.unwrap_err().to_string();
    assert!(
        msg.contains("Server not found"),
        "message d'erreur attendu, obtenu : {}",
        msg
    );
}
