//! Tests — agent 2.3 : détection des nouveaux serveurs.

use chrono::Utc;
use sentinel_monitor::DetecteurNouveauxServeurs;
use sentinel_protocol::{
    Couleur, EtatConstat, Severite, Serveur, ServeurId, StatutServeur, Transport, TypeConstat,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serveur(endpoint: &str, transport: Transport) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: endpoint.to_string(),
        transport,
        portees: vec![],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    }
}

fn serveur_avec_id(endpoint: &str, id: ServeurId) -> Serveur {
    Serveur {
        id,
        endpoint: endpoint.to_string(),
        transport: Transport::Http,
        portees: vec![],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    }
}

// ---------------------------------------------------------------------------
// Test 1 : serveur totalement inconnu → constat émis
// ---------------------------------------------------------------------------

#[test]
fn nouveau_serveur_inconnu_emet_constat() {
    let detecteur = DetecteurNouveauxServeurs::nouveau();
    let observe = serveur("https://shadow.example.com/mcp", Transport::Http);
    let connus: Vec<Serveur> = vec![];

    let constat = detecteur
        .evaluer(&observe, &connus)
        .expect("un constat doit être émis pour un serveur inconnu");

    assert_eq!(constat.type_constat, TypeConstat::NouveauServeur);
    assert_eq!(constat.severite, Severite::Moyenne);
    assert_eq!(constat.titre, "Nouveau serveur MCP inconnu détecté");
    assert!(constat.detail.contains("https://shadow.example.com/mcp"));
    assert!(constat.detail.contains("Http"));
    assert!(constat.references_conformite.contains(&"OWASP MCP09".to_string()));
    assert_eq!(constat.etat, EtatConstat::Ouvert);
    assert_eq!(constat.serveur_id, observe.id);
}

// ---------------------------------------------------------------------------
// Test 2 : endpoint déjà dans `connus` → aucun constat
// ---------------------------------------------------------------------------

#[test]
fn serveur_deja_connu_ne_produit_pas_de_constat() {
    let detecteur = DetecteurNouveauxServeurs::nouveau();
    let connu = serveur("https://approuve.example.com/mcp", Transport::Http);
    let observe = serveur("https://approuve.example.com/mcp", Transport::Http);

    let resultat = detecteur.evaluer(&observe, &[connu]);

    assert!(
        resultat.is_none(),
        "aucun constat attendu pour un serveur déjà connu"
    );
}

// ---------------------------------------------------------------------------
// Test 3 : doublon — le même endpoint inconnu est présenté deux fois
// ---------------------------------------------------------------------------

#[test]
fn doublon_non_emis_au_second_appel() {
    let detecteur = DetecteurNouveauxServeurs::nouveau();
    let observe = serveur("https://shadow.example.com/mcp", Transport::Http);
    let connus: Vec<Serveur> = vec![];

    // Premier appel : doit émettre.
    let premier = detecteur.evaluer(&observe, &connus);
    assert!(premier.is_some(), "premier appel doit émettre un constat");

    // Second appel avec le même endpoint : ne doit plus émettre.
    let second = detecteur.evaluer(&observe, &connus);
    assert!(
        second.is_none(),
        "le doublon ne doit pas produire un second constat"
    );
}

// ---------------------------------------------------------------------------
// Test 4 : même endpoint, ID UUID différent → traité comme même serveur
// ---------------------------------------------------------------------------

#[test]
fn meme_endpoint_ids_differents_compte_comme_meme_serveur() {
    // Teste le helper stateless `nouveau_serveur`.
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    assert_ne!(id_a, id_b, "les UUIDs doivent être différents pour ce test");

    let endpoint = "https://shared.example.com/mcp";
    let serveur_a = serveur_avec_id(endpoint, id_a);
    let serveur_b = serveur_avec_id(endpoint, id_b);

    // serveur_b est dans la liste des connus sous l'endpoint identique.
    let est_nouveau = DetecteurNouveauxServeurs::nouveau_serveur(&serveur_a, &[serveur_b]);

    assert!(
        !est_nouveau,
        "un endpoint déjà connu ne doit pas être considéré nouveau, même si l'UUID diffère"
    );
}

// ---------------------------------------------------------------------------
// Test 5 : helper stateless — endpoint réellement absent
// ---------------------------------------------------------------------------

#[test]
fn helper_stateless_detecte_endpoint_absent() {
    let observe = serveur("https://nouveau.example.com/mcp", Transport::Stdio);
    let connu = serveur("https://autre.example.com/mcp", Transport::Stdio);

    assert!(
        DetecteurNouveauxServeurs::nouveau_serveur(&observe, &[connu]),
        "l'endpoint absent doit être détecté comme nouveau"
    );
}
