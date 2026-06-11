//! Tests du journal d'activité — agent 2.6.

use chrono::{Duration, Utc};
use sentinel_monitor::activity_log::JournalActivite;
use sentinel_protocol::{Couleur, Portee, Serveur, ServeurId, StatutServeur, Transport};
use sentinel_store::Store;
use uuid::Uuid;

/// Crée un store en mémoire et insère un serveur factice pour satisfaire la FK.
fn journal_avec_serveur(serveur_id: ServeurId) -> JournalActivite {
    let store = Store::in_memory().expect("store en mémoire");
    let maintenant = Utc::now();
    let serveur = Serveur {
        id: serveur_id,
        endpoint: format!("http://test-{serveur_id}"),
        transport: Transport::Http,
        portees: vec![Portee::Inconnu],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: maintenant,
        derniere_vue: maintenant,
        empreinte_courante: None,
        tags: vec![],
        scope: sentinel_protocol::ScopeServeur::default(),
    };
    store.upsert_serveur(&serveur).expect("upsert serveur");
    JournalActivite::nouveau(store)
}

/// Un seul enregistrement crée des stats cohérentes :
/// premiere_vue == derniere_vue, nombre_contacts == 1.
#[test]
fn un_enregistrement_cree_des_stats() {
    let serveur_id = Uuid::new_v4();
    let journal = journal_avec_serveur(serveur_id);
    let maintenant = Utc::now();

    journal
        .enregistrer(serveur_id, "sess-1", "tools/list", maintenant)
        .expect("enregistrement");

    let stats = journal.stats(serveur_id).expect("stats");

    assert_eq!(stats.serveur_id, serveur_id);
    assert_eq!(stats.nombre_contacts, 1);
    assert_eq!(stats.premiere_vue, Some(maintenant));
    assert_eq!(stats.derniere_vue, Some(maintenant));
    assert_eq!(stats.frequence_par_heure, 0.0);
}

/// Dix enregistrements consécutifs → nombre_contacts == 10.
#[test]
fn dix_enregistrements_compteur_correct() {
    let serveur_id = Uuid::new_v4();
    let journal = journal_avec_serveur(serveur_id);
    let base = Utc::now();

    for i in 0..10_u64 {
        let ts = base + Duration::seconds(i as i64 * 60);
        journal
            .enregistrer(serveur_id, "sess-x", "initialize", ts)
            .expect("enregistrement");
    }

    let stats = journal.stats(serveur_id).expect("stats");
    assert_eq!(stats.nombre_contacts, 10);
}

/// premiere_vue est toujours ≤ derniere_vue après plusieurs enregistrements,
/// même si les contacts sont insérés dans l'ordre chronologique inverse.
#[test]
fn premiere_vue_avant_ou_egale_derniere_vue() {
    let serveur_id = Uuid::new_v4();
    let journal = journal_avec_serveur(serveur_id);
    let base = Utc::now();

    let ts_recent = base + Duration::hours(2);
    let ts_ancien = base;

    journal
        .enregistrer(serveur_id, "sess-a", "tools/list", ts_recent)
        .expect("enregistrement récent");
    journal
        .enregistrer(serveur_id, "sess-b", "tools/list", ts_ancien)
        .expect("enregistrement ancien");

    let stats = journal.stats(serveur_id).expect("stats");

    let premiere = stats.premiere_vue.expect("premiere_vue présente");
    let derniere = stats.derniere_vue.expect("derniere_vue présente");
    assert!(
        premiere <= derniere,
        "premiere_vue ({premiere}) doit être ≤ derniere_vue ({derniere})"
    );
    assert_eq!(premiere, ts_ancien);
    assert_eq!(derniere, ts_recent);
}

/// Un serveur inconnu (jamais contacté) retourne des stats vides sans erreur.
#[test]
fn serveur_inconnu_stats_vides() {
    let serveur_id = Uuid::new_v4();
    let store = Store::in_memory().expect("store en mémoire");
    let journal = JournalActivite::nouveau(store);

    let stats = journal.stats(serveur_id).expect("stats");

    assert_eq!(stats.nombre_contacts, 0);
    assert!(stats.premiere_vue.is_none());
    assert!(stats.derniere_vue.is_none());
    assert_eq!(stats.frequence_par_heure, 0.0);
}

/// La fréquence par heure est calculée correctement sur une fenêtre connue.
/// 61 contacts espacés d'une minute sur 60 minutes → fenêtre = 1 heure → ~61 contacts/h.
#[test]
fn frequence_par_heure_calculee_correctement() {
    let serveur_id = Uuid::new_v4();
    let journal = journal_avec_serveur(serveur_id);
    let base = Utc::now();
    let nb = 61_u64;

    for i in 0..nb {
        let ts = base + Duration::seconds(i as i64 * 60);
        journal
            .enregistrer(serveur_id, "sess-f", "tools/call", ts)
            .expect("enregistrement");
    }

    let stats = journal.stats(serveur_id).expect("stats");
    // fenêtre = 60 minutes = 1 heure ; 61 contacts → ~61.0/h
    let attendu = nb as f64 / 1.0;
    let ecart = (stats.frequence_par_heure - attendu).abs();
    assert!(
        ecart < 0.5,
        "frequence attendue ≈ {attendu}, obtenue {}",
        stats.frequence_par_heure
    );
}

/// `tous_les_serveurs` liste uniquement les serveurs ayant au moins un contact.
#[test]
fn tous_les_serveurs_liste_correcte() {
    let s1 = Uuid::new_v4();
    let s2 = Uuid::new_v4();
    let s3_sans_contact = Uuid::new_v4();

    // Partage du même store pour tester plusieurs serveurs ensemble.
    let store = Store::in_memory().expect("store en mémoire");
    let maintenant = Utc::now();
    for &id in &[s1, s2, s3_sans_contact] {
        let serveur = Serveur {
            id,
            endpoint: format!("http://test-{id}"),
            transport: Transport::Http,
            portees: vec![Portee::Inconnu],
            statut: StatutServeur::Inconnu,
            couleur: Couleur::Orange,
            premiere_vue: maintenant,
            derniere_vue: maintenant,
            empreinte_courante: None,
            tags: vec![],
            scope: sentinel_protocol::ScopeServeur::default(),
        };
        store.upsert_serveur(&serveur).expect("upsert");
    }

    let journal = JournalActivite::nouveau(store);
    let ts = Utc::now();
    journal.enregistrer(s1, "sess-1", "initialize", ts).unwrap();
    journal.enregistrer(s2, "sess-2", "initialize", ts).unwrap();
    // s3_sans_contact : aucun appel à enregistrer.

    let liste = journal.tous_les_serveurs();
    assert_eq!(liste.len(), 2);
    assert!(liste.contains(&s1));
    assert!(liste.contains(&s2));
    assert!(!liste.contains(&s3_sans_contact));
}
