//! Tests d'intégration pour le champ `tags` sur `Serveur` et pour la
//! migration V2 (`add_tags`) appliquée à des DBs legacy.

use chrono::Utc;
use rusqlite::Connection;
use sentinel_protocol::{Couleur, Portee, ScopeServeur, Serveur, StatutServeur, Transport};
use sentinel_store::Store;
use std::path::Path;
use tempfile::TempDir;
use uuid::Uuid;

fn serveur_fixture(endpoint: &str, tags: Vec<String>) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: endpoint.to_string(),
        transport: Transport::Http,
        portees: vec![Portee::ApiExterne],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags,
        scope: ScopeServeur::default(),
    }
}

/// `lister_tags_distincts` retourne l'union triée et dédupliquée des
/// tags posés sur l'ensemble de l'inventaire.
#[test]
fn lister_tags_distincts_dedoublonne_et_trie() {
    let store = Store::in_memory().expect("store mémoire");

    let s1 = serveur_fixture(
        "http://a",
        vec!["prod".into(), "owner:alice".into()],
    );
    let s2 = serveur_fixture(
        "http://b",
        vec!["staging".into(), "owner:alice".into()],
    );
    let s3 = serveur_fixture("http://c", vec![]);

    store.upsert_serveur(&s1).unwrap();
    store.upsert_serveur(&s2).unwrap();
    store.upsert_serveur(&s3).unwrap();

    let tags = store.lister_tags_distincts().unwrap();
    assert_eq!(
        tags,
        vec![
            "owner:alice".to_string(),
            "prod".to_string(),
            "staging".to_string(),
        ]
    );
}

/// `definir_tags_serveur` met à jour la seule colonne `tags` sans
/// toucher aux autres champs.
#[test]
fn definir_tags_ne_touche_pas_au_reste() {
    let store = Store::in_memory().unwrap();
    let s = serveur_fixture("http://target", vec!["initial".into()]);
    let id = s.id;
    store.upsert_serveur(&s).unwrap();

    let n = store
        .definir_tags_serveur(&id, &["prod".to_string(), "critique".to_string()])
        .unwrap();
    assert_eq!(n, 1);

    let serveurs = store.lister_serveurs().unwrap();
    let recharge = serveurs.iter().find(|x| x.id == id).expect("serveur");
    assert_eq!(recharge.endpoint, "http://target");
    assert_eq!(recharge.transport, Transport::Http);
    assert_eq!(recharge.statut, StatutServeur::Inconnu);
    assert_eq!(recharge.couleur, Couleur::Orange);
    let mut tags = recharge.tags.clone();
    tags.sort();
    assert_eq!(tags, vec!["critique".to_string(), "prod".to_string()]);
}

/// Mise à jour de tags sur un id inconnu : 0 ligne affectée, pas d'erreur.
#[test]
fn definir_tags_serveur_inconnu_retourne_zero() {
    let store = Store::in_memory().unwrap();
    let inconnu = Uuid::new_v4();
    let n = store
        .definir_tags_serveur(&inconnu, &["x".to_string()])
        .unwrap();
    assert_eq!(n, 0);
}

/// Un nouvel upsert avec `tags: vec![]` ne doit pas écraser des tags
/// déjà posés par l'opérateur (les scans périodiques ne connaissent pas
/// les tags).
#[test]
fn upsert_avec_tags_vides_preserve_les_tags_existants() {
    let store = Store::in_memory().unwrap();
    let s = serveur_fixture("http://keep", vec!["important".into()]);
    let id = s.id;
    store.upsert_serveur(&s).unwrap();

    // Re-upsert venant d'un scanner qui ignore les tags.
    let mut maj = s.clone();
    maj.tags = vec![];
    maj.derniere_vue = Utc::now();
    store.upsert_serveur(&maj).unwrap();

    let serveurs = store.lister_serveurs().unwrap();
    let recharge = serveurs.iter().find(|x| x.id == id).unwrap();
    assert_eq!(recharge.tags, vec!["important".to_string()]);
}

/// Simule une DB créée par l'ancien code (sans la colonne `tags` ni la
/// table `refinery_schema_history`), puis ouvre via `Store::open` et
/// vérifie que :
///  1. la migration V2 ajoute la colonne sans perdre les données ;
///  2. l'ancien serveur reste lisible, avec `tags` vide.
#[test]
fn migration_v2_sur_db_legacy_preserve_donnees() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("legacy.sqlite");

    // 1. On crée à la main une DB legacy avec UNIQUEMENT le schéma V1.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1_LEGACY).unwrap();

        let s_id = Uuid::new_v4();
        conn.execute(
            r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            rusqlite::params![
                s_id.to_string(),
                "http://legacy",
                "\"http\"",
                "[\"api_externe\"]",
                "\"inconnu\"",
                "\"orange\"",
                Utc::now().to_rfc3339(),
                Utc::now().to_rfc3339(),
                Option::<String>::None,
            ],
        )
        .unwrap();
    }

    // 2. Ouverture via Store — refinery doit appliquer V2 sans replay
    // de V1 ni perte de données.
    let store = Store::open(&path).expect("open avec migration");
    let serveurs = store.lister_serveurs().unwrap();
    assert_eq!(serveurs.len(), 1);
    assert_eq!(serveurs[0].endpoint, "http://legacy");
    assert!(serveurs[0].tags.is_empty());

    // 3. La colonne `tags` est bien présente et fonctionnelle.
    let id = serveurs[0].id;
    store
        .definir_tags_serveur(&id, &["post-migration".to_string()])
        .unwrap();
    let after = store.lister_serveurs().unwrap();
    assert_eq!(after[0].tags, vec!["post-migration".to_string()]);

    // 4. La table refinery_schema_history existe et contient V1 + V2.
    let conn = Connection::open(&path).unwrap();
    let nb: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM refinery_schema_history",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(nb >= 2, "refinery doit tracker au moins V1 et V2 (vu: {})", nb);
    let _ = path; // silence unused on early returns
    let _: &Path = path.as_path();
}

/// Schéma V1 verbatim — copie de l'ancien `SCHEMA_SQL` AVANT
/// l'introduction de la colonne `tags`. Utilisé pour simuler une DB
/// créée par une version pre-refinery de Sentinel.
const SCHEMA_V1_LEGACY: &str = r#"
CREATE TABLE IF NOT EXISTS serveurs (
    id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    transport TEXT NOT NULL,
    portees TEXT NOT NULL,
    statut TEXT NOT NULL,
    couleur TEXT NOT NULL,
    premiere_vue TEXT NOT NULL,
    derniere_vue TEXT NOT NULL,
    empreinte_courante TEXT
);

CREATE TABLE IF NOT EXISTS outils (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    nom TEXT NOT NULL,
    description TEXT,
    input_schema TEXT NOT NULL,
    empreinte TEXT NOT NULL,
    UNIQUE(serveur_id, nom),
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS baselines (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    empreinte_serveur TEXT NOT NULL,
    empreintes_outils TEXT NOT NULL,
    outils TEXT NOT NULL,
    date_approbation TEXT NOT NULL,
    approuve_par TEXT NOT NULL,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS historique_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serveur_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    methode TEXT NOT NULL,
    horodatage TEXT NOT NULL,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE INDEX IF NOT EXISTS idx_hist_serveur ON historique_contacts(serveur_id);

CREATE TABLE IF NOT EXISTS constats (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    outil_nom TEXT,
    type_constat TEXT NOT NULL,
    severite TEXT NOT NULL,
    titre TEXT NOT NULL,
    detail TEXT NOT NULL,
    diff TEXT,
    references_conformite TEXT NOT NULL,
    horodatage TEXT NOT NULL,
    etat TEXT NOT NULL,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS alertes (
    id TEXT PRIMARY KEY,
    constat_id TEXT NOT NULL,
    canal TEXT NOT NULL,
    severite TEXT NOT NULL,
    titre TEXT NOT NULL,
    message TEXT NOT NULL,
    diff TEXT,
    horodatage TEXT NOT NULL,
    envoyee INTEGER NOT NULL,
    tentatives INTEGER NOT NULL,
    FOREIGN KEY(constat_id) REFERENCES constats(id)
);

CREATE TABLE IF NOT EXISTS inventaire_approuve (
    serveur_id TEXT PRIMARY KEY,
    approuve INTEGER NOT NULL,
    note TEXT,
    FOREIGN KEY(serveur_id) REFERENCES serveurs(id)
);

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    serveur_id TEXT NOT NULL,
    note TEXT NOT NULL,
    cree_par TEXT NOT NULL,
    cree_a TEXT NOT NULL,
    etat TEXT NOT NULL DEFAULT '"ouvert"'
);

CREATE INDEX IF NOT EXISTS idx_investigations_serveur ON investigations(serveur_id);
"#;
