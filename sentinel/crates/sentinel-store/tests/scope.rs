//! Tests d'intégration — colonne `scope` (migration V3) et helpers
//! `ScopeServeur::vers_sql` / `depuis_sql`.

use chrono::Utc;
use rusqlite::Connection;
use sentinel_protocol::{Couleur, Portee, ScopeServeur, Serveur, StatutServeur, Transport};
use sentinel_store::Store;
use tempfile::TempDir;
use uuid::Uuid;

fn serveur_avec_scope(endpoint: &str, scope: ScopeServeur) -> Serveur {
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
        tags: vec![],
        scope,
    }
}

#[test]
fn vers_sql_aller_retour_user() {
    let s = ScopeServeur::User;
    assert_eq!(s.vers_sql(), "user");
    assert_eq!(ScopeServeur::depuis_sql("user"), ScopeServeur::User);
}

#[test]
fn vers_sql_aller_retour_project_simple() {
    let s = ScopeServeur::Project {
        path: "/Users/alice/repo".to_string(),
    };
    assert_eq!(s.vers_sql(), "project:/Users/alice/repo");
    assert_eq!(ScopeServeur::depuis_sql(&s.vers_sql()), s);
}

/// Edge case : un chemin contenant `:` (style Windows `C:\Users\...`)
/// doit être restauré tel quel — le séparateur est le **premier** `:`
/// après `project`, le reste est repassé verbatim.
#[test]
fn vers_sql_aller_retour_project_chemin_avec_colon() {
    let path = "C:\\Users\\bob\\repo:edge".to_string();
    let s = ScopeServeur::Project { path: path.clone() };
    let serialized = s.vers_sql();
    assert_eq!(serialized, format!("project:{}", path));
    assert_eq!(
        ScopeServeur::depuis_sql(&serialized),
        ScopeServeur::Project { path }
    );
}

#[test]
fn depuis_sql_valeur_inconnue_tombe_sur_user() {
    // Toute valeur ne commençant pas par "project:" est interprétée user.
    assert_eq!(ScopeServeur::depuis_sql("user"), ScopeServeur::User);
    assert_eq!(ScopeServeur::depuis_sql(""), ScopeServeur::User);
    assert_eq!(ScopeServeur::depuis_sql("garbage"), ScopeServeur::User);
}

#[test]
fn upsert_et_lecture_preserve_scope_user_et_project() {
    let store = Store::in_memory().unwrap();
    let s_user = serveur_avec_scope("http://u", ScopeServeur::User);
    let s_proj = serveur_avec_scope(
        "http://p",
        ScopeServeur::Project {
            path: "/work/repo".to_string(),
        },
    );
    store.upsert_serveur(&s_user).unwrap();
    store.upsert_serveur(&s_proj).unwrap();

    let liste = store.lister_serveurs().unwrap();
    let u = liste.iter().find(|x| x.endpoint == "http://u").unwrap();
    let p = liste.iter().find(|x| x.endpoint == "http://p").unwrap();
    assert_eq!(u.scope, ScopeServeur::User);
    assert_eq!(
        p.scope,
        ScopeServeur::Project {
            path: "/work/repo".to_string()
        }
    );
}

#[test]
fn upsert_chemin_avec_colon_persiste_correctement() {
    let store = Store::in_memory().unwrap();
    let path = "C:\\dev\\projet:alpha".to_string();
    let s = serveur_avec_scope(
        "http://win",
        ScopeServeur::Project { path: path.clone() },
    );
    store.upsert_serveur(&s).unwrap();
    let liste = store.lister_serveurs().unwrap();
    assert_eq!(
        liste[0].scope,
        ScopeServeur::Project { path }
    );
}

#[test]
fn lister_par_scope_filtre_correctement() {
    let store = Store::in_memory().unwrap();
    store
        .upsert_serveur(&serveur_avec_scope("http://u1", ScopeServeur::User))
        .unwrap();
    store
        .upsert_serveur(&serveur_avec_scope("http://u2", ScopeServeur::User))
        .unwrap();
    store
        .upsert_serveur(&serveur_avec_scope(
            "http://p1",
            ScopeServeur::Project {
                path: "/a".to_string(),
            },
        ))
        .unwrap();

    let users = store
        .lister_serveurs_par_scope(&ScopeServeur::User)
        .unwrap();
    assert_eq!(users.len(), 2);
    let projs = store
        .lister_serveurs_par_scope(&ScopeServeur::Project {
            path: "/a".to_string(),
        })
        .unwrap();
    assert_eq!(projs.len(), 1);
    assert_eq!(projs[0].endpoint, "http://p1");
}

/// Migration V3 sur une DB qui avait déjà V1 + V2 trackés par
/// refinery : ajout de la colonne `scope` avec valeur par défaut
/// `'user'`, sans perte de donnée. Reproduit le chemin réel
/// d'upgrade d'un client Sentinel passant de v0.2 → v0.3.
#[test]
fn migration_v3_sur_db_v1_v2_ajoute_scope_default_user() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("v1v2.sqlite");

    // 1. Construit une DB déjà gérée par refinery au niveau V1+V2 :
    //    schéma V1+V2 appliqué + table `refinery_schema_history`
    //    contenant les deux entrées correspondantes (calculées via
    //    le runner pour garantir le bon checksum).
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1_PLUS_V2).unwrap();
        conn.execute_batch(
            r#"CREATE TABLE refinery_schema_history (
                version INT4 PRIMARY KEY,
                name VARCHAR(255),
                applied_on VARCHAR(255),
                checksum VARCHAR(255)
            );"#,
        )
        .unwrap();
        // Insère V1 + V2 avec leurs vrais checksums, calculés depuis
        // l'API publique du runner (mêmes fichiers que ceux embarqués
        // dans le binaire).
        let migrations_history =
            sentinel_store::migrations_pour_tests_seulement().unwrap();
        for m in migrations_history.iter().filter(|m| m.version() <= 2) {
            conn.execute(
                "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    m.version() as i64,
                    m.name(),
                    Utc::now().to_rfc3339(),
                    m.checksum().to_string(),
                ],
            )
            .unwrap();
        }

        let id = Uuid::new_v4();
        conn.execute(
            r#"INSERT INTO serveurs
               (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante, tags)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            rusqlite::params![
                id.to_string(),
                "http://legacy-v1v2",
                "\"http\"",
                "[]",
                "\"inconnu\"",
                "\"orange\"",
                Utc::now().to_rfc3339(),
                Utc::now().to_rfc3339(),
                Option::<String>::None,
                "[]",
            ],
        )
        .unwrap();
    }

    // 2. Ouverture via Store — refinery doit appliquer V3 et créer
    //    la colonne `scope` avec default `'user'` partout.
    let store = Store::open(&path).expect("open avec migration V3");
    let serveurs = store.lister_serveurs().unwrap();
    assert_eq!(serveurs.len(), 1);
    assert_eq!(serveurs[0].endpoint, "http://legacy-v1v2");
    assert_eq!(
        serveurs[0].scope,
        ScopeServeur::User,
        "default `'user'` doit hydrater en ScopeServeur::User"
    );

    // 3. La colonne `scope` est utilisable en écriture.
    let id = serveurs[0].id;
    let mut maj = serveurs[0].clone();
    maj.scope = ScopeServeur::Project {
        path: "/post-migration".to_string(),
    };
    store.upsert_serveur(&maj).unwrap();
    let recharge = store.lister_serveurs().unwrap();
    assert_eq!(
        recharge.iter().find(|s| s.id == id).unwrap().scope,
        ScopeServeur::Project {
            path: "/post-migration".to_string()
        }
    );

    // 4. L'historique refinery contient V1 + V2 + V3.
    let conn = Connection::open(&path).unwrap();
    let nb: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM refinery_schema_history",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(nb >= 3, "refinery doit tracker V1/V2/V3 (vu: {})", nb);
}

/// Schéma V1 + V2 verbatim. Représente une DB construite par la
/// version précédente du store (refinery tracké V1+V2, mais pas V3).
const SCHEMA_V1_PLUS_V2: &str = r#"
CREATE TABLE IF NOT EXISTS serveurs (
    id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    transport TEXT NOT NULL,
    portees TEXT NOT NULL,
    statut TEXT NOT NULL,
    couleur TEXT NOT NULL,
    premiere_vue TEXT NOT NULL,
    derniere_vue TEXT NOT NULL,
    empreinte_courante TEXT,
    tags TEXT NOT NULL DEFAULT '[]'
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
