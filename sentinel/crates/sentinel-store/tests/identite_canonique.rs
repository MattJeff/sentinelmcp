//! Tests d'intégration — identité canonique des serveurs (migration V4).
//!
//! Couvre les deux propriétés clés :
//!
//!   1. **Dédup au runtime** : deux upserts qui désignent le même paquet
//!      avec des `endpoint` byte-différents (args qui varient, ex. URL
//!      Postgres différente) ne créent qu'**une seule ligne** parce que
//!      l'index unique `(package_id, scope)` ferme la porte.
//!   2. **Backfill** : si une DB pré-V4 contient déjà des doublons
//!      hérités (sérialisés en V1–V3 où la dédup se faisait sur endpoint
//!      brut), le `Store::open` les fusionne sèchement, garde la ligne
//!      qui a le plus d'outils probés, et préserve la `premiere_vue` la
//!      plus ancienne du groupe.

use chrono::{Duration, Utc};
use rusqlite::params;
use sentinel_protocol::{Couleur, Portee, ScopeServeur, Serveur, StatutServeur, Transport};
use sentinel_store::Store;
use tempfile::TempDir;
use uuid::Uuid;

fn fixture(endpoint: &str) -> Serveur {
    Serveur {
        id: Uuid::new_v4(),
        endpoint: endpoint.to_string(),
        transport: Transport::Stdio,
        portees: vec![Portee::ApiExterne],
        statut: StatutServeur::Inconnu,
        couleur: Couleur::Orange,
        premiere_vue: Utc::now(),
        derniere_vue: Utc::now(),
        empreinte_courante: None,
        tags: vec![],
        scope: ScopeServeur::User,
    }
}

#[test]
fn upsert_meme_paquet_args_differents_meme_scope_rejette_le_doublon() {
    let tmp = TempDir::new().unwrap();
    let store = Store::open(tmp.path().join("s.db")).unwrap();

    let a = fixture("npx -y @modelcontextprotocol/server-postgres postgresql://localhost/db_dev");
    store.upsert_serveur(&a).unwrap();

    // Deuxième entrée : MÊME paquet officiel, mêmes scope, args différents
    // (URL postgres). Pré-V4 : nouvelle ligne. Post-V4 : conflit unique →
    // erreur. Le caller (store_contract.rs) doit donc résoudre via
    // `get_serveur_par_identite` avant d'upsert.
    let b = fixture("npx -y @modelcontextprotocol/server-postgres postgresql://localhost/db_test");
    let resultat = store.upsert_serveur(&b);
    assert!(
        resultat.is_err(),
        "l'index unique (package_id, scope) doit refuser le doublon",
    );

    let serveurs = store.lister_serveurs().unwrap();
    assert_eq!(
        serveurs.len(),
        1,
        "une seule ligne doit subsister, pas deux",
    );
}

#[test]
fn get_par_identite_retrouve_la_ligne_quel_que_soit_les_args() {
    let tmp = TempDir::new().unwrap();
    let store = Store::open(tmp.path().join("s.db")).unwrap();

    let a = fixture("npx -y @modelcontextprotocol/server-fetch --max-redirects 5");
    store.upsert_serveur(&a).unwrap();

    let trouve = store
        .get_serveur_par_identite(
            "@modelcontextprotocol/server-fetch",
            &ScopeServeur::User,
        )
        .unwrap();
    assert!(trouve.is_some());
    assert_eq!(trouve.unwrap().id, a.id);
}

#[test]
fn backfill_v4_fusionne_doublons_legacy_et_garde_celui_avec_le_plus_doutils() {
    // Étape 1 : créer une DB pré-V4 (juste V1+V2+V3) avec 3 lignes pour
    // le même paquet officiel. La ligne « riche » a 5 outils, les deux
    // autres en ont 0 (les fantômes typiques de la démo).
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("legacy.db");

    let id_riche = Uuid::new_v4().to_string();
    let id_pauvre_1 = Uuid::new_v4().to_string();
    let id_pauvre_2 = Uuid::new_v4().to_string();
    let premiere_vue_ancienne = (Utc::now() - Duration::days(10)).to_rfc3339();
    let premiere_vue_recente = Utc::now().to_rfc3339();
    let derniere_vue = Utc::now().to_rfc3339();

    {
        // Ouvrir avec le runner refinery jusqu'à V3 inclus : on profite
        // de `Store::open` mais on simule l'absence de la V4 en
        // recalculant l'état nous-mêmes via SQL brut sur la même DB.
        // L'astuce : on ouvre une fois pour matérialiser les tables, on
        // efface le marqueur de V4, puis on injecte les 3 doublons à la
        // main, puis on réouvre — Store::open re-joue alors V4 +
        // backfill.
        let store = Store::open(&path).unwrap();
        drop(store);
        let conn = rusqlite::Connection::open(&path).unwrap();
        // Drop l'index unique posé par V4 pour pouvoir simuler la DB
        // legacy : tant qu'il est en place, l'insertion des 3 doublons
        // ci-dessous échouerait — c'est précisément la situation que le
        // backfill est censé résoudre quand on hérite d'une vraie DB
        // pré-V4 où l'index n'avait jamais été créé.
        conn.execute_batch("DROP INDEX IF EXISTS idx_serveurs_identite;")
            .unwrap();
        // Pousser à 0 les colonnes package_id écrites par V4, comme si
        // les lignes avaient été écrites avant la migration. Puis
        // insérer les 3 doublons. Le scope est `user`.
        for (id, premiere) in [
            (&id_riche, &premiere_vue_ancienne),
            (&id_pauvre_1, &premiere_vue_recente),
            (&id_pauvre_2, &premiere_vue_recente),
        ] {
            conn.execute(
                r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                    premiere_vue, derniere_vue, empreinte_courante, tags, scope, package_id)
                   VALUES (?1, ?2, '"stdio"', '[]', '"inconnu"', '"orange"', ?3, ?4, NULL, '[]', 'user', '')"#,
                params![
                    id,
                    "npx -y @modelcontextprotocol/server-brave-search",
                    premiere,
                    derniere_vue,
                ],
            )
            .unwrap();
        }
        // Donner 5 outils à la ligne « riche ».
        for i in 0..5 {
            conn.execute(
                "INSERT INTO outils (id, serveur_id, nom, description, input_schema, empreinte)
                 VALUES (?1, ?2, ?3, NULL, '{}', 'fp')",
                params![Uuid::new_v4().to_string(), id_riche, format!("outil_{i}")],
            )
            .unwrap();
        }
        // Effacer les package_id (déjà mis à '' par l'INSERT ci-dessus)
        // n'est pas nécessaire ici, mais on s'assure que l'état au
        // ré-open est bien « legacy : aucune ligne n'a de package_id ».
        conn.execute("UPDATE serveurs SET package_id = ''", [])
            .unwrap();
    }

    // Étape 2 : réouvrir → backfill se déclenche.
    let store = Store::open(&path).unwrap();
    let serveurs = store.lister_serveurs().unwrap();

    assert_eq!(
        serveurs.len(),
        1,
        "le backfill doit fusionner les 3 doublons en une seule ligne",
    );
    let restant = &serveurs[0];
    assert_eq!(
        restant.id.to_string(),
        id_riche,
        "la ligne conservée doit être celle qui avait le plus d'outils",
    );
    assert_eq!(
        restant.premiere_vue.to_rfc3339(),
        premiere_vue_ancienne,
        "la `premiere_vue` la plus ancienne du groupe doit être préservée",
    );
}

#[test]
fn backfill_v4_db_neuve_sans_doublons_ne_change_rien() {
    let tmp = TempDir::new().unwrap();
    let store = Store::open(tmp.path().join("clean.db")).unwrap();

    let a = fixture("npx -y @modelcontextprotocol/server-fetch");
    let mut b = fixture("npx -y @modelcontextprotocol/server-brave-search");
    b.transport = Transport::Stdio;

    store.upsert_serveur(&a).unwrap();
    store.upsert_serveur(&b).unwrap();

    let serveurs = store.lister_serveurs().unwrap();
    assert_eq!(serveurs.len(), 2);
}
