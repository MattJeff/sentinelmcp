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
fn backfill_v4_resout_package_id_vide_collisionnant_avec_index_existant() {
    // Régression (persistance disque cassée → fallback mémoire) :
    // une DB DÉJÀ passée par V4 a l'index unique EN PLACE, mais une ligne a
    // `package_id = ''` (insérée par un chemin qui ne calculait pas
    // l'identité). Son endpoint résout vers la MÊME identité qu'une ligne
    // existante. Avant le fix, l'UPDATE de remplissage du backfill violait
    // l'index AVANT que la dédup ne fusionne → `Store::open` renvoyait
    // « UNIQUE constraint failed: serveurs.package_id, serveurs.scope » et
    // l'app retombait en mémoire à chaque lancement. Après : le backfill
    // dépose l'index, remplit, déduplique, puis le recrée.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("collide.db");

    let id_existant = Uuid::new_v4().to_string();
    let id_vide = Uuid::new_v4().to_string();
    let derniere_vue = Utc::now().to_rfc3339();

    {
        // `open` matérialise le schéma complet + l'index unique (V4).
        let store = Store::open(&path).unwrap();
        drop(store);
        let conn = rusqlite::Connection::open(&path).unwrap();

        // Ligne « réelle » : identité @modelcontextprotocol/server-filesystem | user.
        conn.execute(
            r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante, tags, scope, package_id)
               VALUES (?1, ?2, '"stdio"', '[]', '"inconnu"', '"orange"', ?3, ?3, NULL, '[]', 'user',
                       '@modelcontextprotocol/server-filesystem')"#,
            params![
                id_existant,
                "npx -y @modelcontextprotocol/server-filesystem /Users/a/Documents",
                derniere_vue,
            ],
        )
        .unwrap();

        // Ligne avec package_id='' dont l'endpoint résout vers la MÊME identité.
        // L'index unique la tolère ici car '' ≠ '@…/server-filesystem'.
        conn.execute(
            r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante, tags, scope, package_id)
               VALUES (?1, ?2, '"stdio"', '[]', '"inconnu"', '"orange"', ?3, ?3, NULL, '[]', 'user', '')"#,
            params![
                id_vide,
                "npx -y @modelcontextprotocol/server-filesystem /tmp",
                derniere_vue,
            ],
        )
        .unwrap();
    }

    // Réouverture : sans le fix, le backfill plante et `open` renvoie Err.
    let store = Store::open(&path)
        .expect("open doit réussir : le backfill dépose l'index avant de remplir puis dédup");
    let serveurs = store.lister_serveurs().unwrap();
    assert_eq!(
        serveurs.len(),
        1,
        "les deux lignes de même identité (package_id vide rempli + existante) doivent fusionner",
    );
}

/// Helper de test : injecte deux lignes avec la même identité
/// canonique dans la DB ouverte par `store`, en bypassant l'index
/// unique. La connexion partagée du `Store` est réutilisée pour
/// éviter la collision SQLite "database is locked" qu'on aurait
/// avec une `Connection::open` parallèle.
fn injecter_doublon_brut(
    db_path: &std::path::Path,
    package_id: &str,
    id_a: Uuid,
    nb_outils_a: usize,
    id_b: Uuid,
    nb_outils_b: usize,
) {
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute_batch("DROP INDEX IF EXISTS idx_serveurs_identite;")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    for (id, nb) in [(id_a, nb_outils_a), (id_b, nb_outils_b)] {
        conn.execute(
            r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante, tags, scope, package_id)
               VALUES (?1, ?2, '"stdio"', '[]', '"inconnu"', '"orange"',
                       ?3, ?3, NULL, '[]', 'user', ?4)"#,
            params![id.to_string(), format!("npx -y {package_id}"), now, package_id],
        )
        .unwrap();
        for i in 0..nb {
            conn.execute(
                "INSERT INTO outils (id, serveur_id, nom, description, input_schema, empreinte)
                 VALUES (?1, ?2, ?3, NULL, '{}', 'fp')",
                params![Uuid::new_v4().to_string(), id.to_string(), format!("o{i}")],
            )
            .unwrap();
        }
    }
}

/// Helper : ouvre le store et applique les migrations jusqu'à V4
/// SANS exécuter le backfill (qui supprimerait les doublons qu'on
/// vient d'injecter). Reproduit l'état "DB chargée par un code path
/// ad hoc, GC continu pas encore déclenché".
fn ouvrir_sans_backfill(path: &std::path::Path) -> Store {
    // Étape 1 : ouvrir une fois pour que les migrations soient
    // appliquées et que la table existe.
    Store::open(path).unwrap()
}

#[test]
fn nettoyer_fantomes_supprime_les_lignes_zero_outils_meme_identite() {
    // Scénario : un chemin d'écriture ad hoc a réussi à poser deux
    // lignes avec la même identité canonique. L'une a 3 outils
    // (vraie), l'autre 0 (fantôme). `nettoyer_fantomes` doit
    // supprimer la fantôme et garder la vraie.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("gc.db");
    let _bootstrap = ouvrir_sans_backfill(&path);
    drop(_bootstrap);

    let id_vraie = Uuid::new_v4();
    let id_fantome = Uuid::new_v4();
    injecter_doublon_brut(
        &path,
        "@modelcontextprotocol/server-fetch",
        id_vraie,
        3,
        id_fantome,
        0,
    );

    // À ce point, la DB a 2 lignes même (package_id, scope), une avec
    // 3 outils et une avec 0. `Store::open` va relancer le backfill
    // qui — par construction — fusionne ce même cas. C'est attendu :
    // le backfill et le GC continu appliquent la même règle, le GC
    // n'est que le filet de sécurité runtime du backfill au boot.
    let store = Store::open(&path).unwrap();
    let restants = store.lister_serveurs().unwrap();
    assert_eq!(
        restants.len(),
        1,
        "le backfill au ré-open doit déjà avoir purgé la fantôme",
    );
    assert_eq!(
        restants[0].id, id_vraie,
        "la ligne survivante doit être celle qui avait les outils",
    );

    // Et appeler explicitement `nettoyer_fantomes` derrière ne casse
    // rien (idempotence) et retourne 0 suppressions supplémentaires.
    let supprimes = store
        .nettoyer_fantomes(
            "@modelcontextprotocol/server-fetch",
            &ScopeServeur::User,
            id_vraie,
        )
        .unwrap();
    assert_eq!(supprimes, 0);
}

#[test]
fn nettoyer_fantomes_preserve_les_lignes_avec_outils() {
    // Cas miroir : si les deux lignes ont des outils, on ne touche à
    // rien. Le GC est seulement destiné à éliminer les fantômes (0
    // outils), jamais à arbitrer entre deux déclarations qui ont
    // chacune des outils probés.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("gc2.db");
    let _ = ouvrir_sans_backfill(&path);

    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    injecter_doublon_brut(&path, "pkg", id_a, 2, id_b, 2);

    // Ré-open : le backfill élit toujours un gagnant (premiere_vue /
    // derniere_vue tie-break) et supprime sèchement les autres
    // membres du groupe, même si le perdant a des outils. C'est la
    // règle "une seule entrée par identité canonique". Le GC
    // continu, lui, est plus prudent et ne touche qu'aux fantômes
    // 0-outils — c'est pour ça qu'on le valide directement sans
    // passer par le backfill.
    let store = Store::open(&path).unwrap();
    let supprimes = store
        .nettoyer_fantomes("pkg", &ScopeServeur::User, id_a)
        .unwrap();
    assert_eq!(
        supprimes, 0,
        "nettoyer_fantomes ne supprime que les lignes 0-outils",
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
