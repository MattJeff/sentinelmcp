//! sentinel-store — store local embarqué (SQLite) pour Sentinel MCP.
//!
//! Contient l'inventaire (serveurs, outils), les baselines, l'historique
//! des contacts, les constats et les alertes. Aucun contenu de `tools/call`
//! n'est persisté — règle non négociable.

pub mod registry_cache;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use sentinel_protocol::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// DTO miroir d'une ligne de la table `historique_contacts`.
///
/// Représente un contact JSON-RPC observé sur le fil : seules les
/// métadonnées (méthode, session, horodatage) sont persistées — jamais
/// le contenu de `tools/call`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoriqueContact {
    pub id: i64,
    pub serveur_id: String,
    pub session_id: String,
    pub methode: String,
    pub horodatage: DateTime<Utc>,
}

/// Nombre de versions de baseline conservées par serveur par défaut
/// lors du GC de l'historique (`Store::gc_historique_baselines`).
pub const GC_HISTORIQUE_BASELINES_DEFAUT: usize = 50;

/// DTO miroir d'une ligne de la table `historique_baselines` (V5).
///
/// Chaque enregistrement de baseline archive une version complète —
/// empreintes, outils, approbateur, raison — avec un numéro de version
/// monotone par serveur. Sert l'audit (« qui a changé quoi, quand,
/// pourquoi ») et le rollback vers une version antérieure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionBaseline {
    pub id: String,
    pub serveur_id: ServeurId,
    pub baseline_id: BaselineId,
    pub empreinte_serveur: Empreinte,
    pub empreintes_outils: std::collections::BTreeMap<String, Empreinte>,
    pub outils: Vec<Outil>,
    pub horodatage: DateTime<Utc>,
    pub approbateur: String,
    pub raison: String,
    pub version: i64,
}

/// DTO miroir d'une ligne de la table `investigations`.
///
/// Une investigation est une note libre attachée à un serveur — créée
/// quand un opérateur décide d'« investiguer » plutôt qu'approuver ou
/// bloquer. Persistée pour audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    pub id: String,
    pub serveur_id: String,
    pub note: String,
    pub cree_par: String,
    pub cree_a: DateTime<Utc>,
    pub etat: String,
}

/// Migrations SQL embarquées via refinery. Le dossier `src/migrations/`
/// porte les fichiers `V{n}__{nom}.sql` ; refinery les compile dans le
/// binaire et tient à jour la table `refinery_schema_history`.
mod embedded_migrations {
    refinery::embed_migrations!("src/migrations");
}

/// Accès lecture seule aux migrations embarquées — utilisé uniquement
/// par les tests externes qui ont besoin de connaître la liste des
/// migrations et leurs checksums (e.g. pour simuler une DB déjà
/// upgradée jusqu'à une version donnée). À ne PAS utiliser en
/// production : passer par `Store::open` qui orchestre tout.
pub fn migrations_pour_tests_seulement() -> Result<Vec<refinery::Migration>> {
    Ok(embedded_migrations::migrations::runner()
        .get_migrations()
        .to_vec())
}

/// Store SQLite embarqué, partagé par toute l'application via Arc.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Connection>>,
}

impl Store {
    /// Ouvre le store à un chemin donné (ou en mémoire si `:memory:`).
    ///
    /// Exécute les migrations refinery embarquées. Rétrocompat : si la
    /// DB a été créée par l'ancien `execute_batch(SCHEMA_SQL)` (donc sans
    /// historique refinery mais avec la table `serveurs` déjà en place),
    /// on insère manuellement la ligne correspondant à V1 dans
    /// `refinery_schema_history` avant de lancer le runner, sinon
    /// refinery tenterait de rejouer V1 et planterait sur les
    /// `CREATE TABLE`. Les migrations suivantes (V2+) sont appliquées
    /// normalement.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut conn = if path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        Self::amorcer_historique_refinery(&conn)?;
        embedded_migrations::migrations::runner().run(&mut conn)?;
        Self::backfill_v4_identite(&mut conn)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    /// Backfill de la colonne `package_id` (introduite par V4) et fusion
    /// des doublons hérités de la dédup historique sur `endpoint`.
    ///
    /// Stratégie :
    ///   1. Pour chaque ligne dont `package_id` est vide, calculer
    ///      l'identité canonique via `extraire_package_id(endpoint, transport)`.
    ///   2. Grouper les serveurs par `(package_id, scope)`. Tout groupe
    ///      de taille > 1 est un doublon hérité.
    ///   3. Choisir un **gagnant** par groupe : la ligne qui a le plus
    ///      d'outils probés (tie-break sur `derniere_vue` la plus
    ///      récente). C'est la « vraie » entrée, celle qui a effectivement
    ///      vu un `tools/list` réussir.
    ///   4. Avant suppression des perdants, transférer au gagnant les
    ///      bouts d'historique opérateur qui valent la peine d'être
    ///      conservés : `premiere_vue` la plus ancienne du groupe, tags
    ///      non vides s'il n'en a pas, baseline approuvée et statut
    ///      d'approbation s'il n'en a pas.
    ///   5. Suppression sèche des perdants (et de toutes leurs lignes
    ///      filles : outils, historique_contacts, constats, alertes,
    ///      baselines, inventaire_approuve, investigations). C'est le
    ///      compromis demandé : on perd la trace que la ligne fantôme
    ///      a existé, en échange d'un inventaire propre.
    ///   6. Une fois tous les groupes purgés, écrire l'index unique
    ///      `idx_serveurs_identite (package_id, scope)`. Refusera
    ///      désormais toute insertion dupliquée — la dédup endpoint
    ///      historique ne peut plus revenir par accident.
    ///
    /// Toute la fonction tourne dans une transaction unique : si quoi
    /// que ce soit échoue (groupe corrompu, FK orpheline, …) la DB
    /// reste exactement dans son état pré-backfill.
    fn backfill_v4_identite(conn: &mut Connection) -> Result<()> {
        let tx = conn.transaction()?;

        // 1) Calcul du package_id pour toute ligne où il est encore vide.
        //    On lit (id, endpoint, transport, scope) et on remplit la
        //    colonne en un coup. Le transport est stocké en JSON sérialisé
        //    par serde (`"stdio"` ou `"http"`), même valeur que ce que
        //    voit `lister_serveurs`.
        struct LigneBrute {
            id: String,
            endpoint: String,
            transport: String,
        }
        let lignes: Vec<LigneBrute> = {
            let mut stmt = tx.prepare(
                "SELECT id, endpoint, transport FROM serveurs WHERE package_id = ''",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(LigneBrute {
                    id: r.get(0)?,
                    endpoint: r.get(1)?,
                    transport: r.get(2)?,
                })
            })?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r?);
            }
            v
        };

        for ligne in &lignes {
            let transport: Transport =
                serde_json::from_str(&ligne.transport).unwrap_or(Transport::Stdio);
            let package_id = extraire_package_id(&ligne.endpoint, transport);
            tx.execute(
                "UPDATE serveurs SET package_id = ?1 WHERE id = ?2",
                params![package_id, ligne.id],
            )?;
        }

        // 2) Grouper et résoudre les collisions par (package_id, scope).
        //    On lit en une passe (id, package_id, scope, derniere_vue,
        //    premiere_vue, tags) + le nombre d'outils probés sur chaque
        //    serveur. La requête `LEFT JOIN` est plus lisible mais
        //    sqlite n'aime pas trop ; on fait deux passes Rust.
        struct LigneAvecMetadata {
            id: String,
            package_id: String,
            scope: String,
            derniere_vue: String,
            premiere_vue: String,
            tags: String,
            nb_outils: i64,
        }
        let toutes: Vec<LigneAvecMetadata> = {
            let mut stmt = tx.prepare(
                "SELECT s.id, s.package_id, s.scope, s.derniere_vue, s.premiere_vue,
                        s.tags, (SELECT COUNT(*) FROM outils o WHERE o.serveur_id = s.id)
                 FROM serveurs s",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(LigneAvecMetadata {
                    id: r.get(0)?,
                    package_id: r.get(1)?,
                    scope: r.get(2)?,
                    derniere_vue: r.get(3)?,
                    premiere_vue: r.get(4)?,
                    tags: r.get(5)?,
                    nb_outils: r.get(6)?,
                })
            })?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r?);
            }
            v
        };

        use std::collections::HashMap;
        let mut groupes: HashMap<(String, String), Vec<LigneAvecMetadata>> = HashMap::new();
        for ligne in toutes {
            groupes
                .entry((ligne.package_id.clone(), ligne.scope.clone()))
                .or_default()
                .push(ligne);
        }

        for ((_pid, _scope), mut membres) in groupes {
            if membres.len() < 2 {
                continue;
            }
            // 3) Élire le gagnant : max(nb_outils) puis derniere_vue desc.
            membres.sort_by(|a, b| {
                b.nb_outils
                    .cmp(&a.nb_outils)
                    .then_with(|| b.derniere_vue.cmp(&a.derniere_vue))
            });
            let gagnant = membres.remove(0);

            // 4) Préserver les morceaux d'historique opérateur qui valent
            //    la peine : premiere_vue min, tags non vides, baseline et
            //    approbation si le gagnant n'en a pas.
            let mut premiere_vue_min = gagnant.premiere_vue.clone();
            let mut tags_pour_gagnant: Option<String> = None;
            let gagnant_tags_vides = gagnant.tags.trim() == "[]" || gagnant.tags.is_empty();

            for perdant in &membres {
                if perdant.premiere_vue < premiere_vue_min {
                    premiere_vue_min = perdant.premiere_vue.clone();
                }
                if gagnant_tags_vides
                    && tags_pour_gagnant.is_none()
                    && perdant.tags.trim() != "[]"
                    && !perdant.tags.is_empty()
                {
                    tags_pour_gagnant = Some(perdant.tags.clone());
                }
            }

            // Réassigner baseline / inventaire_approuve si le gagnant n'en
            // a pas et qu'un perdant en a une. On boucle sur les perdants
            // dans l'ordre du tri (plus probables avant) et on prend la
            // première trouvée.
            let gagnant_a_baseline: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM baselines WHERE serveur_id = ?1)",
                params![gagnant.id],
                |r| r.get(0),
            )?;
            let gagnant_a_approbation: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM inventaire_approuve WHERE serveur_id = ?1)",
                params![gagnant.id],
                |r| r.get(0),
            )?;
            for perdant in &membres {
                if !gagnant_a_baseline {
                    tx.execute(
                        "UPDATE baselines SET serveur_id = ?1
                         WHERE serveur_id = ?2
                           AND NOT EXISTS (SELECT 1 FROM baselines WHERE serveur_id = ?1)",
                        params![gagnant.id, perdant.id],
                    )?;
                }
                if !gagnant_a_approbation {
                    tx.execute(
                        "UPDATE inventaire_approuve SET serveur_id = ?1
                         WHERE serveur_id = ?2
                           AND NOT EXISTS (SELECT 1 FROM inventaire_approuve WHERE serveur_id = ?1)",
                        params![gagnant.id, perdant.id],
                    )?;
                }
            }

            // Appliquer les mises à jour au gagnant.
            tx.execute(
                "UPDATE serveurs SET premiere_vue = ?1 WHERE id = ?2",
                params![premiere_vue_min, gagnant.id],
            )?;
            if let Some(tags) = tags_pour_gagnant {
                tx.execute(
                    "UPDATE serveurs SET tags = ?1 WHERE id = ?2",
                    params![tags, gagnant.id],
                )?;
            }

            // 5) Suppression sèche des perdants et de toutes leurs lignes
            //    filles. Ordre : feuilles d'abord (alertes via constats),
            //    puis les tables qui pointent directement sur serveurs.
            for perdant in &membres {
                tx.execute(
                    "DELETE FROM alertes
                     WHERE constat_id IN (SELECT id FROM constats WHERE serveur_id = ?1)",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM constats WHERE serveur_id = ?1",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM baselines WHERE serveur_id = ?1",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM outils WHERE serveur_id = ?1",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM historique_contacts WHERE serveur_id = ?1",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM inventaire_approuve WHERE serveur_id = ?1",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM investigations WHERE serveur_id = ?1",
                    params![perdant.id],
                )?;
                tx.execute(
                    "DELETE FROM serveurs WHERE id = ?1",
                    params![perdant.id],
                )?;
            }
        }

        // 6) Index unique. Sûr à créer maintenant que les doublons sont
        //    purgés. `IF NOT EXISTS` pour rester idempotent au prochain
        //    démarrage.
        tx.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_serveurs_identite
             ON serveurs(package_id, scope);",
        )?;

        tx.commit()?;
        Ok(())
    }

    pub fn in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    /// Détecte une DB legacy (créée avant l'introduction de refinery) et
    /// marque V1 comme appliquée pour éviter le re-jeu. Le hash inscrit
    /// est calculé par refinery au moment de `run()` — ici on insère une
    /// ligne pivot que refinery va valider/compléter. La stratégie : si
    /// la table `serveurs` existe mais `refinery_schema_history` n'existe
    /// pas, on crée l'historique et on y insère la ligne V1 avec les
    /// métadonnées attendues. Refinery vérifie ensuite par checksum.
    fn amorcer_historique_refinery(conn: &Connection) -> Result<()> {
        let serveurs_existe: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='serveurs'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        let history_existe: bool = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='refinery_schema_history'",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        // DB neuve : refinery se charge de tout.
        if !serveurs_existe {
            return Ok(());
        }
        // DB déjà gérée par refinery : rien à faire.
        if history_existe {
            return Ok(());
        }

        // DB legacy : on crée la table d'historique au format refinery
        // 0.8 et on marque V1 comme appliquée. Le checksum doit
        // correspondre à celui calculé par refinery sur le fichier
        // `V1__init.sql` embarqué — on récupère donc la première
        // migration via l'API publique du runner pour rester en phase.
        let runner = embedded_migrations::migrations::runner();
        let migrations = runner.get_migrations();
        let v1 = migrations
            .iter()
            .find(|m| m.version() == 1)
            .ok_or_else(|| anyhow::anyhow!("migration V1 introuvable dans le binaire"))?;

        conn.execute_batch(
            r#"CREATE TABLE refinery_schema_history (
                version INT4 PRIMARY KEY,
                name VARCHAR(255),
                applied_on VARCHAR(255),
                checksum VARCHAR(255)
            );"#,
        )?;
        conn.execute(
            "INSERT INTO refinery_schema_history (version, name, applied_on, checksum)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                v1.version() as i64,
                v1.name(),
                Utc::now().to_rfc3339(),
                v1.checksum().to_string(),
            ],
        )?;
        Ok(())
    }

    /// Insère ou met à jour un serveur.
    ///
    /// `tags` est sérialisé en JSON array. Sur conflit on conserve les
    /// tags existants si le payload entrant est vide (préserve les
    /// étiquettes posées par l'opérateur même si le scanner refait un
    /// upsert sans connaissance des tags). `scope` est sérialisé via
    /// `ScopeServeur::vers_sql` (colonne ajoutée par la migration V3) ;
    /// l'UPDATE écrase systématiquement le scope car la couche de
    /// découverte est la source de vérité.
    pub fn upsert_serveur(&self, s: &Serveur) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        let tags_json = serde_json::to_string(&s.tags)?;
        let scope_sql = s.scope.vers_sql();
        // L'identité canonique est dérivée à l'écriture, jamais portée
        // par le `Serveur` côté wire. Garantit que chaque ligne en base
        // a un `package_id` non vide et que l'index unique
        // `idx_serveurs_identite` (package_id, scope) reste activable.
        let package_id = extraire_package_id(&s.endpoint, s.transport);
        conn.execute(
            r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante, tags, scope, package_id)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
               ON CONFLICT(id) DO UPDATE SET
                 derniere_vue = excluded.derniere_vue,
                 statut = excluded.statut,
                 couleur = excluded.couleur,
                 empreinte_courante = excluded.empreinte_courante,
                 portees = excluded.portees,
                 tags = CASE WHEN excluded.tags = '[]' THEN serveurs.tags
                             ELSE excluded.tags END,
                 scope = excluded.scope,
                 package_id = excluded.package_id"#,
            params![
                s.id.to_string(),
                s.endpoint,
                serde_json::to_string(&s.transport)?,
                serde_json::to_string(&s.portees)?,
                serde_json::to_string(&s.statut)?,
                serde_json::to_string(&s.couleur)?,
                s.premiere_vue.to_rfc3339(),
                s.derniere_vue.to_rfc3339(),
                s.empreinte_courante,
                tags_json,
                scope_sql,
                package_id,
            ],
        )?;
        Ok(())
    }

    pub fn lister_serveurs(&self) -> Result<Vec<Serveur>> {
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante, tags, scope FROM serveurs",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let transport: String = row.get(2)?;
            let portees: String = row.get(3)?;
            let statut: String = row.get(4)?;
            let couleur: String = row.get(5)?;
            let premiere_vue: String = row.get(6)?;
            let derniere_vue: String = row.get(7)?;
            let tags_raw: Option<String> = row.get(9)?;
            let scope_raw: String = row.get(10)?;
            let tags = tags_raw
                .as_deref()
                .filter(|s| !s.is_empty())
                .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                .unwrap_or_default();
            Ok(Serveur {
                id: uuid::Uuid::parse_str(&id).unwrap_or_else(|_| uuid::Uuid::nil()),
                endpoint: row.get(1)?,
                transport: serde_json::from_str(&transport).unwrap_or(Transport::Http),
                portees: serde_json::from_str(&portees).unwrap_or_default(),
                statut: serde_json::from_str(&statut).unwrap_or(StatutServeur::Inconnu),
                couleur: serde_json::from_str(&couleur).unwrap_or(Couleur::Orange),
                premiere_vue: DateTime::parse_from_rfc3339(&premiere_vue)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                derniere_vue: DateTime::parse_from_rfc3339(&derniere_vue)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                empreinte_courante: row.get(8)?,
                tags,
                scope: ScopeServeur::depuis_sql(&scope_raw),
            })
        })?;
        let mut v = vec![];
        for r in rows {
            v.push(r?);
        }
        Ok(v)
    }

    /// Liste les serveurs dont le scope correspond exactement à
    /// `scope_filtre`. Pratique pour l'UI : "afficher uniquement les
    /// MCPs déclarés au scope projet `/chemin`".
    pub fn lister_serveurs_par_scope(
        &self,
        scope_filtre: &ScopeServeur,
    ) -> Result<Vec<Serveur>> {
        let attendu = scope_filtre.vers_sql();
        let tous = self.lister_serveurs()?;
        Ok(tous
            .into_iter()
            .filter(|s| s.scope.vers_sql() == attendu)
            .collect())
    }

    /// Remplace l'ensemble des tags d'un serveur sans toucher au reste.
    /// Renvoie une erreur silencieuse si le serveur n'existe pas (0 ligne
    /// affectée — l'appelant peut le détecter via la valeur retournée).
    pub fn definir_tags_serveur(&self, serveur_id: &ServeurId, tags: &[String]) -> Result<usize> {
        let conn = self.inner.lock().unwrap();
        let payload = serde_json::to_string(tags)?;
        let n = conn.execute(
            "UPDATE serveurs SET tags = ?1 WHERE id = ?2",
            params![payload, serveur_id.to_string()],
        )?;
        Ok(n)
    }

    /// Liste l'union triée et dédupliquée des tags posés sur tous les
    /// serveurs. Implémentation simple côté Rust : suffisant tant que
    /// l'inventaire reste de l'ordre de quelques dizaines à centaines
    /// d'entrées.
    pub fn lister_tags_distincts(&self) -> Result<Vec<String>> {
        use std::collections::BTreeSet;
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare("SELECT tags FROM serveurs")?;
        let rows = stmt.query_map([], |row| {
            let raw: Option<String> = row.get(0)?;
            Ok(raw)
        })?;
        let mut set: BTreeSet<String> = BTreeSet::new();
        for r in rows {
            if let Some(raw) = r? {
                if let Ok(v) = serde_json::from_str::<Vec<String>>(&raw) {
                    for tag in v {
                        let t = tag.trim().to_string();
                        if !t.is_empty() {
                            set.insert(t);
                        }
                    }
                }
            }
        }
        Ok(set.into_iter().collect())
    }

    pub fn get_serveur_par_endpoint(&self, endpoint: &str) -> Result<Option<Serveur>> {
        let serveurs = self.lister_serveurs()?;
        Ok(serveurs.into_iter().find(|s| s.endpoint == endpoint))
    }

    /// Supprime sèchement les lignes « fantômes » qui partagent la même
    /// identité canonique `(package_id, scope)` que `id_conserve` mais
    /// qui n'ont jamais vu un `tools/list` réussir (zéro outil probé).
    ///
    /// L'index unique posé par V4 garantit déjà qu'une telle situation
    /// ne se produit plus dans la voie d'écriture canonique
    /// (`AdaptateurStore::enregistrer_inventaire`). Ce GC reste appelé
    /// défensivement à chaque enregistrement d'un inventaire non vide :
    /// si une régression future ou un chemin d'écriture ad hoc (test,
    /// mock, migration partielle) ouvrait une porte, la ligne fantôme
    /// serait nettoyée dès le prochain probe réussi du même paquet.
    ///
    /// Retourne le nombre de lignes supprimées (souvent 0 — c'est le
    /// signe que la voie canonique tient).
    pub fn nettoyer_fantomes(
        &self,
        package_id: &str,
        scope: &ScopeServeur,
        id_conserve: ServeurId,
    ) -> Result<usize> {
        let scope_sql = scope.vers_sql();
        let id_str = id_conserve.to_string();
        let conn = self.inner.lock().unwrap();

        // Cibler : même (package_id, scope), id différent, et 0 outils
        // probés. Le filtre `0 outils` est l'invariant qui distingue un
        // fantôme (jamais vu un tools/list) d'une vraie déclaration
        // dupliquée (qu'on ne voudrait pas supprimer).
        let mut stmt = conn.prepare(
            "SELECT id FROM serveurs
             WHERE package_id = ?1
               AND scope = ?2
               AND id <> ?3
               AND (SELECT COUNT(*) FROM outils o WHERE o.serveur_id = serveurs.id) = 0",
        )?;
        let ids: Vec<String> = stmt
            .query_map(params![package_id, scope_sql, id_str], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<_, _>>()?;
        drop(stmt);

        for id in &ids {
            conn.execute(
                "DELETE FROM alertes
                 WHERE constat_id IN (SELECT id FROM constats WHERE serveur_id = ?1)",
                params![id],
            )?;
            conn.execute("DELETE FROM constats WHERE serveur_id = ?1", params![id])?;
            conn.execute("DELETE FROM baselines WHERE serveur_id = ?1", params![id])?;
            conn.execute("DELETE FROM outils WHERE serveur_id = ?1", params![id])?;
            conn.execute(
                "DELETE FROM historique_contacts WHERE serveur_id = ?1",
                params![id],
            )?;
            conn.execute(
                "DELETE FROM inventaire_approuve WHERE serveur_id = ?1",
                params![id],
            )?;
            conn.execute("DELETE FROM investigations WHERE serveur_id = ?1", params![id])?;
            conn.execute("DELETE FROM serveurs WHERE id = ?1", params![id])?;
        }
        Ok(ids.len())
    }

    /// Résout un serveur par son identité canonique `(package_id, scope)`.
    ///
    /// C'est la voie de dédup officielle depuis V4 : l'index unique
    /// `idx_serveurs_identite` garantit qu'il y a au plus un résultat.
    /// Le scope est sérialisé via `ScopeServeur::vers_sql` pour matcher
    /// exactement la valeur stockée.
    pub fn get_serveur_par_identite(
        &self,
        package_id: &str,
        scope: &ScopeServeur,
    ) -> Result<Option<Serveur>> {
        let scope_sql = scope.vers_sql();
        let serveurs = self.lister_serveurs()?;
        Ok(serveurs
            .into_iter()
            .find(|s| s.scope.vers_sql() == scope_sql
                && extraire_package_id(&s.endpoint, s.transport) == package_id))
    }

    pub fn upsert_outil(&self, serveur_id: ServeurId, outil: &Outil, empreinte: &Empreinte) -> Result<OutilId> {
        let conn = self.inner.lock().unwrap();
        let id = uuid::Uuid::new_v4();
        conn.execute(
            r#"INSERT INTO outils (id, serveur_id, nom, description, input_schema, empreinte)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(serveur_id, nom) DO UPDATE SET
                 description = excluded.description,
                 input_schema = excluded.input_schema,
                 empreinte = excluded.empreinte"#,
            params![
                id.to_string(),
                serveur_id.to_string(),
                outil.nom,
                outil.description,
                serde_json::to_string(&outil.input_schema)?,
                empreinte.as_str(),
            ],
        )?;
        Ok(id)
    }

    pub fn lister_outils(&self, serveur_id: ServeurId) -> Result<Vec<Outil>> {
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT nom, description, input_schema FROM outils WHERE serveur_id = ?1")?;
        let rows = stmt.query_map(params![serveur_id.to_string()], |row| {
            let schema: String = row.get(2)?;
            Ok(Outil {
                nom: row.get(0)?,
                description: row.get(1)?,
                input_schema: serde_json::from_str(&schema).unwrap_or(serde_json::Value::Null),
                meta: Default::default(),
            })
        })?;
        let mut v = vec![];
        for r in rows {
            v.push(r?);
        }
        Ok(v)
    }

    /// Enregistre une baseline (raison vide). Voir
    /// [`Store::enregistrer_baseline_versionnee`] pour fournir une raison
    /// explicite (rollback, import golden, ré-approbation…).
    pub fn enregistrer_baseline(&self, b: &Baseline) -> Result<()> {
        self.enregistrer_baseline_versionnee(b, "").map(|_| ())
    }

    /// Enregistre une baseline et archive simultanément une version dans
    /// `historique_baselines`. Rien n'est jamais écrasé : la table
    /// `baselines` accumule (la « courante » est la plus récente) et
    /// l'historique reçoit une nouvelle ligne au numéro de version
    /// suivant (monotone par serveur). Tout se passe dans une
    /// transaction unique — soit les deux écritures réussissent, soit
    /// aucune. Retourne le numéro de version attribué.
    ///
    /// Attribution de version : `MAX(version) + 1` lu dans une
    /// transaction `BEGIN IMMEDIATE`, qui prend le verrou d'écriture
    /// SQLite dès l'ouverture — le couple lecture/écriture est donc
    /// sérialisé aussi entre process partageant le même fichier (au
    /// sein d'un process, le Mutex suffit). Si un autre process tient
    /// déjà le verrou, SQLite retourne `SQLITE_BUSY` : erreur propre,
    /// jamais de version dupliquée ni de corruption.
    pub fn enregistrer_baseline_versionnee(&self, b: &Baseline, raison: &str) -> Result<i64> {
        let mut conn = self.inner.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let empreintes_outils_json = serde_json::to_string(&b.empreintes_outils)?;
        let outils_json = serde_json::to_string(&b.outils)?;

        tx.execute(
            r#"INSERT INTO baselines (id, serveur_id, empreinte_serveur, empreintes_outils,
                outils, date_approbation, approuve_par)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                b.id.to_string(),
                b.serveur_id.to_string(),
                b.empreinte_serveur.as_str(),
                empreintes_outils_json,
                outils_json,
                b.date_approbation.to_rfc3339(),
                b.approuve_par,
            ],
        )?;

        let version: i64 = tx.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM historique_baselines
             WHERE serveur_id = ?1",
            params![b.serveur_id.to_string()],
            |r| r.get(0),
        )?;

        tx.execute(
            r#"INSERT INTO historique_baselines (id, serveur_id, baseline_id,
                empreinte_serveur, empreintes_outils, outils, horodatage,
                approbateur, raison, version)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                uuid::Uuid::new_v4().to_string(),
                b.serveur_id.to_string(),
                b.id.to_string(),
                b.empreinte_serveur.as_str(),
                empreintes_outils_json,
                outils_json,
                b.date_approbation.to_rfc3339(),
                b.approuve_par,
                raison,
                version,
            ],
        )?;

        tx.commit()?;
        Ok(version)
    }

    /// Liste l'historique versionné des baselines d'un serveur, de la
    /// version la plus récente à la plus ancienne.
    pub fn lister_historique_baselines(
        &self,
        serveur_id: ServeurId,
    ) -> Result<Vec<VersionBaseline>> {
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, baseline_id, empreinte_serveur, empreintes_outils,
                outils, horodatage, approbateur, raison, version
               FROM historique_baselines
               WHERE serveur_id = ?1
               ORDER BY version DESC"#,
        )?;
        let rows = stmt.query_map(params![serveur_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })?;
        let mut v = vec![];
        for r in rows {
            let (id, baseline_id, emp_s, emp_o, outils, horodatage, approbateur, raison, version) =
                r?;
            // Toute ligne illisible est une erreur dure — pas de valeur
            // par défaut silencieuse : un rollback vers une version au
            // JSON corrompu restaurerait sinon une baseline vide (0
            // outil) comme baseline courante sans que personne ne le voie.
            v.push(VersionBaseline {
                id,
                serveur_id,
                baseline_id: uuid::Uuid::parse_str(&baseline_id).map_err(|e| {
                    anyhow::anyhow!(
                        "historique_baselines (serveur {serveur_id}, version {version}) : \
                         baseline_id invalide '{baseline_id}' : {e}"
                    )
                })?,
                empreinte_serveur: Empreinte::new(emp_s),
                empreintes_outils: serde_json::from_str(&emp_o).map_err(|e| {
                    anyhow::anyhow!(
                        "historique_baselines (serveur {serveur_id}, version {version}) : \
                         empreintes_outils JSON corrompu : {e}"
                    )
                })?,
                outils: serde_json::from_str(&outils).map_err(|e| {
                    anyhow::anyhow!(
                        "historique_baselines (serveur {serveur_id}, version {version}) : \
                         outils JSON corrompu : {e}"
                    )
                })?,
                horodatage: DateTime::parse_from_rfc3339(&horodatage)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "historique_baselines (serveur {serveur_id}, version {version}) : \
                             horodatage invalide '{horodatage}' : {e}"
                        )
                    })?,
                approbateur,
                raison,
                version,
            });
        }
        Ok(v)
    }

    /// Restaure une version antérieure de baseline comme baseline
    /// courante. Le contenu (empreintes + outils) de la version visée
    /// est ré-enregistré comme **nouvelle** baseline — l'historique
    /// reste intact et gagne une ligne `rollback vers version N`
    /// attribuée à `approbateur`. Erreur si la version n'existe pas.
    pub fn rollback_baseline(
        &self,
        serveur_id: ServeurId,
        version: i64,
        approbateur: &str,
    ) -> Result<Baseline> {
        let cible = self
            .lister_historique_baselines(serveur_id)?
            .into_iter()
            .find(|v| v.version == version)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "version {} introuvable dans l'historique des baselines du serveur {}",
                    version,
                    serveur_id
                )
            })?;

        let baseline = Baseline {
            id: uuid::Uuid::new_v4(),
            serveur_id,
            empreinte_serveur: cible.empreinte_serveur,
            empreintes_outils: cible.empreintes_outils,
            outils: cible.outils,
            date_approbation: Utc::now(),
            approuve_par: approbateur.to_string(),
        };
        self.enregistrer_baseline_versionnee(
            &baseline,
            &format!("rollback vers version {}", version),
        )?;
        Ok(baseline)
    }

    /// GC de l'historique des baselines : conserve les `garder` versions
    /// les plus récentes de chaque serveur, supprime le reste. Retourne
    /// le nombre de lignes supprimées.
    pub fn gc_historique_baselines(&self, garder: usize) -> Result<usize> {
        let conn = self.inner.lock().unwrap();
        let n = conn.execute(
            r#"DELETE FROM historique_baselines
               WHERE (SELECT COUNT(*) FROM historique_baselines h2
                      WHERE h2.serveur_id = historique_baselines.serveur_id
                        AND h2.version > historique_baselines.version) >= ?1"#,
            params![garder as i64],
        )?;
        Ok(n)
    }

    /// GC avec la rétention par défaut ([`GC_HISTORIQUE_BASELINES_DEFAUT`]).
    pub fn gc_historique_baselines_defaut(&self) -> Result<usize> {
        self.gc_historique_baselines(GC_HISTORIQUE_BASELINES_DEFAUT)
    }

    /// Exécute une requête SQL arbitraire sans paramètres — réservé aux
    /// tests externes qui doivent forger ou corrompre des lignes pour
    /// vérifier la robustesse des lectures (e.g. JSON corrompu dans
    /// `historique_baselines`). À ne PAS utiliser en production.
    pub fn executer_sql_pour_tests_seulement(&self, sql: &str) -> Result<usize> {
        let conn = self.inner.lock().unwrap();
        Ok(conn.execute(sql, [])?)
    }

    /// Liste toutes les baselines enregistrées pour un serveur, du plus récent
    /// au plus ancien (tri par `date_approbation DESC`).
    pub fn lister_baselines(&self, serveur_id: ServeurId) -> Result<Vec<Baseline>> {
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, empreinte_serveur, empreintes_outils, outils,
                date_approbation, approuve_par
               FROM baselines WHERE serveur_id = ?1
               ORDER BY date_approbation DESC"#,
        )?;
        let rows = stmt.query_map(params![serveur_id.to_string()], |row| {
            let id: String = row.get(0)?;
            let emp_serveur: String = row.get(1)?;
            let emp_outils: String = row.get(2)?;
            let outils: String = row.get(3)?;
            let date: String = row.get(4)?;
            let approuve_par: String = row.get(5)?;
            Ok((id, emp_serveur, emp_outils, outils, date, approuve_par))
        })?;
        let mut v = vec![];
        for r in rows {
            let (id, emp_s, emp_o, outils, date, par) = r?;
            v.push(Baseline {
                id: uuid::Uuid::parse_str(&id).unwrap_or_else(|_| uuid::Uuid::nil()),
                serveur_id,
                empreinte_serveur: Empreinte::new(emp_s),
                empreintes_outils: serde_json::from_str(&emp_o).unwrap_or_default(),
                outils: serde_json::from_str(&outils).unwrap_or_default(),
                date_approbation: DateTime::parse_from_rfc3339(&date)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                approuve_par: par,
            });
        }
        Ok(v)
    }

    pub fn derniere_baseline(&self, serveur_id: ServeurId) -> Result<Option<Baseline>> {
        let conn = self.inner.lock().unwrap();
        let row = conn
            .query_row(
                r#"SELECT id, empreinte_serveur, empreintes_outils, outils,
                    date_approbation, approuve_par
                   FROM baselines WHERE serveur_id = ?1
                   ORDER BY date_approbation DESC LIMIT 1"#,
                params![serveur_id.to_string()],
                |row| {
                    let id: String = row.get(0)?;
                    let emp_serveur: String = row.get(1)?;
                    let emp_outils: String = row.get(2)?;
                    let outils: String = row.get(3)?;
                    let date: String = row.get(4)?;
                    let approuve_par: String = row.get(5)?;
                    Ok((id, emp_serveur, emp_outils, outils, date, approuve_par))
                },
            )
            .optional()?;
        Ok(row.map(|(id, emp_s, emp_o, outils, date, par)| Baseline {
            id: uuid::Uuid::parse_str(&id).unwrap_or_else(|_| uuid::Uuid::nil()),
            serveur_id,
            empreinte_serveur: Empreinte::new(emp_s),
            empreintes_outils: serde_json::from_str(&emp_o).unwrap_or_default(),
            outils: serde_json::from_str(&outils).unwrap_or_default(),
            date_approbation: DateTime::parse_from_rfc3339(&date)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            approuve_par: par,
        }))
    }

    pub fn enregistrer_contact(
        &self,
        serveur_id: ServeurId,
        session_id: &str,
        methode: &str,
        horodatage: DateTime<Utc>,
    ) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        conn.execute(
            r#"INSERT INTO historique_contacts (serveur_id, session_id, methode, horodatage)
               VALUES (?1, ?2, ?3, ?4)"#,
            params![
                serveur_id.to_string(),
                session_id,
                methode,
                horodatage.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Retourne les derniers contacts observés (plus récents en premier),
    /// limités à `limit` lignes. Sert à alimenter la page Time-travel.
    pub fn lister_historique(&self, limit: i64) -> Result<Vec<HistoriqueContact>> {
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, serveur_id, session_id, methode, horodatage
               FROM historique_contacts
               ORDER BY id DESC
               LIMIT ?1"#,
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            let horodatage: String = row.get(4)?;
            Ok(HistoriqueContact {
                id: row.get(0)?,
                serveur_id: row.get(1)?,
                session_id: row.get(2)?,
                methode: row.get(3)?,
                horodatage: DateTime::parse_from_rfc3339(&horodatage)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            })
        })?;
        let mut v = vec![];
        for r in rows {
            v.push(r?);
        }
        Ok(v)
    }

    pub fn enregistrer_constat(&self, c: &Constat) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        conn.execute(
            r#"INSERT INTO constats (id, serveur_id, outil_nom, type_constat, severite,
                titre, detail, diff, references_conformite, horodatage, etat)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            params![
                c.id.to_string(),
                c.serveur_id.to_string(),
                c.outil_nom,
                serde_json::to_string(&c.type_constat)?,
                serde_json::to_string(&c.severite)?,
                c.titre,
                c.detail,
                c.diff,
                serde_json::to_string(&c.references_conformite)?,
                c.horodatage.to_rfc3339(),
                serde_json::to_string(&c.etat)?,
            ],
        )?;
        Ok(())
    }

    pub fn lister_constats_ouverts(&self) -> Result<Vec<Constat>> {
        self.lister_constats(false)
    }

    /// Liste les constats. `inclure_resolus = true` retourne aussi ceux marqués
    /// résolus (utilisé par le toggle "Show resolved" du tableau d'alertes).
    pub fn lister_constats(&self, inclure_resolus: bool) -> Result<Vec<Constat>> {
        let conn = self.inner.lock().unwrap();
        let sql = if inclure_resolus {
            r#"SELECT id, serveur_id, outil_nom, type_constat, severite, titre, detail,
                diff, references_conformite, horodatage, etat
               FROM constats ORDER BY horodatage DESC"#
        } else {
            r#"SELECT id, serveur_id, outil_nom, type_constat, severite, titre, detail,
                diff, references_conformite, horodatage, etat
               FROM constats WHERE etat = '"ouvert"' ORDER BY horodatage DESC"#
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let serveur_id: String = row.get(1)?;
            let type_c: String = row.get(3)?;
            let sev: String = row.get(4)?;
            let refs: String = row.get(8)?;
            let date: String = row.get(9)?;
            let etat: String = row.get(10)?;
            Ok(Constat {
                id: uuid::Uuid::parse_str(&id).unwrap_or_else(|_| uuid::Uuid::nil()),
                serveur_id: uuid::Uuid::parse_str(&serveur_id).unwrap_or_else(|_| uuid::Uuid::nil()),
                outil_nom: row.get(2)?,
                type_constat: serde_json::from_str(&type_c).unwrap_or(TypeConstat::Autre),
                severite: serde_json::from_str(&sev).unwrap_or(Severite::Info),
                titre: row.get(5)?,
                detail: row.get(6)?,
                diff: row.get(7)?,
                references_conformite: serde_json::from_str(&refs).unwrap_or_default(),
                horodatage: DateTime::parse_from_rfc3339(&date)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                etat: serde_json::from_str(&etat).unwrap_or(EtatConstat::Ouvert),
            })
        })?;
        let mut v = vec![];
        for r in rows {
            v.push(r?);
        }
        Ok(v)
    }

    /// Marque un constat comme résolu (transition Ouvert → Resolu) et,
    /// si une note est fournie, l'ajoute en fin de `detail`.
    pub fn marquer_constat_resolu(&self, id: ConstatId, note: Option<String>) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        if let Some(n) = note {
            if !n.trim().is_empty() {
                conn.execute(
                    r#"UPDATE constats
                       SET etat = '"resolu"',
                           detail = detail || char(10) || '[résolu] ' || ?2
                       WHERE id = ?1"#,
                    params![id.to_string(), n],
                )?;
                return Ok(());
            }
        }
        conn.execute(
            r#"UPDATE constats SET etat = '"resolu"' WHERE id = ?1"#,
            params![id.to_string()],
        )?;
        Ok(())
    }

    /// Enregistre une nouvelle investigation pour un serveur et renvoie son `id`.
    ///
    /// L'`etat` est initialisé à `"ouvert"` (mirroir des constats).
    pub fn enregistrer_investigation(
        &self,
        serveur_id: ServeurId,
        note: &str,
        par: &str,
    ) -> Result<String> {
        let conn = self.inner.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            r#"INSERT INTO investigations (id, serveur_id, note, cree_par, cree_a, etat)
               VALUES (?1, ?2, ?3, ?4, ?5, '"ouvert"')"#,
            params![id, serveur_id.to_string(), note, par, now],
        )?;
        Ok(id)
    }

    /// Liste les investigations (les plus récentes d'abord), filtrables par serveur.
    pub fn lister_investigations(
        &self,
        serveur_id: Option<ServeurId>,
    ) -> Result<Vec<Investigation>> {
        let conn = self.inner.lock().unwrap();
        let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Investigation> {
            let cree_a: String = row.get(4)?;
            Ok(Investigation {
                id: row.get(0)?,
                serveur_id: row.get(1)?,
                note: row.get(2)?,
                cree_par: row.get(3)?,
                cree_a: DateTime::parse_from_rfc3339(&cree_a)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                etat: row.get(5)?,
            })
        };
        let mut v = vec![];
        match serveur_id {
            Some(id) => {
                let mut stmt = conn.prepare(
                    r#"SELECT id, serveur_id, note, cree_par, cree_a, etat
                       FROM investigations
                       WHERE serveur_id = ?1
                       ORDER BY cree_a DESC"#,
                )?;
                let rows = stmt.query_map(params![id.to_string()], mapper)?;
                for r in rows {
                    v.push(r?);
                }
            }
            None => {
                let mut stmt = conn.prepare(
                    r#"SELECT id, serveur_id, note, cree_par, cree_a, etat
                       FROM investigations
                       ORDER BY cree_a DESC"#,
                )?;
                let rows = stmt.query_map([], mapper)?;
                for r in rows {
                    v.push(r?);
                }
            }
        }
        Ok(v)
    }

    pub fn enregistrer_alerte(&self, a: &Alerte) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        conn.execute(
            r#"INSERT INTO alertes (id, constat_id, canal, severite, titre, message,
                diff, horodatage, envoyee, tentatives)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                a.id.to_string(),
                a.constat_id.to_string(),
                serde_json::to_string(&a.canal)?,
                serde_json::to_string(&a.severite)?,
                a.titre,
                a.message,
                a.diff,
                a.horodatage.to_rfc3339(),
                a.envoyee as i64,
                a.tentatives as i64,
            ],
        )?;
        Ok(())
    }
}

/// Contrat asynchrone d'écriture utilisé par les modules en aval (scan, monitor, detect…).
#[async_trait]
pub trait StoreWrite: Send + Sync {
    async fn enregistrer_serveur(&self, s: Serveur) -> Result<()>;
    async fn enregistrer_outil(
        &self,
        serveur_id: ServeurId,
        outil: Outil,
        empreinte: Empreinte,
    ) -> Result<()>;
    async fn enregistrer_constat(&self, c: Constat) -> Result<()>;
    async fn enregistrer_contact(
        &self,
        serveur_id: ServeurId,
        session_id: String,
        methode: String,
        horodatage: DateTime<Utc>,
    ) -> Result<()>;
}

#[async_trait]
impl StoreWrite for Store {
    async fn enregistrer_serveur(&self, s: Serveur) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.upsert_serveur(&s)).await?
    }
    async fn enregistrer_outil(
        &self,
        serveur_id: ServeurId,
        outil: Outil,
        empreinte: Empreinte,
    ) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.upsert_outil(serveur_id, &outil, &empreinte).map(|_| ()))
            .await?
    }
    async fn enregistrer_constat(&self, c: Constat) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.enregistrer_constat(&c)).await?
    }
    async fn enregistrer_contact(
        &self,
        serveur_id: ServeurId,
        session_id: String,
        methode: String,
        horodatage: DateTime<Utc>,
    ) -> Result<()> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            store.enregistrer_contact(serveur_id, &session_id, &methode, horodatage)
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn ouvre_et_insere() {
        let store = Store::in_memory().unwrap();
        let s = Serveur {
            id: uuid::Uuid::new_v4(),
            endpoint: "http://x".into(),
            transport: Transport::Http,
            portees: vec![Portee::Filesystem],
            statut: StatutServeur::Inconnu,
            couleur: Couleur::Orange,
            premiere_vue: Utc::now(),
            derniere_vue: Utc::now(),
            empreinte_courante: None,
            tags: vec![],
            scope: ScopeServeur::default(),
        };
        store.upsert_serveur(&s).unwrap();
        let liste = store.lister_serveurs().unwrap();
        assert_eq!(liste.len(), 1);
    }
}
