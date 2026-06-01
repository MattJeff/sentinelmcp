//! sentinel-store — store local embarqué (SQLite) pour Sentinel MCP.
//!
//! Contient l'inventaire (serveurs, outils), les baselines, l'historique
//! des contacts, les constats et les alertes. Aucun contenu de `tools/call`
//! n'est persisté — règle non négociable.

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

const SCHEMA_SQL: &str = r#"
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
"#;

/// Store SQLite embarqué, partagé par toute l'application via Arc.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Connection>>,
}

impl Store {
    /// Ouvre le store à un chemin donné (ou en mémoire si `:memory:`).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let conn = if path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    /// Insère ou met à jour un serveur.
    pub fn upsert_serveur(&self, s: &Serveur) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        conn.execute(
            r#"INSERT INTO serveurs (id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
               ON CONFLICT(id) DO UPDATE SET
                 derniere_vue = excluded.derniere_vue,
                 statut = excluded.statut,
                 couleur = excluded.couleur,
                 empreinte_courante = excluded.empreinte_courante,
                 portees = excluded.portees"#,
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
            ],
        )?;
        Ok(())
    }

    pub fn lister_serveurs(&self) -> Result<Vec<Serveur>> {
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, endpoint, transport, portees, statut, couleur,
                premiere_vue, derniere_vue, empreinte_courante FROM serveurs",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let transport: String = row.get(2)?;
            let portees: String = row.get(3)?;
            let statut: String = row.get(4)?;
            let couleur: String = row.get(5)?;
            let premiere_vue: String = row.get(6)?;
            let derniere_vue: String = row.get(7)?;
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
            })
        })?;
        let mut v = vec![];
        for r in rows {
            v.push(r?);
        }
        Ok(v)
    }

    pub fn get_serveur_par_endpoint(&self, endpoint: &str) -> Result<Option<Serveur>> {
        let serveurs = self.lister_serveurs()?;
        Ok(serveurs.into_iter().find(|s| s.endpoint == endpoint))
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

    pub fn enregistrer_baseline(&self, b: &Baseline) -> Result<()> {
        let conn = self.inner.lock().unwrap();
        conn.execute(
            r#"INSERT INTO baselines (id, serveur_id, empreinte_serveur, empreintes_outils,
                outils, date_approbation, approuve_par)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
            params![
                b.id.to_string(),
                b.serveur_id.to_string(),
                b.empreinte_serveur.as_str(),
                serde_json::to_string(&b.empreintes_outils)?,
                serde_json::to_string(&b.outils)?,
                b.date_approbation.to_rfc3339(),
                b.approuve_par,
            ],
        )?;
        Ok(())
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
        let conn = self.inner.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, serveur_id, outil_nom, type_constat, severite, titre, detail,
                diff, references_conformite, horodatage, etat
               FROM constats WHERE etat = '"ouvert"'"#,
        )?;
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
        };
        store.upsert_serveur(&s).unwrap();
        let liste = store.lister_serveurs().unwrap();
        assert_eq!(liste.len(), 1);
    }
}
