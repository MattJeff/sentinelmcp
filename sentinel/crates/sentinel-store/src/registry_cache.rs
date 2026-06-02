//! registry_cache — couche de cache persistante pour les lookups de registres.
//!
//! Évite de battre le réseau à chaque `scan_lookalikes` en mémoïsant les
//! réponses des registres distants (npm, PyPI, crates.io…) dans un petit
//! SQLite local avec un TTL (par défaut 24h). Le payload est stocké en
//! BLOB brut — c'est à l'appelant de sérialiser / désérialiser comme il
//! l'entend.

use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS registry_cache (
    registre TEXT PRIMARY KEY,
    payload BLOB,
    ecrit_a TEXT NOT NULL
);
"#;

/// Cache SQLite des lookups de registres.
///
/// Une seule table `registry_cache (registre, payload, ecrit_a)`. La
/// connexion est protégée par un `Mutex` pour permettre l'utilisation
/// derrière un `Arc` partagé entre threads.
#[derive(Clone)]
pub struct CacheRegistres {
    db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl CacheRegistres {
    /// Ouvre (ou crée) le cache à `db_path`. Si le chemin est `:memory:`,
    /// une base in-memory est utilisée — pratique pour les tests.
    pub fn nouveau(db_path: PathBuf) -> Result<Self> {
        let conn = if db_path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(&db_path)?
        };
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Self {
            db_path,
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Chemin SQLite sous-jacent (utile pour les logs / diagnostics).
    pub fn db_path(&self) -> &PathBuf {
        &self.db_path
    }

    /// Lit une entrée du cache. Retourne `Some((payload, ecrit_a))` si
    /// présente, `None` sinon. Ne tient PAS compte du TTL — c'est à
    /// l'appelant de combiner avec [`Self::est_frais`].
    pub fn lire(&self, registre: &str) -> Result<Option<(Vec<u8>, DateTime<Utc>)>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT payload, ecrit_a FROM registry_cache WHERE registre = ?1",
                params![registre],
                |row| {
                    let payload: Vec<u8> = row.get(0)?;
                    let ecrit_a: String = row.get(1)?;
                    Ok((payload, ecrit_a))
                },
            )
            .optional()?;
        Ok(row.map(|(payload, ecrit_a)| {
            let ts = DateTime::parse_from_rfc3339(&ecrit_a)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            (payload, ts)
        }))
    }

    /// Écrit (ou remplace) une entrée. `ecrit_a` est positionné à
    /// `Utc::now()` — c'est l'horloge qui sert de référence pour le TTL.
    pub fn ecrire(&self, registre: &str, payload: &[u8]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO registry_cache (registre, payload, ecrit_a)
               VALUES (?1, ?2, ?3)
               ON CONFLICT(registre) DO UPDATE SET
                 payload = excluded.payload,
                 ecrit_a = excluded.ecrit_a"#,
            params![registre, payload, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// `true` si l'entrée existe ET a moins de `ttl_secs` secondes. Une
    /// entrée absente renvoie `false` — il n'y a rien de frais à servir.
    pub fn est_frais(&self, registre: &str, ttl_secs: i64) -> Result<bool> {
        match self.lire(registre)? {
            Some((_, ecrit_a)) => {
                let age = Utc::now().signed_duration_since(ecrit_a).num_seconds();
                Ok(age < ttl_secs)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_in_memory() {
        let cache = CacheRegistres::nouveau(PathBuf::from(":memory:")).unwrap();
        cache.ecrire("npm:left-pad", b"{\"version\":\"1.0.0\"}").unwrap();
        let lu = cache.lire("npm:left-pad").unwrap().unwrap();
        assert_eq!(lu.0, b"{\"version\":\"1.0.0\"}");
    }

    #[test]
    fn manquant_renvoie_none() {
        let cache = CacheRegistres::nouveau(PathBuf::from(":memory:")).unwrap();
        assert!(cache.lire("inconnu").unwrap().is_none());
    }
}
