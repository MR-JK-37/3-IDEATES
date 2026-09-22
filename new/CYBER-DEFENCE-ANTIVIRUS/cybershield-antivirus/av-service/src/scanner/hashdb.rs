//! Thread-safe hash database with connection pooling

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::{debug, info};

static DB_POOL: OnceCell<Pool<SqliteConnectionManager>> = OnceCell::new();

#[derive(Debug, Clone)]
pub struct ThreatInfo {
    pub hash: String,
    pub threat_name: String,
    pub category: String,
    pub severity: String,
}

pub fn init_db<P: AsRef<Path>>(db_path: P) -> Result<()> {
    let path = db_path.as_ref();
    
    let manager = SqliteConnectionManager::file(path);
    let pool = Pool::builder()
        .max_size(15)
        .min_idle(Some(2))
        .build(manager)
        .context("Failed to create connection pool")?;

    // Initialize schema
    let conn = pool.get()?;
    init_schema(&conn)?;
    drop(conn);

    DB_POOL.set(pool)
        .map_err(|_| anyhow::anyhow!("Database already initialized"))?;

    Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA cache_size = -64000;"
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS malware_hashes (
            sha256 TEXT PRIMARY KEY,
            threat_name TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            source TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256)",
        [],
    )?;

    debug!("Database schema initialized");
    Ok(())
}

fn get_conn() -> Result<PooledConnection<SqliteConnectionManager>> {
    DB_POOL.get()
        .ok_or_else(|| anyhow::anyhow!("Database not initialized"))?
        .get()
        .context("Failed to get connection from pool")
}

pub fn check_hash(hash: &str) -> Result<Option<ThreatInfo>> {
    let conn = get_conn()?;

    let result = conn.query_row(
        "SELECT sha256, threat_name, category, severity FROM malware_hashes WHERE sha256 = ?1",
        params![hash],
        |row| {
            Ok(ThreatInfo {
                hash: row.get(0)?,
                threat_name: row.get(1)?,
                category: row.get(2)?,
                severity: row.get(3)?,
            })
        },
    );

    match result {
        Ok(info) => {
            debug!("🚨 Hash {} found: {}", &hash[..8], info.threat_name);
            Ok(Some(info))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn add_hash(
    hash: &str,
    threat_name: &str,
    category: &str,
    severity: &str,
    source: &str,
) -> Result<()> {
    let conn = get_conn()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;

    conn.execute(
        "INSERT OR REPLACE INTO malware_hashes 
         (sha256, threat_name, category, severity, first_seen, source) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![hash, threat_name, category, severity, now, source],
    )?;

    info!("Added hash: {} ({})", threat_name, &hash[..8]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_init_and_check() -> Result<()> {
        let db_file = NamedTempFile::new()?;
        init_db(db_file.path())?;

        add_hash(
            "test123",
            "TestMalware",
            "test",
            "low",
            "unit_test",
        )?;

        let result = check_hash("test123")?;
        assert!(result.is_some());
        assert_eq!(result.unwrap().threat_name, "TestMalware");

        Ok(())
    }
}
