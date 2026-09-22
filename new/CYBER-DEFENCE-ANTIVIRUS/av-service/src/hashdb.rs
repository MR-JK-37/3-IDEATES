use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};
use std::path::Path;
use std::time::SystemTime;

type SqlitePool = Pool<SqliteConnectionManager>;

static DB_POOL: OnceCell<SqlitePool> = OnceCell::new();

/// Initialize the global DB connection pool and create schema if missing.
pub fn init_db<P: AsRef<Path>>(db_path: P) -> Result<()> {
    let path = db_path.as_ref();
    let manager = SqliteConnectionManager::file(path);
    let pool = Pool::builder()
        .max_size(10)
        .build(manager)
        .with_context(|| format!("failed to create sqlite pool for {}", path.display()))?;

    // Initialize schema
    {
        let conn = pool.get().context("get connection to initialize schema")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS hashes (
                hash TEXT PRIMARY KEY,
                threat_name TEXT,
                source TEXT,
                added_at INTEGER
            );",
        )?;
        // Remove low-quality historical ML-only cache entries that caused false positives.
        let _ = conn.execute(
            "DELETE FROM hashes
             WHERE source = 'MultiEngine'
               AND (threat_name LIKE 'ML.%' OR threat_name LIKE 'AI-RiskModel%')",
            [],
        );
    }

    DB_POOL
        .set(pool)
        .map_err(|_| anyhow::anyhow!("DB pool already initialized"))?;
    Ok(())
}

fn get_conn() -> Result<PooledConnection<SqliteConnectionManager>> {
    DB_POOL
        .get()
        .context("database not initialized; call init_db() first")?
        .get()
        .map_err(|e| anyhow::anyhow!("failed to get db connection: {}", e))
}

pub fn add_hash(hash: &str, threat_name: &str, source: &str) -> Result<()> {
    let conn = get_conn()?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO hashes (hash, threat_name, source, added_at) VALUES (?1, ?2, ?3, ?4)",
        params![hash, threat_name, source, now],
    )?;
    Ok(())
}

pub fn check_hash(hash: &str) -> Result<Option<String>> {
    let conn = get_conn()?;
    let mut stmt = conn.prepare("SELECT threat_name FROM hashes WHERE hash = ?1")?;
    let name: Option<String> = stmt.query_row(params![hash], |row| row.get(0)).optional()?;
    if let Some(n) = name {
        // Ignore ML-only names in hash DB to avoid promoting model noise as ground truth.
        if n.starts_with("ML.") || n.starts_with("AI-RiskModel") {
            return Ok(None);
        }
        return Ok(Some(n));
    }
    Ok(None)
}
