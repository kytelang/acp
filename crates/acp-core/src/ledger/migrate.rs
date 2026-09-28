//! Ledger-preserving schema migrations with tested rollback (decision H1.2).
//!
//! The evidence store outlives any single schema. Migrations must therefore be ordered, reversible,
//! and above all non-destructive to existing evidence: an up-migration adds structure without
//! touching a single recorded leaf, and a down-migration returns cleanly if a release must be
//! rolled back. Each step runs in a transaction, so a failed migration leaves the store untouched.

use rusqlite::Connection;

/// One reversible migration. `up`/`down` are SQL applied inside a transaction.
pub struct Migration {
    pub version: u32,
    pub up: &'static str,
    pub down: &'static str,
}

fn ensure_version_table(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
        [],
    )
    .map_err(|e| e.to_string())?;
    let n: i64 = conn
        .query_row("SELECT count(*) FROM schema_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if n == 0 {
        conn.execute("INSERT INTO schema_version (version) VALUES (0)", [])
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The current schema version (0 before any migration).
pub fn current_version(conn: &Connection) -> Result<u32, String> {
    ensure_version_table(conn)?;
    conn.query_row("SELECT version FROM schema_version", [], |r| {
        r.get::<_, i64>(0).map(|v| v as u32)
    })
    .map_err(|e| e.to_string())
}

fn set_version(conn: &Connection, v: u32) -> Result<(), String> {
    conn.execute("UPDATE schema_version SET version = ?", [v as i64])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Migrate up or down to `target`, applying each step transactionally. Migrations must be sorted by
/// version. Returns an error (leaving the store at the last good version) if a step fails.
pub fn migrate_to(conn: &Connection, migrations: &[Migration], target: u32) -> Result<(), String> {
    let mut cur = current_version(conn)?;
    while cur < target {
        let m = migrations
            .iter()
            .find(|m| m.version == cur + 1)
            .ok_or_else(|| format!("missing migration to version {}", cur + 1))?;
        conn.execute_batch(&format!("BEGIN; {} COMMIT;", m.up))
            .map_err(|e| format!("up {}: {e}", m.version))?;
        cur += 1;
        set_version(conn, cur)?;
    }
    while cur > target {
        let m = migrations
            .iter()
            .find(|m| m.version == cur)
            .ok_or_else(|| format!("missing migration from version {cur}"))?;
        conn.execute_batch(&format!("BEGIN; {} COMMIT;", m.down))
            .map_err(|e| format!("down {}: {e}", m.version))?;
        cur -= 1;
        set_version(conn, cur)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrations() -> Vec<Migration> {
        vec![
            Migration {
                version: 1,
                up: "CREATE TABLE records (id TEXT PRIMARY KEY, body TEXT);",
                down: "DROP TABLE records;",
            },
            Migration {
                version: 2,
                // Add a column without touching existing rows (expand-only).
                up: "ALTER TABLE records ADD COLUMN tenant TEXT DEFAULT 'default';",
                down: "ALTER TABLE records DROP COLUMN tenant;",
            },
        ]
    }

    #[test]
    fn up_migration_preserves_existing_evidence() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_to(&conn, &migrations(), 1).unwrap();
        conn.execute("INSERT INTO records (id, body) VALUES ('r1', 'evidence')", []).unwrap();

        // Migrate up: the existing row must survive and gain the default for the new column.
        migrate_to(&conn, &migrations(), 2).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 2);
        let (body, tenant): (String, String) = conn
            .query_row("SELECT body, tenant FROM records WHERE id='r1'", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(body, "evidence", "evidence preserved across migration");
        assert_eq!(tenant, "default");
    }

    #[test]
    fn rollback_returns_cleanly_and_keeps_the_data() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_to(&conn, &migrations(), 2).unwrap();
        conn.execute("INSERT INTO records (id, body, tenant) VALUES ('r1', 'x', 't1')", []).unwrap();

        // Roll back to version 1: the down step runs and the base row survives.
        migrate_to(&conn, &migrations(), 1).unwrap();
        assert_eq!(current_version(&conn).unwrap(), 1);
        let body: String = conn
            .query_row("SELECT body FROM records WHERE id='r1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(body, "x", "base evidence survives rollback");
    }
}
