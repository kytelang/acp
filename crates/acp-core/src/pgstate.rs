//! Postgres-backed shared state for budgets and tool pins (pending.md P1 #3, deployment half).
//!
//! `crate::sharedstate` defines the in-process default; this is the shared implementation so several
//! gateway or proxy replicas see one budget and one set of pins. Budgets use a token bucket refilled
//! by elapsed time under a row lock (SELECT ... FOR UPDATE), so concurrent replicas cannot
//! double-spend. Pins are check-and-set. Built on sqlx (the one database library used across the
//! product), matching the async request path.

use crate::toolintegrity::PinResult;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

pub struct PgState {
    pool: PgPool,
}

impl PgState {
    /// Connect (a `postgres://` URL) and create the tables if absent.
    pub async fn connect(conn_str: &str) -> Result<PgState, String> {
        let pool = PgPoolOptions::new().max_connections(5).connect(conn_str).await.map_err(|e| e.to_string())?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS acp_budget (
                key text PRIMARY KEY,
                capacity double precision NOT NULL,
                tokens double precision NOT NULL,
                refill_per_ms double precision NOT NULL,
                last_ms bigint NOT NULL
             )",
        ).execute(&pool).await.map_err(|e| e.to_string())?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS acp_pin (key text PRIMARY KEY, fingerprint text NOT NULL)",
        ).execute(&pool).await.map_err(|e| e.to_string())?;
        Ok(PgState { pool })
    }

    /// Try to consume one unit from `key`'s budget, refilling by elapsed time. Atomic per key via a
    /// row lock within a transaction, so replicas cannot double-spend.
    pub async fn allow(&mut self, key: &str, capacity: f64, refill_per_sec: f64, now_ms: i64) -> Result<bool, String> {
        let refill_per_ms = refill_per_sec / 1000.0;
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("INSERT INTO acp_budget(key,capacity,tokens,refill_per_ms,last_ms) VALUES($1,$2,$2,$3,$4) ON CONFLICT(key) DO NOTHING")
            .bind(key).bind(capacity).bind(refill_per_ms).bind(now_ms)
            .execute(&mut *tx).await.map_err(|e| e.to_string())?;
        let row = sqlx::query("SELECT tokens,last_ms FROM acp_budget WHERE key=$1 FOR UPDATE")
            .bind(key).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
        let tokens: f64 = row.get(0);
        let last_ms: i64 = row.get(1);
        let elapsed = (now_ms - last_ms).max(0) as f64;
        let refilled = (tokens + elapsed * refill_per_ms).min(capacity);
        let allowed = refilled >= 1.0;
        let new_tokens = if allowed { refilled - 1.0 } else { refilled };
        sqlx::query("UPDATE acp_budget SET tokens=$2,last_ms=$3,capacity=$4,refill_per_ms=$5 WHERE key=$1")
            .bind(key).bind(new_tokens).bind(now_ms).bind(capacity).bind(refill_per_ms)
            .execute(&mut *tx).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(allowed)
    }

    /// Pin `fingerprint` for `key` on first sight; report New / Unchanged / Changed on later sight.
    pub async fn check_and_pin(&mut self, key: &str, fingerprint: &str) -> Result<PinResult, String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        let inserted = sqlx::query("INSERT INTO acp_pin(key,fingerprint) VALUES($1,$2) ON CONFLICT(key) DO NOTHING")
            .bind(key).bind(fingerprint).execute(&mut *tx).await.map_err(|e| e.to_string())?.rows_affected();
        let result = if inserted == 1 {
            PinResult::New
        } else {
            let row = sqlx::query("SELECT fingerprint FROM acp_pin WHERE key=$1").bind(key)
                .fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
            let stored: String = row.get(0);
            if stored == fingerprint { PinResult::Unchanged } else { PinResult::Changed }
        };
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(result)
    }

    #[cfg(test)]
    async fn delete_key(&self, table: &str, key: &str) {
        let _ = sqlx::query(&format!("DELETE FROM {table} WHERE key=$1")).bind(key).execute(&self.pool).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> String {
        std::env::var("ACP_PG_TEST").unwrap_or_else(|_| "postgres://kamlesh@localhost/acp_test".to_string())
    }

    #[tokio::test]
    async fn budget_and_pin_against_real_pg() {
        let mut s = match PgState::connect(&conn()).await {
            Ok(s) => s,
            Err(e) => { eprintln!("skipping PG test (no database): {e}"); return; }
        };
        let bkey = format!("budget:test:{}", std::process::id());
        let pkey = format!("pin:test:{}", std::process::id());
        s.delete_key("acp_budget", &bkey).await;
        s.delete_key("acp_pin", &pkey).await;
        assert!(s.allow(&bkey, 2.0, 1.0, 0).await.unwrap());
        assert!(s.allow(&bkey, 2.0, 1.0, 0).await.unwrap());
        assert!(!s.allow(&bkey, 2.0, 1.0, 0).await.unwrap(), "capacity exhausted");
        assert!(s.allow(&bkey, 2.0, 1.0, 1000).await.unwrap(), "refills after 1s");
        assert_eq!(s.check_and_pin(&pkey, "fp1").await.unwrap(), PinResult::New);
        assert_eq!(s.check_and_pin(&pkey, "fp1").await.unwrap(), PinResult::Unchanged);
        assert_eq!(s.check_and_pin(&pkey, "fp2").await.unwrap(), PinResult::Changed);
        s.delete_key("acp_budget", &bkey).await;
        s.delete_key("acp_pin", &pkey).await;
    }
}
