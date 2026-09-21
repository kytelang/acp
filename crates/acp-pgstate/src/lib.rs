//! Postgres-backed shared state for budgets and tool pins (pending.md P1 #3, deployment half).
//!
//! `acp_core::sharedstate` defines the in-process default; this is the shared implementation so
//! several gateway or proxy replicas see one budget and one set of pins. Budgets use a token bucket
//! stored per key and refilled by elapsed time under a row lock (SELECT ... FOR UPDATE), so
//! concurrent replicas cannot double-spend. Pins are check-and-set. Async (tokio-postgres), matching
//! the gateway's async request path.

use acp_core::toolintegrity::PinResult;
use tokio_postgres::{Client, NoTls};

pub struct PgState {
    client: Client,
}

impl PgState {
    /// Connect and create the tables if absent.
    pub async fn connect(conn_str: &str) -> Result<PgState, String> {
        let (client, connection) = tokio_postgres::connect(conn_str, NoTls)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("acp-pgstate: connection error: {e}");
            }
        });
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS acp_budget (
                    key text PRIMARY KEY,
                    capacity double precision NOT NULL,
                    tokens double precision NOT NULL,
                    refill_per_ms double precision NOT NULL,
                    last_ms bigint NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS acp_pin (
                    key text PRIMARY KEY,
                    fingerprint text NOT NULL
                 );",
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(PgState { client })
    }

    /// Try to consume one unit from `key`'s budget, refilling by elapsed time. Returns whether it was
    /// within budget. Atomic per key via a row lock, so replicas cannot double-spend.
    pub async fn allow(
        &mut self,
        key: &str,
        capacity: f64,
        refill_per_sec: f64,
        now_ms: i64,
    ) -> Result<bool, String> {
        let refill_per_ms = refill_per_sec / 1000.0;
        let tx = self.client.transaction().await.map_err(|e| e.to_string())?;
        // Create the bucket full on first sight.
        tx.execute(
            "INSERT INTO acp_budget(key,capacity,tokens,refill_per_ms,last_ms)
             VALUES($1,$2,$2,$3,$4) ON CONFLICT(key) DO NOTHING",
            &[&key, &capacity, &refill_per_ms, &now_ms],
        )
        .await
        .map_err(|e| e.to_string())?;
        // Lock the row, refill, decide, write back.
        let row = tx
            .query_one(
                "SELECT tokens,last_ms FROM acp_budget WHERE key=$1 FOR UPDATE",
                &[&key],
            )
            .await
            .map_err(|e| e.to_string())?;
        let tokens: f64 = row.get(0);
        let last_ms: i64 = row.get(1);
        let elapsed = (now_ms - last_ms).max(0) as f64;
        let refilled = (tokens + elapsed * refill_per_ms).min(capacity);
        let allowed = refilled >= 1.0;
        let new_tokens = if allowed { refilled - 1.0 } else { refilled };
        tx.execute(
            "UPDATE acp_budget SET tokens=$2,last_ms=$3,capacity=$4,refill_per_ms=$5 WHERE key=$1",
            &[&key, &new_tokens, &now_ms, &capacity, &refill_per_ms],
        )
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(allowed)
    }

    /// Pin `fingerprint` for `key` on first sight; report New / Unchanged / Changed on later sight.
    pub async fn check_and_pin(&mut self, key: &str, fingerprint: &str) -> Result<PinResult, String> {
        let tx = self.client.transaction().await.map_err(|e| e.to_string())?;
        let inserted = tx
            .execute(
                "INSERT INTO acp_pin(key,fingerprint) VALUES($1,$2) ON CONFLICT(key) DO NOTHING",
                &[&key, &fingerprint],
            )
            .await
            .map_err(|e| e.to_string())?;
        let result = if inserted == 1 {
            PinResult::New
        } else {
            let row = tx
                .query_one("SELECT fingerprint FROM acp_pin WHERE key=$1", &[&key])
                .await
                .map_err(|e| e.to_string())?;
            let stored: String = row.get(0);
            if stored == fingerprint {
                PinResult::Unchanged
            } else {
                PinResult::Changed
            }
        };
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> String {
        std::env::var("ACP_PG_TEST")
            .unwrap_or_else(|_| "host=/tmp user=kamlesh dbname=acp_test".to_string())
    }

    // Skips (passes) if no Postgres is reachable, so `cargo test --workspace` is green everywhere;
    // runs for real when a local PG is present.
    #[tokio::test]
    async fn budget_and_pin_against_real_pg() {
        let mut s = match PgState::connect(&conn()).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping PG test (no database): {e}");
                return;
            }
        };
        // Unique keys per run so repeated runs are independent.
        let bkey = format!("budget:test:{}", std::process::id());
        let pkey = format!("pin:test:{}", std::process::id());
        let _ = s.client.execute("DELETE FROM acp_budget WHERE key=$1", &[&bkey]).await;
        let _ = s.client.execute("DELETE FROM acp_pin WHERE key=$1", &[&pkey]).await;

        // capacity 2, refill 1/sec.
        assert!(s.allow(&bkey, 2.0, 1.0, 0).await.unwrap());
        assert!(s.allow(&bkey, 2.0, 1.0, 0).await.unwrap());
        assert!(!s.allow(&bkey, 2.0, 1.0, 0).await.unwrap(), "capacity exhausted");
        assert!(s.allow(&bkey, 2.0, 1.0, 1000).await.unwrap(), "refills after 1s");

        assert_eq!(s.check_and_pin(&pkey, "fp1").await.unwrap(), PinResult::New);
        assert_eq!(s.check_and_pin(&pkey, "fp1").await.unwrap(), PinResult::Unchanged);
        assert_eq!(s.check_and_pin(&pkey, "fp2").await.unwrap(), PinResult::Changed);

        let _ = s.client.execute("DELETE FROM acp_budget WHERE key=$1", &[&bkey]).await;
        let _ = s.client.execute("DELETE FROM acp_pin WHERE key=$1", &[&pkey]).await;
    }
}
