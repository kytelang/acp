//! Postgres tenant-isolated store (decision v1.1.1 / H1.1).
//!
//! Multi-tenant GA needs a shared store where one tenant can never read or write another's rows, and
//! where that guarantee does not depend on every query remembering `WHERE tenant_id = ...`. We get it
//! from Postgres Row-Level Security with FORCE: a policy binds every row to a tenant, and FORCE applies
//! it even to the table owner, so a bare `SELECT * FROM records` returns only the current tenant's rows.
//! The tenant is set per transaction via a txn-local config, never trusted from the row payload.
//!
//! Built on sqlx. The RLS guarantee needs the `SET LOCAL` config and the query to run on the SAME
//! connection within one transaction, so each operation runs inside a single sqlx transaction. The
//! isolation test is gated on `ACP_PG_TEST_URL` so CI without a database skips it cleanly.

use sqlx::{postgres::PgPoolOptions, PgPool, Row};

pub struct TenantStore {
    pool: PgPool,
}

impl TenantStore {
    pub async fn connect(conn_str: &str) -> Result<Self, String> {
        let pool = PgPoolOptions::new().max_connections(5).connect(conn_str).await.map_err(|e| e.to_string())?;
        Ok(TenantStore { pool })
    }

    /// Fail closed if the connected role bypasses RLS (superuser or BYPASSRLS): isolation would
    /// silently not hold, so we refuse to initialise rather than pretend.
    async fn ensure_rls_enforceable(&self) -> Result<(), String> {
        let row = sqlx::query("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&self.pool).await.map_err(|e| e.to_string())?;
        let bypasses: bool = row.get(0);
        if bypasses {
            return Err("acp-pgstore: the connected Postgres role bypasses row-level security \
                (superuser or BYPASSRLS). Tenant isolation would NOT be enforced. Connect as a \
                non-superuser role that does not have BYPASSRLS.".to_string());
        }
        Ok(())
    }

    /// Create the records table and install FORCE row-level security. Idempotent.
    pub async fn init_schema(&self) -> Result<(), String> {
        self.ensure_rls_enforceable().await?;
        let stmts = [
            "CREATE TABLE IF NOT EXISTS records (tenant_id text NOT NULL, id text NOT NULL, body jsonb NOT NULL, PRIMARY KEY (tenant_id, id))",
            "ALTER TABLE records ENABLE ROW LEVEL SECURITY",
            "ALTER TABLE records FORCE ROW LEVEL SECURITY",
            "DROP POLICY IF EXISTS tenant_isolation ON records",
            "CREATE POLICY tenant_isolation ON records USING (tenant_id = current_setting('acp.tenant', true)) WITH CHECK (tenant_id = current_setting('acp.tenant', true))",
        ];
        for s in stmts {
            sqlx::query(s).execute(&self.pool).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub async fn truncate_all(&self) -> Result<(), String> {
        sqlx::query("TRUNCATE records").execute(&self.pool).await.map(|_| ()).map_err(|e| e.to_string())
    }

    /// Insert or update a row for a tenant (RLS-scoped in a single transaction).
    pub async fn put(&self, tenant: &str, id: &str, body: &serde_json::Value) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT set_config('acp.tenant', $1, true)").bind(tenant).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        sqlx::query("INSERT INTO records (tenant_id, id, body) VALUES ($1, $2, $3) ON CONFLICT (tenant_id, id) DO UPDATE SET body = EXCLUDED.body")
            .bind(tenant).bind(id).bind(body).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())
    }

    /// Fetch a row for a tenant, honouring RLS (a wrong tenant sees nothing).
    pub async fn get(&self, tenant: &str, id: &str) -> Result<Option<serde_json::Value>, String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT set_config('acp.tenant', $1, true)").bind(tenant).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        let row = sqlx::query("SELECT body FROM records WHERE id = $1").bind(id).fetch_optional(&mut *tx).await.map_err(|e| e.to_string())?;
        tx.commit().await.ok();
        Ok(row.map(|r| r.get::<serde_json::Value, _>(0)))
    }

    /// Count rows visible to a tenant via a bare `SELECT count(*)`; under FORCE RLS this is only the
    /// tenant's own rows, which is the isolation guarantee.
    pub async fn count_visible(&self, tenant: &str) -> Result<i64, String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sqlx::query("SELECT set_config('acp.tenant', $1, true)").bind(tenant).execute(&mut *tx).await.map_err(|e| e.to_string())?;
        let row = sqlx::query("SELECT count(*) FROM records").fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
        tx.commit().await.ok();
        Ok(row.get::<i64, _>(0))
    }
}
