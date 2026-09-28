//! Postgres tenant-isolated store (decision v1.1.1 / H1.1).
//!
//! The v0 evidence ledger is a single-tenant SQLite file. Multi-tenant GA needs a shared store
//! where one tenant can never read or write another's rows, and where that guarantee does not
//! depend on every query remembering to add `WHERE tenant_id = ...`. We get that from Postgres
//! Row-Level Security with FORCE: a policy binds every row to a tenant, and FORCE makes the policy
//! apply even to the table owner, so a bare `SELECT * FROM records` returns only the current
//! tenant's rows. The tenant is set per transaction via a `SET LOCAL`-style config, never trusted
//! from the row payload.
//!
//! This runs against a real Postgres (the local instance in dev, a managed instance in prod). The
//! isolation test is gated on `ACP_PG_TEST_URL` so CI without a database skips it cleanly.

use tokio_postgres::{Client, NoTls};

pub struct TenantStore {
    client: Client,
}

impl TenantStore {
    /// Connect and spawn the connection driver task.
    pub async fn connect(conn_str: &str) -> Result<Self, String> {
        let (client, connection) = tokio_postgres::connect(conn_str, NoTls)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("acp-pgstore: connection error: {e}");
            }
        });
        Ok(TenantStore { client })
    }

    /// Fail closed if the connected role bypasses row-level security. Postgres superusers and roles
    /// with BYPASSRLS ignore RLS policies entirely, so tenant isolation would silently NOT hold. We
    /// refuse to initialise against such a role rather than pretend the guarantee is in place.
    async fn ensure_rls_enforceable(&self) -> Result<(), String> {
        let row = self
            .client
            .query_one(
                "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        let bypasses: bool = row.get(0);
        if bypasses {
            return Err("acp-pgstore: the connected Postgres role bypasses row-level security \
                (superuser or BYPASSRLS). Tenant isolation would NOT be enforced. Connect as a \
                non-superuser role that does not have BYPASSRLS."
                .to_string());
        }
        Ok(())
    }

    /// Create the records table and install FORCE row-level security. Idempotent. Refuses if the
    /// connected role would bypass RLS (see `ensure_rls_enforceable`).
    pub async fn init_schema(&self) -> Result<(), String> {
        self.ensure_rls_enforceable().await?;
        let stmts = [
            "CREATE TABLE IF NOT EXISTS records (
                 tenant_id text NOT NULL,
                 id        text NOT NULL,
                 body      jsonb NOT NULL,
                 PRIMARY KEY (tenant_id, id)
             )",
            "ALTER TABLE records ENABLE ROW LEVEL SECURITY",
            // FORCE makes the policy apply to the table owner too, not just to unprivileged roles.
            "ALTER TABLE records FORCE ROW LEVEL SECURITY",
            "DROP POLICY IF EXISTS tenant_isolation ON records",
            // Every row is visible/writable only when its tenant_id matches the session's tenant.
            "CREATE POLICY tenant_isolation ON records
                 USING (tenant_id = current_setting('acp.tenant', true))
                 WITH CHECK (tenant_id = current_setting('acp.tenant', true))",
        ];
        for s in stmts {
            self.client
                .batch_execute(s)
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Begin a transaction bound to `tenant` via a txn-local config setting. The tenant is never
    /// read from row data; it is set by the trusted caller and scoped to this transaction.
    async fn begin_as(&self, tenant: &str) -> Result<(), String> {
        self.client
            .batch_execute("BEGIN")
            .await
            .map_err(|e| e.to_string())?;
        self.client
            .query("SELECT set_config('acp.tenant', $1, true)", &[&tenant])
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn commit(&self) -> Result<(), String> {
        self.client
            .batch_execute("COMMIT")
            .await
            .map_err(|e| e.to_string())
    }

    /// Remove all rows (owner-level maintenance, not tenant-scoped). For test determinism.
    pub async fn truncate_all(&self) -> Result<(), String> {
        self.client
            .batch_execute("TRUNCATE records")
            .await
            .map_err(|e| e.to_string())
    }

    /// Insert or update a row for a tenant.
    pub async fn put(
        &self,
        tenant: &str,
        id: &str,
        body: &serde_json::Value,
    ) -> Result<(), String> {
        self.begin_as(tenant).await?;
        let res = self
            .client
            .execute(
                "INSERT INTO records (tenant_id, id, body) VALUES ($1, $2, $3)
                 ON CONFLICT (tenant_id, id) DO UPDATE SET body = EXCLUDED.body",
                &[&tenant, &id, body],
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string());
        if res.is_ok() {
            self.commit().await?;
        } else {
            let _ = self.client.batch_execute("ROLLBACK").await;
        }
        res
    }

    /// Fetch a row for a tenant, honouring RLS (a wrong tenant sees nothing).
    pub async fn get(&self, tenant: &str, id: &str) -> Result<Option<serde_json::Value>, String> {
        self.begin_as(tenant).await?;
        let rows = self
            .client
            .query("SELECT body FROM records WHERE id = $1", &[&id])
            .await
            .map_err(|e| e.to_string());
        self.commit().await.ok();
        rows.map(|r| r.first().map(|row| row.get::<_, serde_json::Value>(0)))
    }

    /// Count rows visible to a tenant via a bare, unfiltered `SELECT count(*)`. Under FORCE RLS
    /// this returns only the tenant's own rows, which is the isolation guarantee.
    pub async fn count_visible(&self, tenant: &str) -> Result<i64, String> {
        self.begin_as(tenant).await?;
        let row = self
            .client
            .query_one("SELECT count(*) FROM records", &[])
            .await
            .map_err(|e| e.to_string());
        self.commit().await.ok();
        row.map(|r| r.get::<_, i64>(0))
    }
}
