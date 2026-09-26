//! Config-driven control-plane store. The backend is chosen by the connection URL, so the operator
//! picks the database that fits their size forecast (sqlite for small/single-node, postgres or mysql
//! for larger) without a rebuild. Built on sqlx's Any driver.
//!
//! Portability: queries are written once with `?` placeholders and rewritten to `$1..$n` for
//! Postgres; DDL uses only TEXT / BIGINT / INTEGER; "upsert" is delete-then-insert in a transaction
//! rather than a dialect-specific ON CONFLICT, so the same code runs on sqlite, postgres and mysql.

use serde::Serialize;
use sqlx::any::{install_default_drivers, AnyPoolOptions};
use sqlx::{AnyPool, Row};

#[derive(Debug, Clone, Serialize)]
pub struct App {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Agent {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub active: bool,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Endpoint {
    pub endpoint: String,
    pub kind: String,
    pub provider: String,
    pub disposition: String,
    pub operator: String,
    pub reason: String,
    pub decided_ms: i64,
    pub expires_ms: i64,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrcRecord {
    pub id: String,
    pub kind: String,
    pub subject: String,
    pub title: String,
    pub status: String,
    pub body: String,
    pub operator: String,
    pub created_ms: i64,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

pub struct ControlStore {
    pool: AnyPool,
    pg: bool,
}

impl ControlStore {
    /// Connect using a URL whose scheme selects the backend:
    ///   sqlite://<path>?mode=rwc  |  postgres://user:pass@host/db  |  mysql://user:pass@host/db
    pub async fn connect(url: &str) -> Result<Self, String> {
        install_default_drivers();
        let pg = url.starts_with("postgres:") || url.starts_with("postgresql:");
        let pool = AnyPoolOptions::new()
            .max_connections(8)
            .connect(url)
            .await
            .map_err(|e| e.to_string())?;
        let s = ControlStore { pool, pg };
        s.migrate().await?;
        Ok(s)
    }

    /// Rewrite `?` to `$1..$n` for Postgres; leave it for sqlite/mysql. Our SQL never contains a `?`
    /// inside a string literal, so a positional rewrite is safe.
    fn ph(&self, sql: &str) -> String {
        if !self.pg {
            return sql.to_string();
        }
        let mut out = String::with_capacity(sql.len() + 8);
        let mut n = 0;
        for c in sql.chars() {
            if c == '?' {
                n += 1;
                out.push('$');
                out.push_str(&n.to_string());
            } else {
                out.push(c);
            }
        }
        out
    }

    async fn migrate(&self) -> Result<(), String> {
        for ddl in [
            "CREATE TABLE IF NOT EXISTS apps (id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, app_id TEXT NOT NULL, name TEXT NOT NULL, token_sha256 TEXT NOT NULL, active INTEGER NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS endpoints (endpoint TEXT PRIMARY KEY, kind TEXT NOT NULL, provider TEXT NOT NULL, disposition TEXT NOT NULL, operator TEXT NOT NULL, reason TEXT NOT NULL, decided_ms BIGINT NOT NULL, expires_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS grc_records (id TEXT PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL, operator TEXT NOT NULL, created_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL)",
        ] {
            sqlx::query(ddl).execute(&self.pool).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    // ---- apps ----
    pub async fn add_app(&self, id: &str, name: &str, owner: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO apps (id, name, owner, created_ms) VALUES (?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(name).bind(owner).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_apps(&self) -> Result<Vec<App>, String> {
        let rows = sqlx::query("SELECT id, name, owner, created_ms FROM apps ORDER BY created_ms")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| App {
                id: r.get("id"),
                name: r.get("name"),
                owner: r.get("owner"),
                created_ms: r.get("created_ms"),
            })
            .collect())
    }

    // ---- agents ----
    pub async fn add_agent(&self, id: &str, app_id: &str, name: &str, token_sha256: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO agents (id, app_id, name, token_sha256, active, created_ms) VALUES (?, ?, ?, ?, 1, ?)");
        sqlx::query(&sql).bind(id).bind(app_id).bind(name).bind(token_sha256).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn deactivate_agent(&self, id: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE agents SET active = 0 WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_agents(&self) -> Result<Vec<Agent>, String> {
        let rows = sqlx::query("SELECT id, app_id, name, active, created_ms FROM agents ORDER BY created_ms")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| Agent {
                id: r.get("id"),
                app_id: r.get("app_id"),
                name: r.get("name"),
                active: r.get::<i32, _>("active") != 0,
                created_ms: r.get("created_ms"),
            })
            .collect())
    }

    /// Return the agent id if the token matches its stored hash and it is active.
    pub async fn verify_agent(&self, id: &str, token_sha256: &str) -> Result<bool, String> {
        let row = sqlx::query(&self.ph("SELECT active FROM agents WHERE id = ? AND token_sha256 = ?"))
            .bind(id)
            .bind(token_sha256)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|r| r.get::<i32, _>("active") != 0).unwrap_or(false))
    }

    // ---- endpoints (latest disposition per endpoint; delete-then-insert for portability) ----
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_endpoint(
        &self,
        endpoint: &str,
        kind: &str,
        provider: &str,
        disposition: &str,
        operator: &str,
        reason: &str,
        decided_ms: i64,
        expires_ms: i64,
        pubkey_hex: &str,
        sig_hex: &str,
    ) -> Result<(), String> {
        let mut tx = self.pool.begin().await.map_err(|e| e.to_string())?;
        sqlx::query(&self.ph("DELETE FROM endpoints WHERE endpoint = ?"))
            .bind(endpoint)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        sqlx::query(&self.ph(
            "INSERT INTO endpoints (endpoint, kind, provider, disposition, operator, reason, decided_ms, expires_ms, pubkey_hex, sig_hex) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ))
        .bind(endpoint).bind(kind).bind(provider).bind(disposition).bind(operator).bind(reason)
        .bind(decided_ms).bind(expires_ms).bind(pubkey_hex).bind(sig_hex)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_endpoints(&self) -> Result<Vec<Endpoint>, String> {
        let rows = sqlx::query("SELECT endpoint, kind, provider, disposition, operator, reason, decided_ms, expires_ms, pubkey_hex, sig_hex FROM endpoints ORDER BY endpoint")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| Endpoint {
                endpoint: r.get("endpoint"),
                kind: r.get("kind"),
                provider: r.get("provider"),
                disposition: r.get("disposition"),
                operator: r.get("operator"),
                reason: r.get("reason"),
                decided_ms: r.get("decided_ms"),
                expires_ms: r.get("expires_ms"),
                pubkey_hex: r.get("pubkey_hex"),
                sig_hex: r.get("sig_hex"),
            })
            .collect())
    }

    // ---- GRC records (signed operator documents: assessments, risk, model cards, ...) ----
    #[allow(clippy::too_many_arguments)]
    pub async fn add_grc(
        &self,
        id: &str,
        kind: &str,
        subject: &str,
        title: &str,
        status: &str,
        body: &str,
        operator: &str,
        created_ms: i64,
        pubkey_hex: &str,
        sig_hex: &str,
    ) -> Result<(), String> {
        let sql = self.ph("INSERT INTO grc_records (id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql)
            .bind(id).bind(kind).bind(subject).bind(title).bind(status).bind(body)
            .bind(operator).bind(created_ms).bind(pubkey_hex).bind(sig_hex)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn update_grc_status(&self, id: &str, status: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET status = ? WHERE id = ?");
        sqlx::query(&sql).bind(status).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_grc(&self, kind: Option<&str>) -> Result<Vec<GrcRecord>, String> {
        let rows = match kind {
            Some(k) => sqlx::query(&self.ph("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex FROM grc_records WHERE kind = ? ORDER BY created_ms"))
                .bind(k).fetch_all(&self.pool).await,
            None => sqlx::query("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex FROM grc_records ORDER BY created_ms")
                .fetch_all(&self.pool).await,
        }
        .map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| GrcRecord {
                id: r.get("id"), kind: r.get("kind"), subject: r.get("subject"), title: r.get("title"),
                status: r.get("status"), body: r.get("body"), operator: r.get("operator"),
                created_ms: r.get("created_ms"), pubkey_hex: r.get("pubkey_hex"), sig_hex: r.get("sig_hex"),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn check(url: &str) {
        let s = ControlStore::connect(url).await.expect("connect");
        s.add_app("app-1", "acme", "you", 1000).await.unwrap();
        assert_eq!(s.list_apps().await.unwrap().len(), 1);
        s.add_agent("agt-1", "app-1", "asst", "deadbeef", 1001).await.unwrap();
        assert!(s.verify_agent("agt-1", "deadbeef").await.unwrap());
        assert!(!s.verify_agent("agt-1", "wrong").await.unwrap());
        s.deactivate_agent("agt-1").await.unwrap();
        assert!(!s.verify_agent("agt-1", "deadbeef").await.unwrap(), "deactivated agent must not verify");
        s.upsert_endpoint("claude.ai", "model-api", "Anthropic", "govern", "console", "ok", 2000, 0, "aa", "bb").await.unwrap();
        s.upsert_endpoint("claude.ai", "model-api", "Anthropic", "block", "console", "revoked", 3000, 0, "aa", "cc").await.unwrap();
        let eps = s.list_endpoints().await.unwrap();
        assert_eq!(eps.len(), 1, "upsert keeps one row per endpoint");
        assert_eq!(eps[0].disposition, "block", "latest disposition wins");
        s.add_grc("grc-1", "risk", "checkout-agent", "PII exfiltration", "open", "{\"likelihood\":3,\"impact\":3}", "console", 4000, "aa", "bb").await.unwrap();
        s.add_grc("grc-2", "assessment", "checkout-agent", "EU AI Act tiering", "high", "{}", "console", 4001, "aa", "cc").await.unwrap();
        assert_eq!(s.list_grc(None).await.unwrap().len(), 2);
        assert_eq!(s.list_grc(Some("risk")).await.unwrap().len(), 1);
        s.update_grc_status("grc-1", "mitigated").await.unwrap();
        assert_eq!(s.list_grc(Some("risk")).await.unwrap()[0].status, "mitigated");
    }

    #[tokio::test]
    async fn sqlite_backend() {
        let f = std::env::temp_dir().join(format!("acp-cp-{}-s.db", std::process::id()));
        let _ = std::fs::remove_file(&f);
        check(&format!("sqlite://{}?mode=rwc", f.display())).await;
        let _ = std::fs::remove_file(&f);
    }

    #[tokio::test]
    async fn postgres_backend_if_available() {
        let Some(url) = std::env::var("ACP_CP_PG_URL").ok() else {
            eprintln!("ACP_CP_PG_URL not set; skipping postgres backend test");
            return;
        };
        check(&url).await;
    }
}
