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
pub struct IngestedRecord {
    pub decision_id: String,
    pub pep: String,
    pub kind: String,
    pub verdict: String,
    pub record: String,
    pub operator: String,
    pub created_ms: i64,
    pub pubkey_hex: String,
    pub sig_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ViolationEvent {
    pub id: String,
    pub kind: String,
    pub pep: String,
    pub agent: String,
    pub tool: String,
    pub verdict: String,
    pub rule_id: String,
    pub impact: String,
    pub outcome: String,
    pub ts_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallRule {
    pub id: String,
    pub match_json: String,
    pub classify: String,
    pub action: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FirewallConfig {
    pub enabled: bool,
    pub block_secrets: bool,
    pub deny_topics: String, // JSON array of strings
    pub model: String,       // the ML model JSON content, or "" for signatures-only
    pub scan_url: String,    // B1: external content-scan hook URL ("" = built-in only)
    pub block_on_scanner_error: bool, // B1: fail closed when the external scanner errors
    pub updated_ms: i64,
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
    pub linked_refs: String,
    pub answers_json: String,
    pub assignee: String,
    pub due_ms: i64,
    pub stage: String,
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
            "CREATE TABLE IF NOT EXISTS apps (id VARCHAR(255) PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS agents (id VARCHAR(255) PRIMARY KEY, app_id TEXT NOT NULL, name TEXT NOT NULL, token_sha256 TEXT NOT NULL, active INTEGER NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS endpoints (endpoint VARCHAR(255) PRIMARY KEY, kind TEXT NOT NULL, provider TEXT NOT NULL, disposition TEXT NOT NULL, operator TEXT NOT NULL, reason TEXT NOT NULL, decided_ms BIGINT NOT NULL, expires_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS grc_records (id VARCHAR(255) PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL, operator TEXT NOT NULL, created_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL, linked_refs TEXT NOT NULL DEFAULT '[]', answers_json TEXT NOT NULL DEFAULT '{}', assignee TEXT NOT NULL DEFAULT '', due_ms BIGINT NOT NULL DEFAULT 0, stage TEXT NOT NULL DEFAULT '')",
            "CREATE TABLE IF NOT EXISTS ingested_evidence (decision_id VARCHAR(255) PRIMARY KEY, pep TEXT NOT NULL, kind TEXT NOT NULL, verdict TEXT NOT NULL, record TEXT NOT NULL, operator TEXT NOT NULL, created_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS firewall_config (id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, block_secrets INTEGER NOT NULL, deny_topics TEXT NOT NULL, model TEXT NOT NULL, scan_url TEXT NOT NULL DEFAULT '', block_on_scanner_error INTEGER NOT NULL DEFAULT 0, updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS firewall_rules (id VARCHAR(255) PRIMARY KEY, match_json TEXT NOT NULL, classify TEXT NOT NULL, action TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS violation_events (id VARCHAR(255) PRIMARY KEY, kind TEXT NOT NULL, pep TEXT NOT NULL, agent TEXT NOT NULL, tool TEXT NOT NULL, verdict TEXT NOT NULL, rule_id TEXT NOT NULL, impact TEXT NOT NULL, outcome TEXT NOT NULL, ts_ms BIGINT NOT NULL)",
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

    /// Verify an agent by token hash and return its display identity (agent name, app id, app name)
    /// when active. Used by the enforcement path (the proxy) so DB-registered agents are honoured
    /// without a registry file.
    pub async fn verify_agent_identity(&self, id: &str, token_sha256: &str) -> Result<Option<(String, String, String)>, String> {
        let sql = self.ph("SELECT a.name AS an, a.app_id AS aid, ap.name AS apn FROM agents a LEFT JOIN apps ap ON a.app_id = ap.id WHERE a.id = ? AND a.token_sha256 = ? AND a.active <> 0");
        let row = sqlx::query(&sql)
            .bind(id)
            .bind(token_sha256)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
        Ok(row.map(|r| {
            let an: String = r.get("an");
            let aid: String = r.get("aid");
            let apn: String = r.try_get("apn").unwrap_or_default();
            (an, aid, apn)
        }))
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
        linked_refs: &str,
        answers_json: &str,
        assignee: &str,
        due_ms: i64,
        stage: &str,
    ) -> Result<(), String> {
        let sql = self.ph("INSERT INTO grc_records (id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql)
            .bind(id).bind(kind).bind(subject).bind(title).bind(status).bind(body)
            .bind(operator).bind(created_ms).bind(pubkey_hex).bind(sig_hex).bind(linked_refs)
            .bind(answers_json).bind(assignee).bind(due_ms).bind(stage)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn update_grc_status(&self, id: &str, status: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET status = ? WHERE id = ?");
        sqlx::query(&sql).bind(status).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Central content-firewall configuration (single row): the toggles, the denied topics, and the
    /// ML model content itself, so a workstation PEP fetches everything from the control plane instead
    /// of carrying a local model file. Idempotent replace of the singleton.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_firewall_config(&self, enabled: bool, block_secrets: bool, deny_topics_json: &str, model: &str, scan_url: &str, block_on_scanner_error: bool, updated_ms: i64) -> Result<(), String> {
        sqlx::query("DELETE FROM firewall_config").execute(&self.pool).await.map_err(|e| e.to_string())?;
        let sql = self.ph("INSERT INTO firewall_config(id,enabled,block_secrets,deny_topics,model,scan_url,block_on_scanner_error,updated_ms) VALUES(1,?,?,?,?,?,?,?)");
        sqlx::query(&sql)
            .bind(if enabled {1i64} else {0}).bind(if block_secrets {1i64} else {0})
            .bind(deny_topics_json).bind(model).bind(scan_url).bind(if block_on_scanner_error {1i64} else {0}).bind(updated_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Persist a reported violation event (deny/step_up/block/ssrf-block/break-glass/tool-integrity)
    /// so the console can produce a durable breach-and-violation report, not just a live feed.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_violation_event(&self, id: &str, kind: &str, pep: &str, agent: &str, tool: &str, verdict: &str, rule_id: &str, impact: &str, outcome: &str, ts_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT OR IGNORE INTO violation_events(id,kind,pep,agent,tool,verdict,rule_id,impact,outcome,ts_ms) VALUES(?,?,?,?,?,?,?,?,?,?)");
        sqlx::query(&sql).bind(id).bind(kind).bind(pep).bind(agent).bind(tool).bind(verdict).bind(rule_id).bind(impact).bind(outcome).bind(ts_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    /// Recent violations, newest first, up to `limit`, for the report.
    pub async fn list_violations(&self, limit: i64) -> Result<Vec<ViolationEvent>, String> {
        let sql = self.ph("SELECT id,kind,pep,agent,tool,verdict,rule_id,impact,outcome,ts_ms FROM violation_events ORDER BY ts_ms DESC LIMIT ?");
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| ViolationEvent {
            id: r.get("id"), kind: r.get("kind"), pep: r.get("pep"), agent: r.get("agent"), tool: r.get("tool"),
            verdict: r.get("verdict"), rule_id: r.get("rule_id"), impact: r.get("impact"), outcome: r.get("outcome"), ts_ms: r.get("ts_ms"),
        }).collect())
    }
    /// Operator-authored firewall (interception) rules, merged ahead of the enrolment-derived rules
    /// when the control plane serves GET /intercept/rules. First match wins, so these take precedence.
    pub async fn add_firewall_rule(&self, id: &str, match_json: &str, classify: &str, action: &str, created_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO firewall_rules(id,match_json,classify,action,created_ms) VALUES(?,?,?,?,?)");
        sqlx::query(&sql).bind(id).bind(match_json).bind(classify).bind(action).bind(created_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn list_firewall_rules(&self) -> Result<Vec<FirewallRule>, String> {
        let rows = sqlx::query("SELECT id, match_json, classify, action, created_ms FROM firewall_rules ORDER BY created_ms")
            .fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| FirewallRule {
            id: r.get("id"), match_json: r.get("match_json"), classify: r.get("classify"),
            action: r.get("action"), created_ms: r.get("created_ms"),
        }).collect())
    }
    pub async fn delete_firewall_rule(&self, id: &str) -> Result<(), String> {
        let sql = self.ph("DELETE FROM firewall_rules WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn get_firewall_config(&self) -> Result<Option<FirewallConfig>, String> {
        let row = sqlx::query("SELECT enabled, block_secrets, deny_topics, model, scan_url, block_on_scanner_error, updated_ms FROM firewall_config WHERE id = 1")
            .fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| FirewallConfig {
            enabled: r.get::<i64,_>("enabled") != 0,
            block_secrets: r.get::<i64,_>("block_secrets") != 0,
            deny_topics: r.get("deny_topics"),
            model: r.get("model"),
            scan_url: r.get("scan_url"),
            block_on_scanner_error: r.get::<i64,_>("block_on_scanner_error") != 0,
            updated_ms: r.get("updated_ms"),
        }))
    }

    /// E2: append a PEP-reported decision record to the central ingested-evidence store, signed by
    /// the control plane and deduped by decision_id (idempotent across retries/replays).
    #[allow(clippy::too_many_arguments)]
    pub async fn add_ingested(&self, decision_id: &str, pep: &str, kind: &str, verdict: &str, record: &str, operator: &str, created_ms: i64, pubkey_hex: &str, sig_hex: &str) -> Result<bool, String> {
        let sql = self.ph("INSERT OR IGNORE INTO ingested_evidence(decision_id,pep,kind,verdict,record,operator,created_ms,pubkey_hex,sig_hex) VALUES(?,?,?,?,?,?,?,?,?)");
        let r = sqlx::query(&sql)
            .bind(decision_id).bind(pep).bind(kind).bind(verdict).bind(record).bind(operator).bind(created_ms).bind(pubkey_hex).bind(sig_hex)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(r.rows_affected() == 1)
    }

    /// A2: does a decision id exist in the central ingested-evidence store (for GRC linked-ref checks)?
    pub async fn ingested_exists(&self, decision_id: &str) -> Result<bool, String> {
        let sql = self.ph("SELECT 1 FROM ingested_evidence WHERE decision_id = ?");
        let row = sqlx::query(&sql).bind(decision_id).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.is_some())
    }

    /// E2: most recent ingested decisions, newest first, for the console Fleet evidence view.
    pub async fn list_ingested(&self, limit: i64) -> Result<Vec<IngestedRecord>, String> {
        let sql = self.ph("SELECT decision_id,pep,kind,verdict,record,operator,created_ms,pubkey_hex,sig_hex FROM ingested_evidence ORDER BY created_ms DESC LIMIT ?");
        let rows = sqlx::query(&sql).bind(limit).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| IngestedRecord {
            decision_id: r.get("decision_id"), pep: r.get("pep"), kind: r.get("kind"), verdict: r.get("verdict"),
            record: r.get("record"), operator: r.get("operator"), created_ms: r.get("created_ms"),
            pubkey_hex: r.get("pubkey_hex"), sig_hex: r.get("sig_hex"),
        }).collect())
    }

    /// Fetch a single GRC record by id (for re-signing on a status change).
    pub async fn get_grc(&self, id: &str) -> Result<Option<GrcRecord>, String> {
        let sql = self.ph("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage FROM grc_records WHERE id = ?");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| GrcRecord {
            id: r.get("id"), kind: r.get("kind"), subject: r.get("subject"), title: r.get("title"),
            status: r.get("status"), body: r.get("body"), operator: r.get("operator"),
            created_ms: r.get("created_ms"), pubkey_hex: r.get("pubkey_hex"), sig_hex: r.get("sig_hex"),
            linked_refs: r.get("linked_refs"),
            answers_json: r.get("answers_json"), assignee: r.get("assignee"), due_ms: r.get("due_ms"), stage: r.get("stage"),
        }))
    }

    /// Update a record's status AND its signature together, so the stored signature always matches
    /// the current document (gap A4: a status change must re-sign, or the record reads as tampered).
    pub async fn update_grc_signed(&self, id: &str, status: &str, body: &str, stage: &str, pubkey_hex: &str, sig_hex: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET status = ?, body = ?, stage = ?, pubkey_hex = ?, sig_hex = ? WHERE id = ?");
        sqlx::query(&sql).bind(status).bind(body).bind(stage).bind(pubkey_hex).bind(sig_hex).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// A1: set the assignee and due date on a GRC record. Workflow metadata, not part of the signed
    /// document, so it does not require a re-sign.
    pub async fn set_grc_assignment(&self, id: &str, assignee: &str, due_ms: i64) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET assignee = ?, due_ms = ? WHERE id = ?");
        sqlx::query(&sql).bind(assignee).bind(due_ms).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_grc(&self, kind: Option<&str>) -> Result<Vec<GrcRecord>, String> {
        let rows = match kind {
            Some(k) => sqlx::query(&self.ph("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage FROM grc_records WHERE kind = ? ORDER BY created_ms"))
                .bind(k).fetch_all(&self.pool).await,
            None => sqlx::query("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage FROM grc_records ORDER BY created_ms")
                .fetch_all(&self.pool).await,
        }
        .map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| GrcRecord {
                id: r.get("id"), kind: r.get("kind"), subject: r.get("subject"), title: r.get("title"),
                status: r.get("status"), body: r.get("body"), operator: r.get("operator"),
                created_ms: r.get("created_ms"), pubkey_hex: r.get("pubkey_hex"), sig_hex: r.get("sig_hex"),
                linked_refs: r.get("linked_refs"),
                answers_json: r.get("answers_json"), assignee: r.get("assignee"), due_ms: r.get("due_ms"), stage: r.get("stage"),
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
        s.add_grc("grc-1", "risk", "checkout-agent", "PII exfiltration", "open", "{\"likelihood\":3,\"impact\":3}", "console", 4000, "aa", "bb", "[]", "{}", "", 0, "").await.unwrap();
        s.add_grc("grc-2", "assessment", "checkout-agent", "EU AI Act tiering", "high", "{}", "console", 4001, "aa", "cc", "[]", "{}", "", 0, "").await.unwrap();
        assert_eq!(s.list_grc(None).await.unwrap().len(), 2);
        assert_eq!(s.list_grc(Some("risk")).await.unwrap().len(), 1);
        // A4: get_grc + update_grc_signed round-trip (status + signature updated together).
        let g = s.get_grc("grc-1").await.unwrap().expect("record present");
        assert_eq!(g.status, "open");
        s.update_grc_signed("grc-1", "mitigated", "{\"body\":1}", "treatment", "dd", "ee").await.unwrap();
        let g2 = s.get_grc("grc-1").await.unwrap().unwrap();
        assert_eq!(g2.status, "mitigated");
        assert_eq!(g2.sig_hex, "ee", "signature updated with the status");
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
