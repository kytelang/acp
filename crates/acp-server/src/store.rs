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
    pub metadata_json: String,
    pub tenant: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Agent {
    pub id: String,
    pub app_id: String,
    pub name: String,
    pub owner: String,
    pub metadata_json: String,
    pub active: bool,
    pub tenant: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub version: String,
    pub card_json: String,
    pub scan_status: String,
    pub aibom_json: String,
    pub tenant: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ControlPackRow {
    pub id: String,
    pub version: String,
    pub doc_json: String,   // the exact signed pack document (for re-verification)
    pub pubkey_hex: String,
    pub sig_hex: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Vendor {
    pub id: String,
    pub name: String,
    pub risk_json: String,
    pub tenant: String,
    pub review_due_ms: i64,
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
    pub feed_version: i64,   // B5: threat-feed version (monotonic)
    pub threat_signatures: String, // B5: JSON array of firewall signatures from the loaded threat pack
    pub block_toxicity: bool, // F2: enable the toxicity lexicon
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
    pub tenant: String,
}

pub struct ControlStore {
    pool: AnyPool,
    pg: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiSystem {
    pub id: String,
    pub name: String,
    pub purpose: String,
    pub owner: String,
    pub lifecycle_state: String,
    pub risk_tier: String,
    pub sector: String,
    pub asset_type: String,
    pub jurisdictions: String, // JSON array
    pub tenant: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemRole {
    pub id: String,
    pub system_id: String,
    pub role: String,
    pub jurisdiction: String,
    pub market_date: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoaEntry {
    pub id: String,
    pub system_id: String,
    pub framework: String,
    pub control_id: String,
    pub applicable: bool,
    pub justification: String,
    pub status: String,
    pub evidence_refs: String, // JSON array
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub id: String,
    pub system_id: String,
    pub framework: String,
    pub control_id: String,
    pub title: String,
    pub source: String,
    pub owner: String,
    pub produced_ms: i64,
    pub valid_until_ms: i64,
    pub artefact_ref: String,
    pub note: String,
    pub created_ms: i64,
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
            "CREATE TABLE IF NOT EXISTS apps (id VARCHAR(255) PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS agents (id VARCHAR(255) PRIMARY KEY, app_id TEXT NOT NULL, name TEXT NOT NULL, token_sha256 TEXT NOT NULL, active INTEGER NOT NULL, owner TEXT NOT NULL DEFAULT '', metadata_json TEXT NOT NULL DEFAULT '{}', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS models (id VARCHAR(255) PRIMARY KEY, name TEXT NOT NULL, provider TEXT NOT NULL, version TEXT NOT NULL, card_json TEXT NOT NULL DEFAULT '{}', scan_status TEXT NOT NULL DEFAULT 'unscanned', aibom_json TEXT NOT NULL DEFAULT '', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS vendors (id VARCHAR(255) PRIMARY KEY, name TEXT NOT NULL, risk_json TEXT NOT NULL DEFAULT '{}', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', review_due_ms BIGINT NOT NULL DEFAULT 0, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS control_packs (id VARCHAR(255) PRIMARY KEY, version TEXT NOT NULL, doc_json TEXT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS endpoints (endpoint VARCHAR(255) PRIMARY KEY, kind TEXT NOT NULL, provider TEXT NOT NULL, disposition TEXT NOT NULL, operator TEXT NOT NULL, reason TEXT NOT NULL, decided_ms BIGINT NOT NULL, expires_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS grc_records (id VARCHAR(255) PRIMARY KEY, kind TEXT NOT NULL, subject TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL, operator TEXT NOT NULL, created_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL, linked_refs TEXT NOT NULL DEFAULT '[]', answers_json TEXT NOT NULL DEFAULT '{}', assignee TEXT NOT NULL DEFAULT '', due_ms BIGINT NOT NULL DEFAULT 0, stage TEXT NOT NULL DEFAULT '', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default')",
            "CREATE TABLE IF NOT EXISTS grc_comments (id VARCHAR(255) PRIMARY KEY, grc_id TEXT NOT NULL, author TEXT NOT NULL, body TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS ingested_evidence (decision_id VARCHAR(255) PRIMARY KEY, pep TEXT NOT NULL, kind TEXT NOT NULL, verdict TEXT NOT NULL, record TEXT NOT NULL, operator TEXT NOT NULL, created_ms BIGINT NOT NULL, pubkey_hex TEXT NOT NULL, sig_hex TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS firewall_config (tenant_id VARCHAR(255) PRIMARY KEY, enabled INTEGER NOT NULL, block_secrets INTEGER NOT NULL, deny_topics TEXT NOT NULL, model TEXT NOT NULL, scan_url TEXT NOT NULL DEFAULT '', block_on_scanner_error INTEGER NOT NULL DEFAULT 0, feed_version BIGINT NOT NULL DEFAULT 0, threat_signatures TEXT NOT NULL DEFAULT '[]', block_toxicity INTEGER NOT NULL DEFAULT 0, updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS firewall_rules (id VARCHAR(255) PRIMARY KEY, match_json TEXT NOT NULL, classify TEXT NOT NULL, action TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS violation_events (id VARCHAR(255) PRIMARY KEY, kind TEXT NOT NULL, pep TEXT NOT NULL, agent TEXT NOT NULL, tool TEXT NOT NULL, verdict TEXT NOT NULL, rule_id TEXT NOT NULL, impact TEXT NOT NULL, outcome TEXT NOT NULL, ts_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS control_leader (id INTEGER PRIMARY KEY, holder TEXT NOT NULL, token BIGINT NOT NULL, expires_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS control_state (k VARCHAR(255) PRIMARY KEY, v TEXT NOT NULL, updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS drift_counts (class VARCHAR(255) PRIMARY KEY, hits BIGINT NOT NULL, total BIGINT NOT NULL, baseline DOUBLE PRECISION NOT NULL, updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS report_snapshots (id VARCHAR(255) PRIMARY KEY, framework TEXT NOT NULL, tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', body_json TEXT NOT NULL, created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS lineage_edges (id VARCHAR(255) PRIMARY KEY, data_class TEXT NOT NULL, tool TEXT NOT NULL, count BIGINT NOT NULL, updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS ai_systems (id VARCHAR(255) PRIMARY KEY, name TEXT NOT NULL, purpose TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', lifecycle_state TEXT NOT NULL DEFAULT 'development', risk_tier TEXT NOT NULL DEFAULT '', sector TEXT NOT NULL DEFAULT '', asset_type TEXT NOT NULL DEFAULT '', jurisdictions TEXT NOT NULL DEFAULT '[]', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', created_ms BIGINT NOT NULL, updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS system_roles (id VARCHAR(255) PRIMARY KEY, system_id TEXT NOT NULL, role TEXT NOT NULL, jurisdiction TEXT NOT NULL DEFAULT '', market_date TEXT NOT NULL DEFAULT '', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', created_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS soa_entries (id VARCHAR(255) PRIMARY KEY, system_id TEXT NOT NULL, framework TEXT NOT NULL, control_id TEXT NOT NULL, applicable INTEGER NOT NULL DEFAULT 1, justification TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'planned', evidence_refs TEXT NOT NULL DEFAULT '[]', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', updated_ms BIGINT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS evidence (id VARCHAR(255) PRIMARY KEY, system_id TEXT NOT NULL, framework TEXT NOT NULL, control_id TEXT NOT NULL, title TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT '', owner TEXT NOT NULL DEFAULT '', produced_ms BIGINT NOT NULL DEFAULT 0, valid_until_ms BIGINT NOT NULL DEFAULT 0, artefact_ref TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '', tenant_id VARCHAR(255) NOT NULL DEFAULT 'default', created_ms BIGINT NOT NULL)",
        ] {
            sqlx::query(ddl).execute(&self.pool).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    // ---- apps ----
    pub async fn add_app(&self, id: &str, name: &str, owner: &str, metadata_json: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO apps (id, name, owner, metadata_json, tenant_id, created_ms) VALUES (?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(name).bind(owner).bind(metadata_json).bind(tenant).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_apps(&self, tenant: &str) -> Result<Vec<App>, String> {
        let rows = sqlx::query(&self.ph("SELECT id, name, owner, metadata_json, tenant_id, created_ms FROM apps WHERE tenant_id = ? ORDER BY created_ms"))
            .bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| App {
            id: r.get("id"), name: r.get("name"), owner: r.get("owner"),
            metadata_json: r.get("metadata_json"), tenant: r.get("tenant_id"), created_ms: r.get("created_ms"),
        }).collect())
    }

    // ---- agents ----
    #[allow(clippy::too_many_arguments)]
    pub async fn add_agent(&self, id: &str, app_id: &str, name: &str, token_sha256: &str, owner: &str, metadata_json: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO agents (id, app_id, name, token_sha256, active, owner, metadata_json, tenant_id, created_ms) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(app_id).bind(name).bind(token_sha256).bind(owner).bind(metadata_json).bind(tenant).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn deactivate_agent(&self, id: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE agents SET active = 0 WHERE id = ?");
        sqlx::query(&sql).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_agents(&self, tenant: &str) -> Result<Vec<Agent>, String> {
        let rows = sqlx::query(&self.ph("SELECT id, app_id, name, owner, metadata_json, active, tenant_id, created_ms FROM agents WHERE tenant_id = ? ORDER BY created_ms"))
            .bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows
            .iter()
            .map(|r| Agent {
                id: r.get("id"),
                app_id: r.get("app_id"),
                name: r.get("name"),
                owner: r.get("owner"),
                metadata_json: r.get("metadata_json"),
                active: r.get::<i32, _>("active") != 0,
                tenant: r.get("tenant_id"),
                created_ms: r.get("created_ms"),
            })
            .collect())
    }

    /// M1: distinct tenants that have data (union across records/apps), for the console switcher.
    pub async fn list_tenants(&self) -> Result<Vec<String>, String> {
        let rows = sqlx::query("SELECT tenant_id FROM grc_records UNION SELECT tenant_id FROM apps UNION SELECT tenant_id FROM models UNION SELECT tenant_id FROM vendors ORDER BY tenant_id")
            .fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| r.get::<String,_>("tenant_id")).collect())
    }

    // ---- A3: model registry ----
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn add_model(&self, id: &str, name: &str, provider: &str, version: &str, card_json: &str, scan_status: &str, aibom_json: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO models (id, name, provider, version, card_json, scan_status, aibom_json, tenant_id, created_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(name).bind(provider).bind(version).bind(card_json).bind(scan_status).bind(aibom_json).bind(tenant).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn list_models(&self, tenant: &str) -> Result<Vec<Model>, String> {
        let rows = sqlx::query(&self.ph("SELECT id, name, provider, version, card_json, scan_status, aibom_json, tenant_id, created_ms FROM models WHERE tenant_id = ? ORDER BY created_ms"))
            .bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| Model {
            id: r.get("id"), name: r.get("name"), provider: r.get("provider"), version: r.get("version"),
            card_json: r.get("card_json"), scan_status: r.get("scan_status"), aibom_json: r.get("aibom_json"), tenant: r.get("tenant_id"), created_ms: r.get("created_ms"),
        }).collect())
    }
    pub async fn get_model(&self, id: &str) -> Result<Option<Model>, String> {
        let sql = self.ph("SELECT id, name, provider, version, card_json, scan_status, aibom_json, tenant_id, created_ms FROM models WHERE id = ?");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| Model {
            id: r.get("id"), name: r.get("name"), provider: r.get("provider"), version: r.get("version"),
            card_json: r.get("card_json"), scan_status: r.get("scan_status"), aibom_json: r.get("aibom_json"), tenant: r.get("tenant_id"), created_ms: r.get("created_ms"),
        }))
    }

    // ---- A3: vendor registry ----
    pub async fn add_vendor(&self, id: &str, name: &str, risk_json: &str, tenant: &str, review_due_ms: i64, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO vendors (id, name, risk_json, tenant_id, review_due_ms, created_ms) VALUES (?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(name).bind(risk_json).bind(tenant).bind(review_due_ms).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn list_vendors(&self, tenant: &str) -> Result<Vec<Vendor>, String> {
        let rows = sqlx::query(&self.ph("SELECT id, name, risk_json, tenant_id, review_due_ms, created_ms FROM vendors WHERE tenant_id = ? ORDER BY created_ms"))
            .bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| Vendor {
            id: r.get("id"), name: r.get("name"), risk_json: r.get("risk_json"), tenant: r.get("tenant_id"), review_due_ms: r.get("review_due_ms"), created_ms: r.get("created_ms"),
        }).collect())
    }
    pub async fn set_vendor_review(&self, id: &str, tenant: &str, review_due_ms: i64) -> Result<bool, String> {
        let sql = self.ph("UPDATE vendors SET review_due_ms = ? WHERE id = ? AND tenant_id = ?");
        let r = sqlx::query(&sql).bind(review_due_ms).bind(id).bind(tenant).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(r.rows_affected() == 1)
    }

    // ---- A4: signed control packs ----
    pub async fn add_pack(&self, id: &str, version: &str, doc_json: &str, pubkey_hex: &str, sig_hex: &str, now_ms: i64) -> Result<(), String> {
        // Idempotent replace by id: reloading a pack of the same id updates it in place.
        let del = self.ph("DELETE FROM control_packs WHERE id = ?");
        sqlx::query(&del).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        let sql = self.ph("INSERT INTO control_packs (id, version, doc_json, pubkey_hex, sig_hex, created_ms) VALUES (?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(version).bind(doc_json).bind(pubkey_hex).bind(sig_hex).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn list_packs(&self) -> Result<Vec<ControlPackRow>, String> {
        let rows = sqlx::query("SELECT id, version, doc_json, pubkey_hex, sig_hex, created_ms FROM control_packs ORDER BY created_ms")
            .fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| ControlPackRow {
            id: r.get("id"), version: r.get("version"), doc_json: r.get("doc_json"),
            pubkey_hex: r.get("pubkey_hex"), sig_hex: r.get("sig_hex"), created_ms: r.get("created_ms"),
        }).collect())
    }

    /// Verify an agent by token hash and return its display identity (agent name, app id, app name)
    /// when active. Used by the enforcement path (the proxy) so DB-registered agents are honoured
    /// without a registry file.
    /// Resolve an agent from its per-agent virtual key alone (the token issued at registration), for the
    /// LLM-gateway path where a sanctioned agent presents only its key. Returns (agent_id, agent_name,
    /// app_id, tenant) for the active agent whose token hash matches. Audit P0 F1.
    pub async fn resolve_agent_by_token_sha(&self, token_sha256: &str) -> Result<Option<(String, String, String, String)>, String> {
        let sql = self.ph("SELECT id, name, app_id, tenant_id FROM agents WHERE token_sha256 = ? AND active <> 0");
        let row = sqlx::query(&sql).bind(token_sha256).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| {
            let id: String = r.get("id"); let name: String = r.get("name");
            let app_id: String = r.get("app_id"); let tenant: String = r.get("tenant_id");
            (id, name, app_id, tenant)
        }))
    }

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
        tenant: &str,
    ) -> Result<(), String> {
        let sql = self.ph("INSERT INTO grc_records (id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql)
            .bind(id).bind(kind).bind(subject).bind(title).bind(status).bind(body)
            .bind(operator).bind(created_ms).bind(pubkey_hex).bind(sig_hex).bind(linked_refs)
            .bind(answers_json).bind(assignee).bind(due_ms).bind(stage).bind(tenant)
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
    #[allow(clippy::too_many_arguments)]
    pub async fn set_firewall_config(&self, tenant: &str, enabled: bool, block_secrets: bool, deny_topics_json: &str, model: &str, scan_url: &str, block_on_scanner_error: bool, block_toxicity: bool, updated_ms: i64) -> Result<(), String> {
        // Preserve threat-feed fields across a config save (set by a separate path), per tenant.
        let (fv, ts): (i64, String) = match self.get_firewall_config(tenant).await? {
            Some(c) => (c.feed_version, c.threat_signatures),
            None => (0, "[]".to_string()),
        };
        let del = self.ph("DELETE FROM firewall_config WHERE tenant_id = ?");
        sqlx::query(&del).bind(tenant).execute(&self.pool).await.map_err(|e| e.to_string())?;
        let sql = self.ph("INSERT INTO firewall_config(tenant_id,enabled,block_secrets,deny_topics,model,scan_url,block_on_scanner_error,feed_version,threat_signatures,block_toxicity,updated_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?)");
        sqlx::query(&sql).bind(tenant)
            .bind(if enabled {1i64} else {0}).bind(if block_secrets {1i64} else {0})
            .bind(deny_topics_json).bind(model).bind(scan_url).bind(if block_on_scanner_error {1i64} else {0})
            .bind(fv).bind(ts).bind(if block_toxicity {1i64} else {0}).bind(updated_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// B5: store a loaded threat pack's signatures + feed version onto the firewall_config singleton,
    /// creating the row if the operator has not saved a config yet. Leaves the other fields intact.
    pub async fn set_firewall_threat(&self, tenant: &str, feed_version: i64, signatures_json: &str, updated_ms: i64) -> Result<(), String> {
        let exists = sqlx::query(&self.ph("SELECT 1 FROM firewall_config WHERE tenant_id = ?")).bind(tenant).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        if exists.is_some() {
            let sql = self.ph("UPDATE firewall_config SET feed_version = ?, threat_signatures = ?, updated_ms = ? WHERE tenant_id = ?");
            sqlx::query(&sql).bind(feed_version).bind(signatures_json).bind(updated_ms).bind(tenant).execute(&self.pool).await.map_err(|e| e.to_string())?;
        } else {
            let sql = self.ph("INSERT INTO firewall_config(tenant_id,enabled,block_secrets,deny_topics,model,scan_url,block_on_scanner_error,feed_version,threat_signatures,updated_ms) VALUES(?,0,0,'[]','','',0,?,?,?)");
            sqlx::query(&sql).bind(tenant).bind(feed_version).bind(signatures_json).bind(updated_ms).execute(&self.pool).await.map_err(|e| e.to_string())?;
        }
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

    pub async fn get_firewall_config(&self, tenant: &str) -> Result<Option<FirewallConfig>, String> {
        let row = sqlx::query(&self.ph("SELECT enabled, block_secrets, deny_topics, model, scan_url, block_on_scanner_error, feed_version, threat_signatures, block_toxicity, updated_ms FROM firewall_config WHERE tenant_id = ?"))
            .bind(tenant).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| FirewallConfig {
            enabled: r.get::<i64,_>("enabled") != 0,
            block_secrets: r.get::<i64,_>("block_secrets") != 0,
            deny_topics: r.get("deny_topics"),
            model: r.get("model"),
            scan_url: r.get("scan_url"),
            block_on_scanner_error: r.get::<i64,_>("block_on_scanner_error") != 0,
            feed_version: r.get("feed_version"),
            threat_signatures: r.get("threat_signatures"),
            block_toxicity: r.get::<i64,_>("block_toxicity") != 0,
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

    // ---- C1: HA leader lease (shared-store, fenced) + persisted control state ----
    /// Atomically try to acquire or renew the single control-plane leadership lease. Returns
    /// (is_leader, holder, token). Fencing token increases monotonically on every (re)acquisition, so
    /// a paused old leader that wakes up sees a larger token elsewhere and stands down. Split-brain is
    /// prevented because only the row's current holder or an expired lease can be taken.
    pub async fn try_acquire_leader(&self, node: &str, now_ms: i64, ttl_ms: i64) -> Result<(bool, String, i64), String> {
        let exp = now_ms + ttl_ms;
        // Seed the row on first ever call (no-op if it exists).
        let ins = self.ph("INSERT OR IGNORE INTO control_leader(id,holder,token,expires_ms) VALUES(1,?,1,?)");
        sqlx::query(&ins).bind(node).bind(exp).execute(&self.pool).await.map_err(|e| e.to_string())?;
        // Take over iff the lease is expired or already ours; bump the fencing token. This single
        // conditional UPDATE is atomic per row on both SQLite and Postgres.
        let upd = self.ph("UPDATE control_leader SET holder=?, token=token+1, expires_ms=? WHERE id=1 AND (expires_ms<=? OR holder=?)");
        sqlx::query(&upd).bind(node).bind(exp).bind(now_ms).bind(node)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        // Read back the authoritative row.
        let row = sqlx::query("SELECT holder, token, expires_ms FROM control_leader WHERE id=1")
            .fetch_one(&self.pool).await.map_err(|e| e.to_string())?;
        let holder: String = row.get("holder");
        let token: i64 = row.get("token");
        let expires: i64 = row.get("expires_ms");
        let is_leader = holder == node && expires > now_ms;
        Ok((is_leader, holder, token))
    }

    /// Store a control-state snapshot under a key (liveness/spike survive a restart). Idempotent
    /// replace of the single row for that key.
    pub async fn put_state(&self, key: &str, value: &str, now_ms: i64) -> Result<(), String> {
        let del = self.ph("DELETE FROM control_state WHERE k=?");
        sqlx::query(&del).bind(key).execute(&self.pool).await.map_err(|e| e.to_string())?;
        let ins = self.ph("INSERT INTO control_state(k,v,updated_ms) VALUES(?,?,?)");
        sqlx::query(&ins).bind(key).bind(value).bind(now_ms).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Read a control-state snapshot by key.
    pub async fn get_state(&self, key: &str) -> Result<Option<String>, String> {
        let sql = self.ph("SELECT v FROM control_state WHERE k=?");
        let row = sqlx::query(&sql).bind(key).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| r.get("v")))
    }

    /// List all control-state rows whose key starts with `prefix` (used to restore per-proxy liveness
    /// and per-event spike state across a restart, without any node clobbering another's snapshot).
    pub async fn list_state_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>, String> {
        let like = format!("{prefix}%");
        let sql = self.ph("SELECT k, v FROM control_state WHERE k LIKE ?");
        let rows = sqlx::query(&sql).bind(like).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| (r.get::<String,_>("k"), r.get::<String,_>("v"))).collect())
    }

    /// Delete one control-state row (used to prune expired spike-event keys).
    pub async fn delete_state(&self, key: &str) -> Result<(), String> {
        let sql = self.ph("DELETE FROM control_state WHERE k=?");
        sqlx::query(&sql).bind(key).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    // F3: classifier-drift counts (per class) and data-class -> tool lineage edges. Counts only.
    pub async fn report_drift(&self, class: &str, hits: i64, total: i64, now_ms: i64) -> Result<(), String> {
        let row = sqlx::query(&self.ph("SELECT hits, total FROM drift_counts WHERE class = ?")).bind(class)
            .fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        match row {
            Some(r) => {
                let (h, t): (i64, i64) = (r.get::<i64,_>("hits") + hits, r.get::<i64,_>("total") + total);
                sqlx::query(&self.ph("UPDATE drift_counts SET hits = ?, total = ?, updated_ms = ? WHERE class = ?"))
                    .bind(h).bind(t).bind(now_ms).bind(class).execute(&self.pool).await.map_err(|e| e.to_string())?;
            }
            None => {
                // First report sets the baseline rate for this class.
                let baseline = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
                sqlx::query(&self.ph("INSERT INTO drift_counts(class,hits,total,baseline,updated_ms) VALUES(?,?,?,?,?)"))
                    .bind(class).bind(hits).bind(total).bind(baseline).bind(now_ms).execute(&self.pool).await.map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
    pub async fn list_drift(&self) -> Result<Vec<(String, i64, i64, f64)>, String> {
        let rows = sqlx::query("SELECT class, hits, total, baseline FROM drift_counts ORDER BY class")
            .fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| (r.get::<String,_>("class"), r.get::<i64,_>("hits"), r.get::<i64,_>("total"), r.get::<f64,_>("baseline"))).collect())
    }
    pub async fn report_lineage(&self, data_class: &str, tool: &str, count: i64, now_ms: i64) -> Result<(), String> {
        let id = format!("{data_class}:{tool}");
        let row = sqlx::query(&self.ph("SELECT count FROM lineage_edges WHERE id = ?")).bind(&id)
            .fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        match row {
            Some(r) => {
                let c = r.get::<i64,_>("count") + count;
                sqlx::query(&self.ph("UPDATE lineage_edges SET count = ?, updated_ms = ? WHERE id = ?"))
                    .bind(c).bind(now_ms).bind(&id).execute(&self.pool).await.map_err(|e| e.to_string())?;
            }
            None => {
                sqlx::query(&self.ph("INSERT INTO lineage_edges(id,data_class,tool,count,updated_ms) VALUES(?,?,?,?,?)"))
                    .bind(&id).bind(data_class).bind(tool).bind(count).bind(now_ms).execute(&self.pool).await.map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
    // T6: framework-report snapshots (history).
    pub async fn add_snapshot(&self, id: &str, framework: &str, tenant: &str, body_json: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO report_snapshots (id, framework, tenant_id, body_json, created_ms) VALUES (?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(framework).bind(tenant).bind(body_json).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn list_snapshots(&self, framework: &str, tenant: &str) -> Result<Vec<(String, i64, String)>, String> {
        let rows = sqlx::query(&self.ph("SELECT id, created_ms, body_json FROM report_snapshots WHERE framework = ? AND tenant_id = ? ORDER BY created_ms DESC"))
            .bind(framework).bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| (r.get::<String,_>("id"), r.get::<i64,_>("created_ms"), r.get::<String,_>("body_json"))).collect())
    }

    pub async fn list_lineage(&self) -> Result<Vec<(String, String, i64)>, String> {
        let rows = sqlx::query("SELECT data_class, tool, count FROM lineage_edges ORDER BY data_class, tool")
            .fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| (r.get::<String,_>("data_class"), r.get::<String,_>("tool"), r.get::<i64,_>("count"))).collect())
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
        let sql = self.ph("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage, tenant_id FROM grc_records WHERE id = ?");
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| GrcRecord {
            id: r.get("id"), kind: r.get("kind"), subject: r.get("subject"), title: r.get("title"),
            status: r.get("status"), body: r.get("body"), operator: r.get("operator"),
            created_ms: r.get("created_ms"), pubkey_hex: r.get("pubkey_hex"), sig_hex: r.get("sig_hex"),
            linked_refs: r.get("linked_refs"),
            answers_json: r.get("answers_json"), assignee: r.get("assignee"), due_ms: r.get("due_ms"), stage: r.get("stage"),
            tenant: r.get("tenant_id"),
        }))
    }

    /// Update a record's status AND its signature together, so the stored signature always matches
    /// the current document (gap A4: a status change must re-sign, or the record reads as tampered).
    pub async fn update_grc_signed(&self, id: &str, status: &str, body: &str, stage: &str, pubkey_hex: &str, sig_hex: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET status = ?, body = ?, stage = ?, pubkey_hex = ?, sig_hex = ? WHERE id = ?");
        sqlx::query(&sql).bind(status).bind(body).bind(stage).bind(pubkey_hex).bind(sig_hex).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// G1/A2: replace a GRC record's advisory linked_refs (unsigned; not part of the signed doc).
    pub async fn set_grc_linked_refs(&self, id: &str, linked_refs: &str) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET linked_refs = ? WHERE id = ?");
        sqlx::query(&sql).bind(linked_refs).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    // T5: comment threads on GRC records.
    pub async fn add_comment(&self, id: &str, grc_id: &str, author: &str, body: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO grc_comments (id, grc_id, author, body, created_ms) VALUES (?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(grc_id).bind(author).bind(body).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn list_comments(&self, grc_id: &str) -> Result<Vec<(String, String, String, i64)>, String> {
        let rows = sqlx::query(&self.ph("SELECT id, author, body, created_ms FROM grc_comments WHERE grc_id = ? ORDER BY created_ms"))
            .bind(grc_id).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| (r.get::<String,_>("id"), r.get::<String,_>("author"), r.get::<String,_>("body"), r.get::<i64,_>("created_ms"))).collect())
    }

    /// A1: set the assignee and due date on a GRC record. Workflow metadata, not part of the signed
    /// document, so it does not require a re-sign.
    pub async fn set_grc_assignment(&self, id: &str, assignee: &str, due_ms: i64) -> Result<(), String> {
        let sql = self.ph("UPDATE grc_records SET assignee = ?, due_ms = ? WHERE id = ?");
        sqlx::query(&sql).bind(assignee).bind(due_ms).bind(id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_grc(&self, tenant: &str, kind: Option<&str>) -> Result<Vec<GrcRecord>, String> {
        let rows = match kind {
            Some(k) => sqlx::query(&self.ph("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage, tenant_id FROM grc_records WHERE tenant_id = ? AND kind = ? ORDER BY created_ms"))
                .bind(tenant).bind(k).fetch_all(&self.pool).await,
            None => sqlx::query(&self.ph("SELECT id, kind, subject, title, status, body, operator, created_ms, pubkey_hex, sig_hex, linked_refs, answers_json, assignee, due_ms, stage, tenant_id FROM grc_records WHERE tenant_id = ? ORDER BY created_ms"))
                .bind(tenant).fetch_all(&self.pool).await,
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
                tenant: r.get("tenant_id"),
            })
            .collect())
    }

    // ---- Governance spine (audit P0: ai_system + roles + Statement of Applicability) ----

    #[allow(clippy::too_many_arguments)]
    pub async fn add_system(&self, id: &str, name: &str, purpose: &str, owner: &str, lifecycle: &str, risk_tier: &str, sector: &str, asset_type: &str, jurisdictions_json: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO ai_systems (id, name, purpose, owner, lifecycle_state, risk_tier, sector, asset_type, jurisdictions, tenant_id, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(name).bind(purpose).bind(owner).bind(lifecycle).bind(risk_tier).bind(sector).bind(asset_type).bind(jurisdictions_json).bind(tenant).bind(now_ms).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    fn map_system(r: &sqlx::any::AnyRow) -> AiSystem {
        AiSystem {
            id: r.get("id"), name: r.get("name"), purpose: r.get("purpose"), owner: r.get("owner"),
            lifecycle_state: r.get("lifecycle_state"), risk_tier: r.get("risk_tier"), sector: r.get("sector"),
            asset_type: r.get("asset_type"), jurisdictions: r.get("jurisdictions"), tenant: r.get("tenant_id"),
            created_ms: r.get("created_ms"), updated_ms: r.get("updated_ms"),
        }
    }

    pub async fn list_systems(&self, tenant: &str) -> Result<Vec<AiSystem>, String> {
        let rows = sqlx::query(&self.ph("SELECT * FROM ai_systems WHERE tenant_id = ? ORDER BY created_ms"))
            .bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(Self::map_system).collect())
    }

    pub async fn get_system(&self, id: &str, tenant: &str) -> Result<Option<AiSystem>, String> {
        let rows = sqlx::query(&self.ph("SELECT * FROM ai_systems WHERE id = ? AND tenant_id = ?"))
            .bind(id).bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.first().map(Self::map_system))
    }

    pub async fn add_role(&self, id: &str, system_id: &str, role: &str, jurisdiction: &str, market_date: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO system_roles (id, system_id, role, jurisdiction, market_date, tenant_id, created_ms) VALUES (?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(system_id).bind(role).bind(jurisdiction).bind(market_date).bind(tenant).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_roles(&self, system_id: &str, tenant: &str) -> Result<Vec<SystemRole>, String> {
        let rows = sqlx::query(&self.ph("SELECT * FROM system_roles WHERE system_id = ? AND tenant_id = ? ORDER BY created_ms"))
            .bind(system_id).bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| SystemRole {
            id: r.get("id"), system_id: r.get("system_id"), role: r.get("role"),
            jurisdiction: r.get("jurisdiction"), market_date: r.get("market_date"), created_ms: r.get("created_ms"),
        }).collect())
    }

    /// Upsert one SoA entry, keyed deterministically by (system, framework, control). Delete-then-insert
    /// so it works the same on SQLite and Postgres.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_soa(&self, system_id: &str, framework: &str, control_id: &str, applicable: bool, justification: &str, status: &str, evidence_refs_json: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let id = format!("soa:{system_id}:{framework}:{control_id}");
        let del = self.ph("DELETE FROM soa_entries WHERE id = ?");
        sqlx::query(&del).bind(&id).execute(&self.pool).await.map_err(|e| e.to_string())?;
        let ins = self.ph("INSERT INTO soa_entries (id, system_id, framework, control_id, applicable, justification, status, evidence_refs, tenant_id, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&ins).bind(&id).bind(system_id).bind(framework).bind(control_id).bind(if applicable {1} else {0}).bind(justification).bind(status).bind(evidence_refs_json).bind(tenant).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// All SoA entries for a system across every framework (for crosswalk propagation).
    pub async fn list_all_soa(&self, system_id: &str, tenant: &str) -> Result<Vec<SoaEntry>, String> {
        let rows = sqlx::query(&self.ph("SELECT * FROM soa_entries WHERE system_id = ? AND tenant_id = ?"))
            .bind(system_id).bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| SoaEntry {
            id: r.get("id"), system_id: r.get("system_id"), framework: r.get("framework"), control_id: r.get("control_id"),
            applicable: { let v: i64 = r.get("applicable"); v != 0 }, justification: r.get("justification"),
            status: r.get("status"), evidence_refs: r.get("evidence_refs"), updated_ms: r.get("updated_ms"),
        }).collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_evidence(&self, id: &str, system_id: &str, framework: &str, control_id: &str, title: &str, source: &str, owner: &str, produced_ms: i64, valid_until_ms: i64, artefact_ref: &str, note: &str, tenant: &str, now_ms: i64) -> Result<(), String> {
        let sql = self.ph("INSERT INTO evidence (id, system_id, framework, control_id, title, source, owner, produced_ms, valid_until_ms, artefact_ref, note, tenant_id, created_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        sqlx::query(&sql).bind(id).bind(system_id).bind(framework).bind(control_id).bind(title).bind(source).bind(owner).bind(produced_ms).bind(valid_until_ms).bind(artefact_ref).bind(note).bind(tenant).bind(now_ms)
            .execute(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn list_evidence(&self, system_id: &str, tenant: &str) -> Result<Vec<Evidence>, String> {
        let rows = sqlx::query(&self.ph("SELECT * FROM evidence WHERE system_id = ? AND tenant_id = ? ORDER BY created_ms DESC"))
            .bind(system_id).bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| Evidence {
            id: r.get("id"), system_id: r.get("system_id"), framework: r.get("framework"), control_id: r.get("control_id"),
            title: r.get("title"), source: r.get("source"), owner: r.get("owner"), produced_ms: r.get("produced_ms"),
            valid_until_ms: r.get("valid_until_ms"), artefact_ref: r.get("artefact_ref"), note: r.get("note"), created_ms: r.get("created_ms"),
        }).collect())
    }

    pub async fn list_soa(&self, system_id: &str, framework: &str, tenant: &str) -> Result<Vec<SoaEntry>, String> {
        let rows = sqlx::query(&self.ph("SELECT * FROM soa_entries WHERE system_id = ? AND framework = ? AND tenant_id = ?"))
            .bind(system_id).bind(framework).bind(tenant).fetch_all(&self.pool).await.map_err(|e| e.to_string())?;
        Ok(rows.iter().map(|r| SoaEntry {
            id: r.get("id"), system_id: r.get("system_id"), framework: r.get("framework"), control_id: r.get("control_id"),
            applicable: { let v: i64 = r.get("applicable"); v != 0 }, justification: r.get("justification"),
            status: r.get("status"), evidence_refs: r.get("evidence_refs"), updated_ms: r.get("updated_ms"),
        }).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn check(url: &str) {
        let s = ControlStore::connect(url).await.expect("connect");
        s.add_app("app-1", "acme", "you", "{}", "default", 1000).await.unwrap();
        assert_eq!(s.list_apps("default").await.unwrap().len(), 1);
        // Virtual-key resolution (audit P0 F1): an agent's token alone resolves its authenticated identity.
        s.add_agent("agt-vk", "app-1", "triage", "sha-of-key", "you", "{}", "default", 1000).await.unwrap();
        let vk = s.resolve_agent_by_token_sha("sha-of-key").await.unwrap();
        assert_eq!(vk.as_ref().map(|(id, _, app, _)| (id.clone(), app.clone())), Some(("agt-vk".to_string(), "app-1".to_string())));
        assert!(s.resolve_agent_by_token_sha("nope").await.unwrap().is_none());
        // Governance spine (audit P0): ai_system + roles + Statement of Applicability round-trip.
        s.add_system("sys-1", "resume-screener", "screen resumes", "hr", "development", "high", "hr", "", "[\"UK\"]", "default", 1000).await.unwrap();
        assert_eq!(s.list_systems("default").await.unwrap().len(), 1);
        assert_eq!(s.get_system("sys-1", "default").await.unwrap().unwrap().name, "resume-screener");
        s.add_role("role-1", "sys-1", "deployer", "UK", "", "default", 1000).await.unwrap();
        assert_eq!(s.list_roles("sys-1", "default").await.unwrap()[0].role, "deployer");
        s.set_soa("sys-1", "eu-ai-act", "art-14", true, "", "implemented", "[]", "default", 1000).await.unwrap();
        s.set_soa("sys-1", "eu-ai-act", "art-14", true, "", "partial", "[]", "default", 2000).await.unwrap(); // upsert
        let soa = s.list_soa("sys-1", "eu-ai-act", "default").await.unwrap();
        assert_eq!(soa.len(), 1, "SoA upsert keeps one row per (system,framework,control)");
        assert_eq!(soa[0].status, "partial");
        assert!(soa[0].applicable);
        // Evidence entity (audit P1) + all-SoA round-trip.
        s.add_evidence("ev-1", "sys-1", "eu-ai-act", "art-12", "signed ledger", "acp", "you", 1000, 0, "", "", "default", 1000).await.unwrap();
        let ev = s.list_evidence("sys-1", "default").await.unwrap();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].control_id, "art-12");
        assert!(!s.list_all_soa("sys-1", "default").await.unwrap().is_empty());
        s.add_agent("agt-1", "app-1", "asst", "deadbeef", "you", "{\"deps\":[]}", "default", 1001).await.unwrap();
        assert!(s.verify_agent("agt-1", "deadbeef").await.unwrap());
        assert!(!s.verify_agent("agt-1", "wrong").await.unwrap());
        s.deactivate_agent("agt-1").await.unwrap();
        assert!(!s.verify_agent("agt-1", "deadbeef").await.unwrap(), "deactivated agent must not verify");
        s.upsert_endpoint("claude.ai", "model-api", "Anthropic", "govern", "console", "ok", 2000, 0, "aa", "bb").await.unwrap();
        s.upsert_endpoint("claude.ai", "model-api", "Anthropic", "block", "console", "revoked", 3000, 0, "aa", "cc").await.unwrap();
        let eps = s.list_endpoints().await.unwrap();
        assert_eq!(eps.len(), 1, "upsert keeps one row per endpoint");
        assert_eq!(eps[0].disposition, "block", "latest disposition wins");
        s.add_grc("grc-1", "risk", "checkout-agent", "PII exfiltration", "open", "{\"likelihood\":3,\"impact\":3}", "console", 4000, "aa", "bb", "[]", "{}", "", 0, "", "default").await.unwrap();
        s.add_grc("grc-2", "assessment", "checkout-agent", "EU AI Act tiering", "high", "{}", "console", 4001, "aa", "cc", "[]", "{}", "", 0, "", "default").await.unwrap();
        assert_eq!(s.list_grc("default", None).await.unwrap().len(), 2);
        assert_eq!(s.list_grc("default", Some("risk")).await.unwrap().len(), 1);
        // A4: get_grc + update_grc_signed round-trip (status + signature updated together).
        let g = s.get_grc("grc-1").await.unwrap().expect("record present");
        assert_eq!(g.status, "open");
        s.update_grc_signed("grc-1", "mitigated", "{\"body\":1}", "treatment", "dd", "ee").await.unwrap();
        let g2 = s.get_grc("grc-1").await.unwrap().unwrap();
        assert_eq!(g2.status, "mitigated");
        assert_eq!(g2.sig_hex, "ee", "signature updated with the status");
        s.update_grc_status("grc-1", "mitigated").await.unwrap();
        assert_eq!(s.list_grc("default", Some("risk")).await.unwrap()[0].status, "mitigated");
    }

    #[tokio::test]
    async fn sqlite_backend() {
        let f = std::env::temp_dir().join(format!("acp-cp-{}-s.db", std::process::id()));
        let _ = std::fs::remove_file(&f);
        check(&format!("sqlite://{}?mode=rwc", f.display())).await;
        let _ = std::fs::remove_file(&f);
    }

    #[tokio::test]
    async fn leader_lease_prevents_split_brain_and_fences() {
        let f = std::env::temp_dir().join(format!("acp-cp-{}-lease.db", std::process::id()));
        let _ = std::fs::remove_file(&f);
        let s = ControlStore::connect(&format!("sqlite://{}?mode=rwc", f.display())).await.unwrap();
        let now = 1_000_000i64;
        let ttl = 10_000i64;
        // nodeA acquires; nodeB cannot while the lease is valid.
        let (a_leader, _, a_tok) = s.try_acquire_leader("nodeA", now, ttl).await.unwrap();
        assert!(a_leader, "first acquirer leads");
        let (b_leader, holder, _) = s.try_acquire_leader("nodeB", now + 1, ttl).await.unwrap();
        assert!(!b_leader && holder == "nodeA", "no split-brain: B cannot take a valid lease");
        // nodeA renews; the fencing token strictly increases.
        let (_, _, a_tok2) = s.try_acquire_leader("nodeA", now + 2, ttl).await.unwrap();
        assert!(a_tok2 > a_tok, "fencing token increases on renew");
        // After expiry nodeB takes over with a larger token; the paused nodeA is fenced out.
        // The last renew was at now+2 with expiry (now+2)+ttl, so wait past that.
        let later = now + 2 + ttl + 1;
        let (b_leader2, holder2, b_tok) = s.try_acquire_leader("nodeB", later, ttl).await.unwrap();
        assert!(b_leader2 && holder2 == "nodeB", "B takes over an expired lease");
        assert!(b_tok > a_tok2, "takeover token strictly larger (fences the old leader)");
        // control-state per-entity round-trip (liveness/spike survive restart).
        s.put_state("liveness:proxy-1", "42", later).await.unwrap();
        s.put_state("spike:deny:100", "1", later).await.unwrap();
        let rows = s.list_state_prefix("liveness:").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0], ("liveness:proxy-1".to_string(), "42".to_string()));
        s.delete_state("spike:deny:100").await.unwrap();
        assert!(s.list_state_prefix("spike:").await.unwrap().is_empty());
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
