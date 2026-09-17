//! The step-up approval store (decision D8).
//!
//! An approval authorises exactly one action. The integrity properties, all enforced here:
//!   - single-use: `consume` atomically transitions approved -> consumed; a second consume fails,
//!     and two concurrent consumes cannot both succeed (one SQL UPDATE wins);
//!   - caller-bound: consume must match the `session` + `principal` that the approval was for;
//!   - canonical-bound: consume must match the `arg_hash` of the approved request, so a re-issue
//!     whose arguments differ cannot ride an approval granted for other arguments;
//!   - TTL: an absolute expiry evaluated against a single authority (this store), so clock skew
//!     between proxy and store cannot honour a stale approval;
//!   - presented-context + acknowledgement: the snapshot the approver saw and their identity are
//!     recorded, so "I approved without seeing X" cannot stand.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS approvals (
  id            TEXT PRIMARY KEY,
  session       TEXT NOT NULL,
  principal     TEXT NOT NULL,
  tool          TEXT NOT NULL,
  arg_hash      TEXT NOT NULL,
  presented     TEXT NOT NULL,
  state         TEXT NOT NULL,        -- pending | approved | denied | expired | consumed
  approver      TEXT,
  channel       TEXT,
  resolved_ms   INTEGER,
  consumed_ms   INTEGER,
  created_ms    INTEGER NOT NULL,
  expires_ms    INTEGER NOT NULL
);
"#;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalView {
    pub id: String,
    pub state: String,
    pub tool: String,
    pub approver: Option<String>,
    pub channel: Option<String>,
    pub resolved_ms: Option<u64>,
    pub presented: Value,
    pub expires_ms: u64,
}

pub struct ApprovalStore {
    conn: Connection,
}

impl ApprovalStore {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "busy_timeout", 3000).ok();
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        Ok(ApprovalStore { conn })
    }

    /// Open a pending approval if one does not already exist for this id. Returns true if it was
    /// newly created (first issue) vs already existed (a re-issue while still pending).
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        id: &str,
        session: &str,
        principal: &str,
        tool: &str,
        arg_hash: &str,
        presented: &Value,
        ttl_ms: u64,
    ) -> Result<bool, String> {
        let now = now_ms();
        let n = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO approvals(id,session,principal,tool,arg_hash,presented,state,created_ms,expires_ms) \
                 VALUES(?,?,?,?,?,?,'pending',?,?)",
                params![id, session, principal, tool, arg_hash, presented.to_string(), now as i64, (now + ttl_ms) as i64],
            )
            .map_err(|e| e.to_string())?;
        Ok(n == 1)
    }

    pub fn get(&self, id: &str) -> Result<Option<ApprovalView>, String> {
        self.conn
            .query_row(
                "SELECT id,state,tool,approver,channel,resolved_ms,presented,expires_ms FROM approvals WHERE id=?",
                params![id],
                |r| {
                    Ok(ApprovalView {
                        id: r.get(0)?,
                        state: r.get(1)?,
                        tool: r.get(2)?,
                        approver: r.get(3)?,
                        channel: r.get(4)?,
                        resolved_ms: r.get::<_, Option<i64>>(5)?.map(|v| v as u64),
                        presented: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or(Value::Null),
                        expires_ms: r.get::<_, i64>(7)? as u64,
                    })
                },
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Resolve a pending approval (the human decision). Records approver identity + channel +
    /// timestamp, which together are the explicit acknowledgement (D8/M4.4). One terminal
    /// transition: only a pending approval can be resolved.
    pub fn resolve(
        &self,
        id: &str,
        approve: bool,
        approver: &str,
        channel: &str,
    ) -> Result<(), String> {
        let now = now_ms();
        // expire first if stale
        self.conn
            .execute("UPDATE approvals SET state='expired' WHERE id=? AND state='pending' AND expires_ms<=?", params![id, now as i64])
            .map_err(|e| e.to_string())?;
        let new_state = if approve { "approved" } else { "denied" };
        let n = self
            .conn
            .execute(
                "UPDATE approvals SET state=?, approver=?, channel=?, resolved_ms=? WHERE id=? AND state='pending'",
                params![new_state, approver, channel, now as i64, id],
            )
            .map_err(|e| e.to_string())?;
        if n == 1 {
            Ok(())
        } else {
            match self.get(id)? {
                Some(v) => Err(format!("cannot resolve approval in state '{}'", v.state)),
                None => Err("no such approval".into()),
            }
        }
    }

    /// Atomically consume an approved approval for exactly one action. Enforces single-use,
    /// caller-binding, canonical-binding, and TTL in one UPDATE.
    pub fn consume(
        &self,
        id: &str,
        session: &str,
        principal: &str,
        arg_hash: &str,
    ) -> Result<ApprovalView, String> {
        let now = now_ms();
        // lazily expire
        self.conn
            .execute("UPDATE approvals SET state='expired' WHERE id=? AND state IN ('pending','approved') AND expires_ms<=?", params![id, now as i64])
            .map_err(|e| e.to_string())?;
        let n = self
            .conn
            .execute(
                "UPDATE approvals SET state='consumed', consumed_ms=? \
                 WHERE id=? AND state='approved' AND session=? AND principal=? AND arg_hash=? AND expires_ms>?",
                params![now as i64, id, session, principal, arg_hash, now as i64],
            )
            .map_err(|e| e.to_string())?;
        if n == 1 {
            return self
                .get(id)?
                .ok_or_else(|| "vanished after consume".to_string());
        }
        // Explain why not consumed.
        match self.get(id)? {
            None => Err("no such approval".into()),
            Some(v) => match v.state.as_str() {
                "pending" => Err("approval pending".into()),
                "denied" => Err("approval denied".into()),
                "expired" => Err("approval expired".into()),
                "consumed" => Err("approval already used".into()),
                "approved" => Err("caller or arguments do not match the approved request".into()),
                other => Err(format!("unexpected state '{other}'")),
            },
        }
    }

    pub fn list_pending(&self) -> Result<Vec<ApprovalView>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM approvals WHERE state='pending' ORDER BY created_ms")
            .map_err(|e| e.to_string())?;
        let ids: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        ids.iter()
            .filter_map(|id| self.get(id).transpose())
            .collect()
    }
}
