//! Evidence writing (decisions D5/D7/D11): durable spool then ledger.
//!
//! Every decision is written to the disk-backed spool (fsync) before/at forwarding, then appended
//! to the verifiable ledger. On startup any un-drained spool is replayed idempotently, so a crash
//! between forwarding and the ledger write loses nothing. Each decision gets a linked outcome
//! record so the ledger never implies an action happened.

use acp_core::canonical::sha256_hex;
use acp_core::hlc::Hlc;
use acp_core::sign::{Ed25519Signer, Signer};
use acp_core::types::Verdict;
use acp_jsonrpc::ToolCall;
use acp_ledger::{spool::Spool, Ledger};
use acp_policy::PolicyOutcome;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Evidence {
    ledger: Ledger,
    spool: Spool,
    run: String,
    counter: u64,
    hlc: Hlc,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        Verdict::StepUp => "step_up",
        Verdict::Shadow => "shadow",
    }
}

fn load_or_create_key(path: &str) -> Result<Box<dyn Signer + Send>, String> {
    // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE); else the file key below.
    if let Some(res) = acp_hsm::signer_from_env() {
        if res.is_ok() {
            tracing::info!("signing evidence with a PKCS#11 HSM");
        }
        return res;
    }
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Ok(Box::new(Ed25519Signer::from_seed(&seed)))
        }
        Ok(_) => Err(format!("key file {path} is not 32 bytes")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let signer = Ed25519Signer::generate();
            acp_core::secret::write_key_secure(path, &signer.seed()).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::info!("generated signing key {path}");
            Ok(Box::new(signer))
        }
        Err(e) => Err(e.to_string()),
    }
}

impl Evidence {
    pub fn open(ledger_path: &str, key_path: &str) -> Result<Evidence, String> {
        let signer = load_or_create_key(key_path)?;
        let mut ledger = Ledger::open(ledger_path, signer)?;
        let spool = Spool::open(&format!("{ledger_path}.spool"));
        let report = spool.drain_into(&mut ledger).map_err(|e| e.to_string())?;
        if report.ingested > 0 {
            tracing::info!("replayed {} spooled records", report.ingested);
        }
        if !report.dead_letters.is_empty() {
            tracing::info!(
                "{} dead-lettered spool entries",
                report.dead_letters.len()
            );
        }
        spool.clear().ok();
        let run = format!("{}-{}", std::process::id(), now_ms());
        Ok(Evidence {
            ledger,
            spool,
            run: run.clone(),
            counter: 0,
            hlc: Hlc::new(run),
        })
    }

    fn next_id(&mut self) -> String {
        self.counter += 1;
        format!("{}-{}", self.run, self.counter)
    }

    /// Write a decision record, durably (spool fsync) then to the ledger. Returns the decision id.
    #[allow(clippy::too_many_arguments)]
    pub fn record_decision(
        &mut self,
        agent: &str,
        session: &str,
        tc: &ToolCall,
        outcome: &PolicyOutcome,
        impact: &str,
        env: &str,
        policy_hash: &str,
        impact_taxonomy: &str,
        principal: &str,
        resource: &str,
        operation: &str,
    ) -> (String, bool) {
        let did = self.next_id();
        let ts = now_ms();
        let hlc = self.hlc.tick(ts).encode();
        let record = json!({
            "schema": 1, "type": "decision", "ts_ms": ts, "hlc": hlc,
            "agent_id": agent,
            "principal": {"id": principal, "verified": !principal.is_empty() && principal != "unattributed"},
            "session_id": session,
            "action": {"tool": tc.name, "args_hash": sha256_hex(&tc.arguments), "impact": impact, "env": env,
                       "resource": resource, "operation": operation},
            "decision": {"verdict": verdict_str(outcome.verdict), "rule_id": outcome.rule_id,
                         "matched": outcome.reason, "policy_hash": policy_hash, "reason": outcome.reason},
            "provenance": {"algo": {"hash": "sha256", "sig": "ed25519"},
                           "evaluator": "cedar-policy", "compiler": "acp-policy",
                           "impact_taxonomy": impact_taxonomy}
        });
        // Record-before-forward: the durable spool write (fsync) happens before the caller forwards.
        // `durable` is whether that write succeeded; the caller fails closed if not (D5).
        let durable = self
            .spool
            .append(&json!({"decision_id": did, "kind": "decision", "record": record, "args": tc.arguments}))
            .is_ok();
        let _ = self
            .ledger
            .append(&did, "decision", &record, Some(&tc.arguments));
        (did, durable)
    }

    /// Write the linked outcome record for a decision (D11): forwarded / not_executed.
    pub fn record_outcome(&mut self, decision_id: &str, kind: &str) {
        let oid = format!("{decision_id}:out");
        let record = json!({"schema": 1, "type": "outcome", "ref": decision_id, "kind": kind, "ts_ms": now_ms()});
        let _ = self
            .spool
            .append(&json!({"decision_id": oid, "kind": "outcome", "record": record}));
        let _ = self.ledger.append(&oid, "outcome", &record, None);
    }

    pub fn size(&self) -> usize {
        self.ledger.size()
    }
}
