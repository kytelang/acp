//! Shared per-frame decision logic (used by every transport).
//!
//! A `Controller` holds the policy engine, evidence ledger, and approval store, and turns one
//! client-to-server JSON-RPC frame into a `FrameAction` (forward it, or reply to the client). Both
//! the stdio and HTTP transports call `decide_frame`, so policy enforcement (M2/D9), the step-up
//! approval flow (M4/D8), evidence (M3/D11), shadow mode (M5.3), and the resource limit (M1.5)
//! are identical across transports.

use crate::approvals::Step;
use crate::events::{Event, Sink};
use crate::evidence::Evidence;
use crate::intercept::{decide, Action, CODE_BLOCKED};
use crate::limits;
use crate::policy::{self, Enforce};
use acp_approvals::ApprovalStore;
use acp_core::impact::ImpactTaxonomy;
use acp_core::types::Verdict;
use acp_jsonrpc::{classify, error_response, inspect, ParsedFrame};
use acp_policy::PolicyEngine;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// What a transport should do with one client-to-server frame.
pub enum FrameAction {
    /// Forward the frame to the tool server unchanged.
    Forward,
    /// Do not forward; send this JSON line back to the client.
    Reply(String),
}

struct State {
    evidence: Option<Evidence>,
    approvals: Option<ApprovalStore>,
}

pub struct Controller {
    engine: Option<Arc<PolicyEngine>>,
    env: String,
    shadow: bool,
    state: Mutex<State>,
    agent: String,
    session: String,
    principal: String,
    sinks: Vec<Box<dyn Sink>>,
    fail_open: bool,
    impact_tax: ImpactTaxonomy,
    // F2: break-glass grants, applied to the verdict before enforcement. Empty = no-op.
    breakglass: Mutex<acp_core::breakglass::BreakGlassRegistry>,
}

impl Controller {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine: Option<Arc<PolicyEngine>>,
        env: String,
        shadow: bool,
        evidence: Option<Evidence>,
        approvals: Option<ApprovalStore>,
        sinks: Vec<Box<dyn Sink>>,
        fail_open: bool,
        impact_tax: ImpactTaxonomy,
    ) -> Controller {
        Controller {
            engine,
            env,
            shadow,
            state: Mutex::new(State {
                evidence,
                approvals,
            }),
            agent: "acp-client".to_string(),
            session: "acp-session".to_string(),
            principal: "unknown".to_string(),
            sinks,
            fail_open,
            impact_tax,
            breakglass: Mutex::new(acp_core::breakglass::BreakGlassRegistry::new()),
        }
    }

    /// F2: engage a break-glass mode at runtime. Returns the meta-audit event to record. With no
    /// active grant, decisions are entirely unaffected. Called by the admin control channel (the
    /// server->proxy wiring is the remaining deploy step), and exercised by the bg_tests.
    #[allow(dead_code)]
    pub fn engage_break_glass(
        &self,
        mode: acp_core::breakglass::Mode,
        reason: &str,
        actor: &str,
        ttl_ms: u64,
    ) -> Result<acp_core::metaaudit::MetaEvent, String> {
        self.breakglass
            .lock()
            .unwrap()
            .engage(mode, reason, actor, dispatch_now_ms(), ttl_ms)
    }

    fn emit_event(
        &self,
        tool: &str,
        verdict: &str,
        rule_id: Option<&str>,
        impact: &str,
        outcome: &str,
    ) {
        if self.sinks.is_empty() {
            return;
        }
        let ev = Event {
            agent: &self.agent,
            session: &self.session,
            tool,
            verdict,
            rule_id,
            impact,
            outcome,
        };
        for sink in &self.sinks {
            sink.emit(&ev);
        }
    }

    pub fn decide_frame(&self, raw: &[u8]) -> FrameAction {
        let insp = inspect(raw);

        // Resource limit (M1.5): fail-closed on oversize.
        if !limits::within_size(raw) {
            if let Some(id) = &insp.id {
                return FrameAction::Reply(error_response(
                    id,
                    CODE_BLOCKED,
                    "message exceeds maximum permitted size",
                ));
            }
            return FrameAction::Forward; // no id to reply to; drop by not forwarding is unsafe, so forward
        }

        if insp.method.as_deref() == Some("initialize") {
            if let Some(pv) = serde_json::from_slice::<Value>(raw).ok().and_then(|v| {
                v.get("params")
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(|s| s.as_str().map(str::to_string))
            }) {
                eprintln!("acp-proxy: MCP protocolVersion {pv}");
            }
        }

        if insp.is_tool_call {
            let eng = match &self.engine {
                Some(e) => e.clone(),
                None => return FrameAction::Forward, // no policy: pass through
            };
            let tc = match classify(raw) {
                ParsedFrame::ToolCall(tc) => tc,
                _ => return FrameAction::Forward,
            };
            let mut a = policy::assess(&eng, &self.env, &tc, &self.impact_tax);
            // F2: apply any active break-glass grant to the verdict, then re-derive enforcement.
            // With no grant this is the identity, so the normal path is untouched.
            {
                let eff = self
                    .breakglass
                    .lock()
                    .unwrap()
                    .effective(a.outcome.verdict, dispatch_now_ms());
                if eff != a.outcome.verdict {
                    a.outcome.verdict = eff;
                    a.enforce = policy::enforce_for(eff, &tc, &a.outcome, a.impact);
                }
            }
            let verdict_s = match a.outcome.verdict {
                Verdict::Allow => "allow",
                Verdict::Deny => "deny",
                Verdict::StepUp => "step_up",
                Verdict::Shadow => "shadow",
            };
            let mut st = self.state.lock().unwrap();

            // Shadow mode (M5.3): record what WOULD happen, but forward everything.
            if self.shadow && a.outcome.verdict != Verdict::Allow {
                if let Some(ev) = st.evidence.as_mut() {
                    let (did, _) = ev.record_decision(
                        &self.agent,
                        &self.session,
                        &tc,
                        &a.outcome,
                        a.impact,
                        &self.env,
                        eng.hash(),
                        &a.impact_taxonomy,
                    );
                    ev.record_outcome(&did, "would_block");
                }
                return FrameAction::Forward;
            }

            // Step-up: run the D8 approval flow when a store is present.
            if a.outcome.verdict == Verdict::StepUp && st.approvals.is_some() {
                let step = {
                    let store = st.approvals.as_ref().unwrap();
                    crate::approvals::handle(store, &self.session, &self.principal, &tc, a.impact)
                };
                match step {
                    Step::Forward(_view) => {
                        if let Some(ev) = st.evidence.as_mut() {
                            let (did, _) = ev.record_decision(
                                &self.agent,
                                &self.session,
                                &tc,
                                &a.outcome,
                                a.impact,
                                &self.env,
                                eng.hash(),
                                &a.impact_taxonomy,
                            );
                            ev.record_outcome(&did, "forwarded");
                        }
                        drop(st);
                        self.emit_event(
                            &tc.name,
                            verdict_s,
                            a.outcome.rule_id.as_deref(),
                            a.impact,
                            "approved",
                        );
                        return FrameAction::Forward;
                    }
                    Step::Held(json) => {
                        drop(st);
                        self.emit_event(
                            &tc.name,
                            verdict_s,
                            a.outcome.rule_id.as_deref(),
                            a.impact,
                            "held",
                        );
                        return FrameAction::Reply(json);
                    }
                    Step::Denied(json) => {
                        if let Some(ev) = st.evidence.as_mut() {
                            let (did, _) = ev.record_decision(
                                &self.agent,
                                &self.session,
                                &tc,
                                &a.outcome,
                                a.impact,
                                &self.env,
                                eng.hash(),
                                &a.impact_taxonomy,
                            );
                            ev.record_outcome(&did, "not_executed");
                        }
                        drop(st);
                        self.emit_event(
                            &tc.name,
                            verdict_s,
                            a.outcome.rule_id.as_deref(),
                            a.impact,
                            "denied",
                        );
                        return FrameAction::Reply(json);
                    }
                }
            }

            // Allow / deny / (step_up without a store): enforce and record.
            let rec = st.evidence.as_mut().map(|ev| {
                ev.record_decision(
                    &self.agent,
                    &self.session,
                    &tc,
                    &a.outcome,
                    a.impact,
                    &self.env,
                    eng.hash(),
                    &a.impact_taxonomy,
                )
            });
            let did = rec.as_ref().map(|(d, _)| d.clone());
            let durable = rec.as_ref().map(|(_, dur)| *dur).unwrap_or(true);
            match a.enforce {
                Enforce::Forward => {
                    if !durable && !self.fail_open {
                        if let (Some(ev), Some(did)) = (st.evidence.as_mut(), did.as_ref()) {
                            ev.record_outcome(did, "not_executed");
                        }
                        drop(st);
                        self.emit_event(
                            &tc.name,
                            verdict_s,
                            a.outcome.rule_id.as_deref(),
                            a.impact,
                            "fail_closed",
                        );
                        return FrameAction::Reply(fail_closed_reply(&tc.id));
                    }
                    if let (Some(ev), Some(did)) = (st.evidence.as_mut(), did.as_ref()) {
                        ev.record_outcome(did, "forwarded");
                    }
                    drop(st);
                    self.emit_event(
                        &tc.name,
                        verdict_s,
                        a.outcome.rule_id.as_deref(),
                        a.impact,
                        "forwarded",
                    );
                    FrameAction::Forward
                }
                Enforce::Reply(json) => {
                    // A4: a policy-evaluation error is fail-closed to deny, but it must be
                    // recorded and alarmed as a distinct outcome, never folded into a normal
                    // deny (a silent eval-error deny hides a broken policy).
                    let eval_error = a.outcome.rule_id.as_deref() == Some("eval-error");
                    let outcome = if eval_error {
                        "eval_error"
                    } else {
                        "not_executed"
                    };
                    if let (Some(ev), Some(did)) = (st.evidence.as_mut(), did.as_ref()) {
                        ev.record_outcome(did, outcome);
                    }
                    drop(st);
                    self.emit_event(
                        &tc.name,
                        verdict_s,
                        a.outcome.rule_id.as_deref(),
                        a.impact,
                        if eval_error { "eval_error" } else { "denied" },
                    );
                    FrameAction::Reply(json)
                }
            }
        } else {
            match decide(&insp) {
                Action::Forward => FrameAction::Forward,
                Action::Deny { code, message } => {
                    let id = insp.id.clone().unwrap_or(Value::Null);
                    FrameAction::Reply(error_response(&id, code, &message))
                }
            }
        }
    }
}

fn dispatch_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn fail_closed_reply(id: &Value) -> String {
    json!({
        "jsonrpc": "2.0", "id": id,
        "result": {"isError": true, "content": [{"type": "text",
            "text": "blocked: evidence unavailable, failing closed"}]}
    })
    .to_string()
}

#[cfg(test)]
mod bg_tests {
    use super::*;
    use acp_core::breakglass::Mode;

    fn controller() -> Controller {
        // default-allow policy: `echo` is forwarded unless a break-glass grant overrides it.
        let engine =
            Arc::new(PolicyEngine::from_yaml("version: 1\ndefault: allow\nrules: []\n").unwrap());
        Controller::new(
            Some(engine),
            "prod".to_string(),
            false,
            None,
            None,
            vec![],
            false,
            ImpactTaxonomy::default(),
        )
    }

    fn call() -> Vec<u8> {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}})
            .to_string()
            .into_bytes()
    }

    #[test]
    fn without_break_glass_a_default_allow_is_forwarded() {
        let c = controller();
        assert!(
            matches!(c.decide_frame(&call()), FrameAction::Forward),
            "no grant = normal path"
        );
    }

    #[test]
    fn lockdown_break_glass_denies_an_otherwise_allowed_call() {
        let c = controller();
        // Sanity: allowed before engaging.
        assert!(matches!(c.decide_frame(&call()), FrameAction::Forward));
        // Engage lockdown: the same call is now denied on the hot path.
        c.engage_break_glass(Mode::LockdownAll, "incident-1", "oncall", 60_000)
            .unwrap();
        assert!(
            matches!(c.decide_frame(&call()), FrameAction::Reply(_)),
            "lockdown denies"
        );
    }

    #[test]
    fn engage_requires_a_reason() {
        let c = controller();
        assert!(c
            .engage_break_glass(Mode::LockdownAll, "", "oncall", 60_000)
            .is_err());
    }
}
