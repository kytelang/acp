//! Shared per-frame decision logic (used by every transport).
//!
//! A `Controller` holds the policy engine, evidence ledger, and approval store, and turns one
//! client-to-server JSON-RPC frame into a `FrameAction` (forward it, or reply to the client). Both
//! the stdio and HTTP transports call `decide_frame`, so policy enforcement (M2/D9), the step-up
//! approval flow (M4/D8), evidence (M3/D11), shadow mode (M5.3), and the resource limit (M1.5)
//! are identical across transports.

use crate::approvals::Step;
use crate::evidence::Evidence;
use crate::intercept::{decide, Action, CODE_BLOCKED};
use crate::limits;
use crate::policy::{self, Enforce};
use acp_approvals::ApprovalStore;
use acp_core::types::Verdict;
use acp_jsonrpc::{classify, error_response, inspect, ParsedFrame};
use acp_policy::PolicyEngine;
use serde_json::Value;
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
}

impl Controller {
    pub fn new(
        engine: Option<Arc<PolicyEngine>>,
        env: String,
        shadow: bool,
        evidence: Option<Evidence>,
        approvals: Option<ApprovalStore>,
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
            let a = policy::assess(&eng, &self.env, &tc);
            let mut st = self.state.lock().unwrap();

            // Shadow mode (M5.3): record what WOULD happen, but forward everything.
            if self.shadow && a.outcome.verdict != Verdict::Allow {
                if let Some(ev) = st.evidence.as_mut() {
                    let did = ev.record_decision(
                        &self.agent,
                        &self.session,
                        &tc,
                        &a.outcome,
                        a.impact,
                        eng.hash(),
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
                            let did = ev.record_decision(
                                &self.agent,
                                &self.session,
                                &tc,
                                &a.outcome,
                                a.impact,
                                eng.hash(),
                            );
                            ev.record_outcome(&did, "forwarded");
                        }
                        return FrameAction::Forward;
                    }
                    Step::Held(json) => return FrameAction::Reply(json),
                    Step::Denied(json) => {
                        if let Some(ev) = st.evidence.as_mut() {
                            let did = ev.record_decision(
                                &self.agent,
                                &self.session,
                                &tc,
                                &a.outcome,
                                a.impact,
                                eng.hash(),
                            );
                            ev.record_outcome(&did, "not_executed");
                        }
                        return FrameAction::Reply(json);
                    }
                }
            }

            // Allow / deny / (step_up without a store): enforce and record.
            let did = st.evidence.as_mut().map(|ev| {
                ev.record_decision(
                    &self.agent,
                    &self.session,
                    &tc,
                    &a.outcome,
                    a.impact,
                    eng.hash(),
                )
            });
            match a.enforce {
                Enforce::Forward => {
                    if let (Some(ev), Some(did)) = (st.evidence.as_mut(), did.as_ref()) {
                        ev.record_outcome(did, "forwarded");
                    }
                    FrameAction::Forward
                }
                Enforce::Reply(json) => {
                    if let (Some(ev), Some(did)) = (st.evidence.as_mut(), did.as_ref()) {
                        ev.record_outcome(did, "not_executed");
                    }
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
