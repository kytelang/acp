//! Core value types shared across the proxy, server, and CLI.

use serde::{Deserialize, Serialize};

/// The four possible outcomes of evaluating a tool call against policy.
///
/// Cedar itself is 2-way (permit/forbid); the extra outcomes ride on policy annotations
/// (see decision D2). This enum is the resolved result the proxy enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Forward the call untouched.
    Allow,
    /// Block the call; return a structured error the agent can reason about.
    Deny,
    /// Block and open a human approval; the agent re-issues once resolved.
    StepUp,
    /// Do not enforce; record a would-block. Used to roll policy out safely.
    Shadow,
}

/// A coarse impact score derived by the proxy from the call arguments (decision: heuristic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlastRadius {
    Low,
    Medium,
    High,
}

/// The terminal outcome of a decision, distinct from the verdict (decision D11/D13).
/// A decision record asserts a verdict; a linked outcome record asserts what actually happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// The call was forwarded upstream (carry the upstream status alongside).
    Forwarded,
    /// Allowed/approved but never executed (e.g. a ghost approval).
    NotExecuted,
    /// A policy-evaluation error: fail-closed, never folded into allow/deny (D13/A3).
    EvalError,
}

/// The evaluated impact plus the taxonomy version that produced it (decision D12/D13).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Impact {
    pub level: BlastRadius,
    /// Versioned, per-tenant impact taxonomy id, e.g. "impact@1.3".
    pub taxonomy: String,
}

/// The human on whose behalf the agent acts. `verified` is false when it came from the
/// agent-set `X-ACP-Principal` header (decision D10) and is never signed as verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub verified: bool,
}

/// Reproducibility + crypto-agility provenance stamped into every record (decision D7/D13).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// Named, swappable algorithms, e.g. ("sha256", "ed25519").
    pub algo_hash: String,
    pub algo_sig: String,
    pub evaluator: String,
    pub compiler: String,
    /// Deterministic proxy-side context derivation version (classifiers + impact taxonomy).
    pub context_derivation: String,
}

/// Everything known about a single intercepted tool call at the decision point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    pub agent_id: String,
    pub principal: Principal,
    pub session_id: String,
    pub tool: String,
    /// Raw tool arguments as received (JSON object).
    pub args: serde_json::Value,
    pub impact: Impact,
}

/// The resolved policy decision for an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub rule_id: Option<String>,
    /// Redaction-safe fired condition, for explainability + replay (D12/E3).
    pub matched: Option<String>,
    pub policy_hash: String,
    pub approvers: Vec<String>,
    pub reason: Option<String>,
    pub impact: Impact,
}

/// One evidence record: a leaf in the verifiable log. Serialised via canonical bytes
/// (the `leaf_hash` is computed over those bytes, not stored inside them).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    /// Versioned record schema, for mixed-fleet safety (R5).
    pub schema: u32,
    pub seq: u64,
    pub ts_ms: u64,
    /// Hybrid logical clock for cross-proxy causal ordering (decision D12/F11).
    pub hlc: String,
    /// Verified identity of the launched/dialled tool server (decision D12/B5).
    pub tool_server_fingerprint: Option<String>,
    pub agent_id: String,
    pub principal: Principal,
    pub session_id: String,
    pub tool: String,
    /// SHA-256 of the canonical args; the full args live in a separate blob table.
    pub args_hash: String,
    pub impact: Impact,
    pub verdict: Verdict,
    pub rule_id: Option<String>,
    /// Redaction-safe fired condition (decision D12/E3).
    pub matched: Option<String>,
    pub policy_hash: String,
    pub reason: Option<String>,
    pub provenance: Provenance,
}
