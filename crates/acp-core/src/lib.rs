//! Agent Control Plane: the trust core.
//!
//! This crate is deliberately pure (no sockets, no filesystem in the hot logic) so the
//! trust-critical pieces are unit-testable in isolation: the four-way policy verdict, the
//! RFC 6962-style verifiable log, and the signing seam.

pub mod anchor;
pub mod anomaly;
pub mod blast_radius;
pub mod breakglass;
pub mod canonical;
pub mod classify;
pub mod drift;
pub mod egress;
pub mod hlc;
pub mod impact;
pub mod keymgr;
pub mod liveness;
pub mod merkle;
pub mod metaaudit;
pub mod metering;
pub mod notify;
pub mod posture;
pub mod redact;
pub mod render;
pub mod scim;
pub mod sign;
pub mod types;
pub mod webhook;

pub use types::{ActionContext, BlastRadius, Decision, Record, Verdict};
