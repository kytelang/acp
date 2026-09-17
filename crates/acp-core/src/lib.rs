//! Agent Control Plane: the trust core.
//!
//! This crate is deliberately pure (no sockets, no filesystem in the hot logic) so the
//! trust-critical pieces are unit-testable in isolation: the four-way policy verdict, the
//! RFC 6962-style verifiable log, and the signing seam.

pub mod blast_radius;
pub mod canonical;
pub mod merkle;
pub mod sign;
pub mod types;

pub use types::{ActionContext, BlastRadius, Decision, Record, Verdict};
