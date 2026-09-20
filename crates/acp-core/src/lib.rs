//! Agent Control Plane: the trust core.
//!
//! This crate is deliberately pure (no sockets, no filesystem in the hot logic) so the
//! trust-critical pieces are unit-testable in isolation: the four-way policy verdict, the
//! RFC 6962-style verifiable log, and the signing seam.

pub mod adapter;
pub mod aibom;
pub mod attest;
pub mod agility;
pub mod anchor;
pub mod anomaly;
pub mod apqueue;
pub mod blast_radius;
pub mod breakglass;
pub mod canonical;
pub mod coverage;
pub mod classify;
pub mod discovery;
pub mod drift;
pub mod dualcontrol;
pub mod egress;
pub mod enrollment;
pub mod fleet;
pub mod grc;
pub mod ha;
pub mod hlc;
pub mod hostshim;
pub mod impact;
pub mod keymgr;
pub mod lineage;
pub mod liveness;
pub mod mcpdrift;
pub mod merkle;
pub mod modelclass;
pub mod metaaudit;
pub mod metering;
pub mod notify;
pub mod offboarding;
pub mod otelspan;
pub mod policyprov;
pub mod posture;
pub mod ratelimit;
pub mod redact;
pub mod render;
pub mod resource;
pub mod residency;
pub mod retention;
pub mod riskregister;
pub mod rollout;
pub mod sandbox;
pub mod scim;
pub mod secret;
pub mod shadoweval;
pub mod siem;
pub mod sign;
pub mod supplychain;
pub mod ticket;
pub mod timeline;
pub mod toolintegrity;
pub mod tuning;
pub mod types;
pub mod warehouse;
pub mod webhook;

pub use types::{ActionContext, BlastRadius, Decision, Record, Verdict};
