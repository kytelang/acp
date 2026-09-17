//! Policy authoring surface and its compiler.
//!
//! Humans write policy in the YAML DSL (`dsl`); `compile` lowers it to Cedar text, which is
//! what the formally-verified `cedar-policy` engine evaluates (wired in M2). We never
//! hand-roll the evaluator; this crate only owns the *surface* and the *compiler*, both of
//! which are our unit-tested code. `acp policy-compile` prints the generated Cedar so the
//! mapping is reviewable.

pub mod dsl;
pub mod compile;

pub use compile::compile_to_cedar;
pub use dsl::{parse_str, Policy, Rule};
