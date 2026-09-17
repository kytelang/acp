//! Thin JSON-RPC framing for the interception proxy (decision D1).
//!
//! The proxy is a transparent man-in-the-middle: it relays every message verbatim and only
//! parses enough to (a) route by method/id and (b) extract the tool name + arguments on a
//! `tools/call`. It never re-serialises a message it is passing through, so transparency is
//! structural, not best-effort.

pub mod message;

pub use message::{ParsedFrame, ToolCall};
