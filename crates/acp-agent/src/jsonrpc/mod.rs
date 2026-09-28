//! Thin JSON-RPC framing for the interception proxy (decision D1).
//!
//! The proxy is a transparent man-in-the-middle: it relays every message verbatim and only
//! parses enough to (a) route by method/id and (b) extract the tool name + arguments on a
//! `tools/call`. It never re-serialises a message it is passing through, so transparency is
//! structural, not best-effort.

pub mod message;

pub use message::{
    classify, error_response, inspect, is_request, Inspected, ParsedFrame, ToolCall,
};

#[cfg(test)]
mod restored_fuzz_frames {
#![allow(unused_imports)]
//! H0.11 (in-repo form): fuzz-style robustness of frame inspection. The proxy inspects every byte
//! stream a client sends; a malformed frame must never panic the proxy (which would be a denial of
//! service and, worse, could drop a call out of governance). Deterministic corpus, no toolchain.

use crate::jsonrpc::{classify, inspect};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

#[test]
fn frame_inspection_never_panics() {
    let mut rng = Lcg(0xF00D_1234);
    let seeds: [&[u8]; 3] = [
        br#"{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"x","arguments":{}}}"#,
        br#"{"jsonrpc":"2.0","id":1}"#,
        b"not json at all",
    ];
    for _ in 0..5000 {
        let mut buf = seeds[(rng.next() as usize) % seeds.len()].to_vec();
        // Apply a handful of random mutations.
        for _ in 0..(rng.next() % 8) {
            if buf.is_empty() {
                break;
            }
            let i = (rng.next() as usize) % buf.len();
            match rng.next() % 3 {
                0 => buf[i] = (rng.next() & 0xff) as u8,
                1 => {
                    buf.truncate(i);
                }
                _ => buf.insert(i, (rng.next() & 0xff) as u8),
            }
        }
        std::panic::catch_unwind(|| {
            let _ = classify(&buf);
            let _ = inspect(&buf);
        })
        .expect("frame inspection must not panic on any byte stream");
    }
}

}

#[cfg(test)]
mod restored_transparency {
#![allow(unused_imports)]
use crate::jsonrpc::message::{classify, ParsedFrame};

#[test]
fn non_toolcall_is_passthrough() {
    for raw in [
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#.as_slice(),
    ] {
        assert_eq!(classify(raw), ParsedFrame::Passthrough, "raw: {:?}", raw);
    }
}

#[test]
fn invalid_json_is_opaque_not_an_error() {
    assert_eq!(classify(b"not json at all"), ParsedFrame::Opaque);
    assert_eq!(classify(b""), ParsedFrame::Opaque);
}

#[test]
fn toolcall_is_extracted() {
    let raw = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call",
        "params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}"#;
    match classify(raw) {
        ParsedFrame::ToolCall(tc) => {
            assert_eq!(tc.name, "payments.charge");
            assert_eq!(tc.arguments["amount_cents"], 90000);
            assert_eq!(tc.id, serde_json::json!(7));
        }
        other => panic!("expected ToolCall, got {other:?}"),
    }
}

}
