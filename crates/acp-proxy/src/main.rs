//! acp-proxy: sits between an MCP client and the tool server(s), decides on every
//! `tools/call`, and streams a signed evidence record for each decision.
//!
//! Skeleton: transports (stdio/http), interception, and the evidence client land in M1/M3/M5.

fn main() {
    eprintln!("acp-proxy (skeleton) - transports land in M1; interception in M2; evidence in M3");
    // Prove the trust core is reachable from the proxy binary.
    let frame = acp_jsonrpc::message::classify(
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.delete","arguments":{}}}"#,
    );
    eprintln!("sample classify: {frame:?}");
    let _ = acp_core::types::Verdict::StepUp;
}
