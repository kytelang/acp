//! A minimal MCP-like server used only by the M1 transparency tests. It reads newline-delimited
//! JSON-RPC requests on stdin and writes canned responses on stdout. Not a real MCP server.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut out = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = match v.get("id").cloned() {
            Some(i) => i,
            None => continue, // notification: no response
        };
        let method = v.get("method").and_then(Value::as_str);
        let resp = match method {
            Some("initialize") => {
                json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"mock","version":"0"},"capabilities":{}}})
            }
            Some("ping") => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            Some("tools/list") => {
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"echo","description":"echo","inputSchema":{"type":"object"}}]}})
            }
            Some("resources/list") => json!({"jsonrpc":"2.0","id":id,"result":{"resources":[]}}),
            Some("prompts/list") => json!({"jsonrpc":"2.0","id":id,"result":{"prompts":[]}}),
            Some("tools/call") => {
                let args = v
                    .get("params")
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or(json!({}));
                json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":args.to_string()}]}})
            }
            _ => {
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}})
            }
        };
        writeln!(out, "{resp}").ok();
        out.flush().ok();
    }
}
