//! M5: server->client SSE passthrough. When an upstream MCP server answers a forwarded tools/call
//! with `text/event-stream` (streamable HTTP), the proxy streams it straight through to the client
//! instead of buffering. The request itself was already gated by decide_frame; the SSE body carries
//! server->client results/notifications, which are forwarded, not re-gated.

use axum::{body::Bytes, response::IntoResponse, response::Response, routing::post, Router};
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");
const POLICY: &str = "version: 1\ndefault: allow\nrules: []\n";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

// Mock upstream: answers `stream.events` with an SSE stream, everything else with plain JSON.
async fn mock(body: Bytes) -> Response {
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let tool = v.pointer("/params/name").and_then(Value::as_str);
    if tool == Some("stream.events") {
        let sse = "event: message\ndata: {\"n\":1}\n\nevent: message\ndata: {\"n\":2}\n\n";
        return ([("content-type", "text/event-stream")], sse).into_response();
    }
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    axum::Json(json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"ok"}]}}))
        .into_response()
}

async fn wait_listening(addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy did not start on {addr}");
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[tokio::test]
async fn upstream_sse_is_streamed_through() {
    let mock_port = free_port();
    let proxy_addr = format!("127.0.0.1:{}", free_port());
    let policy = format!("{TMP}/sse-policy.yaml");
    std::fs::write(&policy, POLICY).unwrap();

    let app = Router::new().route("/", post(mock));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", mock_port)).await.unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let child = Command::new(PROXY)
        .args(["http", "--policy", &policy, "--addr", &proxy_addr, "--upstream", &format!("http://127.0.0.1:{mock_port}")])
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _kill = Kill(child);
    wait_listening(&proxy_addr).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{proxy_addr}/"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stream.events","arguments":{}}}))
        .send()
        .await
        .unwrap();

    let ctype = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    assert!(ctype.starts_with("text/event-stream"), "response must be SSE, got '{ctype}'");
    let body = resp.text().await.unwrap();
    assert!(body.contains("\"n\":1") && body.contains("\"n\":2"), "streamed SSE events must arrive: {body}");
    assert!(body.contains("event: message"), "SSE framing preserved: {body}");
}
