//! M5.1: the HTTP transport. Transparency for non-gated methods, and policy enforcement on
//! tools/call, over HTTP, sharing the exact decision logic with stdio.

use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const PROXY: &str = env!("CARGO_BIN_EXE_acp-proxy");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

const POLICY: &str = r#"
version: 1
default: allow
rules:
  - id: cap
    when: { tool: "payments.charge", arg: { amount_cents: { gt: 50000 } } }
    verdict: deny
"#;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// A minimal in-process HTTP MCP upstream.
async fn mock(v: Json<Value>) -> Json<Value> {
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let method = v.get("method").and_then(Value::as_str);
    let result = match method {
        Some("initialize") => {
            json!({"protocolVersion":"2025-06-18","serverInfo":{"name":"mock"},"capabilities":{}})
        }
        Some("tools/call") => {
            let args = v
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(json!({}));
            json!({"content":[{"type":"text","text":args.to_string()}]})
        }
        _ => json!({}),
    };
    Json(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

async fn wait_listening(addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy did not start listening on {addr}");
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[tokio::test]
async fn http_transport_transparency_and_deny() {
    let mock_port = free_port();
    let proxy_addr = format!("127.0.0.1:{}", free_port());
    let policy = format!("{TMP}/m5-policy.yaml");
    std::fs::write(&policy, POLICY).unwrap();

    // upstream mock
    let app = Router::new().route("/", post(mock));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", mock_port))
        .await
        .unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // proxy subprocess in HTTP mode
    let child = Command::new(PROXY)
        .args([
            "http",
            "--policy",
            &policy,
            "--addr",
            &proxy_addr,
            "--upstream",
            &format!("http://127.0.0.1:{mock_port}"),
        ])
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _kill = Kill(child);
    wait_listening(&proxy_addr).await;

    let client = reqwest::Client::new();
    let url = format!("http://{proxy_addr}/");
    let post = |body: Value| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(&url)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };

    // transparency: initialize is forwarded and answered by the upstream
    let init = post(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}})).await;
    assert!(
        init.pointer("/result/protocolVersion").is_some(),
        "initialize forwarded: {init}"
    );

    // deny: a big charge is blocked by the proxy, never reaches the upstream
    let denied = post(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"payments.charge","arguments":{"amount_cents":90000}}})).await;
    assert_eq!(
        denied.pointer("/result/isError"),
        Some(&Value::Bool(true)),
        "big charge denied over HTTP: {denied}"
    );

    // allow: echo is forwarded and the upstream echoes
    let ok = post(json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}})).await;
    assert!(
        ok.pointer("/result/content").is_some(),
        "echo forwarded over HTTP: {ok}"
    );
    assert_ne!(ok.pointer("/result/isError"), Some(&Value::Bool(true)));
}
