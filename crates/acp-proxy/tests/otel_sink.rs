//! F9/D14: the OpenTelemetry (OTLP/HTTP) sink emits a redacted OTLP log record per event.

use axum::{routing::post, Router};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Reach the sink types via the binary crate's path is not possible; test through a tiny copy of
// the public surface by spawning the sink from the crate. acp-proxy is a bin crate, so we test
// the sink by compiling it into this integration test via `path` is not available. Instead we
// exercise the raw OTLP contract the sink produces by importing the module through include.
#[path = "../src/events.rs"]
#[allow(dead_code)]
mod events;
use events::{Event, OtelSink, Sink};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otel_sink_posts_redacted_otlp() {
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let app = Router::new().route(
        "/v1/logs",
        post(move |body: String| {
            let cap = cap.clone();
            async move {
                cap.lock().unwrap().push(body);
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let endpoint = format!("http://127.0.0.1:{port}/v1/logs");
    // emit one event, then drop the sink to flush + join the worker
    {
        let sink = OtelSink::new(endpoint);
        sink.emit(&Event {
            agent: "a",
            session: "s",
            tool: "payments.charge",
            verdict: "deny",
            rule_id: Some("cap"),
            impact: "high",
            outcome: "denied",
        });
    } // drop flushes

    // wait for the collector to receive it
    let mut got = None;
    for _ in 0..40 {
        if let Some(b) = captured.lock().unwrap().first().cloned() {
            got = Some(b);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let body = got.expect("collector must receive an OTLP payload");
    // OTLP structure + redacted attributes present
    assert!(body.contains("resourceLogs"), "OTLP envelope: {body}");
    assert!(body.contains("payments.charge") && body.contains("deny") && body.contains("cap"));
    // never any raw arguments
    assert!(!body.contains("amount_cents"));
}
