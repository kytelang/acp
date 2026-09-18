//! The streamable-HTTP transport (M5.1).
//!
//! The proxy is a reverse proxy in front of an upstream MCP HTTP endpoint. Each POSTed JSON-RPC
//! message goes through the same `Controller::decide_frame` as stdio, so policy, approval, and
//! evidence are identical across transports. A blocked call is answered directly; an allowed call
//! is forwarded to the upstream and its response returned verbatim.
//!
//! Note: server-initiated SSE streaming is a fast-follow; this handles the JSON-RPC
//! request/response path that carries `tools/call`.

use crate::dispatch::{Controller, FrameAction};
use axum::{
    body::Bytes, extract::State, http::StatusCode, response::IntoResponse, response::Response,
    routing::post, Router,
};
use std::sync::Arc;
use std::time::Duration;

/// M5.4: bound in-flight upstream requests so a burst backs off (429-style) rather than exhausting
/// the proxy, and time out a slow upstream so a hung tool server does not pin a connection forever.
const MAX_CONCURRENT: usize = 256;
const UPSTREAM_TIMEOUT_S: u64 = 30;

struct HttpState {
    controller: Arc<Controller>,
    client: reqwest::Client,
    upstream: String,
    sem: Arc<tokio::sync::Semaphore>,
}

pub async fn run(addr: &str, upstream: String, controller: Arc<Controller>) -> anyhow::Result<()> {
    // Upstream transport safety (D10): https is verified by rustls; warn on non-loopback cleartext.
    if upstream.starts_with("http://")
        && !upstream.contains("127.0.0.1")
        && !upstream.contains("localhost")
    {
        eprintln!(
            "acp-proxy: WARNING upstream {upstream} is cleartext http; use https in production"
        );
    }
    let state = Arc::new(HttpState {
        controller,
        client: reqwest::Client::builder()
            .https_only(false)
            .timeout(Duration::from_secs(UPSTREAM_TIMEOUT_S))
            .build()?,
        upstream,
        sem: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT)),
    });
    let app = Router::new().route("/", post(handle)).with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("acp-proxy: HTTP transport listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(State(st): State<Arc<HttpState>>, body: Bytes) -> Response {
    // Concurrency cap: acquire a permit or shed load with 503 + Retry-After (no unbounded queueing).
    let _permit = match st.sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("retry-after", "1")],
                "proxy at capacity, retry shortly",
            )
                .into_response();
        }
    };
    match st.controller.decide_frame(&body) {
        FrameAction::Reply(json) => ([("content-type", "application/json")], json).into_response(),
        FrameAction::Forward => match st
            .client
            .post(&st.upstream)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
        {
            Ok(resp) => {
                let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
                let bytes = resp.bytes().await.unwrap_or_default();
                (status, [("content-type", "application/json")], bytes).into_response()
            }
            Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response(),
        },
    }
}
