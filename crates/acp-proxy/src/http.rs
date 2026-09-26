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
use axum::http::HeaderMap;
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
        tracing::warn!(
            "WARNING upstream {upstream} is cleartext http; use https in production"
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
    tracing::info!("HTTP transport listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle(State(st): State<Arc<HttpState>>, headers: HeaderMap, body: Bytes) -> Response {
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
    // Per-request human identity: verify this request's bearer (if OIDC is configured) and stamp the
    // resulting principal onto the decision. Absent/invalid -> the startup principal (unattributed).
    let principal = {
        let tok = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        st.controller.resolve_principal_from_token(tok)
    };
    let forward_body: reqwest::Body = match st.controller.decide_frame_with_principal(&body, principal) {
        FrameAction::Reply(json) => {
            return ([("content-type", "application/json")], json).into_response()
        }
        FrameAction::Forward => body.into(),
        FrameAction::ForwardRewritten(rewritten) => rewritten.into(),
    };
    let mut upstream_req = st
        .client
        .post(&st.upstream)
        .header("content-type", "application/json");
    if let Some(tok) = st.controller.enforcement_token() {
        // Prove to a guarded tool server that this call passed governance (4b).
        upstream_req = upstream_req.header("x-acp-enforcement", tok);
    }
    match upstream_req.body(forward_body).send().await {
            Ok(resp) => {
                let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::OK);
                let ctype = resp
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                if ctype.starts_with("text/event-stream") {
                    // MCP streamable-HTTP: the upstream answered with an SSE stream (server->client
                    // notifications/results). Stream it through chunk-by-chunk without buffering the
                    // (potentially unbounded) body. The governed request already ran through
                    // decide_frame above. NOTE: SSE response frames are relayed unscreened
                    // (chunk boundaries split frames); buffered responses are screened below (A6).
                    let s = futures_util::stream::unfold(resp, |mut r| async move {
                        match r.chunk().await {
                            Ok(Some(chunk)) => Some((Ok::<_, std::io::Error>(chunk), r)),
                            _ => None,
                        }
                    });
                    let body = axum::body::Body::from_stream(s);
                    (status, [("content-type", "text/event-stream")], body).into_response()
                } else {
                    let bytes = resp.bytes().await.unwrap_or_default();
                    // A6: bring the buffered HTTP path in line with stdio: tool-integrity (tools/list),
                    // the shared pin check, and indirect-injection screening of the tool result.
                    st.controller.inspect_response(&bytes);
                    st.controller.inspect_response_shared(&bytes).await;
                    let out: Vec<u8> = match st.controller.screen_response(&bytes) {
                        Some(replacement) => replacement.into_bytes(),
                        None => bytes.to_vec(),
                    };
                    (status, [("content-type", "application/json")], out).into_response()
                }
            }
            Err(e) => (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response(),
    }
}
