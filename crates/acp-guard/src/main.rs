//! acp-guard: the enforcement guard sidecar binary. A minimal reverse proxy placed in front of an
//! HTTP tool server. It verifies the `x-acp-enforcement` attestation on every request (see
//! `acp_guard::decide`) and forwards only fresh, correctly-signed requests to the tool server, which
//! is bound to loopback so it accepts connections only from the guard. A refused (un-proxied)
//! request is recorded to the tamper-evident ledger when one is configured, so bypass attempts are
//! evidence, not just a 401.

use acp_guard::{decide, GuardDecision};
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct GuardState {
    pubkey: Vec<u8>,
    upstream: String,
    max_age_ms: u64,
    client: reqwest::Client,
    ledger: Option<Mutex<acp_ledger::Ledger>>,
    forwarded: AtomicU64,
    rejected: AtomicU64,
    // A10: active break-glass grant; lockdown_all makes the guard refuse all forwards.
    bg: std::sync::RwLock<Option<acp_core::breakglass::BreakGlass>>,
}

/// Load and verify a break-glass grant file into a live grant (None when absent/invalid). With a
/// pinned key the grant must be validly signed by it.
fn load_grant(path: &str, pinned: Option<&[u8]>) -> Option<acp_core::breakglass::BreakGlass> {
    let src = std::fs::read_to_string(path).ok()?;
    let gf: acp_core::breakglass::GrantFile = serde_json::from_str(&src).ok()?;
    if !gf.verify(pinned) { return None; }
    gf.to_break_glass().map(|(bg, _actor)| bg)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    acp_obs::init("acp-guard");
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8801".to_string();
    let mut upstream: Option<String> = None;
    let mut pubkey_hex: Option<String> = None;
    let mut max_age_ms: u64 = 30_000;
    let mut ledger_path: Option<String> = None;
    let mut ledger_key_hex: Option<String> = None;
    let mut bg_path: Option<String> = None;
    let mut bg_key_hex: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--listen" => addr = it.next().cloned().unwrap_or(addr),
            "--upstream" => upstream = it.next().cloned(),
            "--pubkey" => pubkey_hex = it.next().cloned(),
            "--max-age-ms" => {
                max_age_ms = it.next().and_then(|s| s.parse().ok()).unwrap_or(max_age_ms)
            }
            "--ledger" => ledger_path = it.next().cloned(),
            "--ledger-key" => ledger_key_hex = it.next().cloned(),
            "--break-glass-file" => bg_path = it.next().cloned(),
            "--break-glass-key" => bg_key_hex = it.next().cloned(),
            other => {
                tracing::warn!("unknown option '{other}'");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let upstream = match upstream {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => {
            tracing::error!("--upstream <tool-server-url> is required");
            return std::process::ExitCode::from(2);
        }
    };
    let pubkey = match pubkey_hex.as_ref().map(|h| hex::decode(h)) {
        Some(Ok(b)) => b,
        _ => {
            tracing::error!("--pubkey <hex> (the proxy's pinned public key) is required");
            return std::process::ExitCode::from(2);
        }
    };

    // Optional evidence sink: record refused (un-proxied) attempts. A guard configured with a ledger
    // fails closed on a bad ledger open so bypass attempts are never silently unrecorded.
    let ledger = match (ledger_path.as_ref(), ledger_key_hex.as_ref()) {
        (Some(path), key) => {
            let signer: Box<dyn acp_core::sign::Signer + Send> = match key {
                Some(k) => match hex::decode(k).ok().and_then(|b| b.try_into().ok()) {
                    Some(seed) => Box::new(acp_core::sign::Ed25519Signer::from_seed(&seed)),
                    None => {
                        tracing::error!("--ledger-key must be 32-byte hex");
                        return std::process::ExitCode::from(2);
                    }
                },
                None => Box::new(acp_core::sign::Ed25519Signer::generate()),
            };
            match acp_ledger::Ledger::open(path, signer) {
                Ok(l) => Some(Mutex::new(l)),
                Err(e) => {
                    tracing::error!("cannot open ledger '{path}': {e}");
                    return std::process::ExitCode::from(1);
                }
            }
        }
        _ => None,
    };

    let bg_key: Option<Vec<u8>> = bg_key_hex.as_ref().and_then(|h| hex::decode(acp_core::secret::resolve(h)).ok());
    let bg_initial = bg_path.as_ref().and_then(|p| load_grant(p, bg_key.as_deref()));
    let state = Arc::new(GuardState {
        pubkey,
        upstream: upstream.clone(),
        max_age_ms,
        client: reqwest::Client::new(),
        ledger,
        forwarded: AtomicU64::new(0),
        rejected: AtomicU64::new(0),
        bg: std::sync::RwLock::new(bg_initial),
    });
    // A10: watch the break-glass grant so a lockdown engaged on the control plane reaches the guard.
    if let Some(p) = bg_path.clone() {
        let st_bg = state.clone();
        let key = bg_key.clone();
        tracing::info!("break-glass grant watched at {p}");
        tokio::spawn(async move {
            loop {
                let g = load_grant(&p, key.as_deref());
                if let Ok(mut w) = st_bg.bg.write() { *w = g; }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(|| async { "ready" }))
        .route(
            "/metrics",
            get({
                let s = state.clone();
                move || {
                    let s = s.clone();
                    async move {
                        format!(
                            "acp_guard_forwarded {}\nacp_guard_rejected {}\n",
                            s.forwarded.load(Ordering::Relaxed),
                            s.rejected.load(Ordering::Relaxed)
                        )
                    }
                }
            }),
        )
        .fallback(any(proxy))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("cannot bind {addr}: {e}");
            return std::process::ExitCode::from(1);
        }
    };
    tracing::info!(
        "verifying x-acp-enforcement in front of {upstream}; listening on {addr} (max-age {max_age_ms}ms)"
    );
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("serve error: {e}");
        return std::process::ExitCode::from(1);
    }
    std::process::ExitCode::SUCCESS
}

/// Record a refused, un-proxied attempt to the ledger (evidence of a bypass attempt).
fn record_rejection(state: &GuardState, path: &str, reason: &str) {
    if let Some(l) = state.ledger.as_ref() {
        let did = format!("guard-reject-{}-{}", now_ms(), path.replace('/', "_"));
        let rec = json!({
            "kind": "guard-reject",
            "path": path,
            "reason": reason,
            "ts_ms": now_ms(),
            "upstream": state.upstream,
        });
        if let Ok(mut g) = l.lock() {
            let _ = g.append(&did, "guard-reject", &rec, None);
        }
    }
}

async fn proxy(
    State(state): State<Arc<GuardState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let hdr = headers
        .get("x-acp-enforcement")
        .and_then(|v| v.to_str().ok());

    // A10: a break-glass lockdown refuses every forward, regardless of a valid attestation.
    let locked = {
        let g = state.bg.read().unwrap();
        matches!(g.as_ref(), Some(bg) if bg.active(now_ms()) && bg.mode == acp_core::breakglass::Mode::LockdownAll)
    };
    if locked {
        state.rejected.fetch_add(1, Ordering::Relaxed);
        record_rejection(&state, path, "break-glass lockdown");
        return (StatusCode::SERVICE_UNAVAILABLE, json!({"error": "break-glass-lockdown"}).to_string()).into_response();
    }

    match decide(&state.pubkey, hdr, now_ms(), state.max_age_ms) {
        GuardDecision::Reject(reason) => {
            state.rejected.fetch_add(1, Ordering::Relaxed);
            record_rejection(&state, path, &reason);
            (
                StatusCode::UNAUTHORIZED,
                json!({"error": "enforcement-required", "reason": reason}).to_string(),
            )
                .into_response()
        }
        GuardDecision::Forward => {
            let url = format!("{}{}", state.upstream, path);
            let mut req = state.client.request(method, &url).body(body.to_vec());
            // Forward the caller headers except hop-by-hop and the attestation itself.
            for (name, value) in headers.iter() {
                let n = name.as_str().to_ascii_lowercase();
                if n == "host" || n == "x-acp-enforcement" || n == "content-length" {
                    continue;
                }
                if let Ok(v) = value.to_str() {
                    req = req.header(name.as_str(), v);
                }
            }
            match req.send().await {
                Ok(resp) => {
                    state.forwarded.fetch_add(1, Ordering::Relaxed);
                    let status = resp.status();
                    let bytes = resp.bytes().await.unwrap_or_default();
                    (
                        StatusCode::from_u16(status.as_u16())
                            .unwrap_or(StatusCode::BAD_GATEWAY),
                        bytes,
                    )
                        .into_response()
                }
                Err(e) => (
                    StatusCode::BAD_GATEWAY,
                    json!({"error": "upstream-unreachable", "detail": e.to_string()}).to_string(),
                )
                    .into_response(),
            }
        }
    }
}
