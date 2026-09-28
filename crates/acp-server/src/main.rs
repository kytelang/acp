//! acp-server: the control-plane HTTP service (v1.1 seed, single-tenant).
//!
//! Serves the web approval inbox (M4.3), the current policy endpoint (M2.2), a read-only
//! evidence-verify endpoint, and a basic governance report. HTML is rendered with `maud`, which
//! auto-escapes, so attacker-controlled content in the inbox cannot inject markup (M4.5).
//! Multi-tenant Postgres, per-tenant keys, and SSO are the next layer (v1.1.1-1.1.3 / H1).

mod store;
mod mtls;
use axum::Router;
use std::sync::Arc;


mod state;
mod common;
mod handlers;
mod router;
use state::{AppState, Auth};
use common::*;
use handlers::models::*;
use handlers::reports::*;
use handlers::tickets::*;

/// C1: restore persisted liveness heartbeats and spike-event timestamps from the shared store into
/// the in-memory detectors, so a restart does not lose the dead-man's-switch or the alert state.
async fn restore_control_state(st: &Arc<AppState>, store: &crate::store::ControlStore) {
    // Liveness: one row per proxy ("liveness:{proxy}" -> ts), so replicas never clobber each other.
    if let Ok(rows) = store.list_state_prefix("liveness:").await {
        let mut live = st.liveness.lock().unwrap();
        for (k, v) in rows {
            if let (Some(proxy), Ok(ts)) = (k.strip_prefix("liveness:"), v.parse::<u64>()) {
                live.heartbeat(proxy, ts);
            }
        }
    }
    // Spikes: one row per event ("spike:{kind}:{ts}"), append-only, replayed within the window.
    let cutoff = now_ms() - 300_000;
    if let Ok(rows) = store.list_state_prefix("spike:").await {
        let mut spikes = st.spikes.lock().unwrap();
        for (k, _) in rows {
            let mut it = k.splitn(3, ':'); // "spike", kind, ts
            let _ = it.next();
            if let (Some(kind), Some(ts)) = (it.next(), it.next().and_then(|t| t.parse::<u64>().ok())) {
                if ts >= cutoff {
                    spikes.entry(kind.to_string()).or_insert_with(|| acp_core::anomaly::SpikeDetector::new(60_000, 10)).record(ts);
                }
            }
        }
    }
    tracing::info!("restored control state (liveness + spike) from shared store");
}

/// G4: fire a structured, HMAC-signed event to the configured webhook (best-effort, non-blocking).
/// User-controlled fields (tool name, subject, ...) are placed only as JSON values, never interpolated
/// into markup, so a crafted value cannot forge the notification.
/// Named MLflow adapter: fetch the registry, map latest versions, and register any not already in the
/// ACP inventory (tenant "default"). Uses the normal admission-scan + signed AI-BOM path so imported
/// models are governed exactly like manually registered ones. Idempotent by (name, version).
async fn import_mlflow(st: &Arc<AppState>, mlflow_url: &str) {
    let store = match &st.store { Some(s) => s.clone(), None => return };
    let base = mlflow_url.trim_end_matches('/');
    let url = format!("{base}/api/2.0/mlflow/registered-models/search");
    let client = reqwest::Client::new();
    let v = match client.get(&url).send().await {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(v) => v,
            Err(e) => { tracing::warn!("mlflow import: bad response body: {e}"); return; }
        },
        Err(e) => { tracing::warn!("mlflow import: cannot reach {url}: {e}"); return; }
    };
    if v.get("next_page_token").and_then(|t| t.as_str()).map(|t| !t.is_empty()).unwrap_or(false) {
        tracing::warn!("mlflow import: registry has more than one page; only the first page was imported");
    }
    let models = acp_core::mlflow::models_from_search(&v);
    // Existing (name, version) pairs in the default tenant, to skip re-registration.
    let existing: std::collections::BTreeSet<(String, String)> = match store.list_models("default").await {
        Ok(ms) => ms.into_iter().map(|m| (m.name, m.version)).collect(),
        Err(_) => std::collections::BTreeSet::new(),
    };
    let mut imported = 0usize;
    for m in &models {
        if existing.contains(&(m.name.clone(), m.version.clone())) { continue; }
        let card = serde_json::json!({"stage": m.stage, "source": m.source, "origin": "mlflow"}).to_string();
        let id = format!("mdl-{}", rand_hex(6));
        let (scan_status, aibom, refused) = admission_scan(st, &m.name, "mlflow", &m.version).await;
        if refused {
            tracing::warn!("mlflow import: model '{}' v{} refused by admission scan ({scan_status})", m.name, m.version);
            continue;
        }
        if store.add_model(&id, &m.name, "mlflow", &m.version, &card, &scan_status, &aibom, "default", now_ms() as i64).await.is_ok() {
            imported += 1;
        }
    }
    tracing::info!("mlflow import: {imported} new model(s) imported from {base} ({} in registry)", models.len());
}

#[tokio::main]
async fn main() {
    acp_core::obs::init("acp-server");
    let args: Vec<String> = std::env::args().collect();
    let mut addr = "127.0.0.1:8787".to_string();
    let (mut approvals, mut policy_path, mut ledger) = (None, None, None);
    let mut meta_ledger: Option<String> = None;
    let mut registry: Option<String> = None;
    let mut policy_store: Option<String> = None;
    let mut break_glass_file: Option<String> = None;
    let mut enrollment: Option<String> = None;
    let mut store_url: Option<String> = None;
    let mut cp_key = "acp-cp.key".to_string();
    let mut tls_ca: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut break_glass_seed: Option<[u8; 32]> = None;
    let mut oidc_jwks: Option<String> = None;
    let mut oidc_issuer: Option<String> = None;
    let mut oidc_audience: Option<String> = None;
    let mut dev_auth = false;
    let mut entra_tenant: Option<String> = None;
    let mut entra_audience: Option<String> = None;
    let mut report_token: Option<String> = std::env::var("ACP_REPORT_TOKEN").ok().filter(|s| !s.is_empty());
    let mut scim_users_path: Option<String> = None;
    let mut model_scanner_url: Option<String> = None;
    let mut model_scan_block = false;
    let mut webhook_url: Option<String> = None;
    let mut webhook_secret: Option<String> = None;
    let mut packs_feed_url: Option<String> = None;
    let mut threat_feed_url: Option<String> = None;
    let mut ticket_poll_url: Option<String> = None;
    let mut slack_webhook_url: Option<String> = None;
    let mut mlflow_url: Option<String> = None;
    let mut retrieval_source: Option<String> = None;
    let mut author_llm_url: Option<String> = None;
    let mut author_llm_key: Option<String> = None;
    let mut author_llm_model: Option<String> = None;
    let mut snapshot_interval_ms: i64 = 0;
    let mut snapshot_frameworks: Vec<String> = Vec::new();
    let mut approval_sla_ms: i64 = 0;
    let mut node_id: Option<String> = None;
    let mut lease_ttl_ms: i64 = 15_000;
    let mut entra_preflight = false;
    let mut entra_test_token: Option<String> = None;
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().cloned().unwrap_or(addr),
            "--approvals" => approvals = it.next().cloned(),
            "--policy" => policy_path = it.next().cloned(),
            "--ledger" => ledger = it.next().cloned(),
            "--meta-ledger" => meta_ledger = it.next().cloned(),
            "--registry" => registry = it.next().cloned(),
            "--policy-store" => policy_store = it.next().cloned(),
            "--enrollment" => enrollment = it.next().cloned(),
            "--store" => store_url = it.next().cloned(),
            "--report-token" => report_token = it.next().cloned(),
            "--scim-users" => scim_users_path = it.next().cloned(),
            "--model-scanner-url" => model_scanner_url = it.next().cloned(),
            "--model-scan-block" => model_scan_block = true,
            "--webhook-url" => webhook_url = it.next().cloned(),
            "--webhook-secret" => webhook_secret = it.next().cloned(),
            "--packs-feed-url" => packs_feed_url = it.next().cloned(),
            "--threat-feed-url" => threat_feed_url = it.next().cloned(),
            "--ticket-poll-url" => ticket_poll_url = it.next().cloned(),
            "--slack-webhook-url" => slack_webhook_url = it.next().cloned(),
            "--mlflow-url" => mlflow_url = it.next().cloned(),
            "--retrieval-source" => retrieval_source = it.next().cloned(),
            "--author-llm-url" => author_llm_url = it.next().cloned(),
            "--author-llm-key" => author_llm_key = it.next().cloned(),
            "--author-llm-model" => author_llm_model = it.next().cloned(),
            "--snapshot-interval-ms" => snapshot_interval_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--snapshot-frameworks" => snapshot_frameworks = it.next().map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default(),
            "--approval-sla-ms" => approval_sla_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--node-id" => node_id = it.next().cloned(),
            "--lease-ttl-ms" => lease_ttl_ms = it.next().and_then(|v| v.parse().ok()).unwrap_or(15_000),
            "--cp-key" => { if let Some(v) = it.next() { cp_key = v.clone(); } }
            "--oidc-jwks" => oidc_jwks = it.next().cloned(),
            "--oidc-issuer" => oidc_issuer = it.next().cloned(),
            "--oidc-audience" => oidc_audience = it.next().cloned(),
            "--dev-auth" => dev_auth = true,
            "--entra-tenant" => entra_tenant = it.next().cloned(),
            "--entra-audience" => entra_audience = it.next().cloned(),
            "--entra-preflight" => entra_preflight = true,
            "--entra-test-token" => entra_test_token = it.next().cloned(),
            "--break-glass-file" => break_glass_file = it.next().cloned(),
            "--tls-ca" => tls_ca = it.next().cloned(),
            "--tls-cert" => tls_cert = it.next().cloned(),
            "--tls-key" => tls_key = it.next().cloned(),
            "--break-glass-key" => {
                if let Some(h) = it.next() {
                    match hex::decode(acp_core::secret::resolve(h)) {
                        Ok(b) if b.len() == 32 => {
                            let mut s = [0u8; 32];
                            s.copy_from_slice(&b);
                            break_glass_seed = Some(s);
                        }
                        _ => {
                            tracing::error!("--break-glass-key must be a 32-byte hex seed");
                            std::process::exit(2);
                        }
                    }
                }
            }
            other => {
                tracing::warn!("unknown option '{other}'");
                std::process::exit(2);
            }
        }
    }

    // R7: real-Entra cutover preflight. Verifies the identity setup without starting the full server:
    // fetch the JWKS from the derived Entra/OIDC endpoint, confirm it parses and has keys, and (if a
    // sample token is given) run the full verification and print each claim check and the effective
    // capabilities. Exits 0 on success, 1 on any failure. Gated only on a customer tenant + token.
    if entra_preflight {
        let resolved = if let (Some(tid), Some(aud)) = (&entra_tenant, &entra_audience) {
            Some((
                format!("https://login.microsoftonline.com/{tid}/v2.0"),
                aud.clone(),
                format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"),
            ))
        } else if let (Some(src), Some(iss), Some(aud)) = (&oidc_jwks, &oidc_issuer, &oidc_audience) {
            Some((iss.clone(), aud.clone(), src.clone()))
        } else {
            None
        };
        let (issuer, audience, source) = match resolved {
            Some(t) => t,
            None => {
                eprintln!("preflight: need --entra-tenant + --entra-audience (or the --oidc-* flags)");
                std::process::exit(1);
            }
        };
        println!("entra preflight");
        println!("  issuer:   {issuer}");
        println!("  audience: {audience}");
        println!("  jwks:     {source}");
        let jwks = match load_jwks(&source).await {
            Ok(j) => { println!("  [ok] JWKS fetched: {} key(s)", j.key_count()); j }
            Err(e) => { println!("  [FAIL] JWKS load: {e}"); std::process::exit(1); }
        };
        if let Some(tok) = &entra_test_token {
            let cfg = acp_core::auth::EntraConfig { issuer, audience };
            match acp_core::auth::verify(tok, &jwks, &cfg, now_ms()) {
                Ok(p) => {
                    println!("  [ok] token verified");
                    println!("       oid={} user={} tid={}", p.oid, p.username, p.tenant);
                    println!("       roles: {}", if p.roles.is_empty() { "(none)".to_string() } else { p.roles.join(", ") });
                    let caps: Vec<String> = p.capabilities().into_iter().map(|c| format!("{c:?}")).collect();
                    println!("       capabilities: {}", if caps.is_empty() { "(none, fail-closed)".to_string() } else { caps.join(", ") });
                    if p.roles.is_empty() {
                        println!("  [warn] token carries no app roles; the principal can do nothing. Assign app roles in Entra.");
                    }
                }
                Err(e) => { println!("  [FAIL] token verification: {e:?}"); std::process::exit(1); }
            }
        } else {
            println!("  [note] no --entra-test-token given; JWKS reachability only. Pass a real token to verify iss/aud/nbf/exp/signature/roles end to end.");
        }
        println!("preflight OK");
        std::process::exit(0);
    }

    let policy = match policy_path {
        Some(p) => match std::fs::read_to_string(&p).ok().and_then(|src| {
            acp_core::policy::PolicyEngine::from_yaml(&src)
                .ok()
                .map(|e| (e.hash().to_string(), src))
        }) {
            Some(v) => Some(v),
            None => {
                tracing::error!("could not load policy {p}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    // H0.7: a tamper-evident meta-audit ledger for admin actions (policy/key/RBAC changes).
    let meta = meta_ledger.and_then(|path| {
        let key_path = format!("{path}.key");
        let signer: Box<dyn acp_core::sign::Signer + Send> = match std::fs::read(&key_path) {
            Ok(b) if b.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&b);
                Box::new(acp_core::sign::Ed25519Signer::from_seed(&s))
            }
            _ => {
                let s = acp_core::sign::Ed25519Signer::generate();
                let _ = acp_core::secret::write_key_secure(&key_path, &s.seed());
                Box::new(s)
            }
        };
        // Prefer a PKCS#11 HSM signer when configured (ACP_PKCS11_MODULE).
        let signer: Box<dyn acp_core::sign::Signer + Send> = match acp_core::hsm::signer_from_env() {
            Some(Ok(hsm)) => { tracing::info!("meta-ledger signing with a PKCS#11 HSM"); hsm }
            Some(Err(e)) => { tracing::error!("HSM signer requested but failed: {e}"); return None; }
            None => signer,
        };
        match acp_core::ledger::Ledger::open(&path, signer) {
            Ok(l) => Some(std::sync::Mutex::new(l)),
            Err(e) => {
                tracing::error!("could not open meta-ledger {path}: {e}");
                None
            }
        }
    });

    if dev_auth && std::env::var("ACP_ALLOW_DEV_AUTH").ok().as_deref() != Some("1") {
        tracing::info!("--dev-auth requires ACP_ALLOW_DEV_AUTH=1 (never enable in production)");
        std::process::exit(2);
    }
    // Control-plane RBAC (opt-in). Three ways to enable, in priority order:
    //   --dev-auth                         : in-memory mock issuer (local use)
    //   --entra-tenant + --entra-audience  : real Entra; issuer + JWKS URL derived from the tenant
    //   --oidc-jwks(url|file) + --oidc-issuer + --oidc-audience : explicit
    // With none, RBAC is off and the local demo is unaffected.
    let auth: Option<Auth> = if dev_auth {
        let mock = acp_core::auth::MockEntra::new("common", "acp-app");
        tracing::info!("DEV auth enabled (mock issuer); GET /auth/dev-token?role=PolicyAdmin");
        Some(Auth {
            jwks: std::sync::Arc::new(std::sync::RwLock::new(mock.jwks())),
            cfg: mock.config(),
            dev: Some(mock),
        })
    } else {
        // Resolve (issuer, audience, jwks_source) from either the Entra convenience flags or the
        // explicit OIDC flags.
        let resolved = if let (Some(tid), Some(aud)) = (&entra_tenant, &entra_audience) {
            Some((
                format!("https://login.microsoftonline.com/{tid}/v2.0"),
                aud.clone(),
                format!("https://login.microsoftonline.com/{tid}/discovery/v2.0/keys"),
            ))
        } else if let (Some(src), Some(iss), Some(aud)) = (&oidc_jwks, &oidc_issuer, &oidc_audience) {
            Some((iss.clone(), aud.clone(), src.clone()))
        } else {
            None
        };
        match resolved {
            Some((issuer, audience, source)) => match load_jwks(&source).await {
                Ok(jwks) => {
                    tracing::info!("OIDC RBAC enabled (issuer {issuer}, aud {audience})");
                    let jwks_arc = std::sync::Arc::new(std::sync::RwLock::new(jwks));
                    // Key rotation: refresh the JWKS hourly when it came from a URL.
                    if source.starts_with("http") {
                        let arc = jwks_arc.clone();
                        let url = source.clone();
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                                if let Ok(fresh) = load_jwks(&url).await {
                                    *arc.write().unwrap() = fresh;
                                }
                            }
                        });
                    }
                    Some(Auth {
                        jwks: jwks_arc,
                        cfg: acp_core::auth::EntraConfig { issuer, audience },
                        dev: None,
                    })
                }
                Err(e) => {
                    tracing::error!("could not load JWKS from {source}: {e}; refusing to start (auth was requested, failing closed)");
                    std::process::exit(1);
                }
            },
            None => None,
        }
    };
    // Config-driven control-plane store (identity, endpoints; GRC later). The backend is chosen by
    // the --store URL (sqlite / postgres / mysql). Fail closed if it was requested but cannot connect.
    let store = match store_url {
        Some(u) => match crate::store::ControlStore::connect(&u).await {
            Ok(s) => {
                tracing::info!("control-plane store connected");
                Some(std::sync::Arc::new(s))
            }
            Err(e) => {
                tracing::error!("cannot connect --store: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let state = Arc::new(AppState {
        approvals,
        policy,
        ledger,
        liveness: std::sync::Mutex::new(acp_core::liveness::GapDetector::new()),
        spikes: std::sync::Mutex::new(std::collections::HashMap::new()),
        meta,
        registry,
        policy_store,
        enrollment,
        store,
        cp_key,
        break_glass_file,
        break_glass_seed,
        auth,
        report_token,
        events: std::sync::Mutex::new(std::collections::VecDeque::new()),
        scim_users: load_scim_users(scim_users_path.as_deref()),
        node_id: node_id.unwrap_or_else(|| format!("node-{}", rand_hex(6))),
        lease_ttl_ms,
        model_scanner_url,
        model_scan_block,
        webhook_url,
        webhook_secret,
        packs_feed_url,
        threat_feed_url,
        ticket_poll_url,
        slack_webhook_url,
        mlflow_url,
        retrieval_source,
        author_llm_url,
        author_llm_key,
        author_llm_model,
        snapshot_interval_ms,
        snapshot_frameworks,
        approval_sla_ms,
        escalated: std::sync::Mutex::new(std::collections::HashSet::new()),
        lease: std::sync::Mutex::new((false, String::new(), 0)),
    });
    // C1 (HA): restore persisted liveness/spike state so the dead-man's-switch and alert state survive
    // a restart, then start the leader-lease loop (shared-store fencing prevents split-brain).
    if let Some(store) = state.store.clone() {
        restore_control_state(&state, &store).await;
        let st2 = state.clone();
        let node = st2.node_id.clone();
        let ttl = st2.lease_ttl_ms.max(3000);
        tracing::info!("HA leader lease active as node '{node}' (ttl {ttl}ms)");
        tokio::spawn(async move {
            let period = std::time::Duration::from_millis(((ttl / 3).max(1000)) as u64);
            loop {
                match store.try_acquire_leader(&node, now_ms() as i64, ttl).await {
                    Ok((is_leader, holder, token)) => { *st2.lease.lock().unwrap() = (is_leader, holder, token); }
                    Err(e) => tracing::warn!("leader lease error: {e}"),
                }
                // Prune spike-event keys older than the detection window so control_state stays bounded.
                let cutoff = now_ms() as i64 - 300_000;
                if let Ok(rows) = store.list_state_prefix("spike:").await {
                    for (k, _) in rows {
                        if let Some(ts) = k.rsplit(':').next().and_then(|t| t.parse::<i64>().ok()) {
                            if ts < cutoff { let _ = store.delete_state(&k).await; }
                        }
                    }
                }
                tokio::time::sleep(period).await;
            }
        });
    }
    // G5: poll optional signed-pack / threat-pack feeds and load verified content on an interval.
    if let (Some(store), Some(feed)) = (state.store.clone(), state.packs_feed_url.clone()) {
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                if let Ok(resp) = client.get(&feed).send().await {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        if let Some(arr) = v.get("packs").and_then(|p| p.as_array()) {
                            for one in arr {
                                if let Ok(signed) = serde_json::from_value::<acp_core::pack::SignedPack>(one.clone()) {
                                    if acp_core::pack::verify(&signed) {
                                        let p = &signed.pack;
                                        let id = p.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        let version = p.get("version").and_then(|x| x.as_str()).unwrap_or("").to_string();
                                        if !id.is_empty() {
                                            let _ = store.add_pack(&id, &version, &p.to_string(), &signed.pubkey_hex, &signed.sig_hex, now_ms() as i64).await;
                                        }
                                    } else {
                                        tracing::warn!("packs feed: rejected a pack (signature verification failed)");
                                    }
                                }
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }
    if let (Some(store), Some(feed)) = (state.store.clone(), state.threat_feed_url.clone()) {
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                if let Ok(resp) = client.get(&feed).send().await {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        if let Ok(signed) = serde_json::from_value::<acp_core::threatfeed::SignedThreatPack>(v.clone()) {
                            if acp_core::threatfeed::verify(&signed) {
                                let version = signed.pack.get("version").and_then(|x| x.as_i64()).unwrap_or(0);
                                let sigs = signed.pack.get("signatures").cloned().unwrap_or_else(|| serde_json::json!([])).to_string();
                                let _ = store.set_firewall_threat("default", version, &sigs, now_ms() as i64).await;
                            } else {
                                tracing::warn!("threat feed: rejected a pack (signature verification failed)");
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
    }
    // Named MLflow adapter: on start-up, import the model registry into ACP's inventory (idempotent),
    // running each imported model through the same admission scan + signed AI-BOM path as a manual
    // registration. Re-runs on restart; already-present name+version pairs are skipped.
    if let (Some(_store), Some(mlflow)) = (state.store.clone(), state.mlflow_url.clone()) {
        let st2 = state.clone();
        tokio::spawn(async move {
            import_mlflow(&st2, &mlflow).await;
        });
    }
    // M2: poll a ticket-resolution feed and apply each resolution (idempotent), the pull complement to
    // the inbound /tickets/callback.
    if let Some(feed) = state.ticket_poll_url.clone() {
        let st2 = state.clone();
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            loop {
                if let Ok(resp) = client.get(&feed).send().await {
                    if let Ok(v) = resp.json::<serde_json::Value>().await {
                        let items = v.get("resolutions").and_then(|r| r.as_array()).cloned()
                            .or_else(|| v.as_array().cloned()).unwrap_or_default();
                        for item in items {
                            let action = item.get("action").and_then(|x| x.as_str()).unwrap_or("");
                            let id = item.get("id").and_then(|x| x.as_str()).unwrap_or("");
                            let status = item.get("status").and_then(|x| x.as_str());
                            let tenant = item.get("tenant").and_then(|x| x.as_str()).unwrap_or("default");
                            if !action.is_empty() && !id.is_empty() {
                                let _ = apply_ticket_resolution(&st2, action, id, status, tenant).await;
                            }
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }
    // M3: periodic framework-report snapshots + delivery (fires a signed report.snapshot webhook).
    if state.snapshot_interval_ms > 0 && !state.snapshot_frameworks.is_empty() && state.store.is_some() {
        let st2 = state.clone();
        tokio::spawn(async move {
            let interval = std::time::Duration::from_millis(st2.snapshot_interval_ms.max(1000) as u64);
            loop {
                tokio::time::sleep(interval).await;
                if let Some(store) = &st2.store {
                    for name in &st2.snapshot_frameworks {
                        let report = framework_report_value(&st2, "default", name).await;
                        let id = format!("snap-{}", rand_hex(8));
                        if store.add_snapshot(&id, name, "default", &report.to_string(), now_ms() as i64).await.is_ok() {
                            fire_webhook(&st2, "report.snapshot", serde_json::json!({
                                "framework": name, "id": id,
                                "coverage": report.get("coverage"), "controls_summary": report.get("controls_summary"),
                            }));
                        }
                    }
                }
            }
        });
    }
    // M4: escalate approval holds that sit pending past the SLA (one approval.overdue webhook per hold).
    if state.approval_sla_ms > 0 && state.approvals.is_some() {
        let st2 = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let path = match &st2.approvals { Some(p) => p.clone(), None => continue };
                if let Ok(store) = acp_core::approvals::ApprovalStore::open(&path) {
                    if let Ok(ids) = store.list_overdue(st2.approval_sla_ms as u64, now_ms()) {
                        for id in ids {
                            let already = { st2.escalated.lock().unwrap().contains(&id) };
                            if already { continue; }
                            st2.escalated.lock().unwrap().insert(id.clone());
                            fire_webhook(&st2, "approval.overdue", serde_json::json!({"id": id, "sla_ms": st2.approval_sla_ms}));
                        }
                    }
                }
            }
        });
    }
    let app = crate::router::build_router(state);

    // mTLS between components: when TLS flags are given, require a client cert signed by the ACP CA.
    if let (Some(ca), Some(cert), Some(key)) = (&tls_ca, &tls_cert, &tls_key) {
        tracing::error!("listening on https://{addr} (mTLS, client cert required)");
        serve_mtls(&addr, app, ca, cert, key).await;
        return;
    }
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    tracing::info!("listening on http://{addr}");
    // X.7: drain in-flight requests on SIGTERM/Ctrl-C instead of dropping them. The evidence
    // ledger is durable per-append, so a clean drain loses no decision and double-executes none.
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("serve");
}

/// Serve the axum app over mutual TLS: present the server cert and REQUIRE a client cert signed by
/// the ACP CA, so only enrolled components can reach the control API.
async fn serve_mtls(addr: &str, app: Router, ca: &str, cert: &str, key: &str) {
    crate::mtls::ensure_provider();
    let ca = std::fs::read(ca).expect("read tls-ca");
    let cert = std::fs::read(cert).expect("read tls-cert");
    let key = std::fs::read(key).expect("read tls-key");
    let cfg = crate::mtls::server_config(&ca, &cert, &key).expect("mtls server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(t) => t, // handshake fails here for a client with no/bad cert (mutual auth)
                Err(_) => return,
            };
            let io = hyper_util::rt::TokioIo::new(tls);
            let svc = hyper_util::service::TowerToHyperService::new(app);
            let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

/// Resolve when the process is asked to stop, so the server can drain rather than drop.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received, draining in-flight requests");
}
