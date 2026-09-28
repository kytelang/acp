//! Background tasks for the control plane: restore persisted liveness/spike state on start, run
//! the HA leader lease, poll the optional pack / threat / ticket feeds, import MLflow, snapshot
//! framework reports, and escalate overdue approvals. All are best-effort and never block serving.
use crate::state::AppState;
use crate::common::*;
use crate::handlers::models::admission_scan;
use crate::handlers::tickets::apply_ticket_resolution;
use crate::handlers::reports::framework_report_value;
use std::sync::Arc;

/// Spawn every periodic background task, reading its configuration from the shared state.
pub(crate) async fn spawn_background(state: &Arc<AppState>) {
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
}

pub(crate) async fn restore_control_state(st: &Arc<AppState>, store: &crate::store::ControlStore) {
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

/// Named MLflow adapter: fetch the registry, map latest versions, and register any not already in the
/// ACP inventory (tenant "default"). Uses the normal admission-scan + signed AI-BOM path so imported
/// models are governed exactly like manually registered ones. Idempotent by (name, version).
pub(crate) async fn import_mlflow(st: &Arc<AppState>, mlflow_url: &str) {
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
