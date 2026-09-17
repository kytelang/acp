//! The stdio transport shim (M1) with policy enforcement on `tools/call` (M2).
//!
//! Launches the MCP server as a child and relays newline-delimited JSON-RPC transparently.
//! Non-decision frames pass through; `tools/call` is gated by the policy engine when one is
//! loaded; other client-to-server requests are classified by `intercept::decide`.

use crate::approvals::Step;
use crate::evidence::Evidence;
use crate::intercept::{decide, Action, CODE_BLOCKED};
use crate::limits;
use crate::policy::{self, Enforce};
use acp_approvals::ApprovalStore;
use acp_core::types::Verdict;
use acp_jsonrpc::{classify, error_response, inspect, ParsedFrame};
use acp_policy::PolicyEngine;
use serde_json::Value;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub async fn run(
    cmd: &str,
    args: &[String],
    engine: Option<Arc<PolicyEngine>>,
    env: String,
    mut evidence: Option<Evidence>,
    approvals: Option<ApprovalStore>,
) -> anyhow::Result<i32> {
    let agent = "stdio-client".to_string();
    let session = "stdio-session".to_string();
    let principal = "unknown".to_string();
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    let (to_client, mut to_client_rx) = mpsc::channel::<String>(1024);
    let client_writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(line) = to_client_rx.recv().await {
            if out.write_all(line.as_bytes()).await.is_err() || out.write_all(b"\n").await.is_err()
            {
                break;
            }
            let _ = out.flush().await;
        }
    });

    let (to_child, mut to_child_rx) = mpsc::channel::<String>(1024);
    let child_writer = tokio::spawn(async move {
        let mut cin = child_stdin;
        while let Some(line) = to_child_rx.recv().await {
            if cin.write_all(line.as_bytes()).await.is_err() || cin.write_all(b"\n").await.is_err()
            {
                break;
            }
            let _ = cin.flush().await;
        }
    });

    // server -> client: relay verbatim.
    let s2c_out = to_client.clone();
    let s2c = tokio::spawn(async move {
        let mut lines = BufReader::new(child_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if s2c_out.send(line).await.is_err() {
                break;
            }
        }
    });

    // client -> server: classify, enforce, forward or reply.
    let c2s_out = to_client.clone();
    let c2s = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let raw = line.as_bytes();
            let insp = inspect(raw);

            if !limits::within_size(raw) {
                if let Some(id) = &insp.id {
                    let _ = c2s_out
                        .send(error_response(
                            id,
                            CODE_BLOCKED,
                            "message exceeds maximum permitted size",
                        ))
                        .await;
                }
                continue;
            }

            if insp.method.as_deref() == Some("initialize") {
                if let Ok(v) = serde_json::from_slice::<Value>(raw) {
                    if let Some(pv) = v
                        .get("params")
                        .and_then(|p| p.get("protocolVersion"))
                        .and_then(Value::as_str)
                    {
                        eprintln!("acp-proxy: MCP protocolVersion {pv}");
                    }
                }
            }

            // tools/call: gate through the policy engine when one is loaded.
            if insp.is_tool_call {
                if let Some(eng) = &engine {
                    if let ParsedFrame::ToolCall(tc) = classify(raw) {
                        let a = policy::assess(eng, &env, &tc);

                        // Step-up with an approval store: run the D8 approval flow (M4).
                        if a.outcome.verdict == Verdict::StepUp {
                            if let Some(store) = &approvals {
                                match crate::approvals::handle(
                                    store, &session, &principal, &tc, a.impact,
                                ) {
                                    Step::Forward(_view) => {
                                        let did = evidence.as_mut().map(|ev| {
                                            ev.record_decision(
                                                &agent,
                                                &session,
                                                &tc,
                                                &a.outcome,
                                                a.impact,
                                                eng.hash(),
                                            )
                                        });
                                        let ok = to_child.send(line).await.is_ok();
                                        if let (Some(ev), Some(did)) =
                                            (evidence.as_mut(), did.as_ref())
                                        {
                                            ev.record_outcome(
                                                did,
                                                if ok { "forwarded" } else { "not_executed" },
                                            );
                                        }
                                        if !ok {
                                            break;
                                        }
                                    }
                                    Step::Held(json) => {
                                        let _ = c2s_out.send(json).await;
                                    }
                                    Step::Denied(json) => {
                                        let did = evidence.as_mut().map(|ev| {
                                            ev.record_decision(
                                                &agent,
                                                &session,
                                                &tc,
                                                &a.outcome,
                                                a.impact,
                                                eng.hash(),
                                            )
                                        });
                                        let _ = c2s_out.send(json).await;
                                        if let (Some(ev), Some(did)) =
                                            (evidence.as_mut(), did.as_ref())
                                        {
                                            ev.record_outcome(did, "not_executed");
                                        }
                                    }
                                }
                                continue;
                            }
                        }

                        // record-before-forward (durable spool fsync happens inside record_decision)
                        let did = evidence.as_mut().map(|ev| {
                            ev.record_decision(
                                &agent,
                                &session,
                                &tc,
                                &a.outcome,
                                a.impact,
                                eng.hash(),
                            )
                        });
                        match a.enforce {
                            Enforce::Forward => {
                                let ok = to_child.send(line).await.is_ok();
                                if let (Some(ev), Some(did)) = (evidence.as_mut(), did.as_ref()) {
                                    ev.record_outcome(
                                        did,
                                        if ok { "forwarded" } else { "not_executed" },
                                    );
                                }
                                if !ok {
                                    break;
                                }
                            }
                            Enforce::Reply(json) => {
                                let _ = c2s_out.send(json).await;
                                if let (Some(ev), Some(did)) = (evidence.as_mut(), did.as_ref()) {
                                    ev.record_outcome(did, "not_executed");
                                }
                            }
                        }
                        continue;
                    }
                }
                if to_child.send(line).await.is_err() {
                    break;
                }
                continue;
            }

            match decide(&insp) {
                Action::Forward => {
                    if to_child.send(line).await.is_err() {
                        break;
                    }
                }
                Action::Deny { code, message } => {
                    let id = insp.id.clone().unwrap_or(Value::Null);
                    let _ = c2s_out.send(error_response(&id, code, &message)).await;
                }
            }
        }
    });

    drop(to_client);
    let _ = c2s.await;
    let status = child.wait().await?;
    let _ = s2c.await;
    let _ = child_writer.await;
    let _ = client_writer.await;
    Ok(status.code().unwrap_or(0))
}
