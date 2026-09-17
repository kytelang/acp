//! The stdio transport shim (M1.1 to M1.5).
//!
//! Launches the real MCP server as a child process and sits transparently between the MCP
//! client (this process's stdin/stdout) and the server (the child's stdin/stdout). Messages are
//! newline-delimited JSON-RPC, per the MCP stdio transport. Non-decision frames are relayed
//! verbatim; the client-to-server direction is classified by `intercept::decide`.

use crate::intercept::{decide, Action, CODE_BLOCKED};
use crate::limits;
use acp_jsonrpc::{error_response, inspect};
use serde_json::Value;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub async fn run(cmd: &str, args: &[String]) -> anyhow::Result<i32> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    // One writer to the client (our stdout); deny responses and relayed server frames funnel
    // through here so lines never interleave mid-message.
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

    // One writer to the child (tool server) stdin.
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

    // server -> client: relay every frame verbatim.
    let s2c_out = to_client.clone();
    let s2c = tokio::spawn(async move {
        let mut lines = BufReader::new(child_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if s2c_out.send(line).await.is_err() {
                break;
            }
        }
    });

    // client -> server: classify, then forward or deny.
    let c2s_out = to_client.clone();
    let c2s = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let raw = line.as_bytes();
            let insp = inspect(raw);

            // Resource limit (M1.5): fail-closed on oversize.
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

            // Record the MCP protocol version the interception was verified against (M1.4).
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

    drop(to_client); // writers close once the two relay tasks drop their clones

    // Client closed its stream -> stop forwarding -> child sees EOF -> child exits.
    let _ = c2s.await;
    let status = child.wait().await?;
    let _ = s2c.await;
    let _ = child_writer.await;
    let _ = client_writer.await;
    Ok(status.code().unwrap_or(0))
}
