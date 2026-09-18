//! The stdio transport (M1) driving the shared `Controller` (M2/M3/M4/M5.3).
//!
//! Launches the MCP server as a child and relays newline-delimited JSON-RPC transparently. Each
//! client-to-server frame goes through `Controller::decide_frame`; server-to-client frames relay
//! verbatim. Tool-to-proxy binding is structural here (D10): the child's stdio is owned by the
//! proxy, so the agent cannot reach the tool server out of band.

use crate::dispatch::{Controller, FrameAction};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub async fn run(cmd: &str, args: &[String], controller: Arc<Controller>) -> anyhow::Result<i32> {
    // R5: never orphan the child tool server. kill_on_drop guarantees it is torn down on every
    // exit path from run() (normal return, early error, or panic), so a proxy shutdown does not
    // leave a tool server running un-governed. Held approvals are parked durably in the SQLite
    // approval store, so they survive a restart independently of the child process.
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
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

    let s2c_out = to_client.clone();
    let s2c = tokio::spawn(async move {
        let mut lines = BufReader::new(child_stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if s2c_out.send(line).await.is_err() {
                break;
            }
        }
    });

    let c2s_out = to_client.clone();
    let c2s = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match controller.decide_frame(line.as_bytes()) {
                FrameAction::Forward => {
                    if to_child.send(line).await.is_err() {
                        break;
                    }
                }
                FrameAction::Reply(json) => {
                    let _ = c2s_out.send(json).await;
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
