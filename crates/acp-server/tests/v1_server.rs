//! v1.1: the acp-server control service - web approval inbox, /policy/current, /verify.

use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const SERVER: &str = env!("CARGO_BIN_EXE_acp-server");
const TMP: &str = env!("CARGO_TARGET_TMPDIR");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
async fn wait(addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server not listening on {addr}");
}
struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[tokio::test]
async fn control_service_inbox_and_endpoints() {
    let approvals = format!("{TMP}/v1.approvals");
    let ledger = format!("{TMP}/v1.db");
    let policy = format!("{TMP}/v1-policy.yaml");
    for f in [
        &approvals,
        &ledger,
        &format!("{approvals}-wal"),
        &format!("{approvals}-shm"),
        &format!("{ledger}-wal"),
        &format!("{ledger}-shm"),
    ] {
        let _ = std::fs::remove_file(f);
    }
    std::fs::write(&policy, "version: 1\ndefault: allow\nrules: []\n").unwrap();

    // Seed a pending approval and a small verifiable ledger.
    let store = acp_approvals::ApprovalStore::open(&approvals).unwrap();
    store
        .request(
            "appr-1",
            "sess",
            "alice",
            "payments.charge",
            "h1",
            &json!({"tool":"payments.charge","impact":"high"}),
            900_000,
        )
        .unwrap();
    drop(store);
    {
        let mut l =
            acp_ledger::Ledger::open(&ledger, Box::new(acp_core::sign::Ed25519Signer::generate()))
                .unwrap();
        l.append(
            "d1",
            "decision",
            &json!({"type":"decision","tool":"x"}),
            None,
        )
        .unwrap();
    }

    let addr = format!("127.0.0.1:{}", free_port());
    let child = Command::new(SERVER)
        .args([
            "--addr",
            &addr,
            "--approvals",
            &approvals,
            "--policy",
            &policy,
            "--ledger",
            &ledger,
        ])
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let _k = Kill(child);
    wait(&addr).await;
    let base = format!("http://{addr}");
    let c = reqwest::Client::new();

    // health
    assert_eq!(
        c.get(format!("{base}/healthz"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );

    // inbox shows the pending approval's tool
    let inbox = c.get(&base).send().await.unwrap().text().await.unwrap();
    assert!(
        inbox.contains("payments.charge"),
        "inbox must list the pending approval"
    );
    assert!(inbox.contains("appr-1"));

    // /policy/current returns the hash
    let pc: Value = c
        .get(format!("{base}/policy/current"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(pc["hash"].as_str().unwrap().len() >= 32);

    // /verify on a clean ledger
    let v: Value = c
        .get(format!("{base}/verify"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["ok"], json!(true));

    // web approve resolves the approval in the shared store
    let r = c
        .post(format!("{base}/approvals/appr-1/approve"))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success() || r.status().is_redirection());
    let store = acp_approvals::ApprovalStore::open(&approvals).unwrap();
    let view = store.get("appr-1").unwrap().unwrap();
    assert_eq!(view.state, "approved");
    assert_eq!(view.approver.as_deref(), Some("web-user"));
}
