//! The issuer as it is started: the binary itself, with its files.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use base64::Engine;
use hidravpn_core::http::{call, Url};
use hidravpn_core::pass::{self, IssueRequest, IssueResponse, PassKeyRecord};
use hidravpn_core::payment::{self, ClaimRequest, QuoteRequest};
use sha2::{Digest, Sha256};

const ISSUER: &str = env!("CARGO_BIN_EXE_hidravpn-issuer");
const WALLET: &str = "So11111111111111111111111111111111111111112";

fn issuer(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(ISSUER);
    c.arg("--accounts")
        .arg(dir.join("accounts.json"))
        .arg("--orders")
        .arg(dir.join("orders.json"))
        .args(args);
    c
}

fn output(dir: &Path, args: &[&str]) -> String {
    let out = issuer(dir, args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A running issuer, stopped when dropped.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn post(port: u16, path: &str, body: &str) -> (u16, String) {
    let url = Url::parse(&format!("http://127.0.0.1:{port}"))
        .unwrap()
        .with_path(path);
    call(&url, "POST", body).await.unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hidravpn-issuer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn an_orders_file_that_cannot_be_read_at_the_start_stops_the_sales_only() {
    let dir = scratch("unread-start");
    let key = dir.join("key.json");
    let record: PassKeyRecord =
        serde_json::from_str(&output(&dir, &["keygen", "--out", key.to_str().unwrap()])).unwrap();
    let token = output(&dir, &["account", "add", "--name", "a", "--quota", "5"])
        .trim()
        .to_string();
    let corrupt = b"not json".to_vec();
    std::fs::write(dir.join("orders.json"), &corrupt).unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = issuer(
        &dir,
        &[
            "run",
            "--key",
            key.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--pay-wallet",
            WALLET,
            "--pay-pack",
            "10=50",
            // Never asked: no claim gets as far as the chain here.
            "--pay-rpc",
            "http://127.0.0.1:9",
        ],
    )
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let stderr = child.stderr.take().unwrap();
    let running = Running(child);
    let log = std::thread::spawn(move || std::io::read_to_string(stderr).unwrap_or_default());
    let mut up = false;
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "the issuer did not start");

    // It signs for the account, as ever.
    let issuer_key = record.issuer_key().unwrap();
    let node = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let (blinded, pending) = pass::prepare(&issuer_key, &node).unwrap();
    let body = serde_json::to_string(&IssueRequest {
        token: token.clone(),
        key_id: record.id.clone(),
        blinded: vec![blinded],
    })
    .unwrap();
    let (st, answer) = post(port, "/issue", &body).await;
    assert_eq!(st, 200, "{answer}");
    let r: IssueResponse = serde_json::from_str(&answer).unwrap();
    pending.finalize(&issuer_key, &r.signatures[0]).unwrap();

    // A quote and a claim say what is wrong.
    let quote = serde_json::to_string(&QuoteRequest {
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        passes: 10,
    })
    .unwrap();
    let (st, answer) = post(port, "/quote", &quote).await;
    assert!(st == 503 && answer.contains("orders"), "{st} {answer}");
    let claim = serde_json::to_string(&ClaimRequest {
        token: token.clone(),
        signature: payment::base58_encode(&[7; 64]),
    })
    .unwrap();
    let (st, answer) = post(port, "/claim", &claim).await;
    assert!(st == 503 && answer.contains("orders"), "{st} {answer}");

    // The file is left as it was, for the operator to mend: nothing wrote
    // an empty one over the record of the orders paid.
    assert_eq!(std::fs::read(dir.join("orders.json")).unwrap(), corrupt);

    // Mended (here: no file, which is no orders yet), it sells again.
    std::fs::remove_file(dir.join("orders.json")).unwrap();
    let (st, answer) = post(port, "/quote", &quote).await;
    assert_eq!(st, 200, "{answer}");

    drop(running);
    let log = log.join().unwrap();
    assert!(log.contains("selling is stopped"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
