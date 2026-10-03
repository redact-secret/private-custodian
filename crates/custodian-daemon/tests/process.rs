//! The `custodiand` binary as a real process: argument handling, a start from
//! a file configuration over a real deployment (store, corpus, Git ledger,
//! isolated signer socket), the health check, a signed delivery that queues
//! durably, `SIGTERM` and `SIGINT` shutdown, and a restart that finds the
//! queued work still there. GitHub access is `disabled` in this configuration,
//! so nothing contacts anything. Synthetic only.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::stack::SignerHost;
use common::*;
use custodian_contracts::types::KeyId;
use custodian_ledger::{GitBackend, GitConfig, SignDomain};
use custodian_store::SqliteStore;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde_json::json;

const BIN: &str = env!("CARGO_BIN_EXE_custodiand");

fn run_args(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN).env_clear().args(args).output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn arguments_fail_closed_with_fixed_codes_and_no_stdout() {
    let (code, out, err) = run_args(&["--version"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("custodiand "), "{out}");
    assert_eq!(err, "");
    for args in [
        &[][..],
        &["bogus"],
        &["run"],
        &["check-config"],
        &["run", "--config"],
    ] {
        let (code, out, err) = run_args(args);
        assert!(code == 2 || code == 7, "{args:?} -> {code}");
        assert_eq!(out, "");
        for line in err.lines() {
            assert!(line.starts_with("component=daemon code="), "{line}");
        }
    }
    let (code, out, err) = run_args(&[
        "check-config",
        "--config",
        "/nonexistent/synthetic/path.json",
    ]);
    assert_eq!((code, out.as_str()), (7, ""));
    assert_eq!(err.trim(), "component=daemon code=not_configured");
    assert!(!err.contains("nonexistent"), "a path is never printed");
}

// ---- a real deployment on disk ---------------------------------------------------

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=test", "-c", "user.email=test@invalid"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success());
}

fn put(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn dir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct Deploy {
    root: PathBuf,
    daemon_config: PathBuf,
    store: PathBuf,
    port: u16,
    secret: Vec<u8>,
    _corpus: lc::corpus::Fixture,
    _signer: SignerHost,
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn deploy(label: &str) -> Deploy {
    let root = std::env::temp_dir().join(format!("pcd-proc-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    dir(&root, 0o700);

    // The isolated signer, on the system clock (the binary uses it too).
    let key_id = KeyId::parse(&cc::id("key_", 1)).unwrap();
    let mut signer = SignerHost::new(
        &key_id,
        &root.join("signer"),
        std::sync::Arc::new(custodian_signer::SystemClock),
    );
    signer.up();
    let corpus = lc::corpus::Fixture::new();
    corpus.seal_active(&[("one", b"synthetic-one")]);

    // A bare remote and a working clone for the ledger.
    let remote = root.join("remote.git");
    dir(&remote, 0o700);
    git(&remote, &["init", "--bare", "-q"]);
    let ledger = root.join("ledger");
    dir(&ledger, 0o700);
    GitBackend::init(&ledger, remote.to_str().unwrap(), GitConfig::default()).unwrap();

    put(
        &root.join("operator-policy.json"),
        &serde_json::to_vec(&base::policy_json(1, 4_000_000_000)).unwrap(),
        0o600,
    );
    let roots = json!({"roots": [{
        "key_id": key_id,
        "public_key_hex": signer.engine.public_key_hex(),
        "purposes": SignDomain::ALL.iter().map(|d| d.tag()).collect::<Vec<_>>(),
        "valid_from": 1
    }]});
    put(
        &root.join("roots.json"),
        &serde_json::to_vec(&roots).unwrap(),
        0o600,
    );
    let store = root.join("state").join("store.db");
    let deployment = json!({
        "schema": "private-custodian.cli-config/1",
        "store_path": store,
        "operator_policy_path": root.join("operator-policy.json"),
        "corpus_root": corpus.root(),
        "ledger_dir": ledger,
        "pinned_roots_path": root.join("roots.json"),
        "feed_dir": root.join("feed"),
        "feed_id": cc::id("fed_", 1),
        "feed_destination_label": "public-feed",
        "commitment_key_id": cc::id("key_", 2),
        "signer_key_id": key_id,
        "signer_socket_path": signer.sock,
    });
    put(
        &root.join("deployment.json"),
        &serde_json::to_vec(&deployment).unwrap(),
        0o600,
    );

    put(
        &root.join("intake.json"),
        &serde_json::to_vec(&intake_json()).unwrap(),
        0o600,
    );
    let secret = custodian_intake::testing::random_bytes(32);
    put(&root.join("webhook.secret"), &secret, 0o600);
    put(
        &root.join("policy.json"),
        &serde_json::to_vec(&dc::policy_json()).unwrap(),
        0o644,
    );
    for d in ["requests", "artifacts", "approvals"] {
        dir(&root.join(d), 0o755);
    }
    for d in ["staging", "released"] {
        dir(&root.join(d), 0o700);
    }
    let port = free_port();
    let cfg = json!({
        "schema": "private-custodian.daemon-config/1",
        "deployment_config_path": root.join("deployment.json"),
        "intake": {
            "config_path": root.join("intake.json"),
            "webhook_secret_path": root.join("webhook.secret")
        },
        "listener": {"bind": format!("127.0.0.1:{port}"), "path": "/webhooks/github"},
        "github": {"mode": "disabled"},
        "requests_dir": root.join("requests"),
        "artifacts_dir": root.join("artifacts"),
        "worker": {"sandbox": "none", "staging_dir": root.join("staging")},
        "release": {
            "disclosure_policy_path": root.join("policy.json"),
            "policy_activation": {"activation_id": cc::id("pac_", 2), "sequence": 1},
            "destination": DEST,
            "approvals_dir": root.join("approvals"),
            "output_dir": root.join("released")
        },
        "attestation": {"authorship": "project_authored", "review": "project_reviewed"},
        "pipeline": {"poll_ms": 50, "shutdown_grace_secs": 1}
    });
    put(
        &root.join("daemon.json"),
        &serde_json::to_vec(&cfg).unwrap(),
        0o600,
    );
    Deploy {
        daemon_config: root.join("daemon.json"),
        root,
        store,
        port,
        secret,
        _corpus: corpus,
        _signer: signer,
    }
}

impl Drop for Deploy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn spawn(d: &Deploy) -> Child {
    Command::new(BIN)
        .env_clear()
        .args(["run", "--config", d.daemon_config.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn http(port: u16, raw: &[u8]) -> (u16, String) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(raw).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, text)
}

fn wait_healthy(child: &mut Child, port: u16) {
    let end = Instant::now() + Duration::from_secs(30);
    while Instant::now() < end {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            let _ = child.stderr.take().unwrap().read_to_string(&mut err);
            panic!("the daemon exited early ({status}): {err}");
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok()
            && http(port, b"GET /healthz HTTP/1.1\r\n\r\n").0 == 200
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the daemon never became healthy");
}

fn webhook(d: &Deploy, event: &str, delivery: u64, body: &[u8]) -> (u16, String) {
    let sig = custodian_intake::signature::sign_body(
        &custodian_intake::config::WebhookSecret::new(d.secret.clone()).unwrap(),
        body,
    );
    let mut raw = format!(
        "POST /webhooks/github HTTP/1.1\r\nContent-Type: application/json\r\n\
         X-Hub-Signature-256: {sig}\r\nX-GitHub-Event: {event}\r\n\
         X-GitHub-Delivery: {}\r\nContent-Length: {}\r\n\r\n",
        uuid(delivery),
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    http(d.port, &raw)
}

fn stop(mut child: Child, signal: Signal) -> String {
    kill(Pid::from_raw(i32::try_from(child.id()).unwrap()), signal).unwrap();
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "a signalled daemon exits cleanly: {status}"
            );
            break;
        }
        assert!(
            Instant::now() < end,
            "the daemon did not stop on {signal:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut out = String::new();
    let mut err = String::new();
    let _ = child.stdout.take().unwrap().read_to_string(&mut out);
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    assert_eq!(out, "", "stdout carries nothing");
    err
}

#[test]
fn the_binary_serves_queues_durably_and_stops_cleanly_on_sigterm_and_sigint() {
    let d = deploy("serve");
    // check-config accepts the complete file.
    let (code, _, err) = run_args(&[
        "check-config",
        "--config",
        d.daemon_config.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{err}");

    // First life.
    let mut child = spawn(&d);
    wait_healthy(&mut child, d.port);
    let (status, resp) = webhook(&d, "ping", 1, b"{\"zen\":\"synthetic\"}");
    assert_eq!(status, 200, "{resp}");
    assert!(resp.ends_with("{\"code\":\"ignored\"}"));
    // A forged delivery is refused; a genuine one queues (GitHub access is
    // disabled, so it waits, durably).
    let (status, resp) = http(
        d.port,
        b"POST /webhooks/github HTTP/1.1\r\nContent-Type: application/json\r\n\
          X-Hub-Signature-256: sha256=00\r\nX-GitHub-Event: ping\r\n\
          X-GitHub-Delivery: 00000000-0000-4000-8000-0000000000bb\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert_eq!(status, 401, "{resp}");
    let body = serde_json::to_vec(&pr_payload("opened", REQUESTER_USER, "User", 'a')).unwrap();
    let (status, resp) = webhook(&d, "pull_request", 2, &body);
    assert_eq!(
        (status, resp.ends_with("{\"code\":\"queued\"}")),
        (202, true),
        "{resp}"
    );
    let err = stop(child, Signal::SIGTERM);
    for line in err.lines() {
        assert!(
            line.starts_with("component="),
            "only fixed component/code lines: {line}"
        );
    }
    assert!(err.contains("component=runtime code=started"), "{err}");
    assert!(err.contains("component=runtime code=stopped"), "{err}");
    assert!(
        err.contains("component=runtime code=queue_not_consumed"),
        "{err}"
    );
    assert!(
        !err.contains("SYNTHETIC HOSTILE"),
        "no request text is ever logged"
    );
    // The port is released.
    assert!(TcpStream::connect(("127.0.0.1", d.port)).is_err());

    // The queued delivery survived; the store is intact.
    {
        let s = SqliteStore::open(&d.store).unwrap();
        assert_eq!(s.queue_depth().unwrap(), 1);
        s.integrity_check().unwrap();
    }

    // Second life, stopped with SIGINT: the same delivery is a replay.
    let mut child = spawn(&d);
    wait_healthy(&mut child, d.port);
    let (status, resp) = webhook(&d, "pull_request", 2, &body);
    assert_eq!(
        (status, resp.ends_with("{\"code\":\"delivery_replay\"}")),
        (409, true),
        "{resp}"
    );
    let err = stop(child, Signal::SIGINT);
    assert!(err.contains("component=runtime code=stopped"), "{err}");
    assert_eq!(
        SqliteStore::open(&d.store).unwrap().queue_depth().unwrap(),
        1
    );
}

#[test]
fn a_start_that_cannot_pass_the_startup_sequence_exits_without_binding() {
    let d = deploy("refuse");
    // The signer is gone: the startup export cannot sign its checkpoints, the
    // startup sequence refuses (there is no flag that skips it), and no port
    // is ever bound.
    let mut d = d;
    d._signer.down();
    let mut child = spawn(&d);
    let end = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < end, "it should have exited");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        status.code(),
        Some(8),
        "startup refusal has its own exit code"
    );
    assert!(TcpStream::connect(("127.0.0.1", d.port)).is_err());
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    assert!(err.contains("component=startup code=export"), "{err}");
    assert!(err.contains("code=startup_refused"), "{err}");
}
