//! The whole synthetic stack, in one process, with real components where the
//! issue asks for them: the real HTTP listener on an ephemeral loopback port,
//! the real `Intake`, the durable queue and store, the real consumer, the
//! real isolated-signer process logic behind a real Unix socket, a real local
//! Git ledger (a bare repository on disk), a directory feed, the GitHub
//! adapters over an offline fake served on loopback, and the daemon's own
//! `runtime::run`. The sandbox is the UNSANDBOXED test fake running the real
//! synthetic engine binary, so nothing here is evidence of isolation.
//!
//! Functional verification on public synthetic data with test-generated keys;
//! not an independent protected evaluation.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use custodian_cli::{Command as Cmd, Control, Output, Parts};
use custodian_contracts::types::{KeyId, Timestamp};
use custodian_corpus::testing::TempRoot;
use custodian_corpus::FsEpochStore;
use custodian_daemon::config::DaemonConfig;
use custodian_daemon::github::plain::PlainHttp;
use custodian_daemon::github::testing::FakeGithub;
use custodian_daemon::github::{GithubAdapters, GithubApi, Rs256Signer};
use custodian_daemon::pipeline::approvals::DirApprovals;
use custodian_daemon::pipeline::NoPipelineFault;
use custodian_daemon::runtime::{run, ExitReport, RunInputs};
use custodian_daemon::source::{DirRequestSource, DirStager};
use custodian_daemon::{DaemonReason, Shutdown};
use custodian_intake::credentials::RequestFacingAppCredential;
use custodian_intake::ids::AppId;
use custodian_intake::signature::sign_body;
use custodian_intake::testing::random_bytes;
use custodian_ledger::{GitBackend, GitConfig, KeyEntry, Keyring, RemoteSigner, SignDomain};
use custodian_lifecycle::{DirFeed, NoFault};
use custodian_signer::{
    start, FileKeyProvider, RunningServer, ServerConfig, SignerSetup, SigningEngine,
    UnixSocketTransport,
};
use custodian_store::{Clock, StoreConfig};
use serde_json::json;

use super::*;

pub const GITHUB_APP_ID: u64 = 123_456;

/// The signer's clock is the test's: payloads are stamped with the harness
/// time, and the signer refuses a payload dated in its own future.
pub struct TestClock(pub Arc<custodian_store::ManualClock>);

impl custodian_signer::Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.0.now()
    }
}

/// A real isolated-signer server on a Unix socket in a private directory.
pub struct SignerHost {
    pub dir: PathBuf,
    pub sock: PathBuf,
    pub engine: Arc<SigningEngine>,
    pub server: Option<RunningServer>,
    pub setup: SignerSetup,
}

impl SignerHost {
    pub fn new(key_id: &KeyId, dir: &Path, clock: Arc<dyn custodian_signer::Clock>) -> Self {
        private_dir(dir);
        let key_path = dir.join("k");
        // A restarted stack keeps its key.
        if !key_path.exists() {
            let mut seed = [0u8; 32];
            std::fs::File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut seed)
                .unwrap();
            let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
            std::fs::write(&key_path, hex).unwrap();
            set_mode(&key_path, 0o600);
        }
        let setup = SignerSetup {
            key_id: key_id.clone(),
            purposes: SignDomain::ALL.into_iter().collect::<BTreeSet<_>>(),
            valid_from: 1,
            not_after: None,
            max_request_skew_secs: 120,
        };
        let engine = Arc::new(
            SigningEngine::new(
                &FileKeyProvider::new(key_path),
                setup.clone(),
                clock,
                custodian_signer::silent_sink(),
            )
            .unwrap(),
        );
        // A Unix socket path is short-limited (104 bytes on macOS), so the
        // socket lives in its own short private directory.
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let sock_dir = std::env::temp_dir().join(format!(
            "pcd-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&sock_dir);
        private_dir(&sock_dir);
        Self {
            sock: sock_dir.join("s"),
            dir: dir.to_path_buf(),
            engine,
            server: None,
            setup,
        }
    }

    pub fn up(&mut self) {
        self.server = Some(
            start(
                ServerConfig {
                    socket_path: self.sock.clone(),
                    allowed_peer_uid: custodian_signer::effective_uid(),
                    io_timeout: Duration::from_secs(3),
                    max_concurrent: 4,
                },
                self.engine.clone(),
            )
            .unwrap(),
        );
    }

    pub fn down(&mut self) {
        if let Some(s) = self.server.take() {
            s.shutdown();
        }
    }
}

impl Drop for SignerHost {
    fn drop(&mut self) {
        self.down();
        if let Some(d) = self.sock.parent() {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=test", "-c", "user.email=test@invalid"])
        .args(["-c", "commit.gpgsign=false"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(args)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?} failed");
}

/// Everything a scenario needs to drive and to inspect the stack.
pub struct Stack<'a> {
    pub env: &'a Env,
    pub addr: SocketAddr,
    pub fake: FakeGithub,
    pub secret: Vec<u8>,
    pub parts: Parts<'a, FsEpochStore>,
    pub ledger: &'a GitBackend,
    pub remote: PathBuf,
    pub feed: &'a DirFeed,
    pub roots: &'a Keyring,
    pub signer: &'a Mutex<SignerHost>,
    pub shutdown: Shutdown,
    pub key_dir: PathBuf,
    pub root: PathBuf,
}

impl Stack<'_> {
    /// POST a correctly signed `pull_request` event for `number` from the
    /// requester over the real listener. Returns (status, code).
    pub fn webhook(&self, delivery: u64, number: u64, head: char) -> (u16, String) {
        let mut payload = pr_payload("opened", REQUESTER_USER, "User", head);
        payload["pull_request"]["number"] = json!(number);
        let body = serde_json::to_vec(&payload).unwrap();
        let sig = sign_body(
            &custodian_intake::config::WebhookSecret::new(self.secret.clone()).unwrap(),
            &body,
        );
        let req = format!(
            "POST /webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
             X-Hub-Signature-256: {sig}\r\nX-GitHub-Event: pull_request\r\n\
             X-GitHub-Delivery: {}\r\nContent-Length: {}\r\n\r\n",
            uuid(delivery),
            body.len()
        );
        self.send(req.as_bytes(), &body)
    }

    pub fn send(&self, head: &[u8], body: &[u8]) -> (u16, String) {
        let mut s = TcpStream::connect(self.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(head).unwrap();
        s.write_all(body).unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let text = String::from_utf8_lossy(&out).into_owned();
        let status = text
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let code = text
            .rsplit("\r\n\r\n")
            .next()
            .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
            .and_then(|v| v["code"].as_str().map(str::to_owned))
            .unwrap_or_default();
        (status, code)
    }

    /// A command on the real control plane (the CLI service path), as `who`.
    pub fn control(&self, who: Who, cmd: &Cmd) -> Output {
        let principal = self
            .env
            .p
            .w
            .authority
            .authenticate(
                &who.actor(),
                &who.token(),
                Timestamp::new(self.env.p.w.clock.now()).unwrap(),
            )
            .unwrap();
        Control::new(self.parts.clone()).execute(&principal, cmd, false)
    }

    /// Poll until `f` holds (the daemon runs on its own thread).
    pub fn wait_for(&self, what: &str, f: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(30);
        while Instant::now() < end {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {what}");
    }

    pub fn run_step(
        &self,
        attempt: &custodian_core::RunId,
    ) -> Option<custodian_store::PipelineStep> {
        self.env
            .store()
            .pipeline_run(attempt)
            .unwrap()
            .map(|r| r.step)
    }

    pub fn run_reason(&self, attempt: &custodian_core::RunId) -> String {
        self.env
            .store()
            .pipeline_run(attempt)
            .unwrap()
            .map(|r| r.reason)
            .unwrap_or_default()
    }
}

struct StopOnDrop(Shutdown);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.request();
    }
}

/// Build the stack around `env`, run the daemon on its own thread, give the
/// scenario `f`, then shut the daemon down and return its exit.
pub fn with_stack<R>(
    env: &Env,
    f: impl FnOnce(&Stack<'_>) -> R,
) -> (R, Result<ExitReport, DaemonReason>) {
    let root = TempRoot::new();
    with_stack_in(env, root.path(), true, f)
}

/// Like `with_stack` over a directory that outlives the call (so a second
/// call is a restart: same signer key, same ledger, same feed), and with the
/// queue consumed or not.
pub fn with_stack_in<R>(
    env: &Env,
    root: &Path,
    consume_queue: bool,
    f: impl FnOnce(&Stack<'_>) -> R,
) -> (R, Result<ExitReport, DaemonReason>) {
    let key_id = KeyId::parse(&cc::id("key_", 1)).unwrap();
    let signer_clock: Arc<dyn custodian_signer::Clock> = Arc::new(TestClock(env.p.w.clock.clone()));
    let mut host = SignerHost::new(&key_id, &root.join("signer"), signer_clock.clone());
    host.up();
    let roots = Keyring::new().with_root(
        KeyEntry::root(
            key_id.clone(),
            &host.engine.public_key_hex(),
            SignDomain::ALL,
            Timestamp::new(1).unwrap(),
        )
        .unwrap(),
    );
    let sock = host.sock.clone();
    let host = Mutex::new(host);

    // A real local Git ledger: a bare repository and a working clone.
    let remote = root.join("remote.git");
    std::fs::create_dir_all(&remote).unwrap();
    git(&remote, &["init", "--bare", "-q"]);
    let ledger_dir = root.join("ledger");
    std::fs::create_dir_all(&ledger_dir).unwrap();
    let ledger =
        GitBackend::init(&ledger_dir, remote.to_str().unwrap(), GitConfig::default()).unwrap();
    let feed = DirFeed::new(root.join("feed"));
    private_dir(&root.join("feed"));
    let signer = RemoteSigner::new(
        key_id.clone(),
        UnixSocketTransport::new(sock, Duration::from_secs(3)).with_clock(signer_clock.clone()),
    );

    let w = &env.p.w;
    let parts = Parts {
        store: env.store(),
        clock: w.clock.clone(),
        authority: &w.authority,
        populations: &w.rw.fx.pop,
        ledger: &ledger,
        roots: &roots,
        signer: &signer,
        feed_destination: &feed,
        feed_populations: &w.pubs,
        feed_config: w.parts().feed_config.clone(),
        fault: &NoFault,
    };

    // The GitHub side: an offline fake behind loopback, the RS256 App key
    // generated for this run (never written outside a private directory).
    let fake = FakeGithub::new(&sha40('a'));
    let server = fake.serve();
    let key_dir = root.join("app");
    private_dir(&key_dir);
    let key_path = key_dir.join("app.pem");
    if !key_path.exists() {
        let out = Command::new("openssl")
            .args(["genrsa", "-out", key_path.to_str().unwrap(), "2048"])
            .output()
            .expect("openssl is required by this test");
        assert!(out.status.success());
    }
    set_mode(&key_path, 0o600);
    let http = Arc::new(PlainHttp::loopback(server.addr, Duration::from_secs(5)).unwrap());
    let adapters = GithubAdapters::build(
        RequestFacingAppCredential::new(
            AppId::new(GITHUB_APP_ID).unwrap(),
            Box::new(Rs256Signer::from_pem_file(&key_path).unwrap()),
        ),
        Arc::new(GithubApi::new(http.clone())),
        http,
        intake_config(),
        w.clock.clone(),
    );

    let secret = random_bytes(32);
    let cfg = DaemonConfig::from_json(
        &serde_json::to_vec(&json!({
            "schema": "private-custodian.daemon-config/1",
            "deployment_config_path": root.join("deployment.json"),
            "intake": {
                "config_path": root.join("intake.json"),
                "webhook_secret_path": root.join("webhook.secret")
            },
            "listener": {"bind": "127.0.0.1:0", "path": "/webhooks/github"},
            "github": {
                "mode": "loopback_http", "app_id": GITHUB_APP_ID,
                "app_private_key_path": key_path, "loopback_addr": server.addr.to_string()
            },
            "requests_dir": env.requests_dir,
            "artifacts_dir": env.art_dir,
            "worker": {"sandbox": "none", "staging_dir": env.p.arts.staging},
            "release": {
                "disclosure_policy_path": root.join("policy.json"),
                "policy_activation": {"activation_id": cc::id("pac_", 2), "sequence": 1},
                "destination": DEST,
                "approvals_dir": env.approvals_dir,
                "output_dir": env.out_dir
            },
            "attestation": {"authorship": "project_authored", "review": "project_reviewed"},
            "required_activations": [cc::request().plan.policy_activation],
            "queue": {"poll_ms": 20, "lease_secs": 60, "max_attempts": 5},
            "pipeline": {"poll_ms": 20, "shutdown_grace_secs": 2}
        }))
        .unwrap(),
    )
    .expect("daemon config");
    let shutdown = Shutdown::new();
    let inputs = RunInputs {
        config: cfg,
        parts: parts.clone(),
        store_path: w.rw.db.path(),
        store_config: StoreConfig::enforced().with_clock(w.clock.clone()),
        intake: intake_config(),
        webhook_secret: custodian_intake::config::WebhookSecret::new(secret.clone()).unwrap(),
        policy: dc::policy(),
        dispatcher: Some(env.dispatcher()),
        names: &env.names,
        pulls: adapters.pulls.clone(),
        checks: Some(adapters.checks.clone()),
        consume_queue,
        requests: Arc::new(DirRequestSource::new(env.requests_dir.clone())),
        stager: Arc::new(DirStager::new(&env.art_dir)),
        approvals: Arc::new(DirApprovals::new(env.approvals_dir.clone())),
        sink: Arc::new(custodian_daemon::sink::DirSink::new(env.out_dir.clone())),
        log: env.log.clone(),
        fault: Arc::new(NoPipelineFault),
    };

    std::thread::scope(|s| {
        let _stop = StopOnDrop(shutdown.clone());
        let (tx, rx) = mpsc::channel();
        let down = &shutdown;
        let daemon = s.spawn(move || {
            run(inputs, down, &|a| {
                let _ = tx.send(a);
            })
        });
        let addr = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the daemon never became ready");
        // The first scheduled pass (all seven tasks) completes before the
        // scenario starts disturbing things.
        let end = Instant::now() + Duration::from_secs(20);
        while env.log.count("scheduler", "task_ok") + env.log.count("scheduler", "task_failed") < 7
            && Instant::now() < end
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let stack = Stack {
            env,
            addr,
            fake: fake.clone(),
            secret,
            parts: parts.clone(),
            ledger: &ledger,
            remote: remote.clone(),
            feed: &feed,
            roots: &roots,
            signer: &host,
            shutdown: shutdown.clone(),
            key_dir: key_dir.clone(),
            root: root.to_path_buf(),
        };
        let result = f(&stack);
        shutdown.request();
        let exit = daemon.join().expect("the daemon thread panicked");
        (result, exit)
    })
}
