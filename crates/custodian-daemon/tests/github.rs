//! The GitHub side: the RS256 App JWT with a throwaway key generated inside
//! each test, the API transport and the Check and pull-request adapters over
//! the offline fake and over a loopback socket. Nothing here contacts GitHub:
//! the only network used is loopback, and the real HTTPS client is not built.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use custodian_contracts::types::Timestamp;
use custodian_daemon::github::api::{ApiRequest, Bearer, Method};
use custodian_daemon::github::https::NotBuiltHttps;
use custodian_daemon::github::plain::PlainHttp;
use custodian_daemon::github::testing::FakeGithub;
use custodian_daemon::github::{GithubAdapters, GithubApi, HttpExecutor, KeyError, Rs256Signer};
use custodian_intake::app_auth::{base64url, mint_app_jwt, AccessTokenRequest, AppApiTransport};
use custodian_intake::checks::{CheckPost, CheckSink, GithubConclusion, GithubStatus, CHECK_NAME};
use custodian_intake::config::IntakeConfig;
use custodian_intake::credentials::RequestFacingAppCredential;
use custodian_intake::ids::{AppId, HeadSha, InstallationId, PullRequestNumber, RepositoryId};
use custodian_intake::ports::PullRequestSource;
use custodian_intake::IntakeReason;
use custodian_store::{Clock, ManualClock};
use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
use serde_json::json;

const NOW: u64 = 1_800_000_000;
const INSTALLATION: u64 = 900_001;
const REPO: u64 = 800_001;

// ---- throwaway keys ---------------------------------------------------------------

struct KeyDir(PathBuf);

impl KeyDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = std::env::temp_dir().join(format!(
            "custodian-daemon-keytest-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for KeyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn openssl(args: &[&str]) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("the openssl command line tool is required by this test");
    assert!(out.status.success(), "openssl {args:?} failed");
    out.stdout
}

fn private(p: &Path) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A fresh RSA key, in the form the tool writes by default.
fn gen_key(dir: &KeyDir, name: &str, bits: &str) -> PathBuf {
    let p = dir.path(name);
    openssl(&["genrsa", "-out", p.to_str().unwrap(), bits]);
    private(&p);
    p
}

fn pkcs8_of(dir: &KeyDir, key: &Path, name: &str) -> PathBuf {
    let p = dir.path(name);
    openssl(&[
        "pkcs8",
        "-topk8",
        "-nocrypt",
        "-in",
        key.to_str().unwrap(),
        "-out",
        p.to_str().unwrap(),
    ]);
    private(&p);
    p
}

fn pkcs1_of(dir: &KeyDir, key: &Path, name: &str) -> PathBuf {
    let p = dir.path(name);
    let text = std::fs::read_to_string(key).unwrap();
    if text.contains("BEGIN RSA PRIVATE KEY") {
        std::fs::copy(key, &p).unwrap();
    } else {
        openssl(&[
            "rsa",
            "-in",
            key.to_str().unwrap(),
            "-traditional",
            "-out",
            p.to_str().unwrap(),
        ]);
    }
    private(&p);
    p
}

fn public_der(key: &Path) -> Vec<u8> {
    openssl(&[
        "rsa",
        "-in",
        key.to_str().unwrap(),
        "-RSAPublicKey_out",
        "-outform",
        "DER",
    ])
}

fn b64url_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => panic!("not base64url"),
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

// ---- RS256 ------------------------------------------------------------------------

#[test]
fn a_jwt_signed_with_either_pem_form_verifies_under_the_public_key_only() {
    let dir = KeyDir::new();
    let default_form = gen_key(&dir, "default.pem", "2048");
    let pk8 = pkcs8_of(&dir, &default_form, "pk8.pem");
    let pk1 = pkcs1_of(&dir, &default_form, "pk1.pem");
    let public = public_der(&default_form);
    for (label, path) in [("pkcs8", &pk8), ("pkcs1", &pk1)] {
        let signer = Rs256Signer::from_pem_file(path).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(signer.bits(), 2048);
        assert_eq!(signer.public_key_der(), public, "{label}");
        let cred = RequestFacingAppCredential::new(AppId::new(123_456).unwrap(), Box::new(signer));
        let now = Timestamp::new(NOW).unwrap();
        let jwt = mint_app_jwt(&cred, now).unwrap();
        let token = jwt.expose_secret();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], base64url(br#"{"alg":"RS256","typ":"JWT"}"#));
        let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(parts[1])).unwrap();
        assert_eq!(claims["iss"], "123456");
        assert_eq!(claims["exp"], NOW + 540);
        assert_eq!(claims["iat"], NOW - 60);
        let input = format!("{}.{}", parts[0], parts[1]);
        let sig = b64url_decode(parts[2]);
        let key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public);
        key.verify(input.as_bytes(), &sig).expect("verifies");
        // Any change to the signed bytes, and another key, do not verify.
        assert!(key.verify(format!("{input}x").as_bytes(), &sig).is_err());
        let other_pub = public_der(&gen_key(&dir, "other.pem", "2048"));
        assert!(
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &other_pub)
                .verify(input.as_bytes(), &sig)
                .is_err()
        );
        // The token and the credential never print.
        assert!(!format!("{jwt:?}").contains(parts[2]));
        assert_eq!(
            format!("{cred:?}"),
            "RequestFacingAppCredential(<redacted>)"
        );
    }
}

#[test]
fn the_key_is_read_only_from_a_private_regular_file_and_only_if_it_is_a_plain_rsa_key() {
    let dir = KeyDir::new();
    let key = gen_key(&dir, "k.pem", "2048");
    let text = std::fs::read_to_string(&key).unwrap();

    // Readable by group or other: refused.
    for mode in [0o640, 0o604, 0o644, 0o660] {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            Rs256Signer::from_pem_file(&key).err(),
            Some(KeyError::Unreadable),
            "{mode:o}"
        );
    }
    private(&key);
    assert!(Rs256Signer::from_pem_file(&key).is_ok());
    // A symlink to a good key: refused. A directory, a missing file, an empty
    // file and an oversized file: refused.
    let link = dir.path("link.pem");
    std::os::unix::fs::symlink(&key, &link).unwrap();
    assert_eq!(
        Rs256Signer::from_pem_file(&link).err(),
        Some(KeyError::Unreadable)
    );
    assert_eq!(
        Rs256Signer::from_pem_file(&dir.0).err(),
        Some(KeyError::Unreadable)
    );
    assert_eq!(
        Rs256Signer::from_pem_file(&dir.path("missing.pem")).err(),
        Some(KeyError::Unreadable)
    );
    let empty = dir.path("empty.pem");
    std::fs::write(&empty, b"").unwrap();
    private(&empty);
    assert_eq!(
        Rs256Signer::from_pem_file(&empty).err(),
        Some(KeyError::NotPem)
    );
    let big = dir.path("big.pem");
    std::fs::write(&big, vec![b'A'; 20_000]).unwrap();
    private(&big);
    assert_eq!(
        Rs256Signer::from_pem_file(&big).err(),
        Some(KeyError::Unreadable)
    );

    // An encrypted key, an elliptic-curve key, a too-small key, two keys in
    // one file and a public key are all refused, without echoing anything.
    let enc = dir.path("enc.pem");
    openssl(&[
        "pkcs8",
        "-topk8",
        "-v2",
        "aes-256-cbc",
        "-passout",
        "pass:synthetic",
        "-in",
        key.to_str().unwrap(),
        "-out",
        enc.to_str().unwrap(),
    ]);
    private(&enc);
    assert_eq!(
        Rs256Signer::from_pem_file(&enc).err(),
        Some(KeyError::Unsupported)
    );
    let ec = dir.path("ec.pem");
    openssl(&[
        "ecparam",
        "-name",
        "prime256v1",
        "-genkey",
        "-noout",
        "-out",
        ec.to_str().unwrap(),
    ]);
    private(&ec);
    assert_eq!(
        Rs256Signer::from_pem_file(&ec).err(),
        Some(KeyError::Unsupported)
    );
    let small = gen_key(&dir, "small.pem", "1024");
    assert_eq!(
        Rs256Signer::from_pem_file(&small).err(),
        Some(KeyError::Rejected)
    );
    let two = dir.path("two.pem");
    std::fs::write(&two, format!("{text}{text}")).unwrap();
    private(&two);
    assert_eq!(
        Rs256Signer::from_pem_file(&two).err(),
        Some(KeyError::NotPem)
    );
    let public = dir.path("public.pem");
    openssl(&[
        "rsa",
        "-in",
        key.to_str().unwrap(),
        "-pubout",
        "-out",
        public.to_str().unwrap(),
    ]);
    private(&public);
    assert_eq!(
        Rs256Signer::from_pem_file(&public).err(),
        Some(KeyError::Unsupported)
    );
    // The signer never prints its key.
    let signer = Rs256Signer::from_pem_file(&key).unwrap();
    assert_eq!(format!("{signer:?}"), "Rs256Signer(<redacted>)");
}

// ---- adapters over the offline fake ---------------------------------------------------

fn intake() -> IntakeConfig {
    IntakeConfig::from_json(
        &serde_json::to_vec(&json!({
            "events": ["pull_request"],
            "installations": [{"installation_id": INSTALLATION, "repository_ids": [REPO]}],
            "actors": [{"github_user_id": 700_001, "actor": "act_synthetic000000000001", "roles": ["requester"]}]
        }))
        .unwrap(),
    )
    .unwrap()
}

struct Rig {
    fake: FakeGithub,
    adapters: GithubAdapters,
    clock: Arc<ManualClock>,
    public: Vec<u8>,
    _dir: KeyDir,
}

fn rig_over(
    fake: FakeGithub,
    http: Arc<dyn HttpExecutor>,
    transport: Arc<dyn AppApiTransport>,
) -> Rig {
    let dir = KeyDir::new();
    let key = gen_key(&dir, "app.pem", "2048");
    let signer = Rs256Signer::from_pem_file(&key).unwrap();
    let clock = Arc::new(ManualClock::new(NOW));
    let adapters = GithubAdapters::build(
        RequestFacingAppCredential::new(AppId::new(123_456).unwrap(), Box::new(signer)),
        transport,
        http,
        intake(),
        clock.clone(),
    );
    Rig {
        fake,
        adapters,
        clock,
        public: public_der(&key),
        _dir: dir,
    }
}

fn rig() -> Rig {
    let fake = FakeGithub::new(&"a".repeat(40));
    rig_over(
        fake.clone(),
        Arc::new(fake.clone()),
        Arc::new(GithubApi::new(fake)),
    )
}

fn post(state: GithubStatus, conclusion: Option<GithubConclusion>) -> CheckPost {
    CheckPost {
        installation: InstallationId::new(INSTALLATION).unwrap(),
        repository: RepositoryId::new(REPO).unwrap(),
        head_sha: HeadSha::parse(&"a".repeat(40)).unwrap(),
        name: CHECK_NAME,
        status: state,
        conclusion,
        title: "Request queued",
        summary: "State: queued. Reason: requested. This check reports process state only; \
                  it is not a measurement result or approval."
            .to_owned(),
    }
}

#[test]
fn the_check_sink_creates_then_updates_one_run_with_fixed_text_and_the_installation_token() {
    let r = rig();
    r.adapters
        .checks
        .post(&post(GithubStatus::Queued, None))
        .unwrap();
    r.adapters
        .checks
        .post(&post(
            GithubStatus::Completed,
            Some(GithubConclusion::Neutral),
        ))
        .unwrap();
    let seen = r.fake.seen();
    // The token call: a JWT, minimal permissions, one repository.
    assert_eq!(seen[0].method, Method::Post);
    assert_eq!(
        seen[0].path,
        format!("/app/installations/{INSTALLATION}/access_tokens")
    );
    let jwt = &seen[0].bearer;
    assert_eq!(jwt.split('.').count(), 3);
    let body: serde_json::Value = serde_json::from_str(seen[0].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["repository_ids"], json!([REPO]));
    assert_eq!(
        body["permissions"],
        json!({"metadata": "read", "pull_requests": "read", "checks": "write"})
    );
    // The JWT verifies under the App's public key.
    let parts: Vec<&str> = jwt.split('.').collect();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &r.public)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &b64url_decode(parts[2]),
        )
        .expect("the App's key signed it");
    // Every later call uses the installation token, never the JWT.
    let token = r.fake.token_value();
    for s in &seen[1..] {
        assert_eq!(s.bearer, token);
        assert_ne!(&s.bearer, jwt);
    }
    // The repository name was resolved once, then the run created and updated.
    assert_eq!(seen[1].path, format!("/repositories/{REPO}"));
    assert_eq!(seen[2].method, Method::Post);
    assert_eq!(
        seen[2].path,
        "/repos/synthetic-org/synthetic-repo/check-runs"
    );
    let created: serde_json::Value = serde_json::from_str(seen[2].body.as_ref().unwrap()).unwrap();
    assert_eq!(created["name"], CHECK_NAME);
    assert_eq!(created["head_sha"], "a".repeat(40));
    assert_eq!(created["status"], "queued");
    assert!(created.get("conclusion").is_none());
    assert_eq!(
        created["output"]["summary"],
        "State: queued. Reason: requested. This check reports process state only; it is not a measurement result or approval."
    );
    assert_eq!(seen[3].method, Method::Patch);
    assert!(seen[3]
        .path
        .starts_with("/repos/synthetic-org/synthetic-repo/check-runs/"));
    let updated: serde_json::Value = serde_json::from_str(seen[3].body.as_ref().unwrap()).unwrap();
    assert_eq!(updated["status"], "completed");
    assert_eq!(updated["conclusion"], "neutral");
    // One token was minted for both posts.
    assert_eq!(
        seen.iter()
            .filter(|s| s.path.contains("access_tokens"))
            .count(),
        1
    );
    // The conclusion is never a success.
    assert!(!seen
        .iter()
        .any(|s| s.body.as_deref().is_some_and(|b| b.contains("\"success\""))));
}

#[test]
fn the_pull_request_source_reads_the_head_commit_with_the_scoped_token() {
    let r = rig();
    let head = r
        .adapters
        .pulls
        .current_head(
            InstallationId::new(INSTALLATION).unwrap(),
            RepositoryId::new(REPO).unwrap(),
            PullRequestNumber::new(7).unwrap(),
        )
        .unwrap();
    assert_eq!(head.as_str(), "a".repeat(40));
    let last = r.fake.seen().pop().unwrap();
    assert_eq!(last.method, Method::Get);
    assert_eq!(last.path, "/repos/synthetic-org/synthetic-repo/pulls/7");
    // A moved head is reported as it is; the gate decides what it means.
    r.fake.set_head(&"b".repeat(40));
    let head = r
        .adapters
        .pulls
        .current_head(
            InstallationId::new(INSTALLATION).unwrap(),
            RepositoryId::new(REPO).unwrap(),
            PullRequestNumber::new(7).unwrap(),
        )
        .unwrap();
    assert_eq!(head.as_str(), "b".repeat(40));
    // The repository name and the token were cached.
    assert_eq!(
        r.fake
            .seen()
            .iter()
            .filter(|s| s.path.starts_with("/repositories/"))
            .count(),
        1
    );
    assert_eq!(
        r.fake
            .seen()
            .iter()
            .filter(|s| s.path.contains("access_tokens"))
            .count(),
        1
    );
}

#[test]
fn failures_map_to_fixed_reasons_and_never_to_text() {
    let ids = (
        InstallationId::new(INSTALLATION).unwrap(),
        RepositoryId::new(REPO).unwrap(),
        PullRequestNumber::new(7).unwrap(),
    );
    // Transport down: transient.
    let r = rig();
    r.fake.set_offline(true);
    assert_eq!(
        r.adapters.pulls.current_head(ids.0, ids.1, ids.2).err(),
        Some(IntakeReason::TokenUnavailable)
    );
    // The token endpoint refuses: the App is not accepted.
    let r = rig();
    r.fake.force_status(Some(401));
    assert_eq!(
        r.adapters.pulls.current_head(ids.0, ids.1, ids.2).err(),
        Some(IntakeReason::AppAuthFailed)
    );
    // A rate limit or an outage is transient, not a verdict.
    let r = rig();
    r.fake.force_status(Some(503));
    assert_eq!(
        r.adapters.pulls.current_head(ids.0, ids.1, ids.2).err(),
        Some(IntakeReason::TokenUnavailable)
    );
    // A redirect is never followed.
    let r = rig();
    r.fake.force_status(Some(302));
    assert_eq!(
        r.adapters.pulls.current_head(ids.0, ids.1, ids.2).err(),
        Some(IntakeReason::TokenUnavailable)
    );
    // A token that grants more than was asked for is discarded unused.
    let r = rig();
    r.fake.set_permissions(json!({"metadata": "read", "pull_requests": "read", "checks": "write", "contents": "write"}));
    assert_eq!(
        r.adapters.pulls.current_head(ids.0, ids.1, ids.2).err(),
        Some(IntakeReason::PermissionsExceeded)
    );
    assert!(
        r.fake
            .seen()
            .iter()
            .all(|s| s.path.contains("access_tokens")),
        "the token was never used"
    );
    // A repository outside the allowlist never reaches the network.
    let r = rig();
    assert_eq!(
        r.adapters
            .pulls
            .current_head(ids.0, RepositoryId::new(1).unwrap(), ids.2)
            .err(),
        Some(IntakeReason::RepositoryNotAllowed)
    );
    assert!(r.fake.seen().is_empty());
    // A hostile repository name is not used in a path.
    let r = rig();
    r.fake.set_full_name("../../orgs/x/admin");
    assert!(r
        .adapters
        .checks
        .post(&post(GithubStatus::Queued, None))
        .is_err());
    assert!(r.fake.seen().iter().all(|s| !s.path.contains("..")));
    // A pull request that is gone is a stale commit; an outage is not.
    let r = rig();
    r.fake.set_head(&"c".repeat(40));
    assert!(r.adapters.pulls.current_head(ids.0, ids.1, ids.2).is_ok());
    // An expired cached token is replaced.
    let r = rig();
    r.adapters.pulls.current_head(ids.0, ids.1, ids.2).unwrap();
    r.fake.set_token_expiry("2099-06-01T00:00:00Z");
    r.clock.set(4_070_908_800 - 60); // inside the refresh margin of the first token (2099-01-01)
    r.adapters.pulls.current_head(ids.0, ids.1, ids.2).unwrap();
    assert_eq!(
        r.fake
            .seen()
            .iter()
            .filter(|s| s.path.contains("access_tokens"))
            .count(),
        2
    );
    let _ = r.clock.now();
}

#[test]
fn the_https_client_is_a_skeleton_that_fails_closed_and_the_plain_client_is_loopback_only() {
    let request = ApiRequest {
        method: Method::Get,
        path: "/x".to_owned(),
        bearer: Bearer::new("ghs_SYNTHETIC"),
        json_body: None,
    };
    assert_eq!(
        NotBuiltHttps.execute(&request).err(),
        Some(IntakeReason::TokenUnavailable)
    );
    assert!(!format!("{request:?}").contains("ghs_SYNTHETIC"));
    for not_loopback in [
        "8.8.8.8:443",
        "192.0.2.1:80",
        "[2001:db8::1]:80",
        "0.0.0.0:80",
    ] {
        assert!(
            PlainHttp::loopback(not_loopback.parse().unwrap(), Duration::from_secs(1)).is_none(),
            "{not_loopback}"
        );
    }
    assert!(PlainHttp::loopback("127.0.0.1:1".parse().unwrap(), Duration::from_secs(1)).is_some());
    assert!(PlainHttp::loopback("127.0.0.1:1".parse().unwrap(), Duration::ZERO).is_none());
    // Nothing listens on port 1: a refused connection is a fixed reason.
    let dead =
        PlainHttp::loopback("127.0.0.1:1".parse().unwrap(), Duration::from_millis(500)).unwrap();
    assert_eq!(
        dead.execute(&request).err(),
        Some(IntakeReason::TokenUnavailable)
    );
}

#[test]
fn the_same_flows_work_over_a_real_loopback_socket() {
    let fake = FakeGithub::new(&"a".repeat(40));
    let server = fake.serve();
    let http = Arc::new(PlainHttp::loopback(server.addr, Duration::from_secs(5)).unwrap());
    let r = rig_over(fake.clone(), http.clone(), Arc::new(GithubApi::new(http)));
    r.adapters
        .checks
        .post(&post(GithubStatus::Queued, None))
        .unwrap();
    let head = r
        .adapters
        .pulls
        .current_head(
            InstallationId::new(INSTALLATION).unwrap(),
            RepositoryId::new(REPO).unwrap(),
            PullRequestNumber::new(7).unwrap(),
        )
        .unwrap();
    assert_eq!(head.as_str(), "a".repeat(40));
    let seen = fake.seen();
    assert_eq!(
        seen[0].path,
        format!("/app/installations/{INSTALLATION}/access_tokens")
    );
    assert!(seen
        .iter()
        .any(|s| s.path == "/repos/synthetic-org/synthetic-repo/check-runs"));
    // The wire carried the credential as a bearer header and the JSON body.
    assert_eq!(seen[0].bearer.split('.').count(), 3);
    assert!(seen[0].body.as_ref().unwrap().contains("repository_ids"));
    // The App-level call, directly.
    let jwt_holder = {
        let dir = KeyDir::new();
        let key = gen_key(&dir, "k.pem", "2048");
        let cred = RequestFacingAppCredential::new(
            AppId::new(1).unwrap(),
            Box::new(Rs256Signer::from_pem_file(&key).unwrap()),
        );
        mint_app_jwt(&cred, Timestamp::new(NOW).unwrap()).unwrap()
    };
    let transport =
        GithubApi::new(PlainHttp::loopback(server.addr, Duration::from_secs(5)).unwrap());
    let raw = transport
        .create_installation_token(&AccessTokenRequest {
            jwt: &jwt_holder,
            installation: InstallationId::new(INSTALLATION).unwrap(),
            repository: RepositoryId::new(REPO).unwrap(),
        })
        .unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("expires_at"));
}
