//! The `custodian` binary end to end: arguments in, one JSON object and an
//! exit code out. Uses a temporary deployment with synthetic files only; the
//! ledger has no reachable remote, so anything that needs the ledger reports
//! `ledger_unavailable` and changes nothing.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;

use common::*;
use custodian_ledger::{GitBackend, GitConfig, SignDomain};

struct Deploy {
    dir: PathBuf,
    config: PathBuf,
    _corpus: lc::corpus::Fixture,
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Deploy {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("custodian-cli-bin-{}-{label}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let corpus = lc::corpus::Fixture::new();
        corpus.seal_active(&[("one", b"synthetic-one")]);
        let ledger_dir = dir.join("ledger");
        std::fs::create_dir(&ledger_dir).unwrap();
        GitBackend::init(
            &ledger_dir,
            "file:///nonexistent-synthetic-remote",
            GitConfig::default(),
        )
        .unwrap();
        // Policy and credentials.
        let policy = policy_json(1, 4_000_000_000);
        write_private(
            &dir.join("operator-policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        for who in [Who::Requester, Who::Approver, Who::Operator, Who::Auditor] {
            write_private(&dir.join(format!("{who:?}.token")), &who.token());
        }
        // Pinned roots: public keys only.
        let key = lc::test_key(1, &SignDomain::ALL);
        let roots = serde_json::json!({"roots": [{
            "key_id": cc::id("key_", 1),
            "public_key_hex": key.signer.public_key_hex(),
            "purposes": SignDomain::ALL.iter().map(|d| d.tag()).collect::<Vec<_>>(),
            "valid_from": 1
        }]});
        write_private(
            &dir.join("roots.json"),
            &serde_json::to_vec(&roots).unwrap(),
        );
        let config = serde_json::json!({
            "schema": "private-custodian.cli-config/1",
            "store_path": dir.join("state").join("store.db"),
            "operator_policy_path": dir.join("operator-policy.json"),
            "corpus_root": corpus.root(),
            "ledger_dir": ledger_dir,
            "pinned_roots_path": dir.join("roots.json"),
            "feed_dir": dir.join("feed"),
            "feed_id": cc::id("fed_", 1),
            "feed_destination_label": "public-feed",
            "commitment_key_id": cc::id("key_", 2),
            "signer_key_id": cc::id("key_", 1)
        });
        let config_path = dir.join("config.json");
        write_private(&config_path, &serde_json::to_vec(&config).unwrap());
        Self {
            dir,
            config: config_path,
            _corpus: corpus,
        }
    }

    fn run(&self, who: Option<Who>, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Proc::new(env!("CARGO_BIN_EXE_custodian"));
        cmd.env_clear();
        cmd.arg("--config").arg(&self.config);
        if let Some(w) = who {
            cmd.arg("--identity").arg(w.actor());
            cmd.arg("--token-file")
                .arg(self.dir.join(format!("{w:?}.token")));
        }
        cmd.args(args);
        let out = cmd.output().unwrap();
        (
            out.status.code().unwrap(),
            String::from_utf8(out.stdout).unwrap(),
            String::from_utf8(out.stderr).unwrap(),
        )
    }
}

impl Drop for Deploy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn json(s: &str) -> serde_json::Value {
    assert_eq!(s.lines().count(), 1, "exactly one line: {s}");
    serde_json::from_str(s).unwrap()
}

#[test]
fn usage_errors_exit_2_and_print_one_sanitized_object() {
    let d = Deploy::new("usage");
    for args in [
        &["bogus", "thing"][..],
        &["request"],
        &["request", "status"],
        &[],
    ] {
        let (code, out, err) = d.run(Some(Who::Auditor), args);
        assert_eq!(code, 2, "{args:?} {out}");
        let v = json(&out);
        assert_eq!(v["code"], "usage_error");
        assert_eq!(v["ok"], false);
        assert_eq!(err, "");
    }
}

#[test]
fn a_missing_config_or_credential_is_reported_with_fixed_codes() {
    let d = Deploy::new("noconf");
    let mut c = Proc::new(env!("CARGO_BIN_EXE_custodian"));
    c.env_clear().args(["verify", "all"]);
    let out = c.output().unwrap();
    assert_eq!(out.status.code(), Some(7));
    let v = json(&String::from_utf8(out.stdout).unwrap());
    assert_eq!(v["code"], "not_configured");
    // Config but no identity.
    let (code, out, _) = d.run(None, &["verify", "all"]);
    assert_eq!(code, 3);
    assert_eq!(json(&out)["code"], "unauthenticated");
}

#[test]
fn authentication_is_by_credential_file_and_reveals_nothing() {
    let d = Deploy::new("auth");
    // Right identity, someone else's credential.
    let mut cmd = Proc::new(env!("CARGO_BIN_EXE_custodian"));
    cmd.env_clear()
        .arg("--config")
        .arg(&d.config)
        .arg("--identity")
        .arg(Who::Auditor.actor())
        .arg("--token-file")
        .arg(d.dir.join("Operator.token"))
        .args(["request", "list"]);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(json(&text)["code"], "unauthenticated");
    assert!(!text.contains(&Who::Auditor.actor()));
    // Right credential: status of an unknown request is a plain not_found.
    let (code, out, _) = d.run(
        Some(Who::Auditor),
        &["request", "status", "--request-id", &cc::id("req_", 404)],
    );
    assert_eq!(code, 6);
    assert_eq!(json(&out)["code"], "not_found");
    let (code, out, _) = d.run(Some(Who::Auditor), &["request", "list"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(json(&out)["result"]["count"], 0);
}

#[test]
fn state_changing_commands_need_the_ledger_and_say_so() {
    let d = Deploy::new("ledger");
    let w = World::new(1);
    let (_, doc) = w.request(1);
    let docfile = d.dir.join("request.json");
    write_private(&docfile, &doc);
    // Read-only validation: the deployment has no activation recorded.
    let (code, out, _) = d.run(
        Some(Who::Requester),
        &[
            "policy",
            "validate",
            "--document",
            docfile.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 5, "{out}");
    assert_eq!(json(&out)["code"], "stale_policy");
    // Verification reads the ledger, which has no reachable remote.
    let (code, out, _) = d.run(Some(Who::Auditor), &["verify", "ledger"]);
    assert_eq!(code, 7, "{out}");
    assert_eq!(json(&out)["code"], "ledger_unavailable");
    // And nothing leaks a path, a credential or the document.
    assert!(!out.contains(d.dir.to_str().unwrap()));
    assert!(!out.contains("synthetic-credential"));
}

#[test]
fn a_signer_socket_setting_is_validated_and_a_missing_signer_is_not_a_config_error() {
    let d = Deploy::new("signer-cfg");
    let edit = |extra: serde_json::Value| {
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&d.config).unwrap()).unwrap();
        for (k, val) in extra.as_object().unwrap() {
            v[k] = val.clone();
        }
        write_private(&d.config, &serde_json::to_vec(&v).unwrap());
    };
    // A relative socket path or an out-of-range timeout is a configuration error.
    for bad in [
        serde_json::json!({"signer_socket_path": "relative/signer.sock"}),
        serde_json::json!({"signer_socket_path": d.dir.join("signer.sock"), "signer_timeout_secs": 0}),
        serde_json::json!({"signer_socket_path": d.dir.join("signer.sock"), "signer_timeout_secs": 3600}),
    ] {
        edit(bad);
        let (code, out, _) = d.run(Some(Who::Auditor), &["verify", "ledger"]);
        assert_eq!(code, 7, "{out}");
        assert_eq!(json(&out)["code"], "not_configured");
    }
    // An absolute path with no signer behind it opens fine: the deployment
    // starts, and only commands that must sign report `signer_unavailable`.
    edit(serde_json::json!({
        "signer_socket_path": d.dir.join("signer.sock"),
        "signer_timeout_secs": 2
    }));
    let (code, out, _) = d.run(Some(Who::Auditor), &["verify", "ledger"]);
    assert_eq!(code, 7, "{out}");
    assert_eq!(json(&out)["code"], "ledger_unavailable");
    assert!(!out.contains(d.dir.to_str().unwrap()));
}

/// Regression for the C12 review (finding S-5): the credential file, the
/// operator policy and the pinned roots were read without checking that they
/// are regular, unaliased files with safe modes. The runbook requires 0600.
#[test]
fn credential_policy_and_roots_files_must_be_regular_and_not_loosely_permissioned() {
    use std::os::unix::fs::PermissionsExt;
    let d = Deploy::new("filemodes");
    let auditor_args = ["request", "list"];
    // Baseline: the 0600 credential works.
    let (code, out, _) = d.run(Some(Who::Auditor), &auditor_args);
    assert_eq!(code, 0, "{out}");

    // A group- or other-readable credential is refused, as unauthenticated.
    let token = d.dir.join("Auditor.token");
    for mode in [0o640, 0o604, 0o644] {
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(mode)).unwrap();
        let (code, out, err) = d.run(Some(Who::Auditor), &auditor_args);
        assert_eq!((code, err.as_str()), (3, ""), "mode {mode:o}: {out}");
        assert_eq!(json(&out)["code"], "unauthenticated");
    }
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (code, _, _) = d.run(Some(Who::Auditor), &auditor_args);
    assert_eq!(code, 0);

    // A symbolic link to a good credential is refused too.
    let link = d.dir.join("Auditor.link");
    std::os::unix::fs::symlink(&token, &link).unwrap();
    let mut cmd = Proc::new(env!("CARGO_BIN_EXE_custodian"));
    cmd.env_clear()
        .arg("--config")
        .arg(&d.config)
        .arg("--identity")
        .arg(Who::Auditor.actor())
        .arg("--token-file")
        .arg(&link)
        .args(auditor_args);
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(
        json(&String::from_utf8(out.stdout).unwrap())["code"],
        "unauthenticated"
    );

    // A group- or other-writable operator policy (anyone who can write it can
    // add an operator) or pinned-roots file (a trust anchor) is not loaded.
    for file in ["operator-policy.json", "roots.json"] {
        let path = d.dir.join(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        let (code, out, _) = d.run(Some(Who::Auditor), &auditor_args);
        assert_eq!(code, 7, "{file}: {out}");
        assert_eq!(json(&out)["code"], "not_configured", "{file}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (code, _, _) = d.run(Some(Who::Auditor), &auditor_args);
    assert_eq!(code, 0, "restored modes work again");
}

#[test]
fn credential_digest_prints_only_the_digest() {
    let d = Deploy::new("digest");
    let mut cmd = Proc::new(env!("CARGO_BIN_EXE_custodian"));
    cmd.env_clear()
        .arg("credential-digest")
        .arg("--token-file")
        .arg(d.dir.join("Requester.token"));
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    let v = json(&text);
    assert_eq!(
        v["result"]["credential_sha256"],
        custodian_cli::credential_digest(&Who::Requester.token())
    );
    assert!(!text.contains("synthetic-credential"));
}
