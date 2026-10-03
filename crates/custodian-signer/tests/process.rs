//! The real `custodian-signer` binary as a separate process: serving, kill and
//! restart, refusal to start on an insecure key, fixed-code output, and (on
//! Linux) the process boundary that keeps same-uid processes out of its memory.

mod common;

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use custodian_ledger::{ApprovedPayload, KeyEntry, Keyring, SignDomain, SignRefusal, Signer, Verifier};

const BIN: &str = env!("CARGO_BIN_EXE_custodian-signer");

fn write_config(env: &Env, extra: serde_json::Value) -> std::path::PathBuf {
    let mut v = serde_json::json!({
        "schema": "private-custodian.signer-config/1",
        "key_id": cc::id("key_", 1),
        "key_path": env.key_path,
        "socket_path": env.sock,
        "allowed_peer_uid": custodian_signer::effective_uid(),
        "purposes": SignDomain::ALL.iter().map(|d| d.tag()).collect::<Vec<_>>(),
        "valid_from": 1,
        "io_timeout_secs": 2
    });
    if let Some(o) = extra.as_object() {
        for (k, val) in o {
            v[k] = val.clone();
        }
    }
    let p = env.root.join("c.json");
    std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

fn spawn(config: &Path) -> Child {
    Command::new(BIN)
        .arg("--config")
        .arg(config)
        .env_clear()
        .env("PCSG_CANARY_SECRET", "canary-env-value")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// The client clock for a real-time signer is the real clock.
fn real_client(env: &Env) -> custodian_ledger::RemoteSigner<custodian_signer::UnixSocketTransport> {
    custodian_ledger::RemoteSigner::new(
        key_id(),
        custodian_signer::UnixSocketTransport::new(env.sock.clone(), Duration::from_secs(3)),
    )
}

fn record_payload() -> ApprovedPayload {
    ApprovedPayload::ledger_record(&checkpoint_record(NOW)).unwrap()
}

fn wait_ready(env: &Env, child: &mut Child) {
    let client = real_client(env);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        if child.try_wait().unwrap().is_some() {
            panic!("signer exited early");
        }
        if client.sign(&record_payload()).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("signer did not become ready");
}

fn finish(mut child: Child) -> (Option<i32>, String, String) {
    let _ = child.kill();
    let status = child.wait().unwrap();
    let (mut out, mut err) = (String::new(), String::new());
    child.stdout.take().unwrap().read_to_string(&mut out).unwrap();
    child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    (status.code(), out, err)
}

fn public_key(env: &Env, config: &Path) -> String {
    let out = Command::new(BIN)
        .arg("--config")
        .arg(config)
        .arg("--print-public-key")
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success());
    let hex = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    assert_eq!(hex.len(), 64);
    assert!(!hex.contains(&env.seed_hex));
    assert_ne!(hex, env.seed_hex);
    hex
}

#[test]
fn the_binary_signs_survives_kill_and_restart_and_logs_only_fixed_codes() {
    let env = Env::new();
    let config = write_config(&env, serde_json::json!({}));
    let pubkey = public_key(&env, &config);
    let verifier = Verifier::new(Keyring::new().with_root(
        KeyEntry::root(key_id(), &pubkey, SignDomain::ALL, cc::ts(NOW - 1000)).unwrap(),
    ));

    let mut child = spawn(&config);
    wait_ready(&env, &mut child);
    let client = real_client(&env);
    let signed = sign_record(&client, &checkpoint_record(NOW));
    verifier.verify_ledger_record(&signed).unwrap();

    // Abuse, then a hard kill.
    {
        use std::io::Write;
        let mut s = std::os::unix::net::UnixStream::connect(&env.sock).unwrap();
        s.write_all(b"CANARY-garbage-not-a-frame").unwrap();
    }
    let (_, out, err) = finish(child);
    assert!(out.is_empty());
    assert!(!err.contains(&env.seed_hex), "seed in log");
    assert!(!err.contains(&path_str(&env.root)), "path in log");
    assert!(!err.contains("CANARY"), "client bytes or env in log");

    // Dead signer: fail closed.
    assert_eq!(
        client.sign(&record_payload()).unwrap_err(),
        SignRefusal::SignerUnavailable
    );
    assert!(env.sock.exists(), "a killed signer leaves a stale socket");

    // Restart reclaims the stale socket and yields the same key and signature.
    let mut child = spawn(&config);
    wait_ready(&env, &mut child);
    let again = sign_record(&client, &checkpoint_record(NOW));
    assert_eq!(again.signature, signed.signature);
    verifier.verify_ledger_record(&again).unwrap();
    // A second instance on the same socket refuses to start.
    let dup = Command::new(BIN)
        .arg("--config")
        .arg(&config)
        .env_clear()
        .output()
        .unwrap();
    assert_eq!(dup.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&dup.stderr).contains("signer_already_running"));
    let _ = finish(child);
}

#[test]
fn the_binary_refuses_to_start_on_insecure_keys_configs_and_arguments() {
    let env = Env::new();
    let config = write_config(&env, serde_json::json!({}));
    let run = |args: &[&str]| {
        let out = Command::new(BIN).args(args).env_clear().output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let cfg = config.to_str().unwrap();

    // Key readable by group or other: exit 3 with the fixed code, no key bytes
    // and no path in the output.
    std::fs::set_permissions(&env.key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (code, err) = run(&["--config", cfg]);
    assert_eq!(code, Some(3));
    assert!(err.contains("key_permissions_insecure"));
    assert!(!err.contains(&env.seed_hex) && !err.contains(&path_str(&env.root)));
    std::fs::set_permissions(&env.key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Socket directory open to others: exit 4.
    std::fs::set_permissions(&env.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (code, err) = run(&["--config", cfg]);
    assert!(
        code == Some(3) || code == Some(4),
        "directory checks fail closed"
    );
    assert!(err.contains("insecure"));
    std::fs::set_permissions(&env.root, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Usage and configuration errors.
    assert_eq!(run(&[]).0, Some(2));
    assert_eq!(run(&["--bogus"]).0, Some(2));
    assert_eq!(run(&["--config", "/nonexistent/synthetic.json"]).0, Some(2));
    let bad = write_config(&env, serde_json::json!({"purposes": ["not-a-domain"]}));
    assert_eq!(run(&["--config", bad.to_str().unwrap()]).0, Some(2));
    let bad = write_config(&env, serde_json::json!({"unknown_field": 1}));
    assert_eq!(run(&["--config", bad.to_str().unwrap()]).0, Some(2));
    let bad = write_config(&env, serde_json::json!({"key_path": "relative/path"}));
    assert_eq!(run(&["--config", bad.to_str().unwrap()]).0, Some(2));
    // A config anyone can write is refused.
    let cfg_path = write_config(&env, serde_json::json!({}));
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(run(&["--config", cfg_path.to_str().unwrap()]).0, Some(2));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_process_boundary_keeps_same_uid_readers_out_of_signer_memory() {
    let env = Env::new();
    let config = write_config(&env, serde_json::json!({}));
    let mut child = spawn(&config);
    wait_ready(&env, &mut child);
    let pid = child.id();

    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    assert!(core.split_whitespace().rev().take(3).any(|w| w == "0"), "{core}");
    assert!(core.matches('0').count() >= 2, "{core}");

    // With PR_SET_DUMPABLE off, /proc/<pid>/{mem,environ} are not readable by
    // other processes of the same uid (root excepted, so skip there).
    if custodian_signer::effective_uid() != 0 {
        assert!(std::fs::File::open(format!("/proc/{pid}/mem")).is_err());
        assert!(std::fs::read(format!("/proc/{pid}/environ")).is_err());
    }
    let (_, _, err) = finish(child);
    assert!(!err.contains(&env.seed_hex));
}
