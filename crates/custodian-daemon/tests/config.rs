//! The daemon configuration: strict, secrets by path only, files checked.
//! Synthetic only; every path is a throwaway directory.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use custodian_daemon::config::{DaemonConfig, GithubMode, QueueConfig, Sandbox};
use custodian_daemon::reason::DaemonReason;
use serde_json::{json, Value};

fn example() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/examples/daemon-config.example.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn parse(v: &Value) -> Result<DaemonConfig, DaemonReason> {
    DaemonConfig::from_json(&serde_json::to_vec(v).unwrap())
}

#[test]
fn the_example_parses_and_names_nothing_real() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/examples/daemon-config.example.json"),
    )
    .unwrap();
    let c = parse(&example()).expect("the documented example is structurally valid");
    assert_eq!(c.github.mode, GithubMode::Disabled);
    assert_eq!(c.worker.sandbox, Sandbox::None);
    assert!(c.listener.bind.ip().is_loopback());
    assert!(!c.listener.allow_non_loopback);
    // Placeholders only: no secret, no token, no key, no real id.
    for needle in ["BEGIN", "PRIVATE KEY", "ghp_", "ghs_", "sha256=", "@"] {
        assert!(!text.contains(needle), "{needle}");
    }
    assert!(text.matches("PLACEHOLDER").count() >= 8);
    // Placeholder paths name nothing, so the loader refuses the file as is.
    let dir = tmp("example-load");
    let path = dir.join("daemon.json");
    std::fs::write(&path, &text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        DaemonConfig::load(&path).err(),
        Some(DaemonReason::NotConfigured)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_missing_and_out_of_range_values_are_refused() {
    type Mutation = Box<dyn Fn(&mut Value)>;
    let mut cases: Vec<(&str, Mutation)> = vec![
        (
            "unknown top-level field",
            Box::new(|v| v["extra"] = json!(1)),
        ),
        (
            "unknown nested field",
            Box::new(|v| v["listener"]["extra"] = json!(1)),
        ),
        (
            "unknown intake field",
            Box::new(|v| v["intake"]["webhook_secret"] = json!("inline")),
        ),
        (
            "inline github key",
            Box::new(|v| v["github"]["private_key"] = json!("x")),
        ),
        (
            "wrong schema",
            Box::new(|v| v["schema"] = json!("private-custodian.daemon-config/2")),
        ),
        (
            "relative path",
            Box::new(|v| v["requests_dir"] = json!("requests")),
        ),
        (
            "relative secret path",
            Box::new(|v| v["intake"]["webhook_secret_path"] = json!("secret")),
        ),
        (
            "missing attestation",
            Box::new(|v| {
                v.as_object_mut().unwrap().remove("attestation");
            }),
        ),
        (
            "unknown authorship",
            Box::new(|v| v["attestation"]["authorship"] = json!("independent")),
        ),
        (
            "bind not an address",
            Box::new(|v| v["listener"]["bind"] = json!("localhost:80")),
        ),
        (
            "path without slash",
            Box::new(|v| v["listener"]["path"] = json!("hook")),
        ),
        (
            "health path reused",
            Box::new(|v| v["listener"]["path"] = json!("/healthz")),
        ),
        (
            "zero connections",
            Box::new(|v| v["listener"]["max_connections"] = json!(0)),
        ),
        (
            "too many connections",
            Box::new(|v| v["listener"]["max_connections"] = json!(257)),
        ),
        (
            "zero timeout",
            Box::new(|v| v["listener"]["head_timeout_secs"] = json!(0)),
        ),
        (
            "huge timeout",
            Box::new(|v| v["listener"]["body_timeout_secs"] = json!(61)),
        ),
        (
            "tiny request line",
            Box::new(|v| v["listener"]["max_request_line_bytes"] = json!(8)),
        ),
        (
            "disabled github with an app id",
            Box::new(|v| v["github"]["app_id"] = json!(1)),
        ),
        (
            "loopback mode without an address",
            Box::new(|v| {
                v["github"] =
                    json!({"mode": "loopback_http", "app_id": 1, "app_private_key_path": "/k"});
            }),
        ),
        (
            "loopback mode with a remote address",
            Box::new(|v| {
                v["github"] = json!({"mode": "loopback_http", "app_id": 1,
                "app_private_key_path": "/k", "loopback_addr": "8.8.8.8:443"});
            }),
        ),
        (
            "https mode without a key",
            Box::new(|v| v["github"] = json!({"mode": "https", "app_id": 1})),
        ),
        (
            "zero app id",
            Box::new(|v| {
                v["github"] = json!({"mode": "https", "app_id": 0, "app_private_key_path": "/k"});
            }),
        ),
        (
            "bubblewrap without a probe",
            Box::new(|v| v["worker"]["sandbox"] = json!("bubblewrap")),
        ),
        (
            "unknown sandbox",
            Box::new(|v| v["worker"]["sandbox"] = json!("none-at-all")),
        ),
        (
            "bad destination",
            Box::new(|v| v["release"]["destination"] = json!("Bad Label")),
        ),
        (
            "zero activation sequence",
            Box::new(|v| v["release"]["policy_activation"]["sequence"] = json!(0)),
        ),
        (
            "zero queue workers",
            Box::new(|v| v["queue"]["workers"] = json!(0)),
        ),
        (
            "too many queue workers",
            Box::new(|v| v["queue"]["workers"] = json!(9)),
        ),
        (
            "zero lease",
            Box::new(|v| v["queue"]["lease_secs"] = json!(0)),
        ),
        (
            "huge lease",
            Box::new(|v| v["queue"]["lease_secs"] = json!(3601)),
        ),
        (
            "zero attempts",
            Box::new(|v| v["queue"]["max_attempts"] = json!(0)),
        ),
        (
            "backoff max below base",
            Box::new(|v| {
                v["queue"]["backoff_base_secs"] = json!(60);
                v["queue"]["backoff_max_secs"] = json!(10);
            }),
        ),
        (
            "bad owner label",
            Box::new(|v| v["queue"]["owner"] = json!("has space")),
        ),
        (
            "zero interval",
            Box::new(|v| v["schedule"]["export_secs"] = json!(0)),
        ),
        (
            "huge interval",
            Box::new(|v| v["schedule"]["recover_secs"] = json!(86_401)),
        ),
        (
            "short pipeline lease",
            Box::new(|v| v["pipeline"]["lease_secs"] = json!(10)),
        ),
        (
            "huge shutdown grace",
            Box::new(|v| v["pipeline"]["shutdown_grace_secs"] = json!(601)),
        ),
        (
            "bad actor",
            Box::new(|v| v["pipeline"]["worker_actor"] = json!("a b")),
        ),
    ];
    cases.push((
        "an activation that is not one",
        Box::new(|v| {
            v["required_activations"] = json!([{"activation_id": "x"}]);
        }),
    ));
    for (label, mutate) in cases {
        let mut v = example();
        mutate(&mut v);
        assert_eq!(
            parse(&v).err(),
            Some(DaemonReason::ConfigInvalid),
            "{label}"
        );
    }
    // Garbage and an oversized file.
    assert_eq!(
        DaemonConfig::from_json(b"not json").err(),
        Some(DaemonReason::ConfigInvalid)
    );
    assert_eq!(
        DaemonConfig::from_json(&vec![b' '; 40_000]).err(),
        Some(DaemonReason::ConfigInvalid)
    );
    // A non-loopback bind is refused by name, and fine only when allowed
    // explicitly.
    let mut v = example();
    v["listener"]["bind"] = json!("0.0.0.0:8787");
    assert_eq!(parse(&v).err(), Some(DaemonReason::BindRefused));
    v["listener"]["allow_non_loopback"] = json!(true);
    assert!(parse(&v).is_ok());
}

#[test]
fn defaults_are_the_documented_ones() {
    let mut v = example();
    for k in ["queue", "schedule", "pipeline"] {
        v.as_object_mut().unwrap().remove(k);
    }
    let c = parse(&v).unwrap();
    assert_eq!(
        (c.queue.workers, c.queue.lease_secs, c.queue.max_attempts),
        (1, 120, 5)
    );
    assert_eq!(
        (c.schedule.export_secs, c.schedule.startup_check_secs),
        (30, 300)
    );
    assert_eq!(c.pipeline.lease_secs, 300);
    // Backoff doubles from the base to the cap, with no jitter.
    let q = QueueConfig::default();
    let secs: Vec<u64> = (1..=9).map(|n| q.backoff_secs(n)).collect();
    assert_eq!(secs, vec![5, 10, 20, 40, 80, 160, 300, 300, 300]);
    assert_eq!(q.backoff_secs(0), 5);
    assert_eq!(q.backoff_secs(u32::MAX), 300);
}

// ---- the files on disk ----------------------------------------------------------

fn tmp(label: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "custodian-daemon-config-{}-{label}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    p
}

fn put(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn dir(path: &Path, mode: u32) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A complete, valid tree under `root`; returns the config document.
fn tree(root: &Path) -> Value {
    let intake = json!({
        "events": ["pull_request"],
        "installations": [{"installation_id": 900001, "repository_ids": [800001]}],
        "actors": [{"github_user_id": 700001, "actor": "act_synthetic000000000001", "roles": ["requester"]}]
    });
    put(&root.join("deployment.json"), b"{}", 0o600);
    put(
        &root.join("intake.json"),
        &serde_json::to_vec(&intake).unwrap(),
        0o600,
    );
    put(&root.join("policy.json"), b"{}", 0o644);
    put(&root.join("webhook.secret"), &[b'S'; 40], 0o600);
    for d in ["requests", "artifacts", "approvals"] {
        dir(&root.join(d), 0o755);
    }
    for d in ["staging", "released"] {
        dir(&root.join(d), 0o700);
    }
    let mut v = example();
    let s = |n: &str| json!(root.join(n));
    v["deployment_config_path"] = s("deployment.json");
    v["intake"]["config_path"] = s("intake.json");
    v["intake"]["webhook_secret_path"] = s("webhook.secret");
    v["requests_dir"] = s("requests");
    v["artifacts_dir"] = s("artifacts");
    v["worker"]["staging_dir"] = s("staging");
    v["release"]["disclosure_policy_path"] = s("policy.json");
    v["release"]["approvals_dir"] = s("approvals");
    v["release"]["output_dir"] = s("released");
    v
}

fn write_cfg(root: &Path, v: &Value, mode: u32) -> PathBuf {
    let p = root.join("daemon.json");
    put(&p, &serde_json::to_vec(v).unwrap(), mode);
    p
}

#[test]
fn a_complete_tree_loads_and_the_secrets_come_only_from_their_files() {
    let root = tmp("ok");
    let v = tree(&root);
    let path = write_cfg(&root, &v, 0o600);
    let c = DaemonConfig::load(&path).expect("loads");
    assert!(c.read_intake_config().is_ok());
    assert!(c.read_webhook_secret().is_ok());
    assert!(c.read_policy_bytes().is_ok());
    // The configuration holds paths, not secrets: nothing of the secret is in
    // its debug form, and the secret type redacts itself.
    assert!(!format!("{c:?}").contains("SSSS"));
    assert_eq!(
        format!("{:?}", c.read_webhook_secret().unwrap()),
        "WebhookSecret(<redacted>)"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_loader_refuses_unsafe_files_and_directories_without_naming_them() {
    let root = tmp("unsafe");
    let v = tree(&root);
    let load = |mode: u32| DaemonConfig::load(&write_cfg(&root, &v, mode));

    // The config file itself must not be writable by others.
    assert_eq!(load(0o666).err(), Some(DaemonReason::NotConfigured));
    assert_eq!(load(0o620).err(), Some(DaemonReason::NotConfigured));
    assert!(load(0o644).is_ok());
    // A symlink as the config file.
    let real = write_cfg(&root, &v, 0o600);
    let link = root.join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        DaemonConfig::load(&link).err(),
        Some(DaemonReason::NotConfigured)
    );
    // A missing file.
    assert_eq!(
        DaemonConfig::load(&root.join("nope.json")).err(),
        Some(DaemonReason::NotConfigured)
    );

    // The webhook secret: group or other bits, a symlink, a directory, absent.
    let secret = root.join("webhook.secret");
    for mode in [0o640, 0o604, 0o644, 0o660] {
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            load(0o600).err(),
            Some(DaemonReason::SecretFileRejected),
            "{mode:o}"
        );
    }
    std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
    let moved = root.join("moved.secret");
    std::fs::rename(&secret, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &secret).unwrap();
    assert_eq!(load(0o600).err(), Some(DaemonReason::SecretFileRejected));
    std::fs::remove_file(&secret).unwrap();
    assert_eq!(load(0o600).err(), Some(DaemonReason::SecretFileRejected));
    std::fs::rename(&moved, &secret).unwrap();
    assert!(load(0o600).is_ok());

    // Directories: group- or other-writable ones are refused, a symlinked
    // one is refused, and the private ones must be owner-only.
    std::fs::set_permissions(
        root.join("requests"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert_eq!(load(0o600).err(), Some(DaemonReason::NotConfigured));
    std::fs::set_permissions(
        root.join("requests"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::set_permissions(root.join("staging"), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(load(0o600).err(), Some(DaemonReason::NotConfigured));
    std::fs::set_permissions(root.join("staging"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(
        root.join("released"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert_eq!(load(0o600).err(), Some(DaemonReason::NotConfigured));
    std::fs::set_permissions(
        root.join("released"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let approvals = root.join("approvals");
    let elsewhere = root.join("approvals-real");
    std::fs::rename(&approvals, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &approvals).unwrap();
    assert_eq!(load(0o600).err(), Some(DaemonReason::NotConfigured));
    std::fs::remove_file(&approvals).unwrap();
    std::fs::rename(&elsewhere, &approvals).unwrap();
    assert!(load(0o600).is_ok());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_secret_and_the_intake_configuration_are_validated_when_read() {
    let root = tmp("read");
    let v = tree(&root);
    let c = DaemonConfig::load(&write_cfg(&root, &v, 0o600)).unwrap();
    // A trailing newline is not part of the secret; a short secret is refused.
    put(&root.join("webhook.secret"), &[b'S'; 40], 0o600);
    assert!(c.read_webhook_secret().is_ok());
    let mut with_newline = vec![b'S'; 32];
    with_newline.push(b'\n');
    put(&root.join("webhook.secret"), &with_newline, 0o600);
    assert!(c.read_webhook_secret().is_ok());
    put(&root.join("webhook.secret"), &[b'S'; 31], 0o600);
    assert_eq!(
        c.read_webhook_secret().err(),
        Some(DaemonReason::SecretFileRejected)
    );
    put(&root.join("webhook.secret"), b"", 0o600);
    assert_eq!(
        c.read_webhook_secret().err(),
        Some(DaemonReason::SecretFileRejected)
    );
    // The intake configuration rejects unknown fields and empty allowlists.
    put(
        &root.join("intake.json"),
        br#"{"events":["pull_request"],"extra":1}"#,
        0o600,
    );
    assert_eq!(
        c.read_intake_config().err(),
        Some(DaemonReason::ConfigInvalid)
    );
    put(&root.join("intake.json"), b"{}", 0o600);
    assert_eq!(
        c.read_intake_config().err(),
        Some(DaemonReason::ConfigInvalid)
    );
    let _ = std::fs::remove_dir_all(&root);
}
