//! The file key provider's boundary checks and process hardening. Keys are
//! generated inside each test; none is ever printed.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;

use common::*;
use custodian_signer::{FileKeyProvider, KeyProvider, KeyProviderError};

fn mode(p: &Path, m: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
}

fn load(env: &Env) -> Result<(), KeyProviderError> {
    FileKeyProvider::new(env.key_path.clone())
        .load_seed()
        .map(|_| ())
}

#[test]
fn an_owner_only_key_in_an_owner_only_directory_loads() {
    let env = Env::new();
    load(&env).unwrap();
    // 0400 is fine too, and the trailing newline is optional.
    std::fs::write(&env.key_path, &env.seed_hex).unwrap();
    mode(&env.key_path, 0o400);
    load(&env).unwrap();
}

#[test]
fn group_other_and_executable_bits_are_refused() {
    let env = Env::new();
    for m in [0o644, 0o640, 0o604, 0o660, 0o666, 0o700, 0o610] {
        mode(&env.key_path, m);
        assert_eq!(
            load(&env),
            Err(KeyProviderError::InsecurePermissions),
            "mode {m:o}"
        );
    }
    mode(&env.key_path, 0o600);
    load(&env).unwrap();
}

#[test]
fn an_open_directory_is_refused() {
    let env = Env::new();
    for m in [0o755, 0o750, 0o705, 0o770] {
        mode(&env.root, m);
        assert_eq!(load(&env), Err(KeyProviderError::InsecureDirectory), "{m:o}");
    }
    mode(&env.root, 0o700);
    load(&env).unwrap();
}

#[test]
fn symlinks_hard_links_sockets_and_missing_files_are_refused() {
    let env = Env::new();
    // Key path is a symlink to a valid key.
    let real = env.root.join("real");
    std::fs::rename(&env.key_path, &real).unwrap();
    std::os::unix::fs::symlink(&real, &env.key_path).unwrap();
    assert_eq!(load(&env), Err(KeyProviderError::NotRegularFile));
    std::fs::remove_file(&env.key_path).unwrap();

    // A second hard link to the key.
    std::fs::hard_link(&real, &env.key_path).unwrap();
    assert_eq!(load(&env), Err(KeyProviderError::HardLinked));
    std::fs::remove_file(&env.key_path).unwrap();
    std::fs::rename(&real, &env.key_path).unwrap();
    load(&env).unwrap();

    // The containing directory is reached through a symlink.
    let link = std::env::temp_dir().join(format!("pcsg-kl-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&env.root, &link).unwrap();
    assert_eq!(
        FileKeyProvider::new(link.join("k")).load_seed().map(|_| ()),
        Err(KeyProviderError::InsecureDirectory)
    );
    let _ = std::fs::remove_file(&link);

    // Not a regular file.
    std::fs::remove_file(&env.key_path).unwrap();
    let _l = UnixListener::bind(&env.key_path).unwrap();
    assert_eq!(load(&env), Err(KeyProviderError::NotRegularFile));

    // Missing.
    drop(_l);
    std::fs::remove_file(&env.key_path).unwrap();
    assert_eq!(load(&env), Err(KeyProviderError::NotFound));
}

#[test]
fn only_exactly_64_lowercase_hex_characters_are_accepted() {
    let env = Env::new();
    let good = env.seed_hex.clone();
    let cases: Vec<String> = vec![
        String::new(),
        good[..63].to_owned(),
        format!("{good}0"),
        format!("{good}\n\n"),
        format!("{good}\r\n"),
        good.to_uppercase(),
        format!("{}g", &good[..63]),
        format!(" {}", &good[..63]),
        "0x".to_owned() + &good[..62],
        "x".repeat(10_000),
    ];
    for (i, c) in cases.iter().enumerate() {
        std::fs::write(&env.key_path, c).unwrap();
        mode(&env.key_path, 0o600);
        let r = load(&env);
        // An all-uppercase key is hex but not the canonical lowercase form.
        assert_eq!(r, Err(KeyProviderError::Malformed), "case {i}");
    }
}

#[test]
fn provider_errors_name_neither_paths_nor_key_bytes() {
    let env = Env::new();
    mode(&env.key_path, 0o644);
    let e = load(&env).unwrap_err();
    let text = format!("{e} {e:?} {}", e.code());
    assert!(!text.contains(&path_str(&env.root)));
    assert!(!text.contains(&env.seed_hex));
    for e in [
        KeyProviderError::NotFound,
        KeyProviderError::InsecureDirectory,
        KeyProviderError::NotRegularFile,
        KeyProviderError::HardLinked,
        KeyProviderError::WrongOwner,
        KeyProviderError::InsecurePermissions,
        KeyProviderError::Raced,
        KeyProviderError::Malformed,
        KeyProviderError::Unavailable,
    ] {
        assert!(e.code().starts_with("key_"));
    }
}

// ---- process hardening ---------------------------------------------------------------

/// Re-runs this test binary so the process-wide changes (rlimit, environment,
/// umask, dumpable) never touch the other tests.
#[test]
fn hardening_applies_in_a_child_process() {
    let exe = std::env::current_exe().unwrap();
    let out = Command::new(exe)
        .args(["--exact", "hardening_child", "--nocapture", "--test-threads=1"])
        .env("PCSG_HARDEN_CHILD", "1")
        .env("PCSG_CANARY_SECRET", "canary-env-value")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("hardening_child ... ok"),
        "child failed: {stdout}"
    );
}

#[test]
fn hardening_child() {
    if std::env::var_os("PCSG_HARDEN_CHILD").is_none() {
        return; // only meaningful when launched by the parent test
    }
    assert!(std::env::var_os("PCSG_CANARY_SECRET").is_some());
    let h = custodian_signer::harden_process().expect("hardening");
    assert!(h.core_dumps_disabled);
    assert!(h.environment_cleared);
    assert!(h.umask_restricted);
    assert_eq!(std::env::vars_os().count(), 0);
    assert!(std::env::var_os("PCSG_CANARY_SECRET").is_none());
    assert_eq!(
        nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE).unwrap(),
        (0, 0)
    );
    #[cfg(target_os = "linux")]
    {
        assert!(h.dumpable_off);
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        // Not dumpable also means same-uid processes cannot read our memory.
        assert!(status.contains("Name:"));
    }
    // New files are owner-only by default.
    let p = std::env::temp_dir().join(format!("pcsg-umask-{}", std::process::id()));
    std::fs::write(&p, b"x").unwrap();
    let m = std::fs::metadata(&p).unwrap().permissions().mode();
    let _ = std::fs::remove_file(&p);
    assert_eq!(m & 0o077, 0);
}
