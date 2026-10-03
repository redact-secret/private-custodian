//! Git backend against tempdir repositories with a local bare repository as
//! the "remote". No network, no real ledger, no credentials.

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use common::*;
use custodian_ledger::{
    startup_check, walk_ledger, BackendError, ExportStatus, Exporter, GitBackend, GitConfig,
    LedgerBackend, LedgerPath, PutOutcome,
};

fn git(dir: &Path, args: &[&str]) -> String {
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
    String::from_utf8(out.stdout).unwrap()
}

fn bare(dir: &TempDir) -> std::path::PathBuf {
    let p = dir.sub("remote.git");
    git(&p, &["init", "--bare", "-q"]);
    p
}

fn writer(dir: &TempDir, name: &str, remote: &Path) -> GitBackend {
    let p = dir.sub(name);
    GitBackend::init(&p, remote.to_str().unwrap(), GitConfig::default()).unwrap()
}

fn lp(s: &str) -> LedgerPath {
    LedgerPath::parse(s).unwrap()
}

/// What the exporter does with a retryable backend error: try again.
fn put_retry(w: &GitBackend, p: &LedgerPath, bytes: &[u8]) -> PutOutcome {
    for _ in 0..200 {
        match w.put_new(p, bytes) {
            Ok(o) => return o,
            Err(e) if e.is_retryable() => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(e) => panic!("{e:?}"),
        }
    }
    panic!("never succeeded");
}

fn remote_files(remote: &Path) -> Vec<String> {
    git(remote, &["ls-tree", "-r", "--name-only", "main"])
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn ledger_paths_are_validated() {
    for bad in [
        "", "/abs", "../x", "a/../b", "a//b", "a/./b", "-rf", "a/-b", "UPPER", "a b", "a\\b",
        "a/b/",
    ] {
        assert_eq!(
            LedgerPath::parse(bad),
            Err(BackendError::InvalidPath),
            "{bad}"
        );
    }
    assert!(LedgerPath::parse("records/audit/rec-audit-00.json").is_ok());
}

#[test]
fn create_identical_and_conflict_against_an_empty_remote() {
    let dir = TempDir::new("git-basic");
    let remote = bare(&dir);
    let w = writer(&dir, "w1", &remote);

    assert_eq!(
        w.put_new(&lp("records/a/one.json"), b"1").unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        w.put_new(&lp("records/a/one.json"), b"1").unwrap(),
        PutOutcome::Identical
    );
    assert_eq!(
        w.put_new(&lp("records/a/one.json"), b"2").unwrap(),
        PutOutcome::Conflict
    );
    assert_eq!(remote_files(&remote), vec!["records/a/one.json"]);
    // The conflicting write left nothing behind, locally or remotely.
    assert_eq!(git(&remote, &["rev-list", "--count", "main"]).trim(), "1");
    assert_eq!(
        w.get(&lp("records/a/one.json")).unwrap().unwrap(),
        b"1".to_vec()
    );
    assert_eq!(w.list("records").unwrap(), vec![lp("records/a/one.json")]);
    assert!(w.get(&lp("records/a/none.json")).unwrap().is_none());
}

#[test]
fn a_second_writer_sees_the_first_and_conflicts_are_detected_across_clones() {
    let dir = TempDir::new("git-two");
    let remote = bare(&dir);
    let w1 = writer(&dir, "w1", &remote);
    let w2 = writer(&dir, "w2", &remote);

    assert_eq!(
        w1.put_new(&lp("records/a/x.json"), b"from-1").unwrap(),
        PutOutcome::Created
    );
    // w2 has never fetched; it must still detect the existing file.
    assert_eq!(
        w2.put_new(&lp("records/a/x.json"), b"from-2").unwrap(),
        PutOutcome::Conflict
    );
    assert_eq!(
        w2.put_new(&lp("records/a/x.json"), b"from-1").unwrap(),
        PutOutcome::Identical
    );
    // And can add other records on top of w1's history.
    assert_eq!(
        w2.put_new(&lp("records/a/y.json"), b"y").unwrap(),
        PutOutcome::Created
    );
    w1.refresh().unwrap();
    assert_eq!(w1.list("records").unwrap().len(), 2);
}

#[test]
fn concurrent_writers_serialize_through_compare_and_swap() {
    let dir = TempDir::new("git-race");
    let remote = bare(&dir);
    let writers: Vec<Arc<GitBackend>> = (0..4)
        .map(|i| Arc::new(writer(&dir, &format!("w{i}"), &remote)))
        .collect();

    // Each writer adds its own records, plus all race for one shared id with
    // different bytes: exactly one wins, the rest see a conflict.
    let handles: Vec<_> = writers
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let w = Arc::clone(w);
            std::thread::spawn(move || {
                let mut created = 0;
                let mut conflicts = 0;
                for n in 0..3 {
                    let p = lp(&format!("records/a/w{i}-{n}.json"));
                    // Identical means an earlier attempt of ours landed.
                    assert!(matches!(
                        put_retry(&w, &p, b"own"),
                        PutOutcome::Created | PutOutcome::Identical
                    ));
                }
                match put_retry(&w, &lp("records/a/shared.json"), format!("w{i}").as_bytes()) {
                    // Identical: our own earlier attempt landed.
                    PutOutcome::Created | PutOutcome::Identical => created += 1,
                    PutOutcome::Conflict => conflicts += 1,
                }
                (created, conflicts)
            })
        })
        .collect();
    let (mut created, mut conflicts) = (0, 0);
    for h in handles {
        let (c, f) = h.join().unwrap();
        created += c;
        conflicts += f;
    }
    assert_eq!((created, conflicts), (1, 3));
    let files = remote_files(&remote);
    assert_eq!(files.len(), 4 * 3 + 1);
    // History is linear and append-only: no merge commits, no rewrites.
    assert_eq!(
        git(&remote, &["rev-list", "--merges", "--count", "main"]).trim(),
        "0"
    );
    let w0 = &writers[0];
    assert!(w0.audit_history().unwrap().is_empty());
}

#[test]
fn unreachable_remote_is_unavailable_and_recovers_without_duplicates() {
    let dir = TempDir::new("git-unavail");
    let remote = bare(&dir);
    let w = writer(&dir, "w1", &remote);
    assert_eq!(
        w.put_new(&lp("records/a/one.json"), b"1").unwrap(),
        PutOutcome::Created
    );

    let moved = dir.path().join("remote-away.git");
    std::fs::rename(&remote, &moved).unwrap();
    assert_eq!(
        w.put_new(&lp("records/a/two.json"), b"2").unwrap_err(),
        BackendError::Unavailable
    );
    assert_eq!(w.refresh().unwrap_err(), BackendError::Unavailable);

    std::fs::rename(&moved, &remote).unwrap();
    assert_eq!(
        w.put_new(&lp("records/a/two.json"), b"2").unwrap(),
        PutOutcome::Created
    );
    assert_eq!(remote_files(&remote).len(), 2);
    assert_eq!(git(&remote, &["rev-list", "--count", "main"]).trim(), "2");
}

#[test]
fn push_rejected_by_the_remote_is_not_reported_as_created() {
    let dir = TempDir::new("git-reject");
    let remote = bare(&dir);
    let w = writer(&dir, "w1", &remote);
    assert_eq!(
        w.put_new(&lp("records/a/one.json"), b"1").unwrap(),
        PutOutcome::Created
    );
    // Server-side policy refuses all further pushes (like a protected branch).
    let hook = remote.join("hooks").join("pre-receive");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let r = w.put_new(&lp("records/a/two.json"), b"2");
    assert!(r.is_err(), "{r:?}");
    assert_eq!(remote_files(&remote).len(), 1);
    // The unpushed local commit does not leak into reads.
    w.refresh().unwrap();
    assert!(w.get(&lp("records/a/two.json")).unwrap().is_none());
}

#[test]
fn history_audit_flags_modified_and_deleted_ledger_files() {
    let dir = TempDir::new("git-history");
    let remote = bare(&dir);
    let w = writer(&dir, "w1", &remote);
    w.put_new(&lp("records/a/one.json"), b"1").unwrap();
    w.put_new(&lp("records/a/two.json"), b"2").unwrap();
    assert!(w.audit_history().unwrap().is_empty());

    // Someone with push rights edits and deletes records (plain commits).
    let evil = dir.sub("evil");
    git(
        &evil,
        &["clone", "-q", "-b", "main", remote.to_str().unwrap(), "."],
    );
    std::fs::write(evil.join("records/a/one.json"), b"edited").unwrap();
    git(&evil, &["rm", "-q", "records/a/two.json"]);
    git(&evil, &["commit", "-q", "-am", "oops"]);
    git(&evil, &["push", "-q", "origin", "HEAD:main"]);

    let v = w.audit_history().unwrap();
    assert!(v
        .iter()
        .any(|v| v.status == 'M' && v.path == "records/a/one.json"));
    assert!(v
        .iter()
        .any(|v| v.status == 'D' && v.path == "records/a/two.json"));
}

#[test]
fn exporter_writes_through_git_and_survives_loss_of_the_writer_clone() {
    let dir = TempDir::new("git-e2e");
    let remote = bare(&dir);
    let db = TempDb::new("git-e2e-db");
    let (store, _fx, settle) = populated_store(&db);
    let s = setup();

    {
        let w = writer(&dir, "writer", &remote);
        let ex = Exporter::new(&w, &s.key.signer, &s.verifier);
        let r = ex.export_pending(&store, NOW + 10).unwrap();
        assert_eq!(r.status, ExportStatus::Drained);
        ex.record_store_checkpoint(&store, NOW + 11).unwrap();
        assert!(store.check_disclosure_precondition(&settle.attempt).is_ok());
    }
    // The writer's clone is destroyed. A brand new clone of the remote
    // verifies the ledger and the startup check passes.
    std::fs::remove_dir_all(dir.path().join("writer")).unwrap();
    let fresh = dir.sub("fresh");
    let w = GitBackend::init(&fresh, remote.to_str().unwrap(), GitConfig::default()).unwrap();
    let walk = walk_ledger(&w, &s.keyring).unwrap();
    assert!(walk.is_trustworthy(), "{:?}", walk.findings);
    assert_eq!(walk.store_checkpoint, store.latest_checkpoint().unwrap());
    startup_check(&w, &s.keyring, &store, None).unwrap();
    assert!(w.audit_history().unwrap().is_empty());

    // Receipts and checkpoints also survive a store restart.
    drop(store);
    let reopened = open(&db);
    startup_check(&w, &s.keyring, &reopened, None).unwrap();
}

#[test]
fn retry_after_remote_outage_does_not_duplicate_or_quarantine() {
    let dir = TempDir::new("git-outage");
    let remote = bare(&dir);
    let db = TempDb::new("git-outage-db");
    let (store, _fx, _s) = populated_store(&db);
    let s = setup();
    let w = writer(&dir, "w1", &remote);
    let ex = Exporter::new(&w, &s.key.signer, &s.verifier).with_config(
        custodian_ledger::ExporterConfig {
            batch: 10,
            retry: custodian_ledger::RetryPolicy {
                max_attempts: 2,
                base_delay_secs: 1,
                max_delay_secs: 2,
            },
        },
    );
    let moved = dir.path().join("away.git");
    std::fs::rename(&remote, &moved).unwrap();
    let r = ex.export_pending(&store, NOW + 10).unwrap();
    assert!(matches!(r.status, ExportStatus::Deferred { .. }));
    std::fs::rename(&moved, &remote).unwrap();
    let r = ex.export_pending(&store, NOW + 20).unwrap();
    assert_eq!(r.status, ExportStatus::Drained);
    assert!(store.outbox_pending(100).unwrap().is_empty());
    assert!(walk_ledger(&w, &s.keyring).unwrap().quarantined.is_empty());
}

#[test]
fn git_backend_debug_hides_paths_and_rejects_unsafe_refs() {
    let dir = TempDir::new("git-misc");
    let remote = bare(&dir);
    let w = writer(&dir, "w1", &remote);
    assert!(!format!("{w:?}").contains("custodian-ledger-test"));
    let bad = GitConfig {
        branch: "--upload-pack=x".to_owned(),
        ..GitConfig::default()
    };
    assert!(GitBackend::init(&dir.sub("w2"), remote.to_str().unwrap(), bad).is_err());
    assert!(GitBackend::init(&dir.sub("w3"), "--evil", GitConfig::default()).is_err());
}
