//! C5 failure-mode tests. Synthetic data generated in tempdirs only.

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use common::*;
use custodian_contracts::common::{BudgetScope, EvaluationDomain, ReviewStatus};
use custodian_contracts::types::EpochId;
use custodian_core::lifecycle::ReasonCode;
use custodian_core::ports::{CorpusAccess, Refusal};
use custodian_corpus::fsguard;
use custodian_corpus::manifest::Manifest;
use custodian_corpus::registry::EpochState;
use custodian_corpus::store::{SealedDoc, Stage};
use custodian_corpus::testing::{FaultyStore, MemoryEpochStore, TempRoot};
use custodian_corpus::{
    conformance, CommitmentKey, EpochBlobStore, FsEpochStore, ProtectedPopulations, Registry,
    StorageReason as R,
};

const A: &[u8] = b"synthetic-placeholder-alpha";
const B: &[u8] = b"synthetic-placeholder-beta";

// ---- seal ---------------------------------------------------------------

#[test]
fn seal_activate_open_read_round_trip() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A), ("two", B)]);
    let h = f.pop.open_verified(&authorization(&e)).unwrap();
    assert_eq!(
        f.pop.entry_names(&h).unwrap(),
        vec![name("one"), name("two")]
    );
    assert_eq!(f.pop.read_entry(&h, &name("one")).unwrap().expose(), A);
    assert_eq!(f.pop.read_entry(&h, &name("two")).unwrap().expose(), B);
    let binding = f.pop.binding(&h).unwrap();
    assert_eq!(binding.epoch_id, e);
    // The commitment is exactly the manifest digest over names, sizes, hashes.
    let manifest = Manifest::decode_canonical(
        &store_of(&f.root())
            .read_doc(&e, SealedDoc::Manifest)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(binding.population_digest, manifest.population_digest());
    f.pop.verify_epoch(&e).unwrap();
    f.pop.close(h);
}

#[test]
fn epoch_ids_are_opaque_and_unique() {
    let f = Fixture::new();
    let a = f.seal(&[("one", A)]);
    let b = f.seal(&[("one", A)]);
    assert_ne!(a, b);
    assert!(a.as_str().starts_with("epo_"));
    // Same content, different epochs: distinct seals, equal commitments.
    let (sa, sb) = (
        f.pop.verify_epoch(&a).unwrap(),
        f.pop.verify_epoch(&b).unwrap(),
    );
    assert_ne!(sa, sb);
}

#[test]
fn changed_content_is_a_new_epoch_old_state_untouched() {
    let f = Fixture::new();
    let old = f.seal(&[("one", A)]);
    let before = f.pop.verify_epoch(&old).unwrap();
    let new = f.seal(&[("one", B)]);
    assert_ne!(old, new);
    assert_eq!(f.pop.verify_epoch(&old).unwrap(), before);
    // The adapter refuses any mutation of a sealed epoch.
    let store = store_of(&f.root());
    assert_eq!(
        store.put_entry(&old, &name("two"), b"x"),
        Err(R::EpochSealed)
    );
    assert_eq!(store.finalize(&old, b"m", b"s"), Err(R::EpochSealed));
    assert_eq!(store.discard_staging(&old), Err(R::EpochSealed));
    assert_eq!(store.create_staging(&old), Err(R::AlreadyExists));
}

#[test]
fn sealed_files_are_read_only_on_disk() {
    let f = Fixture::new();
    let e = f.seal(&[("one", A)]);
    assert!(fs::write(f.sealed_entry(&e, "one"), b"x").is_err());
    assert!(fs::write(f.sealed_dir(&e).join("SEAL"), b"x").is_err());
    assert!(fs::write(f.sealed_dir(&e).join("entries").join("new"), b"x").is_err());
}

#[test]
fn seal_requires_review_matching_budget_and_entries() {
    let f = Fixture::new();
    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Pii, None)
        .unwrap();
    f.pop.add_entry(&w, &name("one"), A).unwrap();
    let unreviewed = inputs_for(w.epoch_id(), ReviewStatus::NotReviewed);
    assert_eq!(f.pop.seal(w, unreviewed).unwrap_err(), R::ReviewMissing);

    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Pii, None)
        .unwrap();
    f.pop.add_entry(&w, &name("one"), A).unwrap();
    let mut wrong_budget = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
    wrong_budget.budget = BudgetScope::PopulationEpoch {
        corpus_id: corpus_id(),
        epoch_id: EpochId::parse("epo_00000000000000000000000000000000").unwrap(),
        family_id: None,
    };
    assert_eq!(f.pop.seal(w, wrong_budget).unwrap_err(), R::BindingMismatch);

    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Pii, None)
        .unwrap();
    let inputs = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
    assert_eq!(f.pop.seal(w, inputs).unwrap_err(), R::EmptyCorpus);
    // Failed seals leave nothing registered and nothing staged.
    assert_eq!(f.pop.registry().view().unwrap().epochs().count(), 0);
    assert_eq!(fs::read_dir(f.root().join("staging")).unwrap().count(), 0);
}

// ---- tamper ---------------------------------------------------------------

fn expect_open_err(f: &Fixture, e: &EpochId, want: R) {
    assert_eq!(f.pop.open_verified(&authorization(e)).unwrap_err(), want);
    // The port itself reports only a coarse core reason code.
    assert_eq!(
        f.pop.open(&authorization(e)).unwrap_err(),
        Refusal(ReasonCode::CorpusUnavailable)
    );
}

#[test]
fn tampered_entry_bytes_are_detected_on_open_and_read() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A), ("two", B)]);
    let h = f.pop.open_verified(&authorization(&e)).unwrap();
    tamper_file(&f.sealed_entry(&e, "one"), b"synthetic-placeholder-ALPHA");
    // Open handle: read re-verifies and refuses.
    assert_eq!(
        f.pop.read_entry(&h, &name("one")).unwrap_err(),
        R::IntegrityMismatch
    );
    // Untouched sibling still verifies per entry.
    assert_eq!(f.pop.read_entry(&h, &name("two")).unwrap().expose(), B);
    expect_open_err(&f, &e, R::IntegrityMismatch);
    assert_eq!(f.pop.verify_epoch(&e), Err(R::IntegrityMismatch));
}

#[test]
fn tampered_length_is_detected() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    tamper_file(&f.sealed_entry(&e, "one"), b"");
    expect_open_err(&f, &e, R::IntegrityMismatch);
}

#[test]
fn tampered_manifest_or_seal_is_detected() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let seal_path = f.sealed_dir(&e).join("SEAL");
    let good_seal = fs::read(&seal_path).unwrap();
    let mut bad = good_seal.clone();
    let i = bad.iter().position(|b| *b == b'1').unwrap();
    bad[i] = b'2';
    tamper_file(&seal_path, &bad);
    let err = f.pop.open_verified(&authorization(&e)).unwrap_err();
    assert!(
        matches!(err, R::IntegrityMismatch | R::SealInvalid),
        "{err}"
    );
    tamper_file(&seal_path, &good_seal);
    f.pop.open_verified(&authorization(&e)).unwrap();

    let man_path = f.sealed_dir(&e).join("MANIFEST");
    let good_man = fs::read(&man_path).unwrap();
    let forged = Manifest::new(vec![custodian_corpus::manifest::ManifestEntry {
        name: name("one"),
        sha256: custodian_corpus::manifest::sha256_hex(b"other"),
        size: 5,
    }])
    .unwrap();
    tamper_file(&man_path, &forged.canonical_bytes());
    expect_open_err(&f, &e, R::IntegrityMismatch);
    tamper_file(&man_path, b"{}");
    expect_open_err(&f, &e, R::ManifestInvalid);
    tamper_file(&man_path, &good_man);
    f.pop.open_verified(&authorization(&e)).unwrap();
}

#[test]
fn added_or_removed_entries_are_detected() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A), ("two", B)]);
    let entries = f.sealed_dir(&e).join("entries");
    chmod(&entries, 0o700);
    fs::write(entries.join("extra"), b"x").unwrap();
    chmod(&entries.join("extra"), 0o400);
    chmod(&entries, 0o500);
    assert_eq!(
        f.pop.open_verified(&authorization(&e)).unwrap_err(),
        R::IntegrityMismatch
    );
    chmod(&entries, 0o700);
    fs::remove_file(entries.join("extra")).unwrap();
    chmod(&f.sealed_entry(&e, "two"), 0o600);
    fs::remove_file(f.sealed_entry(&e, "two")).unwrap();
    chmod(&entries, 0o500);
    assert_eq!(
        f.pop.open_verified(&authorization(&e)).unwrap_err(),
        R::IntegrityMismatch
    );
}

#[test]
fn unexpected_file_in_sealed_epoch_is_a_layout_error() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let dir = f.sealed_dir(&e);
    chmod(&dir, 0o700);
    fs::write(dir.join("README"), b"x").unwrap();
    chmod(&dir, 0o500);
    assert_eq!(
        f.pop.open_verified(&authorization(&e)).unwrap_err(),
        R::LayoutInvalid
    );
}

// ---- traversal and names ----------------------------------------------------

#[test]
fn entry_names_reject_traversal_and_odd_shapes() {
    for bad in [
        "",
        ".",
        "..",
        "../x",
        "a/b",
        "a\\b",
        "/abs",
        ".hidden",
        "-x",
        "A",
        "a b",
        "a\0b",
        "a..b",
        "é",
        &"a".repeat(65),
    ] {
        assert_eq!(
            custodian_corpus::EntryName::parse(bad).unwrap_err(),
            R::NameInvalid,
            "name should be rejected"
        );
    }
    assert!(custodian_corpus::EntryName::parse(&"a".repeat(64)).is_ok());
}

#[test]
fn population_id_cannot_traverse_out_of_the_layout() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    for bad in [
        format!("../sealed/{}", e.as_str()),
        format!("{}/../{}", e.as_str(), e.as_str()),
        "epo_../../keys".to_owned(),
        String::new(),
        "not-an-epoch".to_owned(),
    ] {
        let mut auth = authorization(&e);
        auth.population = custodian_core::PopulationId::new(bad);
        assert_eq!(f.pop.open_verified(&auth).unwrap_err(), R::WrongEpoch);
    }
}

// ---- symlink, hardlink, special files -----------------------------------------

#[test]
fn symlinked_entry_in_staging_is_refused_at_seal() {
    let f = Fixture::new();
    let outside = f.tmp.path().join("outside-synthetic");
    fs::write(&outside, A).unwrap();
    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    symlink(&outside, f.staging_entries(w.epoch_id()).join("one")).unwrap();
    let inputs = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
    assert_eq!(f.pop.seal(w, inputs).unwrap_err(), R::SymlinkRefused);
}

#[test]
fn symlink_swapped_into_sealed_epoch_is_refused() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let outside = f.tmp.path().join("outside-synthetic");
    fs::write(&outside, A).unwrap(); // identical bytes: only the link is wrong
    chmod(&outside, 0o400);
    let entries = f.sealed_dir(&e).join("entries");
    chmod(&entries, 0o700);
    chmod(&f.sealed_entry(&e, "one"), 0o600);
    fs::remove_file(f.sealed_entry(&e, "one")).unwrap();
    symlink(&outside, f.sealed_entry(&e, "one")).unwrap();
    chmod(&entries, 0o500);
    expect_open_err(&f, &e, R::SymlinkRefused);
}

#[test]
fn symlinked_epoch_directory_is_refused() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let real = f.sealed_dir(&e);
    chmod(&real, 0o700);
    let moved = f.tmp.path().join("moved-synthetic");
    fs::rename(&real, &moved).unwrap();
    symlink(&moved, &real).unwrap();
    expect_open_err(&f, &e, R::SymlinkRefused);
}

#[test]
fn hardlinked_entry_is_refused() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let alias = f.tmp.path().join("alias-synthetic");
    fs::hard_link(f.sealed_entry(&e, "one"), &alias).unwrap();
    expect_open_err(&f, &e, R::HardlinkRefused);
    fs::remove_file(&alias).unwrap();
    f.pop.open_verified(&authorization(&e)).unwrap();
}

#[test]
fn hardlinked_staging_entry_is_refused_at_seal() {
    let f = Fixture::new();
    let outside = f.tmp.path().join("outside-synthetic");
    fs::write(&outside, A).unwrap();
    chmod(&outside, 0o600);
    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    fs::hard_link(&outside, f.staging_entries(w.epoch_id()).join("one")).unwrap();
    let inputs = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
    assert_eq!(f.pop.seal(w, inputs).unwrap_err(), R::HardlinkRefused);
}

#[test]
fn special_file_is_refused() {
    let f = Fixture::new();
    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    let fifo = f.staging_entries(w.epoch_id()).join("one");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap();
    assert!(status.success());
    let inputs = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
    assert_eq!(f.pop.seal(w, inputs).unwrap_err(), R::SpecialFileRefused);
}

// ---- permissions and ownership ------------------------------------------------

#[test]
fn root_must_be_mode_0700() {
    let tmp = TempRoot::new();
    for mode in [0o755, 0o750, 0o770, 0o701, 0o500] {
        let root = tmp.path().join(format!("r{mode:o}"));
        mkdir_private(&root);
        chmod(&root, mode);
        assert_eq!(
            FsEpochStore::open(&root).unwrap_err(),
            R::PermissionViolation,
            "mode {mode:o}"
        );
        chmod(&root, 0o700);
    }
}

#[test]
fn loosened_permissions_are_refused_on_access() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let file = f.sealed_entry(&e, "one");
    for mode in [0o644, 0o440, 0o600, 0o404] {
        chmod(&file, mode);
        expect_open_err(&f, &e, R::PermissionViolation);
    }
    chmod(&file, 0o400);
    let dir = f.sealed_dir(&e);
    chmod(&dir, 0o755);
    expect_open_err(&f, &e, R::PermissionViolation);
    chmod(&dir, 0o500);
    let sub = dir.join("entries");
    chmod(&sub, 0o755);
    expect_open_err(&f, &e, R::PermissionViolation);
    chmod(&sub, 0o500);
    f.pop.open_verified(&authorization(&e)).unwrap();
}

#[test]
fn staging_permissions_are_enforced() {
    let f = Fixture::new();
    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    f.pop.add_entry(&w, &name("one"), A).unwrap();
    chmod(&f.staging_entries(w.epoch_id()).join("one"), 0o644);
    let inputs = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
    assert_eq!(f.pop.seal(w, inputs).unwrap_err(), R::PermissionViolation);
}

#[test]
fn created_files_and_dirs_have_exact_private_modes() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let e = f.seal(&[("one", A)]);
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&f.root()), 0o700);
    assert_eq!(mode(&f.sealed_dir(&e)), 0o500);
    assert_eq!(mode(&f.sealed_dir(&e).join("entries")), 0o500);
    assert_eq!(mode(&f.sealed_entry(&e, "one")), 0o400);
    assert_eq!(mode(&f.sealed_dir(&e).join("SEAL")), 0o400);
    assert_eq!(mode(&f.sealed_dir(&e).join("MANIFEST")), 0o400);
    assert_eq!(mode(&f.root().join("registry").join("events.jsonl")), 0o600);
    assert_eq!(mode(&f.root().join("keys").join("commitment.key")), 0o600);
    for d in ["staging", "sealed", "registry", "keys"] {
        assert_eq!(mode(&f.root().join(d)), 0o700);
    }
}

#[test]
fn owner_mismatch_is_refused() {
    let tmp = TempRoot::new();
    let uid = fsguard::probe_owner(tmp.path()).unwrap();
    assert_eq!(
        fsguard::check_dir(tmp.path(), uid.wrapping_add(1), 0o700),
        Err(R::OwnerMismatch)
    );
    let p = tmp.path().join("f");
    fsguard::create_file(&p, b"x", 0o600).unwrap();
    assert_eq!(
        fsguard::read_checked(&p, uid.wrapping_add(1), 0o600, 10),
        Err(R::OwnerMismatch)
    );
    assert_eq!(fsguard::read_checked(&p, uid, 0o600, 10).unwrap(), b"x");
    assert_eq!(fsguard::read_checked(&p, uid, 0o600, 0), Err(R::TooLarge));
}

#[test]
fn key_file_permissions_are_enforced_on_reopen() {
    let f = Fixture::new();
    let key = f.root().join("keys").join("commitment.key");
    chmod(&key, 0o644);
    assert!(ProtectedPopulations::open_fs(&f.root()).is_err());
    chmod(&key, 0o600);
    fs::write(&key, "not-hex").unwrap();
    assert!(ProtectedPopulations::open_fs(&f.root()).is_err());
}

// ---- wrong epoch and state ------------------------------------------------------

#[test]
fn swapped_epoch_directories_are_a_wrong_epoch() {
    let f = Fixture::new();
    let a = f.seal_active(&[("one", A)]);
    let b = f.seal(&[("one", B)]);
    let (da, db) = (f.sealed_dir(&a), f.sealed_dir(&b));
    let tmp = f.root().join("sealed").join("swap-tmp");
    // macOS requires owner write permission on the directory being renamed.
    // Simulate the owner's swap, then restore sealed permissions before checking.
    chmod(&da, 0o700);
    chmod(&db, 0o700);
    fs::rename(&da, &tmp).unwrap();
    fs::rename(&db, &da).unwrap();
    fs::rename(&tmp, &db).unwrap();
    chmod(&da, 0o500);
    chmod(&db, 0o500);
    expect_open_err(&f, &a, R::WrongEpoch);
    assert_eq!(f.pop.verify_epoch(&b), Err(R::WrongEpoch));
}

#[test]
fn unknown_unsealed_inactive_and_retired_epochs_are_refused() {
    let f = Fixture::new();
    let unknown = EpochId::parse("epo_11111111111111111111111111111111").unwrap();
    expect_open_err(&f, &unknown, R::UnknownEpoch);

    let sealed_only = f.seal(&[("one", A)]);
    expect_open_err(&f, &sealed_only, R::NotActive);

    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    f.pop.add_entry(&w, &name("one"), A).unwrap();
    expect_open_err(&f, w.epoch_id(), R::UnknownEpoch);
    f.pop.abandon(w).unwrap();

    let e = f.seal_active(&[("one", A)]);
    let h = f.pop.open_verified(&authorization(&e)).unwrap();
    f.pop.retire(&e, now()).unwrap();
    assert_eq!(
        f.pop.read_entry(&h, &name("one")).unwrap_err(),
        R::NotActive
    );
    expect_open_err(&f, &e, R::NotActive);
}

#[test]
fn handles_are_scoped_to_the_issuing_instance_and_closed_handles_die() {
    let f = Fixture::new();
    let e = f.seal_active(&[("one", A)]);
    let h = f.pop.open(&authorization(&e)).unwrap();
    let forged = custodian_core::ports::CorpusHandle::new(h.token() + 1000);
    assert_eq!(
        f.pop.read_entry(&forged, &name("one")).unwrap_err(),
        R::InvalidHandle
    );
    let token = h.token();
    f.pop.close(h);
    let stale = custodian_core::ports::CorpusHandle::new(token);
    assert_eq!(f.pop.entry_names(&stale).unwrap_err(), R::InvalidHandle);
    // Reading a name that is not in the manifest is refused, not guessed.
    let h = f.pop.open(&authorization(&e)).unwrap();
    assert_eq!(f.pop.read_entry(&h, &name("zzz")).unwrap_err(), R::NotFound);
}

// ---- root inside a git tree -----------------------------------------------------

#[test]
fn root_inside_git_working_tree_is_refused() {
    let tmp = TempRoot::new();
    // Repository directory with a .git directory.
    let repo = tmp.path().join("repo");
    mkdir_private(&repo);
    fs::create_dir(repo.join(".git")).unwrap();
    let inside = repo.join("protected");
    mkdir_private(&inside);
    assert_eq!(
        FsEpochStore::open(&inside).unwrap_err(),
        R::RootInsideGitTree
    );
    // Deeper nesting.
    let deep = inside.join("a");
    mkdir_private(&deep);
    assert_eq!(FsEpochStore::open(&deep).unwrap_err(), R::RootInsideGitTree);
    // The root itself being a repo root.
    let own = tmp.path().join("own");
    mkdir_private(&own);
    fs::create_dir(own.join(".git")).unwrap();
    assert_eq!(FsEpochStore::open(&own).unwrap_err(), R::RootInsideGitTree);
    // Worktrees and submodules use a `.git` file.
    let wt = tmp.path().join("wt");
    mkdir_private(&wt);
    fs::write(wt.join(".git"), "gitdir: elsewhere").unwrap();
    let wt_root = wt.join("protected");
    mkdir_private(&wt_root);
    assert_eq!(
        FsEpochStore::open(&wt_root).unwrap_err(),
        R::RootInsideGitTree
    );
    // And through the full constructor.
    assert!(ProtectedPopulations::open_fs(&inside).is_err());
    // Nothing was created in the refused roots.
    assert_eq!(fs::read_dir(&deep).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&wt_root).unwrap().count(), 0);
}

#[test]
fn root_must_be_absolute_real_directory() {
    let tmp = TempRoot::new();
    assert_eq!(
        FsEpochStore::open(std::path::Path::new("relative/protected")).unwrap_err(),
        R::RootInvalid
    );
    assert_eq!(
        FsEpochStore::open(&tmp.path().join("missing")).unwrap_err(),
        R::RootInvalid
    );
    let real = tmp.path().join("real");
    mkdir_private(&real);
    let link = tmp.path().join("link");
    symlink(&real, &link).unwrap();
    assert_eq!(FsEpochStore::open(&link).unwrap_err(), R::RootInvalid);
    let file = tmp.path().join("file");
    fs::write(&file, "x").unwrap();
    assert_eq!(FsEpochStore::open(&file).unwrap_err(), R::RootInvalid);
}

// ---- registry ---------------------------------------------------------------------

#[test]
fn registry_lifecycle_is_enforced() {
    let f = Fixture::new();
    let a = f.seal(&[("one", A)]);
    let b = f.seal(&[("one", B)]);
    assert_eq!(f.pop.state(&a).unwrap(), EpochState::Sealed);
    f.pop.activate(&a, now()).unwrap();
    assert_eq!(f.pop.activate(&a, now()), Err(R::InvalidTransition));
    // One active epoch per corpus and family.
    assert_eq!(f.pop.activate(&b, now()), Err(R::InvalidTransition));
    f.pop.retire(&a, now()).unwrap();
    assert_eq!(f.pop.activate(&a, now()), Err(R::InvalidTransition));
    assert_eq!(f.pop.retire(&a, now()), Err(R::InvalidTransition));
    f.pop.activate(&b, now()).unwrap();
    assert_eq!(f.pop.state(&a).unwrap(), EpochState::Retired);
    assert_eq!(f.pop.state(&b).unwrap(), EpochState::Active);
    let unknown = EpochId::parse("epo_22222222222222222222222222222222").unwrap();
    assert_eq!(f.pop.retire(&unknown, now()), Err(R::UnknownEpoch));
}

#[test]
fn registry_chain_detects_edits_and_interior_deletion() {
    let f = Fixture::new();
    let a = f.seal(&[("one", A)]);
    f.pop.activate(&a, now()).unwrap();
    let path = f.root().join("registry").join("events.jsonl");
    let good = fs::read(&path).unwrap();
    assert!(!good.is_empty());

    let mut edited = good.clone();
    let i = edited.iter().position(|b| *b == b'9').unwrap();
    edited[i] = b'8';
    tamper_registry(&path, &edited);
    assert!(f.pop.registry().view().is_err());
    assert!(ProtectedPopulations::open_fs(&f.root()).is_err());

    // Delete the first of two events: chain no longer starts at genesis.
    let lines: Vec<&[u8]> = good.split_inclusive(|b| *b == b'\n').collect();
    assert_eq!(lines.len(), 2);
    tamper_registry(&path, lines[1]);
    assert!(f.pop.registry().view().is_err());

    // Swapped order.
    let swapped = [lines[1], lines[0]].concat();
    tamper_registry(&path, &swapped);
    assert!(f.pop.registry().view().is_err());

    // Missing trailing newline (torn write).
    tamper_registry(&path, &good[..good.len() - 1]);
    assert!(f.pop.registry().view().is_err());

    tamper_registry(&path, &good);
    assert!(f.pop.registry().view().is_ok());
    // While the log is invalid, nothing is usable (fail closed).
    tamper_registry(&path, b"garbage\n");
    assert!(f.pop.open(&authorization(&a)).is_err());
}

fn tamper_registry(path: &std::path::Path, bytes: &[u8]) {
    tamper_file(path, bytes);
    chmod(path, 0o600);
}

#[test]
fn lifecycle_observer_sees_transitions_without_data() {
    use custodian_corpus::LifecycleObserver;
    use std::sync::{Arc, Mutex};
    struct Rec(Mutex<Vec<(String, Option<EpochState>, EpochState)>>);
    impl LifecycleObserver for Rec {
        fn on_transition(&self, e: &EpochId, from: Option<EpochState>, to: EpochState) {
            self.0
                .lock()
                .unwrap()
                .push((e.as_str().to_owned(), from, to));
        }
    }
    let tmp = TempRoot::new();
    let root = tmp.path().join("p");
    mkdir_private(&root);
    let rec = Arc::new(Rec(Mutex::new(Vec::new())));
    let pop = ProtectedPopulations::open_fs(&root)
        .unwrap()
        .with_observer(rec.clone());
    let w = pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    pop.add_entry(&w, &name("one"), A).unwrap();
    let e = w.epoch_id().clone();
    let inputs = inputs_for(&e, ReviewStatus::ProjectReviewed);
    pop.seal(w, inputs).unwrap();
    pop.activate(&e, now()).unwrap();
    pop.retire(&e, now()).unwrap();
    let seen = rec.0.lock().unwrap();
    let states: Vec<_> = seen.iter().map(|(_, f, t)| (*f, *t)).collect();
    assert_eq!(
        states,
        vec![
            (None, EpochState::Sealed),
            (Some(EpochState::Sealed), EpochState::Active),
            (Some(EpochState::Active), EpochState::Retired)
        ]
    );
}

// ---- commitment ---------------------------------------------------------------------

#[test]
fn public_commitment_is_keyed_stable_and_not_the_digest() {
    let f = Fixture::new();
    let e = f.seal(&[("one", A)]);
    let c1 = f.pop.public_commitment(&e).unwrap();
    assert_eq!(c1, f.pop.public_commitment(&e).unwrap());
    assert!(c1.as_str().starts_with("hmac-sha256:"));
    let h = f.pop.verify_epoch(&e).unwrap();
    let digest = f
        .pop
        .registry()
        .view()
        .unwrap()
        .get(&e)
        .unwrap()
        .0
        .population_digest
        .clone();
    assert!(!c1.as_str().contains(&digest.as_str()["sha256:".len()..]));
    drop(h);
    // The key persists across reopen; a different key gives a different value.
    let again = ProtectedPopulations::open_fs(&f.root()).unwrap();
    assert_eq!(again.public_commitment(&e).unwrap(), c1);
    let other = CommitmentKey::generate().unwrap();
    assert_ne!(other.commit(digest.as_str()).unwrap(), c1);
}

// ---- adapters -------------------------------------------------------------------------

#[test]
fn fs_adapter_passes_conformance() {
    let tmp = TempRoot::new();
    let root = tmp.path().join("p");
    mkdir_private(&root);
    conformance::run(|| FsEpochStore::open(&root).unwrap());
}

#[test]
fn memory_adapter_passes_conformance() {
    conformance::run(MemoryEpochStore::new);
}

fn mem_pop(
    tmp: &TempRoot,
    store: FaultyStore<MemoryEpochStore>,
) -> ProtectedPopulations<FaultyStore<MemoryEpochStore>> {
    let dir = tmp.path().join("registry");
    if !dir.exists() {
        mkdir_private(&dir);
    }
    let uid = fsguard::probe_owner(tmp.path()).unwrap();
    let registry = Registry::open(&dir, uid).unwrap();
    ProtectedPopulations::new(store, registry, CommitmentKey::generate().unwrap())
}

#[test]
fn backend_failure_at_any_step_fails_closed() {
    // Fail the backend after n healthy calls, for every n up to the number of
    // calls a full seal/activate/open/read needs. No run may hand out wrong
    // bytes, and a failed seal must leave nothing active or readable.
    let mut completed = false;
    for n in 0..60 {
        let tmp = TempRoot::new();
        let pop = mem_pop(&tmp, FaultyStore::new(MemoryEpochStore::new(), n));
        let activated = std::cell::Cell::new(false);
        let flow = || -> Result<Vec<u8>, R> {
            let w = pop.begin_epoch(corpus_id(), EvaluationDomain::Credential, None)?;
            pop.add_entry(&w, &name("one"), A)?;
            let e = w.epoch_id().clone();
            pop.seal(w, inputs_for(&e, ReviewStatus::ProjectReviewed))?;
            pop.activate(&e, now())?;
            activated.set(true);
            let h = pop.open_verified(&authorization(&e))?;
            let b = pop.read_entry(&h, &name("one"))?;
            Ok(b.expose().to_vec())
        };
        match flow() {
            Ok(bytes) => {
                assert_eq!(bytes, A);
                completed = true;
                break;
            }
            Err(r) => {
                // Only fixed, known reasons; backend loss is io_failure.
                assert_eq!(r, R::Io);
                let view = pop.registry().view().unwrap();
                if !activated.get() {
                    for (_, s) in view.epochs() {
                        assert_ne!(s, EpochState::Active, "failed seal left an active epoch");
                    }
                }
            }
        }
    }
    assert!(completed, "flow never completed; raise the bound");
}

#[test]
fn backend_outage_after_activation_refuses_with_store_unavailable() {
    let tmp = TempRoot::new();
    let pop = mem_pop(&tmp, FaultyStore::new(MemoryEpochStore::new(), usize::MAX));
    let w = pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    pop.add_entry(&w, &name("one"), A).unwrap();
    let e = w.epoch_id().clone();
    pop.seal(w, inputs_for(&e, ReviewStatus::ProjectReviewed))
        .unwrap();
    pop.activate(&e, now()).unwrap();
    let h = pop.open(&authorization(&e)).unwrap();
    pop.store().heal(0); // backend goes away
    assert_eq!(pop.read_entry(&h, &name("one")).unwrap_err(), R::Io);
    assert_eq!(
        pop.open(&authorization(&e)).unwrap_err(),
        Refusal(ReasonCode::StoreUnavailable)
    );
    pop.store().heal(usize::MAX); // backend returns: nothing was cached as trusted
    assert_eq!(pop.read_entry(&h, &name("one")).unwrap().expose(), A);
}

#[test]
fn memory_backend_corruption_is_detected_by_the_commitment() {
    let tmp = TempRoot::new();
    let mem = MemoryEpochStore::new();
    // Share the store through a reference-counted wrapper.
    let shared = std::sync::Arc::new(mem);
    struct Shared(std::sync::Arc<MemoryEpochStore>);
    impl EpochBlobStore for Shared {
        fn create_staging(&self, e: &EpochId) -> Result<(), R> {
            self.0.create_staging(e)
        }
        fn put_entry(
            &self,
            e: &EpochId,
            n: &custodian_corpus::EntryName,
            b: &[u8],
        ) -> Result<(), R> {
            self.0.put_entry(e, n, b)
        }
        fn list_entries(
            &self,
            e: &EpochId,
            s: Stage,
        ) -> Result<Vec<custodian_corpus::EntryName>, R> {
            self.0.list_entries(e, s)
        }
        fn read_entry(
            &self,
            e: &EpochId,
            s: Stage,
            n: &custodian_corpus::EntryName,
        ) -> Result<custodian_corpus::ProtectedBytes, R> {
            self.0.read_entry(e, s, n)
        }
        fn finalize(&self, e: &EpochId, m: &[u8], s: &[u8]) -> Result<(), R> {
            self.0.finalize(e, m, s)
        }
        fn read_doc(&self, e: &EpochId, d: SealedDoc) -> Result<Vec<u8>, R> {
            self.0.read_doc(e, d)
        }
        fn discard_staging(&self, e: &EpochId) -> Result<(), R> {
            self.0.discard_staging(e)
        }
        fn is_sealed(&self, e: &EpochId) -> Result<bool, R> {
            self.0.is_sealed(e)
        }
    }
    let dir = tmp.path().join("registry");
    mkdir_private(&dir);
    let uid = fsguard::probe_owner(tmp.path()).unwrap();
    let pop = ProtectedPopulations::new(
        Shared(shared.clone()),
        Registry::open(&dir, uid).unwrap(),
        CommitmentKey::generate().unwrap(),
    );
    let w = pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    pop.add_entry(&w, &name("one"), A).unwrap();
    let e = w.epoch_id().clone();
    pop.seal(w, inputs_for(&e, ReviewStatus::ProjectReviewed))
        .unwrap();
    pop.activate(&e, now()).unwrap();
    let h = pop.open_verified(&authorization(&e)).unwrap();
    shared.corrupt_entry(&e, &name("one"), b"corrupted");
    assert_eq!(
        pop.read_entry(&h, &name("one")).unwrap_err(),
        R::IntegrityMismatch
    );
    assert_eq!(
        pop.open(&authorization(&e)).unwrap_err(),
        Refusal(ReasonCode::CorpusUnavailable)
    );
}
