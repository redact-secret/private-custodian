#![allow(clippy::assertions_on_constants)]
//! Canary leakage scan. A unique canary string is injected into protected
//! bytes and entry names, a battery of success and failure paths runs, and
//! every emitted error, `Debug` rendering, registry row and seal document is
//! scanned. The crate writes no logs of its own; this proves that anything a
//! caller could log from it is free of protected content and paths.

mod common;

use std::fs;
use std::marker::PhantomData;

use common::*;
use custodian_contracts::common::{EvaluationDomain, ReviewStatus};
use custodian_contracts::types::EpochId;
use custodian_core::ports::CorpusAccess;
use custodian_corpus::testing::{FaultyStore, MemoryEpochStore};
use custodian_corpus::{CommitmentKey, EntryName, ProtectedBytes, StorageReason as R};

// Compile-time facts about the private types: no Display, Clone or Serialize.
trait Fallback {
    const DISPLAY: bool = false;
    const CLONE: bool = false;
    const SERIALIZE: bool = false;
}
impl<T> Fallback for T {}
struct Probe<T>(PhantomData<T>);
#[allow(dead_code)]
impl<T: core::fmt::Display> Probe<T> {
    const DISPLAY: bool = true;
}
#[allow(dead_code)]
impl<T: Clone> Probe<T> {
    const CLONE: bool = true;
}
#[allow(dead_code)]
impl<T: serde::Serialize> Probe<T> {
    const SERIALIZE: bool = true;
}

#[test]
fn private_types_have_no_display_clone_or_serialize() {
    assert!(!Probe::<ProtectedBytes>::DISPLAY);
    assert!(!Probe::<ProtectedBytes>::CLONE);
    assert!(!Probe::<ProtectedBytes>::SERIALIZE);
    assert!(!Probe::<CommitmentKey>::DISPLAY);
    assert!(!Probe::<CommitmentKey>::CLONE);
    assert!(!Probe::<CommitmentKey>::SERIALIZE);
    // Sanity: the probe does detect the traits when present.
    assert!(Probe::<String>::DISPLAY && Probe::<String>::CLONE && Probe::<String>::SERIALIZE);
    // Entry names are redacted in Debug.
    let n = EntryName::parse(CANARY).unwrap();
    assert!(!format!("{n:?}").contains(CANARY));
}

fn assert_clean(label: &str, text: &str, extra_forbidden: &[&str]) {
    assert!(!text.contains(CANARY), "canary leaked via {label}");
    for f in extra_forbidden {
        assert!(!text.contains(f), "path or secret leaked via {label}");
    }
}

#[test]
fn errors_and_debug_output_never_carry_canaries_or_paths() {
    let f = Fixture::new();
    let canary_bytes = format!("synthetic {CANARY} payload");
    let root = f.root();
    let root_s = root.to_string_lossy().into_owned();
    let tmp_s = f.tmp.path().to_string_lossy().into_owned();
    let forbidden = [root_s.as_str(), tmp_s.as_str()];
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut note = |label: &str, text: String| seen.push((label.to_owned(), text));

    // Success path, then a battery of failures that touch canary content.
    let e = f.seal_active(&[
        (CANARY, canary_bytes.as_bytes()),
        ("other", b"synthetic-two"),
    ]);
    let h = f.pop.open_verified(&authorization(&e)).unwrap();
    note("handle debug", format!("{h:?}"));
    note("pop debug", format!("{:?}", f.pop));
    note("store debug", format!("{:?}", f.pop.store()));
    note("registry debug", format!("{:?}", f.pop.registry()));
    let bytes = f
        .pop
        .read_entry(&h, &EntryName::parse(CANARY).unwrap())
        .unwrap();
    assert_eq!(bytes.expose(), canary_bytes.as_bytes());
    note("bytes debug", format!("{bytes:?}"));
    note(
        "key debug",
        format!("{:?}", CommitmentKey::generate().unwrap()),
    );
    note(
        "commitment",
        f.pop.public_commitment(&e).unwrap().as_str().to_owned(),
    );

    // Tamper the canary entry, then provoke every kind of refusal.
    tamper_file(&f.sealed_entry(&e, CANARY), b"canary-tampered-content");
    for r in [
        f.pop
            .read_entry(&h, &EntryName::parse(CANARY).unwrap())
            .map(|_| ()),
        f.pop.open_verified(&authorization(&e)).map(|_| ()),
        f.pop.verify_epoch(&e).map(|_| ()),
    ] {
        let err = r.unwrap_err();
        note("tamper error display", err.to_string());
        note("tamper error debug", format!("{err:?}"));
    }
    let refusal = f.pop.open(&authorization(&e)).unwrap_err();
    note("refusal", format!("{refusal:?}"));

    let unknown = EpochId::parse("epo_33333333333333333333333333333333").unwrap();
    for err in [
        f.pop
            .open_verified(&authorization(&unknown))
            .map(|_| ())
            .unwrap_err(),
        EntryName::parse(&format!("../{CANARY}"))
            .map(|_| ())
            .unwrap_err(),
        custodian_corpus::FsEpochStore::open(&f.tmp.path().join(CANARY))
            .map(|_| ())
            .unwrap_err(),
    ] {
        note("error display", err.to_string());
        note("error debug", format!("{err:?}"));
    }
    // Writer paths.
    let w = f
        .pop
        .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
        .unwrap();
    note("writer debug", format!("{w:?}"));
    f.pop
        .add_entry(&w, &EntryName::parse(CANARY).unwrap(), b"x")
        .unwrap();
    let dup = f
        .pop
        .add_entry(&w, &EntryName::parse(CANARY).unwrap(), b"x")
        .unwrap_err();
    note("dup error", format!("{dup} {dup:?}"));
    let inputs = inputs_for(w.epoch_id(), ReviewStatus::NotReviewed);
    let err = f.pop.seal(w, inputs).unwrap_err();
    note("seal error", format!("{err} {err:?}"));
    assert_eq!(err, R::ReviewMissing);

    // Backend failure path.
    let out = FaultyStore::new(MemoryEpochStore::new(), 0);
    let err = custodian_corpus::EpochBlobStore::is_sealed(&out, &unknown).unwrap_err();
    note("backend error", format!("{err} {err:?}"));

    for (label, text) in &seen {
        assert_clean(label, text, &forbidden);
    }

    // Registry rows, the seal document and public output carry no content or
    // entry names; the manifest carries names but never bytes.
    let registry = fs::read(root.join("registry").join("events.jsonl")).unwrap();
    let registry = String::from_utf8(registry).unwrap();
    assert_clean("registry file", &registry, &[]);
    assert!(!registry.contains("other"), "entry name in registry");
    assert!(!registry.contains("synthetic"), "content in registry");

    let seal = fs::read_to_string(f.sealed_dir(&e).join("SEAL")).unwrap();
    assert_clean("seal document", &seal, &[]);
    assert!(
        !seal.contains("payload") && !seal.contains("synthetic-two") && !seal.contains("other")
    );

    let manifest = fs::read_to_string(f.sealed_dir(&e).join("MANIFEST")).unwrap();
    assert!(!manifest.contains("payload") && !manifest.contains("synthetic-two"));

    let key = fs::read_to_string(root.join("keys").join("commitment.key")).unwrap();
    assert_clean("key file", &key, &[]);

    // The only files holding canary bytes are sealed/staging entries.
    for dir in ["registry", "keys"] {
        for c in fs::read_dir(root.join(dir)).unwrap().flatten() {
            let text = fs::read(c.path()).unwrap();
            assert!(!String::from_utf8_lossy(&text).contains(CANARY));
        }
    }
}

#[test]
fn stack_free_text_is_limited_to_the_fixed_code_set() {
    // Every reason renders as a short snake_case code.
    let all = [
        R::RootInvalid,
        R::RootInsideGitTree,
        R::PathEscape,
        R::NameInvalid,
        R::SymlinkRefused,
        R::HardlinkRefused,
        R::SpecialFileRefused,
        R::PermissionViolation,
        R::OwnerMismatch,
        R::AlreadyExists,
        R::NotFound,
        R::LayoutInvalid,
        R::EpochSealed,
        R::EpochNotSealed,
        R::WrongEpoch,
        R::UnknownEpoch,
        R::NotActive,
        R::IntegrityMismatch,
        R::SealInvalid,
        R::ManifestInvalid,
        R::ReviewMissing,
        R::BindingMismatch,
        R::EmptyCorpus,
        R::TooLarge,
        R::RegistryInvalid,
        R::InvalidTransition,
        R::InvalidHandle,
        R::KeyInvalid,
        R::Io,
    ];
    let mut codes = std::collections::HashSet::new();
    for r in all {
        let c = r.to_string();
        assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        assert!(codes.insert(c), "duplicate code");
    }
}
