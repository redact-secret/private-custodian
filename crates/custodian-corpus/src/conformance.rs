//! Adapter conformance suite (ADR 0030). Any `EpochBlobStore`, including a
//! future object-store adapter, must pass [`run`]. It checks the behaviors
//! in the trait documentation using synthetic bytes only, and panics with a
//! case name (never data) on the first violation.
//!
//! Permission and symlink controls are filesystem concepts and are covered by
//! the filesystem adapter's own tests; an object-store adapter must document
//! the equivalent (private bucket, no public ACL, server-side encryption,
//! versioning/object-lock for immutability) in its own ADR.

use custodian_contracts::types::EpochId;

use crate::reason::StorageReason as R;
use crate::secret::hex;
use crate::secret::random_bytes;
use crate::store::{EntryName, EpochBlobStore, SealedDoc, Stage};

fn epoch() -> EpochId {
    EpochId::parse(&format!("epo_{}", hex(&random_bytes(16).expect("urandom")))).expect("epoch id")
}

fn name(s: &str) -> EntryName {
    EntryName::parse(s).expect("name")
}

fn check<T: core::fmt::Debug>(case: &str, got: Result<T, R>, want: R) {
    match got {
        Err(r) if r == want => {}
        _ => panic!("conformance case failed: {case}"),
    }
}

fn ok<T>(case: &str, got: Result<T, R>) -> T {
    match got {
        Ok(v) => v,
        Err(_) => panic!("conformance case failed: {case}"),
    }
}

/// Run every conformance case against fresh adapters from `make`.
pub fn run<S: EpochBlobStore>(make: impl Fn() -> S) {
    let s = make();
    let e = epoch();
    let other = epoch();

    check(
        "unknown epoch put",
        s.put_entry(&e, &name("a"), b"1"),
        R::NotFound,
    );
    ok("create", s.create_staging(&e));
    check("duplicate create", s.create_staging(&e), R::AlreadyExists);
    ok("put a", s.put_entry(&e, &name("a"), b"alpha"));
    ok("put b", s.put_entry(&e, &name("b"), b"beta"));
    check(
        "no overwrite",
        s.put_entry(&e, &name("a"), b"x"),
        R::AlreadyExists,
    );

    let listed = ok("list staging", s.list_entries(&e, Stage::Staging));
    assert_eq!(
        listed,
        vec![name("a"), name("b")],
        "conformance case failed: list sorted"
    );
    let a = ok("read staging", s.read_entry(&e, Stage::Staging, &name("a")));
    assert_eq!(a.expose(), b"alpha", "conformance case failed: exact bytes");
    check(
        "sealed read before finalize",
        s.read_entry(&e, Stage::Sealed, &name("a")),
        R::EpochNotSealed,
    );
    check(
        "doc before finalize",
        s.read_doc(&e, SealedDoc::Seal),
        R::EpochNotSealed,
    );
    assert!(
        !ok("is_sealed false", s.is_sealed(&e)),
        "conformance case failed: is_sealed false"
    );

    // Isolation: a second epoch sees nothing of the first.
    ok("create other", s.create_staging(&other));
    assert!(
        ok("list other", s.list_entries(&other, Stage::Staging)).is_empty(),
        "conformance case failed: epoch isolation"
    );
    check(
        "cross-epoch read",
        s.read_entry(&other, Stage::Staging, &name("a")),
        R::NotFound,
    );

    ok("finalize", s.finalize(&e, b"manifest-bytes", b"seal-bytes"));
    check(
        "second finalize",
        s.finalize(&e, b"m", b"s"),
        R::EpochSealed,
    );
    check(
        "put after seal",
        s.put_entry(&e, &name("c"), b"x"),
        R::EpochSealed,
    );
    check("discard after seal", s.discard_staging(&e), R::EpochSealed);
    assert!(
        ok("is_sealed true", s.is_sealed(&e)),
        "conformance case failed: is_sealed true"
    );
    assert_eq!(
        ok("manifest doc", s.read_doc(&e, SealedDoc::Manifest)),
        b"manifest-bytes",
        "conformance case failed: manifest bytes"
    );
    assert_eq!(
        ok("seal doc", s.read_doc(&e, SealedDoc::Seal)),
        b"seal-bytes",
        "conformance case failed: seal bytes"
    );
    assert_eq!(
        ok("list sealed", s.list_entries(&e, Stage::Sealed)),
        vec![name("a"), name("b")],
        "conformance case failed: sealed list"
    );
    let b = ok("read sealed", s.read_entry(&e, Stage::Sealed, &name("b")));
    assert_eq!(b.expose(), b"beta", "conformance case failed: sealed bytes");
    check("create over sealed", s.create_staging(&e), R::AlreadyExists);

    // The other epoch is unaffected and can be discarded.
    ok("discard other", s.discard_staging(&other));
    check("discard twice", s.discard_staging(&other), R::NotFound);
    check(
        "doc of unknown epoch",
        s.read_doc(&other, SealedDoc::Seal),
        R::EpochNotSealed,
    );
}
