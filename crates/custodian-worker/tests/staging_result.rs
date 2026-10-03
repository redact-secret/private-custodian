//! Staging, path validation and bounded result validation.

mod common;

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

use common::*;
use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::ExecutionOutcome as O;
use custodian_worker::artifacts::{hash_file, Staging};
use custodian_worker::result::{job_document, validate_result, MAX_RESULT_BYTES};
use custodian_worker::WorkerReason as R;

fn protocol(domain: &str) -> ProtocolRef {
    serde_json::from_value(serde_json::json!(
        {"domain": domain, "name": "synthetic-protocol", "version": "1"}
    ))
    .unwrap()
}

fn doc(domain: &str, status: &str, e: u64, o: u64, f: u64) -> Vec<u8> {
    format!(
        "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
         \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\"status\":\"{status}\",\
         \"roster\":{{\"expected\":{e},\"observed\":{o},\"failed\":{f}}}}}"
    )
    .into_bytes()
}

#[test]
fn validator_accepts_exact_shape_and_maps_outcomes_for_both_domains() {
    for (d, dom) in [
        ("credential", EvaluationDomain::Credential),
        ("pii", EvaluationDomain::Pii),
    ] {
        let p = protocol(d);
        let ok = validate_result(&doc(d, "complete", 5, 5, 0), dom, &p, 5).unwrap();
        assert_eq!(ok.outcome, O::Success);
        assert_eq!(
            ok.artifact.size_bytes.get() as usize,
            ok.private_bytes().len()
        );
        let part = validate_result(&doc(d, "partial", 5, 3, 0), dom, &p, 5).unwrap();
        assert_eq!(part.outcome, O::Partial);
        let failed = validate_result(&doc(d, "complete", 5, 5, 2), dom, &p, 5).unwrap();
        assert_eq!(failed.outcome, O::Partial);
    }
}

#[test]
fn validator_rejects_malformed_inconsistent_and_oversized_results() {
    let d = EvaluationDomain::Credential;
    let p = protocol("credential");
    let bad: Vec<(Vec<u8>, R)> = vec![
        (b"".to_vec(), R::ResultMalformed),
        (b"null".to_vec(), R::ResultMalformed),
        (b"{}".to_vec(), R::ResultMalformed),
        (
            doc("credential", "complete", 5, 5, 0)
                .into_iter()
                .chain(*b" trailing")
                .collect(),
            R::ResultMalformed,
        ),
        (
            doc("credential", "complete", 5, 5, 0)
                .into_iter()
                .chain(*b"{}")
                .collect(),
            R::ResultMalformed,
        ),
        (doc("credential", "finished", 5, 5, 0), R::ResultMalformed),
        (doc("pii", "complete", 5, 5, 0), R::ResultMismatch),
        (doc("credential", "complete", 6, 6, 0), R::RosterMismatch),
        (doc("credential", "complete", 5, 4, 0), R::RosterMismatch),
        (doc("credential", "partial", 5, 5, 0), R::RosterMismatch),
        (doc("credential", "complete", 5, 6, 0), R::RosterMismatch),
        (doc("credential", "complete", 5, 5, 6), R::RosterMismatch),
        (
            vec![b'a'; MAX_RESULT_BYTES as usize + 1],
            R::ResultOversized,
        ),
    ];
    for (bytes, reason) in bad {
        assert_eq!(
            validate_result(&bytes, d, &p, 5).err(),
            Some(reason),
            "{:?}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(40)])
        );
    }
    // Wrong protocol name or version, free-form fields and duplicates.
    let s = String::from_utf8(doc("credential", "complete", 5, 5, 0)).unwrap();
    for t in [
        s.replace("synthetic-protocol", "other-protocol"),
        s.replace("\"version\":\"1\"", "\"version\":\"2\""),
        s.replace(
            "\"status\"",
            "\"message\":\"secret-shaped synthetic text\",\"status\"",
        ),
        s.replace("\"status\"", "\"status\":\"complete\",\"status\""),
        s.replace("\"failed\":0", "\"failed\":0,\"failed\":0"),
        s.replace(
            "private-custodian.worker-result/1",
            "private-custodian.worker-result/2",
        ),
    ] {
        assert!(validate_result(t.as_bytes(), d, &p, 5).is_err(), "{t}");
    }
    // An empty authorized roster is never complete.
    assert!(validate_result(&doc("credential", "complete", 0, 0, 0), d, &p, 0).is_err());
}

#[test]
fn job_document_carries_only_names_roster_domain_and_protocol() {
    let bytes = job_document(
        EvaluationDomain::Pii,
        &protocol("pii"),
        &["a".to_owned(), "b".to_owned()],
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["roster"], 2);
    assert_eq!(v["schema"], "private-custodian.worker-job/1");
    assert_eq!(v.as_object().unwrap().len(), 5);
}

#[test]
fn staging_hashes_copied_bytes_and_rejects_a_mismatch() {
    let env = Env::new("stage");
    let src = env.put("thing", b"synthetic artifact", 0o755);
    let good = hash_file(&src).unwrap();
    let mut st = Staging::create(&env.staging).unwrap();
    st.stage_pinned("thing", &src, &good, true).unwrap();
    assert_eq!(
        st.stage_pinned("other", &src, &common::dg("not it"), true)
            .err(),
        Some(R::IdentityMismatch)
    );
    assert!(
        !st.stage_dir().join("other").exists(),
        "mismatched copy is removed"
    );
    // Never overwrites an existing staged name.
    assert_eq!(
        st.stage_pinned("thing", &src, &good, true).err(),
        Some(R::StagingFailed)
    );
    st.verify(R::IdentityChangedAfterStaging).unwrap();
    // Tamper with the staged copy: verify fails closed.
    let staged = st.stage_dir().join("thing");
    assert_eq!(
        fs::metadata(&staged).unwrap().permissions().mode() & 0o777,
        0o500
    );
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&staged, b"changed").unwrap();
    assert_eq!(
        st.verify(R::IdentityChangedAfterStaging).err(),
        Some(R::IdentityChangedAfterStaging)
    );
    let root = env.staging.clone();
    drop(st);
    assert_eq!(fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn materialization_refuses_unsafe_names_overwrite_and_links() {
    let env = Env::new("mat");
    let st = Staging::create(&env.staging).unwrap();
    for bad in ["../x", "/abs", "a/b", "A", "..", "a\0b", "", ".hidden"] {
        assert_eq!(
            st.materialize_input(bad, b"x").err(),
            Some(R::PathRejected),
            "{bad:?}"
        );
    }
    st.materialize_input("ok-1", b"synthetic").unwrap();
    assert!(
        st.materialize_input("ok-1", b"again").is_err(),
        "no overwrite"
    );
    let m = fs::metadata(st.input_dir().join("ok-1")).unwrap();
    assert_eq!(m.permissions().mode() & 0o777, 0o400);
    st.verify_input_shape(1).unwrap();
    // A planted symlink or extra file is caught by the shape check.
    symlink("/etc/hosts", st.input_dir().join("link")).unwrap();
    assert!(st.verify_input_shape(2).is_err());
}

#[test]
fn staging_base_must_be_private() {
    let env = Env::new("base");
    fs::set_permissions(&env.staging, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(Staging::create(&env.staging).err(), Some(R::StagingFailed));
}

#[test]
fn allowlist_roots_must_exist_be_absolute_and_not_world_writable() {
    use custodian_worker::artifacts::ArtifactAllowlist;
    let env = Env::new("allowroots");
    assert!(ArtifactAllowlist::new(&[]).is_err());
    assert!(ArtifactAllowlist::new(&["relative".into()]).is_err());
    assert!(ArtifactAllowlist::new(&[env.root.join("missing")]).is_err());
    fs::set_permissions(&env.art, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ArtifactAllowlist::new(std::slice::from_ref(&env.art)).is_err());
}
