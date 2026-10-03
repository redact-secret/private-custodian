//! The synthetic engine fixture binary, for both evaluation domains.
//!
//! It is the one stand-in for an engine that prints a `worker-result/1`
//! document with an embedded `private-custodian.aggregates/1` artifact. REAL
//! ENGINES DO NOT EMIT THIS YET (a cross-repository job; docs/daemon.md). The
//! tests show that what it prints is accepted by exactly the validators the
//! pipeline uses, for both domains, and that its failure modes are rejected
//! by them with fixed reasons.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use custodian_contracts::common::{EvaluationDomain, ProtocolRef};
use custodian_contracts::execution::{ExecutionOutcome, PrivateArtifactRef};
use custodian_contracts::types::{Count, ResultDigest};
use custodian_disclosure::compose::check_artifact;
use custodian_disclosure::{DisclosurePolicy, PrivateAggregates};
use custodian_worker::result::{job_document, validate_result};
use custodian_worker::WorkerReason as R;
use serde_json::json;
use sha2::{Digest, Sha256};

const ENGINE: &str = env!("CARGO_BIN_EXE_custodian-synthetic-engine");

struct Dirs(PathBuf);

/// Tests run on parallel threads of one process and several use the same
/// label, so the process id and label alone are not unique: one test's cleanup
/// would remove another's directory. A per-call counter makes every `Dirs` its own.
static NEXT: AtomicUsize = AtomicUsize::new(0);

impl Dirs {
    fn new(label: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "custodian-synthetic-engine-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        for d in ["stage", "job", "input", "scratch"] {
            std::fs::create_dir_all(p.join(d)).unwrap();
        }
        Self(p)
    }
    fn p(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn protocol(domain: &str) -> ProtocolRef {
    serde_json::from_value(json!({"domain": domain, "name": "synthetic-protocol", "version": "1"}))
        .unwrap()
}

fn domain_of(d: &str) -> EvaluationDomain {
    match d {
        "credential" => EvaluationDomain::Credential,
        _ => EvaluationDomain::Pii,
    }
}

/// Run the engine exactly as the dispatcher stages it: `config` names the
/// mode, `job.json` is the worker job document.
fn run(domain: &str, mode: &str, roster: usize) -> (Dirs, std::process::Output) {
    let d = Dirs::new(&format!("{domain}-{}", mode.replace(' ', "_")));
    std::fs::write(d.p("stage/config"), mode).unwrap();
    let names: Vec<String> = (0..roster).map(|i| format!("entry{i:04}")).collect();
    for n in &names {
        std::fs::write(d.p("input").join(n), format!("synthetic-input-{n}")).unwrap();
    }
    std::fs::write(
        d.p("job/job.json"),
        job_document(domain_of(domain), &protocol(domain), &names).unwrap(),
    )
    .unwrap();
    let out = Command::new(ENGINE)
        .env_clear()
        .env("CUSTODIAN_STAGE_ROOT", d.p("stage"))
        .env("CUSTODIAN_JOB_ROOT", d.p("job"))
        .env("CUSTODIAN_INPUT_ROOT", d.p("input"))
        .env("CUSTODIAN_SCRATCH", d.p("scratch"))
        .args(["--job", d.p("job/job.json").to_str().unwrap()])
        .output()
        .unwrap();
    (d, out)
}

/// The disclosure policy the pipeline tests use (strata a, b, c, t1, t2, all).
fn policy() -> DisclosurePolicy {
    let p: DisclosurePolicy = serde_json::from_value(json!({
        "schema": "private-custodian.disclosure-policy/1",
        "policy": {"kind":"disclosure","domain":"credential","name":"synthetic-disclosure","version":1},
        "strata": [
            {"stratum":"a","dimension":"len"}, {"stratum":"b","dimension":"len"},
            {"stratum":"c","dimension":"len"}, {"stratum":"t1","dimension":"cat"},
            {"stratum":"t2","dimension":"cat"}, {"stratum":"all","dimension":"total"}
        ],
        "metrics": ["detected"],
        "total_stratum": "all",
        "relations": [
            {"total":"all","parts":["a","b","c"]}, {"total":"all","parts":["t1","t2"]}
        ],
        "min_stratum_size": 10, "min_interval_width": 2,
        "perturbation": {"mechanism":"none"},
        "budgets": {"per_population": 5, "per_lineage": 3, "per_requester": 4, "units_per_attempt": 1},
        "withheld_attempts": "charged", "failed_attempts": "charged", "audit": "acknowledged",
        "destinations": ["benchmarks-feed"], "freshness_secs": 86400, "state_max_age_secs": 300
    }))
    .unwrap();
    p.validate().unwrap();
    p
}

#[test]
fn both_domains_print_a_result_every_validator_accepts() {
    for domain in ["credential", "pii"] {
        for roster in [75usize, 150, 300] {
            let (_d, out) = run(domain, "ok", roster);
            assert!(out.status.success(), "{domain}");
            assert!(out.stderr.is_empty(), "no stderr output");
            // The worker's validator: strict shape, domain, protocol, roster.
            let v = validate_result(
                &out.stdout,
                domain_of(domain),
                &protocol(domain),
                roster as u64,
            )
            .unwrap_or_else(|e| panic!("{domain} {roster}: {e}"));
            assert_eq!(v.outcome, ExecutionOutcome::Success);
            // The disclosure validator: bound to the receipt it would get,
            // strict closed schema, within the policy's strata and relations.
            let agg = v.aggregates_bytes().expect("aggregates embedded");
            let reference = PrivateArtifactRef {
                digest: ResultDigest::from_raw(Sha256::digest(agg).into()),
                size_bytes: Count::new(agg.len() as u64).unwrap(),
                protocol: protocol(domain),
            };
            let decoded = PrivateAggregates::decode(
                agg,
                &reference,
                domain_of(domain),
                &protocol(domain),
                &v.roster,
            )
            .unwrap_or_else(|e| panic!("{domain} {roster}: {e}"));
            check_artifact(&policy(), &decoded)
                .unwrap_or_else(|e| panic!("{domain} {roster}: {e}"));
        }
    }
}

#[test]
fn for_a_roster_of_75_the_numbers_are_the_documented_fixture() {
    let (_d, out) = run("credential", "ok", 75);
    let v = validate_result(
        &out.stdout,
        EvaluationDomain::Credential,
        &protocol("credential"),
        75,
    )
    .unwrap();
    let agg: serde_json::Value = serde_json::from_slice(v.aggregates_bytes().unwrap()).unwrap();
    let cell = |s: &str| {
        let c = agg["cells"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["stratum"] == s)
            .unwrap();
        (
            c["numerator"].as_u64().unwrap(),
            c["denominator"].as_u64().unwrap(),
        )
    };
    assert_eq!(cell("a"), (30, 40));
    assert_eq!(cell("b"), (18, 30));
    assert_eq!(cell("c"), (2, 5));
    assert_eq!(cell("t1"), (35, 50));
    assert_eq!(cell("t2"), (15, 25));
    assert_eq!(cell("all"), (50, 75));
}

#[test]
fn the_failure_modes_are_rejected_by_the_validators_with_fixed_reasons() {
    let rejected = |mode: &str| {
        let (_d, out) = run("credential", mode, 75);
        validate_result(
            &out.stdout,
            EvaluationDomain::Credential,
            &protocol("credential"),
            75,
        )
    };
    // Some inputs measured: a partial, with its aggregates.
    let p = rejected("partial").unwrap();
    assert_eq!(p.outcome, ExecutionOutcome::Partial);
    assert!(p.aggregates_bytes().is_some());
    // Everything observed, one item failed: still a partial, never a success.
    assert_eq!(
        rejected("failed-items").unwrap().outcome,
        ExecutionOutcome::Partial
    );
    // A clean run with no aggregate artifact: valid for the worker, and the
    // pipeline then closes it (it cannot be projected).
    let n = rejected("no-aggregates").unwrap();
    assert_eq!(n.outcome, ExecutionOutcome::Success);
    assert!(n.aggregates_bytes().is_none());
    // Not JSON, and an unknown field (the "leak" engine's smuggling attempt).
    assert_eq!(rejected("garbage").err(), Some(R::ResultMalformed));
    assert_eq!(rejected("leak").err(), Some(R::ResultMalformed));
    // The aggregate artifact whose roster disagrees with the result's: the
    // worker accepts the result, the disclosure validator refuses the artifact.
    let w = rejected("aggregates-wrong-roster").unwrap();
    let agg = w.aggregates_bytes().unwrap();
    let reference = PrivateArtifactRef {
        digest: ResultDigest::from_raw(Sha256::digest(agg).into()),
        size_bytes: Count::new(agg.len() as u64).unwrap(),
        protocol: protocol("credential"),
    };
    assert!(PrivateAggregates::decode(
        agg,
        &reference,
        EvaluationDomain::Credential,
        &protocol("credential"),
        &w.roster
    )
    .is_err());
}

#[test]
fn crashes_and_bad_exits_produce_no_result_at_all() {
    for mode in ["crash", "exit3"] {
        let (_d, out) = run("pii", mode, 75);
        assert!(!out.status.success(), "{mode}");
        assert!(out.stdout.is_empty() || mode == "exit3" || !out.stdout.starts_with(b"{"));
    }
}

#[test]
fn the_leak_mode_reads_the_inputs_but_the_result_is_refused_whatever_it_carries() {
    let (_d, out) = run("pii", "leak", 5);
    // It did try: the stderr carries the synthetic inputs (the dispatcher
    // counts and discards stderr; it is never retained or logged).
    assert!(String::from_utf8_lossy(&out.stderr).contains("synthetic-input-entry0000"));
    assert_eq!(
        validate_result(&out.stdout, EvaluationDomain::Pii, &protocol("pii"), 5).err(),
        Some(R::ResultMalformed)
    );
    let _ = Path::new(ENGINE);
}
