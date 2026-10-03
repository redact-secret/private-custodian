//! Leakage tests (C8): protected details injected into every input, error and
//! log path must not appear in any public release, error string or Check.
//!
//! The "protected details" are synthetic canary strings. They are valid
//! identifier or label shapes on purpose, so the only thing keeping them out
//! of a public output is the allowlist and the type split, not a parse
//! failure.

mod common;

use common::*;
use custodian_contracts::Contract;
use custodian_disclosure::check::check_update;
use custodian_disclosure::testing::RecordingSink;
use custodian_disclosure::{DisclosureReason as R, PrivateAggregates};
use custodian_intake::checks::CheckPost;
use custodian_intake::ids::{HeadSha, InstallationId, RepositoryId};
use custodian_ledger::LedgerBackend;
use serde_json::json;

/// Everything internal that must not appear in a public release: canaries,
/// custody identities, internal digests and approval identities.
fn internal_strings(w: &World) -> Vec<String> {
    let mut v: Vec<String> = all_canaries().into_iter().map(str::to_owned).collect();
    let plan = &w.request.plan;
    v.push(plan.population.corpus_id.as_str().to_owned());
    v.push(plan.population.epoch_id.as_str().to_owned());
    if let Some(f) = &plan.population.family_id {
        v.push(f.as_str().to_owned());
    }
    v.push(plan.population.population_digest.as_str().to_owned());
    v.push(plan.config_digest.as_str().to_owned());
    v.push(plan.adapter.digest.as_str().to_owned());
    v.push(plan.adapter.name.as_str().to_owned());
    for s in plan.scanners.as_slice() {
        v.push(s.digest.as_str().to_owned());
        v.push(s.name.as_str().to_owned());
    }
    v.push(w.request.plan.plan_digest().unwrap().as_str().to_owned());
    v.push(w.request.request_id.as_str().to_owned());
    v.push(w.request.idempotency_key.as_str().to_owned());
    v.push(w.request.asserted_actor.as_str().to_owned());
    v.push(w.exec_approval.approval_id.as_str().to_owned());
    v.push(w.exec_approval.approver.as_str().to_owned());
    v.push(w.reservation.reservation_id.as_str().to_owned());
    v.push(w.execution.execution_id.as_str().to_owned());
    v.push(w.receipt.receipt_id.as_str().to_owned());
    v.push(w.receipt.result.digest.as_str().to_owned());
    v.push(w.attempt.as_str().to_owned());
    v.push(cc::id("apr_", 2));
    v.push(cc::id("pac_", 1));
    v.push(cc::id("pac_", 2));
    v
}

fn assert_clean(label: &str, haystack: &[u8], forbidden: &[String]) {
    let text = String::from_utf8_lossy(haystack);
    for f in forbidden {
        assert!(!text.contains(f.as_str()), "{label} leaks {f}");
    }
}

fn run_release(w: &World) -> Vec<u8> {
    let sink = RecordingSink::new();
    with_default_service(w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        let p = svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        w.export();
        // The projection under review is public by construction.
        let reviewed = serde_json::to_vec(p.projection()).unwrap();
        let approval = w.release_approval(&p);
        let dest = w.destination("benchmarks-feed");
        let obs = disclosure_activation(RELEASE_AT, "active");
        svc.release(
            &p,
            &w.release_request(&approval, &dest, &obs),
            &sink,
            now(RELEASE_AT),
        )
        .unwrap();
        let delivered = sink.delivered();
        assert_eq!(delivered.len(), 1);
        let mut out = delivered[0].1.clone();
        out.extend_from_slice(&reviewed);
        out
    })
}

#[test]
fn no_internal_identity_or_canary_reaches_a_public_release() {
    for lineage in [false, true] {
        for conformance in [false, true] {
            let w = World::new(Opts {
                canary: true,
                lineage,
                conformance,
                ..Opts::default()
            });
            let forbidden = internal_strings(&w);
            // The canaries really are present in the internal inputs.
            let internal = serde_json::to_string(&w.request).unwrap();
            assert!(internal.contains(CANARY_CORPUS) && internal.contains(CANARY_ACTOR));
            let out = run_release(&w);
            assert_clean("public release", &out, &forbidden);
        }
    }
}

#[test]
fn released_output_is_exactly_the_public_contract_fields() {
    // The projection carries only the allowlisted keys.
    let w = World::new(Opts::default());
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        let p = svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        let v = serde_json::to_value(p.projection()).unwrap();
        let keys: std::collections::BTreeSet<&str> =
            v.as_object().unwrap().keys().map(String::as_str).collect();
        let allowed: std::collections::BTreeSet<&str> = [
            "schema",
            "projection_id",
            "receipt_id",
            "domain",
            "population",
            "candidate",
            "engine",
            "protocol",
            "scope_kind",
            "disclosure_policy",
            "attestation",
            "cells",
            "issued_at",
            "fresh_until",
            "revocation_feed",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys, allowed);
    });
}

#[test]
fn errors_debug_output_and_checks_never_echo_injected_details() {
    let w = World::new(Opts {
        canary: true,
        ..Opts::default()
    });
    let forbidden = internal_strings(&w);
    let mut produced: Vec<R> = Vec::new();

    // Protected details injected into the aggregate artifact in every shape.
    let injections: Vec<serde_json::Value> = {
        let mut v = Vec::new();
        for (k, val) in [
            ("case_ids", json!([CANARY_CASE])),
            ("seed", json!(CANARY_SEED)),
            ("text", json!(CANARY_TEXT)),
            ("log", json!(CANARY_TEXT)),
            ("error", json!(CANARY_TEXT)),
            ("path", json!(CANARY_CASE)),
        ] {
            let mut a = aggregates_json();
            a[k] = val;
            v.push(a);
        }
        let mut a = aggregates_json();
        a["cells"][0]["stratum"] = json!(CANARY_CASE);
        v.push(a);
        let mut a = aggregates_json();
        a["cells"][0]["metric"] = json!(CANARY_SEED);
        v.push(a);
        let mut a = aggregates_json();
        a["domain"] = json!(CANARY_TEXT);
        v.push(a);
        v
    };
    for agg in injections {
        let w = World::new(Opts {
            canary: true,
            aggregates: agg,
            ..Opts::default()
        });
        let err = with_default_service(&w, |svc| {
            w.provision(svc);
            let key = w.release_key(1);
            svc.prepare(&w.input(&key), now(PREPARE_AT)).err().unwrap()
        });
        produced.push(err);
    }

    // Canaries in the other inputs: unknown policy fields, tampered receipt.
    let mut v = policy_json();
    v["note"] = json!(CANARY_TEXT);
    assert!(serde_json::from_value::<custodian_disclosure::DisclosurePolicy>(v).is_err());
    let mut r = serde_json::to_value(&w.receipt).unwrap();
    r["note"] = json!(CANARY_TEXT);
    let err = custodian_contracts::execution::InternalReceipt::decode(&cc::to_bytes(&r)).err();
    assert!(err.is_some());
    assert_clean("contract error", format!("{err:?}").as_bytes(), &forbidden);

    // Every reason code, however produced, is a fixed string.
    produced.extend(R::ALL);
    let installation = InstallationId::new(7).unwrap();
    let repository = RepositoryId::new(11).unwrap();
    let head = HeadSha::parse(&"a".repeat(40)).unwrap();
    for reason in produced {
        for text in [
            format!("{reason}"),
            format!("{reason:?}"),
            reason.as_str().to_owned(),
        ] {
            assert_clean("reason", text.as_bytes(), &forbidden);
        }
        // The Check text is rendered by the intake crate from fixed strings
        // and one core reason code.
        let update = check_update(installation, repository, head.clone(), &Err(reason));
        let post = CheckPost::render(&update);
        assert_clean("check", post.summary.as_bytes(), &forbidden);
        assert_clean("check title", post.title.as_bytes(), &forbidden);
        let core = reason.check_reason().code();
        assert!(
            post.summary.contains(&format!("Reason: {core}.")),
            "{}",
            post.summary
        );
        // The fine-grained code (which binding or rule refused) never shows.
        if reason.as_str() != core {
            assert!(!post.summary.contains(reason.as_str()), "{}", post.summary);
        }
        // Only the three coarse core codes are ever displayed.
        assert!([
            "budget_exhausted",
            "store_unavailable",
            "disclosure_not_permitted"
        ]
        .contains(&core.as_str()));
    }
}

#[test]
fn a_successful_release_renders_a_neutral_check_with_no_result() {
    let update = check_update(
        InstallationId::new(7).unwrap(),
        RepositoryId::new(11).unwrap(),
        HeadSha::parse(&"b".repeat(40)).unwrap(),
        &Ok(()),
    );
    let post = CheckPost::render(&update);
    assert_eq!(
        post.conclusion,
        Some(custodian_intake::checks::GithubConclusion::Neutral)
    );
    assert!(post.summary.contains("process state only"));
    assert!(!post.summary.contains("numerator") && !post.summary.contains("sha256"));
}

#[test]
fn debug_output_of_internal_values_prints_no_values() {
    let w = World::new(Opts {
        canary: true,
        ..Opts::default()
    });
    let forbidden = internal_strings(&w);
    let agg = PrivateAggregates::decode(
        &w.aggregates,
        &w.receipt.result,
        w.request.plan.domain,
        &w.receipt.frozen.protocol,
        &w.receipt.roster,
    )
    .unwrap();
    let text = format!("{agg:?}");
    assert!(!text.contains("50") && !text.contains("75") && !text.contains("detected"));
    with_default_service(&w, |svc| {
        w.provision(svc);
        let key = w.release_key(1);
        let p = svc.prepare(&w.input(&key), now(PREPARE_AT)).unwrap();
        assert_clean("prepared debug", format!("{p:?}").as_bytes(), &forbidden);
        let sink = RecordingSink::new();
        w.export();
        let approval = w.release_approval(&p);
        let dest = w.destination("benchmarks-feed");
        let obs = disclosure_activation(RELEASE_AT, "active");
        let released = svc
            .release(
                &p,
                &w.release_request(&approval, &dest, &obs),
                &sink,
                now(RELEASE_AT),
            )
            .unwrap();
        assert_clean(
            "released debug",
            format!("{released:?}").as_bytes(),
            &forbidden,
        );
    });
}

#[test]
fn the_private_ledger_never_holds_protected_text_seeds_or_case_identities() {
    // Even the private ledger carries identities and counters only. Inject
    // the text-like canaries into the one free-form-capable input and make
    // sure nothing written durably contains them.
    let w = World::new(Opts {
        canary: true,
        ..Opts::default()
    });
    let mut a = aggregates_json();
    a["cells"][0]["stratum"] = json!(CANARY_CASE);
    let rejected = World::new(Opts {
        canary: true,
        aggregates: a,
        ..Opts::default()
    });
    with_default_service(&rejected, |svc| {
        rejected.provision(svc);
        let key = rejected.release_key(1);
        assert!(svc.prepare(&rejected.input(&key), now(PREPARE_AT)).is_err());
    });
    rejected.export();
    run_release(&w);
    for world in [&w, &rejected] {
        for path in world.backend.paths() {
            let bytes = world
                .backend
                .get(&custodian_ledger::LedgerPath::parse(&path).unwrap())
                .unwrap()
                .unwrap();
            for c in [CANARY_TEXT, CANARY_SEED, CANARY_CASE] {
                assert!(
                    !String::from_utf8_lossy(&bytes).contains(c),
                    "{path} contains a canary"
                );
            }
        }
    }
}

#[test]
fn the_crate_has_no_logging_or_printing_path() {
    // No log path exists to inject into: the crate source never prints,
    // logs or debugs. Errors are reason codes. If a logging path is ever
    // added, it must go through a reviewed, fixed-code interface and this
    // test must be revisited deliberately.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let src = std::fs::read_to_string(&path).unwrap();
        for banned in [
            "println!",
            "eprintln!",
            "print!(",
            "eprint!(",
            "dbg!(",
            "log::",
            "tracing::",
            "std::io::stderr",
            "std::io::stdout",
        ] {
            assert!(!src.contains(banned), "{} uses {banned}", path.display());
        }
    }
}
