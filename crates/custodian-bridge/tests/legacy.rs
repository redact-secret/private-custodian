//! Legacy metadata import (C11, ADR 0091 and 0092): spent stays spent,
//! ambiguity is consumption, the independence vocabulary is preserved,
//! results are deterministic, re-import is idempotent and monotone, malformed
//! or path-like input is refused, and the handoff record only proposes.

use custodian_bridge::legacy::handoff::{contested_scopes, Blocker, HandoffEntry, HandoffRecord};
use custodian_bridge::legacy::import::*;
use custodian_bridge::legacy::report::DifferenceCode;
use custodian_bridge::legacy::{
    apply, dry_run, Ambiguity, ApplyRefusal, CheckEvidence, ConsumptionBasis,
    ContaminationStanding, DryRun, ExtractRefusal, HandoffStatus, ImportStore, MemoryImportStore,
    RefusalCode,
};
use custodian_contracts::common::{BudgetScope, EvaluationDomain};
use custodian_contracts::public::ScopeKind;
use custodian_contracts::types::Timestamp;
use serde_json::{json, Value};

const T0: u64 = 1_800_000_000;

fn sha(n: u64) -> String {
    format!("sha256:{n:064x}")
}

fn src(kind: &str, locator: &str, n: u64) -> Value {
    json!({"kind": kind, "locator": locator, "sha256": sha(n), "observed_at": T0})
}

fn statement(label: &str) -> Value {
    json!({"kind": "custodian-statement", "locator": label, "observed_at": T0})
}

fn extract(scopes: Vec<Value>) -> Value {
    json!({
        "schema": "private-custodian.legacy-extract/1",
        "extracted_at": T0,
        "review": {"reviewer_role": "maintainer", "review_ref": "review-synthetic-1", "reviewed_at": T0 + 10},
        "scopes": scopes
    })
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// A holdout epoch with one complete attempt against a limit of one.
fn spent_holdout() -> Value {
    json!({
        "lifecycle": "holdout", "domain": "credential",
        "scope": {"kind": "population_epoch", "population": "synthetic-pop-a", "epoch": "epoch-1"},
        "declared_limit": 1,
        "attempts": [{"run": "run-0001", "state": "complete", "source": 1}],
        "reported_consumed": 1, "reported_receipts": 1,
        "independence": {"claim": "custodian-declared"},
        "contamination": {"state": "none_recorded", "source": 2},
        "sources": [
            src("manifest", "holdout/synthetic-manifest.json", 1),
            src("aggregate", "evidence/synthetic/aggregate.json", 2),
            statement("reviewed-no-contamination-mark")
        ]
    })
}

/// A PII family epoch attested unspent.
fn unspent_pii() -> Value {
    json!({
        "lifecycle": "pii-protected", "domain": "pii",
        "scope": {"kind": "population_epoch", "population": "synthetic-pii", "epoch": "epoch-1", "family": "global-email"},
        "declared_limit": 1, "attempts": [],
        "independence": {"claim": "custodian-declared"},
        "contamination": {"state": "none_recorded", "source": 1},
        "sources": [
            src("unspent-attestation", "evidence/synthetic/unspent.json", 3),
            statement("reviewed-no-contamination-mark")
        ]
    })
}

fn blind() -> Value {
    json!({
        "lifecycle": "blind", "domain": "credential",
        "scope": {"kind": "candidate_epoch", "candidate": "artifact-sha-aaaa", "epoch": "synthetic-e1"},
        "declared_limit": 1,
        "attempts": [{"run": "run-b-0001", "state": "reserved"}],
        "reported_receipts": 1,
        "independence": {
            "claim": "procedural-separation", "organisational_independence_claimed": false,
            "evidence_class": "custodian-blind", "statement_sha256": sha(9)
        },
        "contamination": {"state": "unknown"},
        "sources": [src("blind-aggregate", "docs/reports/synthetic-blind.json", 4)]
    })
}

fn run(scopes: Vec<Value>) -> DryRun {
    dry_run(&bytes(&extract(scopes))).unwrap()
}

fn only(r: &DryRun) -> &LegacyImportRecord {
    assert_eq!(r.records.len(), 1, "{:?}", r.report.refused);
    &r.records[0]
}

#[test]
fn spent_stays_spent_and_both_budget_semantics_stay_distinct() {
    let r = run(vec![spent_holdout(), unspent_pii(), blind()]);
    assert_eq!(r.records.len(), 3);
    let by = |l: &str| {
        r.records
            .iter()
            .find(|x| x.body.scope_key.as_str().starts_with(l))
            .unwrap()
    };

    let h = &by("holdout").body.budget;
    assert_eq!((h.consumed, h.remaining, h.exhausted), (1, 0, true));
    assert_eq!(h.scope_kind, ScopeKind::PopulationEpoch);
    assert_eq!(h.basis, ConsumptionBasis::Attempts);

    let p = &by("pii-protected").body.budget;
    assert_eq!((p.consumed, p.remaining, p.exhausted), (0, 1, false));
    assert_eq!(p.basis, ConsumptionBasis::UnspentAttested);

    // Blind is per candidate identity per epoch, a different semantics. A
    // reservation is spent at reservation, so a crash counts.
    let b = &by("blind").body.budget;
    assert_eq!((b.consumed, b.exhausted), (1, true));
    assert_eq!(b.scope_kind, ScopeKind::CandidateLineageEpoch);
}

#[test]
fn ambiguity_counts_as_consumed() {
    // No attempt, no count, no attestation: the whole budget is consumed.
    let mut silent = spent_holdout();
    silent["attempts"] = json!([]);
    silent.as_object_mut().unwrap().remove("reported_consumed");
    silent["reported_receipts"] = json!(1);
    let r = run(vec![silent]);
    let b = &only(&r).body;
    assert_eq!(b.budget.basis, ConsumptionBasis::NoEvidenceAssumedConsumed);
    assert_eq!((b.budget.consumed, b.budget.exhausted), (1, true));
    assert!(b.ambiguities.contains(&Ambiguity::NoSpendEvidence));
    // Explained (conservative), not an unexplained difference.
    assert!(r.report.scopes[0]
        .explained
        .contains(&DifferenceCode::ConservativeAmbiguity));
    assert!(r.report.scopes[0].unexplained.is_empty());

    // An unknown limit is an exhausted budget.
    let mut nolimit = unspent_pii();
    nolimit.as_object_mut().unwrap().remove("declared_limit");
    let r = run(vec![nolimit]);
    let b = &only(&r).body;
    assert!(b.budget.exhausted);
    assert_eq!(b.budget.remaining, 0);
    assert!(b.ambiguities.contains(&Ambiguity::LimitUnknown));

    // A state the reviewer could not classify counts.
    let mut unk = spent_holdout();
    unk["attempts"] = json!([{"run": "run-0002", "state": "unknown"}]);
    let r = run(vec![unk]);
    assert_eq!(only(&r).body.budget.consumed, 1);
    assert!(only(&r)
        .body
        .ambiguities
        .contains(&Ambiguity::UnknownAttemptState));

    // A refusal before exposure is not spent only with a cited source.
    let mut refused = unspent_pii();
    refused["attempts"] =
        json!([{"run": "run-0003", "state": "refused_before_exposure", "source": 0}]);
    let r = run(vec![refused.clone()]);
    assert_eq!(only(&r).body.budget.consumed, 0);
    refused["attempts"] = json!([{"run": "run-0003", "state": "refused_before_exposure"}]);
    let r = run(vec![refused]);
    assert_eq!(only(&r).body.budget.consumed, 1);
    assert!(only(&r)
        .body
        .ambiguities
        .contains(&Ambiguity::RefusalUnsupported));

    // An attestation never overrides a spent attempt.
    let mut contra = unspent_pii();
    contra["attempts"] = json!([{"run": "run-0004", "state": "complete"}]);
    let r = run(vec![contra]);
    assert_eq!(only(&r).body.budget.consumed, 1);
    assert!(r.report.scopes[0]
        .unexplained
        .contains(&DifferenceCode::AttestationContradictsSpend));
    assert!(!r.report.gate.ready_for_review);
}

#[test]
fn disagreeing_counts_are_unexplained_and_take_the_larger() {
    let mut s = spent_holdout();
    s["reported_consumed"] = json!(0);
    let r = run(vec![s]);
    assert_eq!(only(&r).body.budget.consumed, 1);
    assert!(r.report.scopes[0]
        .unexplained
        .contains(&DifferenceCode::ReportedCountDisagrees));

    let mut s = spent_holdout();
    s["attempts"] = json!([]);
    s["reported_consumed"] = json!(1);
    let r = run(vec![s]);
    assert_eq!(only(&r).body.budget.basis, ConsumptionBasis::ReportedCount);
    assert!(r.report.scopes[0].unexplained.is_empty());

    let mut s = spent_holdout();
    s["reported_receipts"] = json!(3);
    let r = run(vec![s]);
    assert!(r.report.scopes[0]
        .unexplained
        .contains(&DifferenceCode::ReceiptCountDisagrees));
    assert_eq!(r.report.gate.unexplained_differences, 1);
    assert!(!r.report.gate.ready_for_review);

    // A clean run is ready for review (but still only a proposal).
    let clean = run(vec![spent_holdout(), unspent_pii()]);
    assert!(clean.report.gate.ready_for_review);
    assert_eq!(clean.report.gate.unexplained_differences, 0);
    assert_eq!(clean.report.gate.refused_scopes, 0);
    // Blind has unknown contamination: not ready until a reviewer decides.
    let r = run(vec![spent_holdout(), blind()]);
    assert_eq!(r.report.gate.unknown_contamination, 1);
    assert!(!r.report.gate.ready_for_review);
}

#[test]
fn contamination_marks_and_unknowns_are_carried_never_cleared() {
    let mut s = spent_holdout();
    s["contamination"] = json!({"state": "marked", "reason": "exposed", "source": 2});
    let r = run(vec![s]);
    assert!(matches!(
        &only(&r).body.contamination,
        ContaminationStanding::Contaminated { reason } if reason.as_str() == "exposed"
    ));
    assert_eq!(r.report.totals.contaminated_scopes, 1);
    let r = run(vec![blind()]);
    assert_eq!(
        only(&r).body.contamination,
        ContaminationStanding::Unknown {}
    );
}

#[test]
fn the_legacy_independence_vocabulary_is_preserved_verbatim() {
    for (claim, domain_lifecycle) in [
        ("public-control", "holdout"),
        ("custodian-declared", "holdout"),
        ("procedural-separation", "holdout"),
    ] {
        let mut s = spent_holdout();
        s["lifecycle"] = json!(domain_lifecycle);
        s["independence"] = json!({"claim": claim});
        let r = run(vec![s]);
        let rec = only(&r);
        let text = String::from_utf8(rec.canonical_bytes().unwrap()).unwrap();
        assert!(text.contains(&format!("\"claim\":\"{claim}\"")), "{claim}");
        assert!(!text.contains("\"independent\""));
    }
    // The blind statement keeps its evidence class, digest and the flag.
    let r = run(vec![blind()]);
    let i = only(&r).body.independence.as_ref().unwrap();
    assert_eq!(
        i.evidence_class.as_ref().unwrap().as_str(),
        "custodian-blind"
    );
    assert_eq!(i.statement_sha256.as_ref().unwrap().as_str(), sha(9));
    let text = serde_json::to_string(&i).unwrap();
    assert!(text.contains("procedural-separation") && text.contains("not_claimed"));

    // Nothing maps to independence.
    for bad in [
        "independent",
        "Independent",
        "externally-validated",
        "",
        "custodian_declared",
    ] {
        let mut s = spent_holdout();
        s["independence"] = json!({"claim": bad});
        let r = run(vec![s]);
        assert!(r.records.is_empty());
        assert_eq!(
            r.report.refused[0].code,
            RefusalCode::IndependenceUnrepresentable
        );
    }
    let mut s = blind();
    s["independence"]["organisational_independence_claimed"] = json!(true);
    let r = run(vec![s]);
    assert_eq!(
        r.report.refused[0].code,
        RefusalCode::OrganisationalIndependenceClaimed
    );
}

#[test]
fn import_is_deterministic_and_independent_of_scope_order() {
    let a = bytes(&extract(vec![spent_holdout(), unspent_pii(), blind()]));
    let r1 = dry_run(&a).unwrap();
    let r2 = dry_run(&a).unwrap();
    assert_eq!(r1, r2);
    assert_eq!(r1.report.digest(), r2.report.digest());
    assert_eq!(r1.report.to_bytes(), r2.report.to_bytes());
    for (x, y) in r1.records.iter().zip(&r2.records) {
        assert_eq!(x.canonical_bytes().unwrap(), y.canonical_bytes().unwrap());
    }
    // Reordered scopes: the same facts, in the same order, with the
    // provenance digest of the different bytes.
    let b = bytes(&extract(vec![blind(), spent_holdout(), unspent_pii()]));
    let r3 = dry_run(&b).unwrap();
    assert_ne!(r1.report.extract_digest, r3.report.extract_digest);
    let facts = |r: &DryRun| {
        r.records
            .iter()
            .map(|x| {
                let mut body = x.body.clone();
                body.provenance.extract_digest =
                    r1.records[0].body.provenance.extract_digest.clone();
                body
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(facts(&r1), facts(&r3));
    assert_eq!(r1.report.scopes, r3.report.scopes);
    // Identity is stable and URL safe.
    for r in &r1.records {
        assert!(r.import_id.as_str().starts_with("lgi_"));
        assert_eq!(r.import_id.as_str().len(), 36);
    }
    // Changing any fact changes the identity.
    let mut s = spent_holdout();
    s["attempts"][0]["run"] = json!("run-0009");
    let other = run(vec![s]);
    let base = run(vec![spent_holdout()]);
    assert_ne!(only(&other).import_id, only(&base).import_id);
}

#[test]
fn reimport_is_idempotent_and_never_lowers_anything() {
    let r = run(vec![spent_holdout(), unspent_pii()]);
    let mut store = MemoryImportStore::new();
    let first = apply(&r.records, &mut store).unwrap();
    assert_eq!(
        (first.created, first.already_imported, first.superseded),
        (2, 0, 0)
    );
    let again = apply(&r.records, &mut store).unwrap();
    assert_eq!(
        (again.created, again.already_imported, again.superseded),
        (0, 2, 0)
    );
    assert_eq!(store.rows().len(), 2);

    // More information (a new attempt appears) supersedes, and the older
    // record is kept.
    let mut more = unspent_pii();
    more["attempts"] = json!([{"run": "run-0004", "state": "complete"}]);
    let r2 = run(vec![spent_holdout(), more]);
    let rep = apply(&r2.records, &mut store).unwrap();
    assert_eq!(
        (rep.created, rep.already_imported, rep.superseded),
        (0, 1, 1)
    );
    assert_eq!(store.rows().len(), 3);
    assert!(store.rows().iter().any(|s| s.supersedes.is_some()));
    let key = r
        .records
        .iter()
        .find(|x| x.body.scope_key.as_str().starts_with("pii"))
        .unwrap()
        .body
        .scope_key
        .clone();
    assert_eq!(store.latest(&key).unwrap().body.budget.consumed, 1);

    // Re-applying the older "unspent" record is a harmless no-op: the newest
    // record for the scope still says spent.
    let back = run(vec![spent_holdout(), unspent_pii()]);
    let before = store.rows().len();
    let noop = apply(&back.records, &mut store).unwrap();
    assert_eq!((noop.created, noop.superseded), (0, 0));
    assert_eq!(store.rows().len(), before);
    assert_eq!(store.latest(&key).unwrap().body.budget.consumed, 1);

    // A new record that would forget a spent attempt is refused.
    let mut forgetful = spent_holdout();
    forgetful["attempts"] = json!([]);
    forgetful
        .as_object_mut()
        .unwrap()
        .remove("reported_consumed");
    forgetful["sources"].as_array_mut().unwrap().push(src(
        "unspent-attestation",
        "evidence/synthetic/unspent.json",
        8,
    ));
    let f = run(vec![forgetful]);
    assert_eq!(only(&f).body.budget.consumed, 0);
    assert_eq!(
        apply(&f.records, &mut store).unwrap_err(),
        ApplyRefusal::WouldReduceConsumption
    );
    assert_eq!(store.rows().len(), before);

    // A mark is not dropped, independence is not changed, the limit is not
    // changed, and nothing is half applied when one record is refused.
    let mut marked = spent_holdout();
    marked["contamination"] = json!({"state": "marked", "reason": "exposed", "source": 2});
    let mut s2 = MemoryImportStore::new();
    apply(&run(vec![marked]).records, &mut s2).unwrap();
    assert_eq!(
        apply(&run(vec![spent_holdout()]).records, &mut s2).unwrap_err(),
        ApplyRefusal::WouldClearContamination
    );
    let mut s3 = MemoryImportStore::new();
    apply(&run(vec![spent_holdout()]).records, &mut s3).unwrap();
    let mut changed = spent_holdout();
    changed["independence"] = json!({"claim": "public-control"});
    assert_eq!(
        apply(&run(vec![changed]).records, &mut s3).unwrap_err(),
        ApplyRefusal::WouldChangeIndependence
    );
    let mut lim = spent_holdout();
    lim["declared_limit"] = json!(3);
    assert_eq!(
        apply(&run(vec![lim]).records, &mut s3).unwrap_err(),
        ApplyRefusal::WouldChangeLimit
    );
    let mut mixed = run(vec![spent_holdout()]).records;
    let mut fresh = unspent_pii();
    fresh["scope"]["epoch"] = json!("epoch-2");
    let mut bad = spent_holdout();
    bad["declared_limit"] = json!(3);
    mixed.extend(run(vec![fresh]).records);
    mixed.extend(run(vec![bad]).records);
    let n = s3.rows().len();
    assert!(apply(&mixed, &mut s3).is_err());
    assert_eq!(s3.rows().len(), n);
}

fn refused(v: Value) -> RefusalCode {
    let r = dry_run(&bytes(&extract(vec![v]))).unwrap();
    assert!(r.records.is_empty());
    assert_eq!(r.report.gate.refused_scopes, 1);
    assert!(!r.report.gate.ready_for_review);
    r.report.refused[0].code
}

#[test]
fn malformed_ambiguous_and_path_like_input_is_refused() {
    // Whole-extract refusals.
    assert_eq!(
        dry_run(&vec![b' '; 1_048_577]).unwrap_err(),
        ExtractRefusal::Oversized
    );
    assert_eq!(dry_run(b"not json").unwrap_err(), ExtractRefusal::Malformed);
    assert_eq!(dry_run(b"").unwrap_err(), ExtractRefusal::Malformed);
    let mut wrong = extract(vec![]);
    wrong["schema"] = json!("private-custodian.legacy-extract/2");
    assert_eq!(
        dry_run(&bytes(&wrong)).unwrap_err(),
        ExtractRefusal::WrongSchema
    );
    let mut extra = extract(vec![]);
    extra["note"] = json!("x");
    assert_eq!(
        dry_run(&bytes(&extra)).unwrap_err(),
        ExtractRefusal::Malformed
    );
    let mut many = extract(vec![]);
    many["scopes"] = json!(vec![spent_holdout(); 257]);
    assert_eq!(
        dry_run(&bytes(&many)).unwrap_err(),
        ExtractRefusal::TooLarge
    );
    let mut unk = spent_holdout();
    unk["state_path"] = json!("x");
    assert_eq!(
        dry_run(&bytes(&extract(vec![unk]))).unwrap_err(),
        ExtractRefusal::Malformed
    );
    // A bad count (negative, fractional) is not a number the types accept.
    let mut neg = spent_holdout();
    neg["declared_limit"] = json!(-1);
    assert_eq!(
        dry_run(&bytes(&extract(vec![neg]))).unwrap_err(),
        ExtractRefusal::Malformed
    );

    // Local and protected paths: refused as a whole, never echoed.
    for loc in [
        "/Users/someone/private-root/ledger.json",
        "/home/x/y.json",
        "~/private/state.json",
        "../outside/manifest.json",
        "holdout/../../etc/passwd",
        "C:/Users/x/manifest.json",
        "holdout\\manifest.json",
        "holdout/generated/abcdef/corpus.json",
        "private/blind/fixtures.json",
        "evidence/runs/run-1/aggregate.json",
        "holdout//manifest.json",
        "",
    ] {
        let mut s = spent_holdout();
        s["sources"][0]["locator"] = json!(loc);
        assert_eq!(
            dry_run(&bytes(&extract(vec![s]))).unwrap_err(),
            ExtractRefusal::Malformed,
            "{loc}"
        );
    }

    // Scope-level refusals.
    let mut nodigest = spent_holdout();
    nodigest["sources"][0]
        .as_object_mut()
        .unwrap()
        .remove("sha256");
    assert_eq!(refused(nodigest), RefusalCode::SourceInvalid);
    let mut stmt_digest = spent_holdout();
    stmt_digest["sources"][2]["sha256"] = json!(sha(5));
    assert_eq!(refused(stmt_digest), RefusalCode::SourceInvalid);
    let mut stmt_path = spent_holdout();
    stmt_path["sources"][2]["locator"] = json!("holdout/some-statement");
    assert_eq!(refused(stmt_path), RefusalCode::SourceInvalid);
    let mut dangling = spent_holdout();
    dangling["attempts"][0]["source"] = json!(9);
    assert_eq!(refused(dangling), RefusalCode::SourceInvalid);
    let mut dangling = spent_holdout();
    dangling["contamination"] = json!({"state": "none_recorded", "source": 9});
    assert_eq!(refused(dangling), RefusalCode::SourceInvalid);
    let mut kind = blind();
    kind["scope"] = json!({"kind": "population_epoch", "population": "p", "epoch": "e"});
    assert_eq!(refused(kind), RefusalCode::ScopeMismatch);
    let mut kind = spent_holdout();
    kind["scope"] = json!({"kind": "candidate_epoch", "candidate": "c", "epoch": "e"});
    assert_eq!(refused(kind), RefusalCode::ScopeMismatch);
    let mut zero = spent_holdout();
    zero["declared_limit"] = json!(0);
    assert_eq!(refused(zero), RefusalCode::LimitInvalid);

    // Two statements about one budget cannot both be right.
    let r = dry_run(&bytes(&extract(vec![
        spent_holdout(),
        spent_holdout(),
        unspent_pii(),
    ])))
    .unwrap();
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.report.refused.len(), 2);
    assert!(r
        .report
        .refused
        .iter()
        .all(|x| x.code == RefusalCode::DuplicateScope));
}

#[test]
fn canary_protected_details_never_reach_any_output() {
    // Protected-looking strings in the places a careless extract might put
    // them. Each makes the extract or scope refuse, and no output echoes them.
    const CANARIES: [&str; 5] = [
        "canary-protected-text-7f3a",
        "canary-seed-9c1d",
        "canary-case-0042",
        "canary-private-root-location",
        "canary-fixture-body",
    ];
    for c in CANARIES {
        // As an unknown field.
        let mut s = spent_holdout();
        s[c] = json!(c);
        let err = dry_run(&bytes(&extract(vec![s]))).unwrap_err();
        assert!(!format!("{err:?} {err}").contains(c));
        // As free text where a label is required (spaces and quotes).
        let mut s = spent_holdout();
        s["attempts"][0]["run"] = json!(format!("{c} with text"));
        assert_eq!(
            dry_run(&bytes(&extract(vec![s]))).unwrap_err(),
            ExtractRefusal::Malformed
        );
        // As a protected locator.
        let mut s = spent_holdout();
        s["sources"][0]["locator"] = json!(format!("holdout/generated/{c}/corpus.json"));
        let err = dry_run(&bytes(&extract(vec![s]))).unwrap_err();
        assert!(!format!("{err:?} {err}").contains(c));
        // As a bad independence claim: scope refused, report silent.
        let mut s = spent_holdout();
        s["independence"] = json!({"claim": c});
        let r = dry_run(&bytes(&extract(vec![s]))).unwrap();
        let shown = format!(
            "{:?} {} {}",
            r.report,
            r.report.render(),
            String::from_utf8_lossy(&r.report.to_bytes())
        );
        assert!(!shown.contains(c));
    }
    // A clean run contains no path-like or private strings either.
    let r = run(vec![spent_holdout(), unspent_pii(), blind()]);
    let mut all = r.report.render();
    all.push_str(&String::from_utf8_lossy(&r.report.to_bytes()));
    for rec in &r.records {
        all.push_str(&String::from_utf8(rec.canonical_bytes().unwrap()).unwrap());
    }
    for forbidden in [
        "/Users/",
        "/home/",
        "~/",
        "\\",
        "generated",
        "corpus.json",
        "seed",
        "fixtures.json",
    ] {
        assert!(!all.contains(forbidden), "{forbidden}");
    }
}

// ---- handoff ------------------------------------------------------------------

fn cor() -> custodian_contracts::types::CorpusId {
    custodian_contracts::types::CorpusId::parse("cor_synthetic000000000001").unwrap()
}
fn epo(n: u32) -> custodian_contracts::types::EpochId {
    custodian_contracts::types::EpochId::parse(&format!("epo_synthetic{n:012}")).unwrap()
}

fn pop_scope(n: u32) -> BudgetScope {
    BudgetScope::PopulationEpoch {
        corpus_id: cor(),
        epoch_id: epo(n),
        family_id: None,
    }
}

fn evidence(n: u64) -> Option<CheckEvidence> {
    Some(CheckEvidence {
        reference: custodian_bridge::legacy::model::Label::parse(&format!("review-{n}")).unwrap(),
        at: Timestamp::new(T0 + n).unwrap(),
    })
}

fn complete(h: &mut HandoffRecord) {
    h.checks.inventory_reviewed = evidence(1);
    h.checks.dry_run_zero_unexplained = evidence(2);
    h.checks.envelope_verification_proven = evidence(3);
    h.checks.rollback_rehearsed = evidence(4);
    h.checks.legacy_runner_disabled_same_change = evidence(5);
}

fn entries_for(r: &DryRun, scopes: &[BudgetScope]) -> Vec<HandoffEntry> {
    r.records
        .iter()
        .zip(scopes)
        .map(|(rec, s)| HandoffEntry {
            import_id: rec.import_id.clone(),
            custodian_scope: s.clone(),
        })
        .collect()
}

fn blockers(s: HandoffStatus) -> Vec<Blocker> {
    match s {
        HandoffStatus::Proposed(b) => b,
        HandoffStatus::ReadyForSignoff => vec![],
    }
}

#[test]
fn a_handoff_only_proposes_until_every_gate_has_evidence() {
    // PII holdout-style scope (domain pii) with a clean dry run.
    let r = run(vec![unspent_pii()]);
    assert!(r.report.gate.ready_for_review);
    let mut h = HandoffRecord::propose(
        EvaluationDomain::Pii,
        Timestamp::new(T0 + 100).unwrap(),
        &r.report,
        entries_for(&r, &[pop_scope(1)]),
    );
    let b = blockers(h.assess(&r.report, &r.records));
    for want in [
        Blocker::MissingInventoryReview,
        Blocker::MissingDryRunEvidence,
        Blocker::MissingEnvelopeVerification,
        Blocker::MissingRollbackRehearsal,
        Blocker::MissingRunnerDisable,
    ] {
        assert!(b.contains(&want), "{want:?}");
    }
    complete(&mut h);
    assert_eq!(
        h.assess(&r.report, &r.records),
        HandoffStatus::ReadyForSignoff
    );

    // The record cannot say a cutover happened, a rerun was used, or a new
    // execution needs no approval.
    let text = String::from_utf8(h.canonical_bytes().unwrap()).unwrap();
    for must in [
        "\"cutover\":\"not_executed\"",
        "\"parity\":\"metadata_only\"",
        "\"prior_evidence\":\"preserved\"",
        "\"new_protected_execution\":\"requires_approval\"",
    ] {
        assert!(text.contains(must), "{must}");
    }
    assert_eq!(
        HandoffRecord::decode(&h.canonical_bytes().unwrap()).unwrap(),
        h
    );
    let mut forged: Value = serde_json::from_slice(&h.canonical_bytes().unwrap()).unwrap();
    forged["cutover"] = json!("executed");
    assert!(serde_json::from_value::<HandoffRecord>(forged).is_err());
    let mut forged: Value = serde_json::from_slice(&h.canonical_bytes().unwrap()).unwrap();
    forged["parity"] = json!("protected_rerun");
    assert!(serde_json::from_value::<HandoffRecord>(forged).is_err());

    // A different dry run invalidates it.
    let other = run(vec![unspent_pii(), spent_holdout()]);
    assert!(
        blockers(h.assess(&other.report, &other.records)).contains(&Blocker::DryRunDigestMismatch)
    );
}

#[test]
fn credential_is_not_forced_and_unready_or_partial_handoffs_are_blocked() {
    let r = run(vec![spent_holdout()]);
    let mut h = HandoffRecord::propose(
        EvaluationDomain::Credential,
        Timestamp::new(T0 + 100).unwrap(),
        &r.report,
        entries_for(&r, &[pop_scope(1)]),
    );
    complete(&mut h);
    assert_eq!(
        blockers(h.assess(&r.report, &r.records)),
        vec![Blocker::CredentialNotReady]
    );
    h.checks.credential_readiness = evidence(6);
    assert_eq!(
        h.assess(&r.report, &r.records),
        HandoffStatus::ReadyForSignoff
    );

    // The two budget semantics are never collapsed.
    let mut wrong = h.clone();
    wrong.entries[0].custodian_scope = BudgetScope::CandidateLineageEpoch {
        corpus_id: cor(),
        epoch_id: epo(1),
        family_id: None,
        lineage_id: custodian_contracts::types::LineageId::parse("lin_synthetic000000000001")
            .unwrap(),
    };
    assert!(blockers(wrong.assess(&r.report, &r.records)).contains(&Blocker::ScopeKindMismatch));

    // Domain mismatch, unknown import, duplicate entry.
    let mut dom = h.clone();
    dom.domain = EvaluationDomain::Pii;
    assert!(blockers(dom.assess(&r.report, &r.records)).contains(&Blocker::DomainMismatch));
    let mut unknown = h.clone();
    unknown.entries[0].import_id = ImportId::parse("lgi_00000000000000000000000000000000").unwrap();
    assert!(blockers(unknown.assess(&r.report, &r.records)).contains(&Blocker::UnknownImport));
    let mut dup = h.clone();
    dup.entries.push(dup.entries[0].clone());
    assert!(blockers(dup.assess(&r.report, &r.records)).contains(&Blocker::DuplicateEntry));

    // A dry run that is not ready blocks, whatever the record says.
    let mut bad = spent_holdout();
    bad["reported_receipts"] = json!(5);
    let rb = run(vec![bad]);
    let mut hb = HandoffRecord::propose(
        EvaluationDomain::Credential,
        Timestamp::new(T0 + 100).unwrap(),
        &rb.report,
        entries_for(&rb, &[pop_scope(1)]),
    );
    complete(&mut hb);
    hb.checks.credential_readiness = evidence(6);
    assert!(blockers(hb.assess(&rb.report, &rb.records)).contains(&Blocker::DryRunNotReady));

    // A population moves whole: two epochs of one population, one included.
    let mut e2 = spent_holdout();
    e2["scope"]["epoch"] = json!("epoch-2");
    let rp = run(vec![spent_holdout(), e2]);
    let mut hp = HandoffRecord::propose(
        EvaluationDomain::Credential,
        Timestamp::new(T0 + 100).unwrap(),
        &rp.report,
        entries_for(&rp, &[pop_scope(1)]),
    );
    complete(&mut hp);
    hp.checks.credential_readiness = evidence(6);
    assert!(blockers(hp.assess(&rp.report, &rp.records)).contains(&Blocker::PartialPopulation));
    let full = HandoffRecord {
        entries: entries_for(&rp, &[pop_scope(1), pop_scope(2)]),
        ..hp.clone()
    };
    assert_eq!(
        full.assess(&rp.report, &rp.records),
        HandoffStatus::ReadyForSignoff
    );

    // Two handoffs may not both claim one scope (dual authority).
    assert_eq!(
        contested_scopes(&[full.clone(), hp.clone()], &rp.records).len(),
        1
    );
    assert!(contested_scopes(&[full], &rp.records).is_empty());
}

#[test]
fn the_synthetic_fixture_extract_is_ready_for_review_and_executes_nothing() {
    let fixture = include_bytes!("../testdata/synthetic-extract.json");
    let r = dry_run(fixture).unwrap();
    assert!(r.report.gate.ready_for_review, "{}", r.report.render());
    assert_eq!(
        r.report.executed,
        custodian_bridge::legacy::report::Executed::Nothing
    );
    assert!(r.report.render().contains("nothing executed"));
}
