//! Small-cell suppression and differencing attacks (C8).
//!
//! The adversary here knows only what was published (reported cells across
//! releases) and the declared relations. It enumerates every integer
//! assignment of the never-published cells that satisfies the relations and
//! non-negativity, and "pins" a cell when the feasible values span less than
//! the policy's protection width. The first tests show the attack works on a
//! naive publication; the same adversary must then fail against the real
//! decisions, within one release, across overlapping totals and across
//! successive releases.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use custodian_contracts::common::ProtocolRef;
use custodian_contracts::execution::{PrivateArtifactRef, RosterCounts};
use custodian_contracts::types::{Count, ResultDigest};
use custodian_disclosure::compose::{decide, history_payload, Decision, Prior};
use custodian_disclosure::policy::DisclosurePolicy;
use custodian_disclosure::{DisclosureReason as R, PrivateAggregates};
use custodian_store::DisclosureHistoryEntry;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn aggregates(v: &Value) -> PrivateAggregates {
    let bytes = serde_json::to_vec(v).unwrap();
    let protocol: ProtocolRef = serde_json::from_value(cc::protocol()).unwrap();
    let reference = PrivateArtifactRef {
        digest: ResultDigest::from_raw(Sha256::digest(&bytes).into()),
        size_bytes: Count::new(bytes.len() as u64).unwrap(),
        protocol: protocol.clone(),
    };
    let roster = RosterCounts {
        expected: Count::new(75).unwrap(),
        observed: Count::new(75).unwrap(),
        failed: Count::new(0).unwrap(),
    };
    PrivateAggregates::decode(
        &bytes,
        &reference,
        custodian_contracts::common::EvaluationDomain::Credential,
        &protocol,
        &roster,
    )
    .unwrap()
}

/// One sequential release against an in-memory series history.
fn round(
    policy: &DisclosurePolicy,
    data: &Value,
    history: &mut Vec<DisclosureHistoryEntry>,
    measurement: &str,
) -> Result<Vec<Decision>, R> {
    let a = aggregates(data);
    let prior = Prior::from_history(history, measurement)?;
    let d = decide(policy, &a, &prior)?;
    history.push(DisclosureHistoryEntry {
        seq: history.len() as u64 + 1,
        release_id: format!("prj_round{}", history.len() + 1),
        payload: history_payload(policy, measurement, &d)?,
        recorded_at: 0,
    });
    Ok(d)
}

fn table(cells: &[(&str, u64, u64)]) -> Value {
    let mut v = aggregates_json();
    v["cells"] = Value::Array(
        cells
            .iter()
            .map(|(s, n, d)| json!({"stratum": s, "metric": "detected", "numerator": n, "denominator": d}))
            .collect(),
    );
    v
}

/// What the adversary sees: the reported (stratum -> (numerator, denominator)).
type Published = BTreeMap<String, (u64, u64)>;

fn published(decisions: &[Decision]) -> Published {
    decisions
        .iter()
        .filter_map(|d| d.value.map(|v| (d.stratum.as_str().to_owned(), v)))
        .collect()
}

#[derive(Clone, Copy)]
enum Family {
    Num,
    Den,
}

/// Brute-force oracle. Returns the strata whose feasible range is narrower
/// than `width`, among the strata nobody published. Depth-first over the
/// unknowns, pruning as soon as a relation is fully assigned.
fn pinned(
    published: &[&Published],
    relations: &[(String, Vec<String>)],
    strata: &[&str],
    family: Family,
    width: u64,
    max: u64,
) -> BTreeSet<String> {
    let mut known: BTreeMap<String, u64> = BTreeMap::new();
    for p in published {
        for (s, (n, d)) in *p {
            known.insert(
                s.clone(),
                if matches!(family, Family::Num) {
                    *n
                } else {
                    *d
                },
            );
        }
    }
    let unknown: Vec<String> = strata
        .iter()
        .filter(|s| !known.contains_key(**s))
        .map(|s| (*s).to_owned())
        .collect();
    struct Ctx<'a> {
        known: &'a BTreeMap<String, u64>,
        unknown: &'a [String],
        relations: &'a [(String, Vec<String>)],
        max: u64,
        lo: Vec<u64>,
        hi: Vec<u64>,
        feasible: u64,
    }
    fn value(c: &Ctx<'_>, assign: &[u64], s: &str) -> Option<u64> {
        if let Some(v) = c.known.get(s) {
            return Some(*v);
        }
        let i = c.unknown.iter().position(|u| u == s)?;
        assign.get(i).copied()
    }
    fn consistent(c: &Ctx<'_>, assign: &[u64]) -> bool {
        c.relations.iter().all(|(t, parts)| {
            let tv = value(c, assign, t);
            let pv: Vec<Option<u64>> = parts.iter().map(|p| value(c, assign, p)).collect();
            match (tv, pv.iter().all(Option::is_some)) {
                (Some(t), true) => pv.iter().map(|x| x.unwrap()).sum::<u64>() == t,
                _ => true,
            }
        })
    }
    fn dfs(c: &mut Ctx<'_>, assign: &mut Vec<u64>) {
        if !consistent(c, assign) {
            return;
        }
        if assign.len() == c.unknown.len() {
            c.feasible += 1;
            for (i, v) in assign.iter().enumerate() {
                c.lo[i] = c.lo[i].min(*v);
                c.hi[i] = c.hi[i].max(*v);
            }
            return;
        }
        for v in 0..=c.max {
            assign.push(v);
            dfs(c, assign);
            assign.pop();
        }
    }
    let mut c = Ctx {
        known: &known,
        unknown: &unknown,
        relations,
        max,
        lo: vec![u64::MAX; unknown.len()],
        hi: vec![0; unknown.len()],
        feasible: 0,
    };
    dfs(&mut c, &mut Vec::new());
    assert!(c.feasible > 0, "published values must be feasible");
    unknown
        .iter()
        .enumerate()
        .filter(|(i, _)| c.hi[*i] - c.lo[*i] < width)
        .map(|(_, u)| u.clone())
        .collect()
}

fn rels(p: &DisclosurePolicy) -> Vec<(String, Vec<String>)> {
    p.relations
        .iter()
        .map(|r| {
            (
                r.total.as_str().to_owned(),
                r.parts.iter().map(|s| s.as_str().to_owned()).collect(),
            )
        })
        .collect()
}

const STANDARD: [(&str, u64, u64); 6] = [
    ("a", 30, 40),
    ("b", 18, 30),
    ("c", 2, 5),
    ("t1", 35, 50),
    ("t2", 15, 25),
    ("all", 50, 75),
];

#[test]
fn naive_primary_only_publication_is_differenced_but_real_suppression_is_not() {
    let p = policy();
    let strata = ["a", "b", "c", "t1", "t2", "all"];
    let width = p.min_interval_width.get();

    // Naive: withhold only the small cell. The attack recovers it exactly.
    let naive: Published = STANDARD
        .iter()
        .filter(|(s, _, _)| *s != "c")
        .map(|(s, n, d)| ((*s).to_owned(), (*n, *d)))
        .collect();
    let hit = pinned(&[&naive], &rels(&p), &strata, Family::Num, width, 75);
    assert_eq!(hit, ["c".to_owned()].into_iter().collect());
    let hit = pinned(&[&naive], &rels(&p), &strata, Family::Den, width, 75);
    assert_eq!(hit, ["c".to_owned()].into_iter().collect());

    // Real: the same adversary pins nothing, in either family.
    let mut history = Vec::new();
    let d = round(&p, &table(&STANDARD), &mut history, "m1").unwrap();
    let real = published(&d);
    assert!(!real.contains_key("c"));
    assert!(real.len() < naive.len(), "a complementary cell is withheld");
    for fam in [Family::Num, Family::Den] {
        assert!(pinned(&[&real], &rels(&p), &strata, fam, width, 75).is_empty());
    }
    // The roster total is still published.
    assert_eq!(real.get("all"), Some(&(50, 75)));
}

#[test]
fn overlapping_dimensions_cannot_be_used_to_difference_a_withheld_cell() {
    // y2 = c + z overlaps the length dimension: c = y2 - z unless one of them
    // is also withheld.
    let mut v = policy_json();
    v["strata"] = json!([
        {"stratum":"a","dimension":"len"}, {"stratum":"b","dimension":"len"},
        {"stratum":"c","dimension":"len"}, {"stratum":"z","dimension":"cat"},
        {"stratum":"y2","dimension":"cat"}, {"stratum":"y1","dimension":"cat"},
        {"stratum":"all","dimension":"total"}
    ]);
    v["relations"] = json!([
        {"total":"all","parts":["a","b","c"]},
        {"total":"y2","parts":["c","z"]},
        {"total":"all","parts":["y1","y2"]}
    ]);
    let p: DisclosurePolicy = serde_json::from_value(v).unwrap();
    p.validate().unwrap();
    // c=2/5, z=10/10, y2=12/15, y1=38/60, a=30/40, b=18/30, all=50/75.
    let data = table(&[
        ("a", 30, 40),
        ("b", 18, 30),
        ("c", 2, 5),
        ("z", 10, 10),
        ("y2", 12, 15),
        ("y1", 38, 60),
        ("all", 50, 75),
    ]);
    let mut history = Vec::new();
    let d = round(&p, &data, &mut history, "m1").unwrap();
    let real = published(&d);
    assert!(!real.contains_key("c"));
    let strata = ["a", "b", "c", "z", "y2", "y1", "all"];
    for fam in [Family::Num, Family::Den] {
        assert!(
            pinned(&[&real], &rels(&p), &strata, fam, 2, 75).is_empty(),
            "pattern: {:?}",
            real.keys().collect::<Vec<_>>()
        );
    }
}

/// Policy 1 prefers to withhold `a` after `c`; policy 2 prefers `b`.
fn two_policies() -> (DisclosurePolicy, DisclosurePolicy) {
    let order = |first: &str, second: &str| {
        let mut v = policy_json();
        v["strata"] = json!([
            {"stratum": first, "dimension":"len"}, {"stratum": second, "dimension":"len"},
            {"stratum":"c","dimension":"len"}, {"stratum":"all","dimension":"total"}
        ]);
        v["relations"] = json!([{"total":"all","parts":["a","b","c"]}]);
        let p: DisclosurePolicy = serde_json::from_value(v).unwrap();
        p.validate().unwrap();
        p
    };
    (order("a", "b"), order("b", "a"))
}

#[test]
fn successive_releases_cannot_difference_a_withheld_cell() {
    let (p1, p2) = two_policies();
    let data = table(
        &STANDARD[..4]
            .iter()
            .cloned()
            .chain([("all", 50, 75)])
            .collect::<Vec<_>>(),
    );
    // Fix: four-stratum table a, b, c, all (the overlapping t-cells are not
    // part of these policies).
    let data = {
        let mut v = data;
        v["cells"] = Value::Array(
            [("a", 30, 40), ("b", 18, 30), ("c", 2, 5), ("all", 50, 75)]
                .iter()
                .map(|(s, n, d)| json!({"stratum": s, "metric": "detected", "numerator": n, "denominator": d}))
                .collect(),
        );
        v
    };
    let strata = ["a", "b", "c", "all"];

    // Each release alone is safe...
    let mut alone1 = Vec::new();
    let r1 = published(&round(&p1, &data, &mut alone1, "m1").unwrap());
    let mut alone2 = Vec::new();
    let r2 = published(&round(&p2, &data, &mut alone2, "m1").unwrap());
    for r in [&r1, &r2] {
        assert!(pinned(&[r], &rels(&p1), &strata, Family::Num, 2, 75).is_empty());
    }
    // ...but a requester who keeps both and differences them recovers c.
    let hit = pinned(&[&r1, &r2], &rels(&p1), &strata, Family::Num, 2, 75);
    assert_eq!(
        hit,
        ["c".to_owned()].into_iter().collect(),
        "r1={r1:?} r2={r2:?}"
    );

    // With composition accounting the second release is checked against the
    // first and withholds what would complete the difference.
    let mut history = Vec::new();
    let s1 = published(&round(&p1, &data, &mut history, "m1").unwrap());
    let s2 = published(&round(&p2, &data, &mut history, "m1").unwrap());
    assert_eq!(s1, r1);
    // The cell that would have completed the difference is not published
    // the second time.
    assert!(r2.contains_key("a") && !s2.contains_key("a"));
    assert!(pinned(&[&s1, &s2], &rels(&p1), &strata, Family::Num, 2, 75).is_empty());
    assert!(pinned(&[&s1, &s2], &rels(&p1), &strata, Family::Den, 2, 75).is_empty());
}

#[test]
fn denominators_compose_across_different_candidates_on_one_population() {
    let (p1, p2) = two_policies();
    let cells = |scale: u64| {
        let mut v = aggregates_json();
        v["cells"] = Value::Array(
            [
                ("a", 30 / scale, 40),
                ("b", 18 / scale, 30),
                ("c", 2 / scale, 5),
                ("all", 50 / scale, 75),
            ]
            .iter()
            .map(|(s, n, d)| json!({"stratum": s, "metric": "detected", "numerator": n, "denominator": d}))
            .collect(),
        );
        v
    };
    // Candidate 2 scores differently but the population is the same, so its
    // denominators are the same numbers that candidate 1 already revealed.
    let strata = ["a", "b", "c", "all"];
    let mut alone = Vec::new();
    let r1 = published(&round(&p1, &cells(1), &mut alone, "m1").unwrap());
    let mut alone = Vec::new();
    let r2 = published(&round(&p2, &cells(1), &mut alone, "m2").unwrap());
    // Denominator family: the two releases together pin den(c).
    assert!(!pinned(&[&r1, &r2], &rels(&p1), &strata, Family::Den, 2, 75).is_empty());

    let mut history = Vec::new();
    let s1 = published(&round(&p1, &cells(1), &mut history, "m1").unwrap());
    let s2 = published(&round(&p2, &cells(1), &mut history, "m2").unwrap());
    assert!(pinned(&[&s1, &s2], &rels(&p1), &strata, Family::Den, 2, 75).is_empty());
    // Numerators belong to one measurement each: m2's numerators are not
    // composed with m1's.
    let m1_nums: Published = s1.clone();
    let m2_nums: Published = s2.clone();
    assert!(pinned(&[&m2_nums], &rels(&p1), &strata, Family::Num, 2, 75).is_empty());
    assert!(pinned(&[&m1_nums], &rels(&p1), &strata, Family::Num, 2, 75).is_empty());
}

#[test]
fn a_release_that_contradicts_an_earlier_one_is_a_conflict() {
    let p = policy();
    let mut history = Vec::new();
    round(&p, &table(&STANDARD), &mut history, "m1").unwrap();
    // Same measurement, a different numerator for an already published cell:
    // repeated runs are not allowed to be averaged.
    let mut changed = STANDARD;
    changed[5] = ("all", 51, 75);
    changed[0] = ("a", 31, 40);
    changed[3] = ("t1", 36, 50);
    assert_eq!(
        round(&p, &table(&changed), &mut history, "m1").err(),
        Some(R::MeasurementConflict)
    );
    // Same population, a different denominator.
    let mut changed = STANDARD;
    changed[3] = ("t1", 35, 49);
    changed[4] = ("t2", 15, 26);
    assert_eq!(
        round(&p, &table(&changed), &mut history, "m2").err(),
        Some(R::MeasurementConflict)
    );
    // An unreadable history entry is never skipped.
    history.push(DisclosureHistoryEntry {
        seq: 9,
        release_id: "prj_bad".into(),
        payload: "not json".into(),
        recorded_at: 0,
    });
    assert_eq!(
        round(&p, &table(&STANDARD), &mut history, "m1").err(),
        Some(R::HistoryConflict)
    );
}

#[test]
fn a_release_that_cannot_be_made_safe_is_refused() {
    // Everything else in the only relation is already public from earlier
    // releases, so withholding a cell now cannot protect the small one.
    let mut v = policy_json();
    v["strata"] = json!([
        {"stratum":"a","dimension":"len"}, {"stratum":"c","dimension":"len"},
        {"stratum":"all","dimension":"total"}
    ]);
    v["relations"] = json!([{"total":"all","parts":["a","c"]}]);
    let p: DisclosurePolicy = serde_json::from_value(v).unwrap();
    p.validate().unwrap();
    let data = {
        let mut d = aggregates_json();
        d["cells"] = json!([
            {"stratum":"a","metric":"detected","numerator":30,"denominator":70},
            {"stratum":"c","metric":"detected","numerator":2,"denominator":5},
            {"stratum":"all","metric":"detected","numerator":32,"denominator":75}
        ]);
        d
    };
    let prior_payload = json!({
        "v": 1, "measurement": "m1",
        "relations": [{"t":"all","p":["a","c"]}],
        "cells": [
            {"s":"a","m":"detected","n":30,"d":70},
            {"s":"all","m":"detected","n":32,"d":75}
        ]
    })
    .to_string();
    let mut history = vec![DisclosureHistoryEntry {
        seq: 1,
        release_id: "prj_earlier".into(),
        payload: prior_payload,
        recorded_at: 0,
    }];
    assert_eq!(
        round(&p, &data, &mut history, "m1").err(),
        Some(R::CompositionUnresolvable)
    );
}

/// Deterministic generator for the randomized check below.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

#[test]
fn randomized_tables_and_release_sequences_never_pin_a_withheld_cell() {
    let p = policy();
    let strata = ["a", "b", "c", "t1", "t2", "all"];
    let mut rng = Lcg(0x5eed);
    let mut refused = 0;
    let mut effective = 0;
    let mut withheld_cells = 0;
    for case in 0..120 {
        // A consistent table: len dimension a+b+c, cat dimension t1+t2.
        let dens = [1 + rng.next(12), 1 + rng.next(12), 1 + rng.next(12)];
        let nums: Vec<u64> = dens.iter().map(|d| rng.next(d + 1)).collect();
        let den_all: u64 = dens.iter().sum();
        let num_all: u64 = nums.iter().sum();
        let t1d = rng.next(den_all + 1);
        let t1n = rng
            .next(num_all.min(t1d) + 1)
            .max(num_all.saturating_sub(den_all - t1d));
        if t1n > t1d || num_all - t1n > den_all - t1d {
            continue;
        }
        let table1 = table(&[
            ("a", nums[0], dens[0]),
            ("b", nums[1], dens[1]),
            ("c", nums[2], dens[2]),
            ("t1", t1n, t1d),
            ("t2", num_all - t1n, den_all - t1d),
            ("all", num_all, den_all),
        ]);
        // Three sequential releases of the same measurement: each must stay
        // safe together with everything before it.
        let mut history = Vec::new();
        let mut seen: Vec<Published> = Vec::new();
        for _ in 0..3 {
            match round(&p, &table1, &mut history, "m1") {
                Ok(d) => seen.push(published(&d)),
                Err(R::CompositionUnresolvable) => {
                    refused += 1;
                    break;
                }
                Err(e) => panic!("case {case}: {e}"),
            }
        }
        effective += 1;
        withheld_cells += seen.iter().map(|p| 6 - p.len()).sum::<usize>();
        let refs: Vec<&Published> = seen.iter().collect();
        for fam in [Family::Num, Family::Den] {
            let hit = pinned(&refs, &rels(&p), &strata, fam, 2, num_all.max(den_all));
            assert!(hit.is_empty(), "case {case}: pinned {hit:?} in {seen:?}");
        }
    }
    // The check is not vacuous: most generated tables were used and
    // suppression actually happened.
    assert!(effective >= 60, "effective cases: {effective}");
    assert!(withheld_cells > 60, "withheld cells: {withheld_cells}");
    let _ = refused;
}
