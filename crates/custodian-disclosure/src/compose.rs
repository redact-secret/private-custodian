//! Composition accounting: what past releases revealed, and the decision of
//! which cells of this release to publish given all of it (ADR 0062).
//!
//! The history is per population series. Each entry records only what was made
//! public: the relations in force, and the reported (stratum, metric,
//! numerator, denominator) cells, tagged with a measurement identity. Withheld
//! values are never stored. Numerators are knowledge about one measurement
//! (candidate, engine, protocol, configuration, population); denominators are
//! knowledge about the population and are shared by every measurement of it.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::types::{MetricId, StratumId};
use custodian_store::DisclosureHistoryEntry;
use serde::{Deserialize, Serialize};

use crate::aggregate::PrivateAggregates;
use crate::policy::DisclosurePolicy;
use crate::reason::DisclosureReason;
use crate::suppress::{suppress, Problem, SuppressError};

const HISTORY_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistRelation {
    t: StratumId,
    p: Vec<StratumId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistCell {
    s: StratumId,
    m: MetricId,
    n: u64,
    d: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistPayload {
    v: u32,
    measurement: String,
    relations: Vec<HistRelation>,
    cells: Vec<HistCell>,
}

/// Everything earlier releases in the series made public.
#[derive(Debug, Default)]
pub struct Prior {
    relations: BTreeSet<(StratumId, Vec<StratumId>)>,
    /// Numerators of the same measurement.
    num: BTreeMap<(StratumId, MetricId), u64>,
    /// Denominators of the population.
    den: BTreeMap<(StratumId, MetricId), u64>,
}

impl Prior {
    /// Fold history entries (oldest first). An entry that does not parse is a
    /// refusal, never skipped: skipping would forget what was revealed.
    pub fn from_history(
        entries: &[DisclosureHistoryEntry],
        measurement: &str,
    ) -> Result<Self, DisclosureReason> {
        let mut prior = Prior::default();
        for e in entries {
            let h: HistPayload =
                serde_json::from_str(&e.payload).map_err(|_| DisclosureReason::HistoryConflict)?;
            if h.v != HISTORY_VERSION {
                return Err(DisclosureReason::HistoryConflict);
            }
            for r in h.relations {
                prior.relations.insert((r.t, r.p));
            }
            for c in h.cells {
                let key = (c.s, c.m);
                match prior.den.insert(key.clone(), c.d) {
                    Some(old) if old != c.d => return Err(DisclosureReason::MeasurementConflict),
                    _ => {}
                }
                if h.measurement == measurement {
                    match prior.num.insert(key, c.n) {
                        Some(old) if old != c.n => {
                            return Err(DisclosureReason::MeasurementConflict)
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(prior)
    }
}

/// One published-or-withheld cell, in policy order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub stratum: StratumId,
    pub metric: MetricId,
    /// `None` is withheld.
    pub value: Option<(u64, u64)>,
}

/// Check the artifact against the policy allowlist and the relations. Run
/// before any budget is charged; [`decide`] runs it again.
pub fn check_artifact(
    policy: &DisclosurePolicy,
    aggregates: &PrivateAggregates,
) -> Result<(), DisclosureReason> {
    // Allowlist: nothing outside the policy, and nothing missing.
    for (s, m) in aggregates.cells.keys() {
        if policy.stratum_index(s).is_none() {
            return Err(DisclosureReason::StratumNotAllowed);
        }
        if !policy.allows_metric(m) {
            return Err(DisclosureReason::MetricNotAllowed);
        }
    }
    for r in &policy.strata {
        for m in &policy.metrics {
            if !aggregates
                .cells
                .contains_key(&(r.stratum.clone(), m.clone()))
            {
                return Err(DisclosureReason::ArtifactIncomplete);
            }
        }
    }
    // Relations must hold in the data: a measurement that contradicts the
    // declared structure is rejected, not published.
    for m in &policy.metrics {
        for rel in &policy.relations {
            let get = |s: &StratumId| aggregates.cells[&(s.clone(), m.clone())];
            let (tn, td) = get(&rel.total);
            let (mut pn, mut pd) = (0u64, 0u64);
            for p in &rel.parts {
                let (n, d) = get(p);
                pn = pn.saturating_add(n);
                pd = pd.saturating_add(d);
            }
            if (tn, td) != (pn, pd) {
                return Err(DisclosureReason::ArtifactInconsistent);
            }
        }
    }
    Ok(())
}

/// Decide which cells to publish.
pub fn decide(
    policy: &DisclosurePolicy,
    aggregates: &PrivateAggregates,
    prior: &Prior,
) -> Result<Vec<Decision>, DisclosureReason> {
    check_artifact(policy, aggregates)?;

    // Variable universe: policy strata in preference order, then any stratum
    // earlier policies related that this policy does not publish.
    let mut names: Vec<StratumId> = policy.strata.iter().map(|r| r.stratum.clone()).collect();
    let mut relations: BTreeSet<(StratumId, Vec<StratumId>)> = prior.relations.clone();
    for rel in &policy.relations {
        relations.insert((rel.total.clone(), rel.parts.clone()));
    }
    let mut extra: BTreeSet<StratumId> = BTreeSet::new();
    for (t, parts) in &relations {
        for s in std::iter::once(t).chain(parts.iter()) {
            if !names.contains(s) {
                extra.insert(s.clone());
            }
        }
    }
    for (s, _) in prior.num.keys().chain(prior.den.keys()) {
        if !names.contains(s) {
            extra.insert(s.clone());
        }
    }
    names.extend(extra);
    let index: BTreeMap<&StratumId, usize> =
        names.iter().enumerate().map(|(i, s)| (s, i)).collect();
    let rels: Vec<(usize, Vec<usize>)> = relations
        .iter()
        .map(|(t, parts)| (index[t], parts.iter().map(|p| index[p]).collect()))
        .collect();

    let mut out = Vec::new();
    let mut by_metric: BTreeMap<&MetricId, Vec<bool>> = BTreeMap::new();
    for m in &policy.metrics {
        let n = names.len();
        let mut problem = Problem {
            present: vec![false; n],
            num: vec![0; n],
            den: vec![0; n],
            relations: rels.clone(),
            prior_num: vec![None; n],
            prior_den: vec![None; n],
            min_size: policy.min_stratum_size.get(),
            min_width: policy.min_interval_width.get(),
        };
        for (i, s) in names.iter().enumerate() {
            if let Some((num, den)) = aggregates.cells.get(&(s.clone(), m.clone())) {
                if policy.stratum_index(s).is_some() {
                    problem.present[i] = true;
                    problem.num[i] = *num;
                    problem.den[i] = *den;
                }
            }
            problem.prior_num[i] = prior.num.get(&(s.clone(), m.clone())).copied();
            problem.prior_den[i] = prior.den.get(&(s.clone(), m.clone())).copied();
        }
        let withheld = suppress(&problem).map_err(|e| match e {
            SuppressError::Conflict => DisclosureReason::MeasurementConflict,
            SuppressError::Unresolvable | SuppressError::Arithmetic => {
                DisclosureReason::CompositionUnresolvable
            }
        })?;
        by_metric.insert(m, withheld);
    }
    for r in &policy.strata {
        let i = index[&r.stratum];
        for m in &policy.metrics {
            let withheld = by_metric[m][i];
            let v = aggregates.cells[&(r.stratum.clone(), m.clone())];
            out.push(Decision {
                stratum: r.stratum.clone(),
                metric: m.clone(),
                value: if withheld { None } else { Some(v) },
            });
        }
    }
    Ok(out)
}

/// The history entry to append once a release is built: relations in force
/// and the cells actually reported.
pub fn history_payload(
    policy: &DisclosurePolicy,
    measurement: &str,
    decisions: &[Decision],
) -> Result<String, DisclosureReason> {
    let payload = HistPayload {
        v: HISTORY_VERSION,
        measurement: measurement.to_owned(),
        relations: policy
            .relations
            .iter()
            .map(|r| HistRelation {
                t: r.total.clone(),
                p: r.parts.clone(),
            })
            .collect(),
        cells: decisions
            .iter()
            .filter_map(|d| {
                d.value.map(|(n, den)| HistCell {
                    s: d.stratum.clone(),
                    m: d.metric.clone(),
                    n,
                    d: den,
                })
            })
            .collect(),
    };
    serde_json::to_string(&payload).map_err(|_| DisclosureReason::HistoryConflict)
}
