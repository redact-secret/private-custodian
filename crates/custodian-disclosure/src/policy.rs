//! The versioned disclosure policy (C8, ADR 0061).
//!
//! A disclosure policy is a reviewed, closed document: which strata and
//! metrics may be published, the linear relations between strata that
//! suppression must respect, the minimum stratum size, the protection width,
//! the (absent) perturbation, the release and query budgets, the allowed
//! destinations and freshness. A change is a new policy version and a new
//! activation, never an edit. Its canonical digest is what the ledger `policy`
//! record carries.
//!
//! The policy is project-maintained configuration. It is not independent
//! validation, and following it does not guarantee privacy (docs/disclosure.md).

use std::collections::BTreeSet;

use custodian_contracts::canonical::{to_canonical_bytes, MAX_DOCUMENT_BYTES};
use custodian_contracts::common::{ActivationRef, PolicyKind, PolicyRef};
use custodian_contracts::policy::MAX_STATE_AGE_SECS;
use custodian_contracts::public::MAX_PROJECTION_FRESHNESS_SECS;
use custodian_contracts::types::{Count, DestinationId, DocumentDigest, MetricId, StratumId};
use custodian_ledger::{LedgerRecord, RecordError, SignDomain};
use serde::{Deserialize, Serialize};

use crate::reason::DisclosureReason;

/// Schema tag of the policy document.
pub const POLICY_SCHEMA: &str = "private-custodian.disclosure-policy/1";

pub const MAX_STRATA: usize = 64;
pub const MAX_METRICS: usize = 16;
pub const MAX_RELATIONS: usize = 64;
pub const MAX_RELATION_PARTS: usize = 32;
pub const MAX_DESTINATIONS: usize = 16;

/// A named grouping of strata (for example `length` or `family`). Allowlisted
/// by the policy; carries no value.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Dimension(String);

impl Dimension {
    pub fn parse(s: &str) -> Result<Self, DisclosureReason> {
        let ok = !s.is_empty()
            && s.len() <= 64
            && s.as_bytes()
                .first()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(DisclosureReason::PolicyInvalid)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Dimension {
    type Error = DisclosureReason;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<Dimension> for String {
    fn from(d: Dimension) -> String {
        d.0
    }
}

/// One publishable stratum. The order of `strata` in the policy is the order
/// in which suppression prefers to withhold further cells (earlier first).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StratumRule {
    pub stratum: StratumId,
    pub dimension: Dimension,
}

/// `total = sum(parts)`, for numerators and for denominators, in every
/// metric. This is what an observer can use to difference a cell back out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub total: StratumId,
    pub parts: Vec<StratumId>,
}

/// Statistical perturbation. The only value is `none`: nothing is rounded,
/// noised or bucketed. A mechanism that changes published numbers would be a
/// new policy schema major with the measurement consequences stated in an ADR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mechanism", rename_all = "snake_case", deny_unknown_fields)]
pub enum Perturbation {
    None {},
}

/// Cumulative release and query limits, enforced by the store and never
/// reset. Units per attempt are charged against every applicable scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    /// Per population epoch (and family): all requesters and candidates.
    pub per_population: Count<1_000_000>,
    /// Per candidate lineage per epoch (blind scope only).
    pub per_lineage: Count<1_000_000>,
    /// Per authenticated requester, across populations of the policy.
    pub per_requester: Count<1_000_000>,
    pub units_per_attempt: Count<16>,
}

/// The policy rule for requests that did not release anything. There is one
/// value for each: they are charged. A withheld or failed attempt still
/// consumed protected evidence and told the requester something, so it counts
/// like a released one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptCharge {
    Charged,
}

/// Durable audit acknowledgement before release. One value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRequirement {
    Acknowledged,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicy {
    pub schema: String,
    pub policy: PolicyRef,
    pub strata: Vec<StratumRule>,
    pub metrics: Vec<MetricId>,
    /// The stratum covering the whole roster.
    pub total_stratum: StratumId,
    pub relations: Vec<Relation>,
    /// Cells whose denominator is below this are never published.
    pub min_stratum_size: Count<1_000_000>,
    /// A withheld cell must stay uncertain over an interval at least this
    /// wide (upper bound minus lower bound derived from what is published).
    pub min_interval_width: Count<1_000_000>,
    pub perturbation: Perturbation,
    pub budgets: BudgetLimits,
    pub withheld_attempts: AttemptCharge,
    pub failed_attempts: AttemptCharge,
    pub audit: AuditRequirement,
    pub destinations: Vec<DestinationId>,
    /// How long a released projection may be relied on.
    pub freshness_secs: Count<{ MAX_PROJECTION_FRESHNESS_SECS }>,
    /// Oldest activation state a release may rely on.
    pub state_max_age_secs: Count<{ MAX_STATE_AGE_SECS }>,
}

impl DisclosurePolicy {
    /// Structural and cross-field validation. Fails closed.
    pub fn validate(&self) -> Result<(), DisclosureReason> {
        let bad = DisclosureReason::PolicyInvalid;
        if self.schema != POLICY_SCHEMA || self.policy.kind != PolicyKind::Disclosure {
            return Err(bad);
        }
        if self.strata.is_empty() || self.strata.len() > MAX_STRATA {
            return Err(bad);
        }
        if self.metrics.is_empty() || self.metrics.len() > MAX_METRICS {
            return Err(bad);
        }
        if self.destinations.is_empty() || self.destinations.len() > MAX_DESTINATIONS {
            return Err(bad);
        }
        if self.relations.len() > MAX_RELATIONS {
            return Err(bad);
        }
        let strata: BTreeSet<&StratumId> = self.strata.iter().map(|s| &s.stratum).collect();
        if strata.len() != self.strata.len() || !strata.contains(&self.total_stratum) {
            return Err(bad);
        }
        if self.metrics.iter().collect::<BTreeSet<_>>().len() != self.metrics.len() {
            return Err(bad);
        }
        if self.destinations.iter().collect::<BTreeSet<_>>().len() != self.destinations.len() {
            return Err(bad);
        }
        for r in &self.relations {
            let parts: BTreeSet<&StratumId> = r.parts.iter().collect();
            if r.parts.len() < 2
                || r.parts.len() > MAX_RELATION_PARTS
                || parts.len() != r.parts.len()
                || parts.contains(&r.total)
                || !strata.contains(&r.total)
                || !parts.iter().all(|p| strata.contains(*p))
            {
                return Err(bad);
            }
        }
        if self.min_stratum_size.get() == 0 || self.min_interval_width.get() == 0 {
            return Err(bad);
        }
        let b = &self.budgets;
        if b.per_population.get() == 0
            || b.per_lineage.get() == 0
            || b.per_requester.get() == 0
            || b.units_per_attempt.get() == 0
        {
            return Err(bad);
        }
        if self.freshness_secs.get() == 0 || self.state_max_age_secs.get() == 0 {
            return Err(bad);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DisclosureReason> {
        to_canonical_bytes(self).map_err(|_| DisclosureReason::PolicyInvalid)
    }

    /// Strict parse of canonical bytes: size cap, closed schema (unknown
    /// fields rejected), validation, and byte equality with the canonical
    /// encoding.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DisclosureReason> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(DisclosureReason::PolicyInvalid);
        }
        let p: Self = serde_json::from_slice(bytes).map_err(|_| DisclosureReason::PolicyInvalid)?;
        p.validate()?;
        if p.canonical_bytes()? != bytes {
            return Err(DisclosureReason::PolicyInvalid);
        }
        Ok(p)
    }

    /// Domain-separated digest of the canonical document (the `policy`
    /// ledger domain). A reviewer compares this value with the ledger record.
    pub fn document_digest(&self) -> Result<DocumentDigest, DisclosureReason> {
        self.validate()?;
        Ok(SignDomain::LedgerPolicy.digest(&self.canonical_bytes()?))
    }

    /// The `policy` ledger record for one activation of this policy. `at`
    /// must be deterministic (for example the activation's `changed_at`) so a
    /// retry writes identical bytes.
    pub fn ledger_record(
        &self,
        activation: ActivationRef,
        at: u64,
    ) -> Result<LedgerRecord, DisclosureReason> {
        if activation.policy != self.policy {
            return Err(DisclosureReason::PolicyMismatch);
        }
        LedgerRecord::policy(activation, self.document_digest()?, at)
            .map_err(|_: RecordError| DisclosureReason::PolicyInvalid)
    }

    pub fn allows_destination(&self, d: &DestinationId) -> bool {
        self.destinations.contains(d)
    }

    pub fn stratum_index(&self, s: &StratumId) -> Option<usize> {
        self.strata.iter().position(|r| r.stratum == *s)
    }

    pub fn allows_metric(&self, m: &MetricId) -> bool {
        self.metrics.contains(m)
    }
}
