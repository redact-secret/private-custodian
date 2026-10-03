//! The reviewed handoff record (ADR 0092).
//!
//! A handoff record is the explicit, reviewable statement that a legacy
//! population may move to custodian authority. It is a proposal until every
//! gate of ADR 0003 item 5 has cited evidence and the dry run it binds to has
//! zero unexplained differences. Nothing in this crate executes a cutover:
//! the record has one cutover state, `not_executed`, and no code path writes
//! a budget, disables a runner or runs a protected evaluation.
//!
//! What the record fixes in its types, so no reviewer can forget it:
//!
//! * parity is by metadata only (`metadata_only`): no protected data is
//!   rerun to compare;
//! * prior evidence is preserved (`preserved`): receipts are not erased and
//!   spent budgets are not reset;
//! * any new protected execution requires an explicit approval
//!   (`requires_approval`), the same one every other execution needs.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{BudgetScope, EvaluationDomain};
use custodian_contracts::public::ScopeKind;
use custodian_contracts::types::{DocumentDigest, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::import::{ImportId, LegacyImportRecord, ScopeKey};
use super::model::{Label, ScopeSpec};
use super::report::DryRunReport;

pub const HANDOFF_SCHEMA: &str = "private-custodian.legacy-handoff/1";
pub const HANDOFF_DOMAIN: &str = "private-custodian/v1/legacy-handoff";
pub const MAX_HANDOFF_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityMethod {
    MetadataOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorEvidence {
    Preserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NewProtectedExecution {
    RequiresApproval,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoverState {
    NotExecuted,
}

/// Evidence that a gate was met: a reference to the recorded review or
/// result, and when.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckEvidence {
    pub reference: Label,
    pub at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffChecks {
    /// The maintainer reviewed the inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_reviewed: Option<CheckEvidence>,
    /// The dry run shows zero unexplained differences (also recomputed from
    /// the report by `assess`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run_zero_unexplained: Option<CheckEvidence>,
    /// Benchmarks verified signed envelopes with freshness and revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_verification_proven: Option<CheckEvidence>,
    /// Rollback was rehearsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_rehearsed: Option<CheckEvidence>,
    /// The legacy runner is disabled for these populations in the same
    /// change as the cutover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_runner_disabled_same_change: Option<CheckEvidence>,
    /// The credential domain's own readiness, required when the handoff is
    /// for the credential domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_readiness: Option<CheckEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffEntry {
    pub import_id: ImportId,
    /// The custodian budget scope the imported consumption is recorded
    /// against, with custodian identities assigned when the population is
    /// registered. Must be the variant that matches the legacy semantics.
    pub custodian_scope: BudgetScope,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRecord {
    pub schema: String,
    pub domain: EvaluationDomain,
    pub prepared_at: Timestamp,
    /// Digest of the dry-run report this handoff was reviewed against.
    pub dry_run_digest: DocumentDigest,
    pub entries: Vec<HandoffEntry>,
    pub checks: HandoffChecks,
    pub parity: ParityMethod,
    pub prior_evidence: PriorEvidence,
    pub new_protected_execution: NewProtectedExecution,
    pub cutover: CutoverState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Blocker {
    WrongSchema,
    TooManyEntries,
    DryRunDigestMismatch,
    DryRunNotReady,
    UnknownImport,
    DuplicateEntry,
    DomainMismatch,
    /// The custodian scope variant does not match the legacy budget
    /// semantics: the two are never collapsed.
    ScopeKindMismatch,
    /// The handoff covers some scopes of a population but not all of them:
    /// partial dual authority is refused.
    PartialPopulation,
    MissingInventoryReview,
    MissingDryRunEvidence,
    MissingEnvelopeVerification,
    MissingRollbackRehearsal,
    MissingRunnerDisable,
    /// Credential handoff without the credential domain's own readiness.
    CredentialNotReady,
}

impl Blocker {
    pub fn code(self) -> &'static str {
        match self {
            Self::WrongSchema => "wrong_schema",
            Self::TooManyEntries => "too_many_entries",
            Self::DryRunDigestMismatch => "dry_run_digest_mismatch",
            Self::DryRunNotReady => "dry_run_not_ready",
            Self::UnknownImport => "unknown_import",
            Self::DuplicateEntry => "duplicate_entry",
            Self::DomainMismatch => "domain_mismatch",
            Self::ScopeKindMismatch => "scope_kind_mismatch",
            Self::PartialPopulation => "partial_population",
            Self::MissingInventoryReview => "missing_inventory_review",
            Self::MissingDryRunEvidence => "missing_dry_run_evidence",
            Self::MissingEnvelopeVerification => "missing_envelope_verification",
            Self::MissingRollbackRehearsal => "missing_rollback_rehearsal",
            Self::MissingRunnerDisable => "missing_runner_disable",
            Self::CredentialNotReady => "credential_not_ready",
        }
    }
}

/// `Proposed` until every blocker is cleared; then `ReadyForSignoff`. There
/// is no executed state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandoffStatus {
    Proposed(Vec<Blocker>),
    ReadyForSignoff,
}

impl HandoffRecord {
    /// A new proposal with no gate evidence yet.
    pub fn propose(
        domain: EvaluationDomain,
        prepared_at: Timestamp,
        report: &DryRunReport,
        entries: Vec<HandoffEntry>,
    ) -> Self {
        Self {
            schema: HANDOFF_SCHEMA.to_owned(),
            domain,
            prepared_at,
            dry_run_digest: report.digest(),
            entries,
            checks: HandoffChecks::default(),
            parity: ParityMethod::MetadataOnly,
            prior_evidence: PriorEvidence::Preserved,
            new_protected_execution: NewProtectedExecution::RequiresApproval,
            cutover: CutoverState::NotExecuted,
        }
    }

    pub fn canonical_bytes(&self) -> Option<Vec<u8>> {
        to_canonical_bytes(self).ok()
    }

    /// Strict parse of a stored handoff record, requiring canonical form.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let r: Self = serde_json::from_slice(bytes).ok()?;
        (r.canonical_bytes()? == bytes).then_some(r)
    }

    pub fn digest(&self) -> Option<DocumentDigest> {
        let mut h = Sha256::new();
        h.update(HANDOFF_DOMAIN.as_bytes());
        h.update([0u8]);
        h.update(self.canonical_bytes()?);
        Some(DocumentDigest::from_raw(h.finalize().into()))
    }

    /// Everything that still stands between this record and a maintainer's
    /// sign-off. Recomputed from the report and records, never taken on the
    /// record's word.
    pub fn assess(&self, report: &DryRunReport, records: &[LegacyImportRecord]) -> HandoffStatus {
        let mut b = BTreeSet::new();
        if self.schema != HANDOFF_SCHEMA {
            b.insert(Blocker::WrongSchema);
        }
        if self.entries.is_empty() || self.entries.len() > MAX_HANDOFF_ENTRIES {
            b.insert(Blocker::TooManyEntries);
        }
        if self.dry_run_digest != report.digest() {
            b.insert(Blocker::DryRunDigestMismatch);
        }
        if !report.gate.ready_for_review {
            b.insert(Blocker::DryRunNotReady);
        }

        let by_id: BTreeMap<&ImportId, &LegacyImportRecord> =
            records.iter().map(|r| (&r.import_id, r)).collect();
        let mut included = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for e in &self.entries {
            if !seen.insert(&e.import_id) {
                b.insert(Blocker::DuplicateEntry);
                continue;
            }
            let Some(r) = by_id.get(&e.import_id) else {
                b.insert(Blocker::UnknownImport);
                continue;
            };
            included.insert(&r.body.scope_key);
            if r.body.domain != self.domain {
                b.insert(Blocker::DomainMismatch);
            }
            let kind_ok = matches!(
                (&e.custodian_scope, r.body.budget.scope_kind),
                (
                    BudgetScope::PopulationEpoch { .. },
                    ScopeKind::PopulationEpoch
                ) | (
                    BudgetScope::CandidateLineageEpoch { .. },
                    ScopeKind::CandidateLineageEpoch
                )
            );
            if !kind_ok {
                b.insert(Blocker::ScopeKindMismatch);
            }
        }

        // A population moves whole: group every record by the thing the
        // legacy lifecycle treats as one population (the population label for
        // holdout and PII, the epoch for blind) and require all or none.
        let group = |r: &LegacyImportRecord| -> (u8, String) {
            match &r.body.scope {
                ScopeSpec::PopulationEpoch { population, .. } => {
                    (0, population.as_str().to_owned())
                }
                ScopeSpec::CandidateEpoch { epoch, .. } => (1, epoch.as_str().to_owned()),
            }
        };
        let touched: BTreeSet<(u8, String)> = records
            .iter()
            .filter(|r| included.contains(&r.body.scope_key))
            .map(group)
            .collect();
        if records
            .iter()
            .any(|r| touched.contains(&group(r)) && !included.contains(&r.body.scope_key))
        {
            b.insert(Blocker::PartialPopulation);
        }

        let c = &self.checks;
        if c.inventory_reviewed.is_none() {
            b.insert(Blocker::MissingInventoryReview);
        }
        if c.dry_run_zero_unexplained.is_none() {
            b.insert(Blocker::MissingDryRunEvidence);
        }
        if c.envelope_verification_proven.is_none() {
            b.insert(Blocker::MissingEnvelopeVerification);
        }
        if c.rollback_rehearsed.is_none() {
            b.insert(Blocker::MissingRollbackRehearsal);
        }
        if c.legacy_runner_disabled_same_change.is_none() {
            b.insert(Blocker::MissingRunnerDisable);
        }
        if self.domain == EvaluationDomain::Credential && c.credential_readiness.is_none() {
            b.insert(Blocker::CredentialNotReady);
        }
        if b.is_empty() {
            HandoffStatus::ReadyForSignoff
        } else {
            HandoffStatus::Proposed(b.into_iter().collect())
        }
    }
}

/// Two handoffs may not claim the same legacy scope: partial dual authority
/// over one population is refused. Returns the contested scope keys.
pub fn contested_scopes(
    handoffs: &[HandoffRecord],
    records: &[LegacyImportRecord],
) -> Vec<ScopeKey> {
    let by_id: BTreeMap<&ImportId, &ScopeKey> = records
        .iter()
        .map(|r| (&r.import_id, &r.body.scope_key))
        .collect();
    let mut owner: BTreeMap<&ScopeKey, usize> = BTreeMap::new();
    let mut contested = BTreeSet::new();
    for (i, h) in handoffs.iter().enumerate() {
        for e in &h.entries {
            if let Some(k) = by_id.get(&e.import_id) {
                if owner.insert(k, i).is_some_and(|prev| prev != i) {
                    contested.insert((*k).clone());
                }
            }
        }
    }
    contested.into_iter().collect()
}
