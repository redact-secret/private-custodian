//! The dry-run report: what an import would record, how it compares with what
//! the legacy records say, and what is still unexplained.
//!
//! The report names scopes by their deterministic key and counts by number.
//! It carries no path, no digest of a protected file and no free text. It
//! says in a field of its own that nothing was executed.

use custodian_contracts::types::DocumentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::import::ScopeKey;
use super::model::Lifecycle;

pub const REPORT_SCHEMA: &str = "private-custodian.legacy-dry-run/1";
pub const REPORT_DOMAIN: &str = "private-custodian/v1/legacy-dry-run";

/// A dry run executes nothing. One value, so no report can claim otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Executed {
    Nothing,
}

/// A fixed reason a scope was refused. The input is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    DuplicateScope,
    /// The scope shape does not match the lifecycle's budget semantics.
    ScopeMismatch,
    LimitInvalid,
    /// A source without a digest (except reviewed statements), a statement
    /// with a digest or a path, or a reference to a source that is not there.
    SourceInvalid,
    /// An independence value outside the three legacy values.
    IndependenceUnrepresentable,
    OrganisationalIndependenceClaimed,
    TooLarge,
}

impl RefusalCode {
    pub fn code(self) -> &'static str {
        match self {
            Self::DuplicateScope => "duplicate_scope",
            Self::ScopeMismatch => "scope_mismatch",
            Self::LimitInvalid => "limit_invalid",
            Self::SourceInvalid => "source_invalid",
            Self::IndependenceUnrepresentable => "independence_unrepresentable",
            Self::OrganisationalIndependenceClaimed => "organisational_independence_claimed",
            Self::TooLarge => "too_large",
        }
    }
}

/// A difference between what a legacy record reports and what would be
/// imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceCode {
    /// Explained: the import counts more as consumed than the legacy record
    /// states, because the record was ambiguous or silent (ADR 0003).
    ConservativeAmbiguity,
    /// Explained: more was consumed than the stated limit.
    ConsumedAboveLimit,
    /// Unexplained: a legacy summary count and the legacy attempt list differ.
    ReportedCountDisagrees,
    /// Unexplained: the receipts listed and the legacy receipt count differ.
    ReceiptCountDisagrees,
    /// Unexplained: an unspent attestation sits beside a spent attempt.
    AttestationContradictsSpend,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeReport {
    pub scope_key: ScopeKey,
    pub lifecycle: Lifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_consumed: Option<u32>,
    pub imported_consumed: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_receipts: Option<u32>,
    pub imported_receipts: u32,
    pub explained: Vec<DifferenceCode>,
    pub unexplained: Vec<DifferenceCode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedScope {
    /// Position in the extract's `scopes`.
    pub index: u32,
    pub code: RefusalCode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Totals {
    pub scopes_in_extract: u32,
    pub imported: u32,
    pub refused: u32,
    pub consumed_units: u32,
    pub exhausted_scopes: u32,
    pub receipts: u32,
    pub contaminated_scopes: u32,
    pub ambiguous_scopes: u32,
}

/// The ADR 0003 handoff condition on the import itself: zero unexplained
/// differences. Refused scopes and unknown contamination also block, because
/// the import would silently drop or soften them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateStatus {
    pub unexplained_differences: u32,
    pub refused_scopes: u32,
    pub unknown_contamination: u32,
    pub ready_for_review: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DryRunReport {
    pub schema: String,
    pub extract_digest: DocumentDigest,
    pub totals: Totals,
    pub scopes: Vec<ScopeReport>,
    pub refused: Vec<RefusedScope>,
    pub gate: GateStatus,
    pub executed: Executed,
}

impl DryRunReport {
    /// Stable bytes of the report (struct field order, no maps).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Domain-separated digest of [`Self::to_bytes`]: what a handoff binds to.
    pub fn digest(&self) -> DocumentDigest {
        let mut h = Sha256::new();
        h.update(REPORT_DOMAIN.as_bytes());
        h.update([0u8]);
        h.update(self.to_bytes());
        DocumentDigest::from_raw(h.finalize().into())
    }

    /// A plain-text rendering for a human reviewer.
    pub fn render(&self) -> String {
        let t = &self.totals;
        let mut out = String::new();
        out.push_str("legacy import dry run (nothing executed)\n");
        out.push_str(&format!(
            "scopes {} imported {} refused {} consumed_units {} exhausted {} receipts {} contaminated {} ambiguous {}\n",
            t.scopes_in_extract,
            t.imported,
            t.refused,
            t.consumed_units,
            t.exhausted_scopes,
            t.receipts,
            t.contaminated_scopes,
            t.ambiguous_scopes
        ));
        for s in &self.scopes {
            out.push_str(&format!(
                "- {} consumed legacy={} imported={} receipts legacy={} imported={} explained={} unexplained={}\n",
                s.scope_key.as_str(),
                s.reported_consumed.map_or_else(|| "none".to_owned(), |n| n.to_string()),
                s.imported_consumed,
                s.reported_receipts.map_or_else(|| "none".to_owned(), |n| n.to_string()),
                s.imported_receipts,
                s.explained.len(),
                s.unexplained.len()
            ));
        }
        for r in &self.refused {
            out.push_str(&format!(
                "- scope #{} refused: {}\n",
                r.index,
                r.code.code()
            ));
        }
        out.push_str(&format!(
            "gate: unexplained={} refused={} unknown_contamination={} ready_for_review={}\n",
            self.gate.unexplained_differences,
            self.gate.refused_scopes,
            self.gate.unknown_contamination,
            self.gate.ready_for_review
        ));
        out
    }
}
