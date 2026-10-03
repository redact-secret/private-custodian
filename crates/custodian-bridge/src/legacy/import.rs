//! The deterministic legacy metadata import (ADR 0091).
//!
//! `dry_run` is a pure function of the extract bytes: no file is read, no
//! clock is consulted, no store is opened, no corpus is touched. The same
//! bytes give the same records, the same report and the same digests.
//!
//! Rules, in the order they bind (ADR 0003):
//!
//! 1. A spent attempt stays spent. Every attempt that is not positively
//!    shown to have been refused before any protected input was read counts
//!    as consumed, including any state the reviewer could not classify.
//! 2. A scope with no attempt, no reported count and no unspent attestation
//!    is ambiguous, so its whole budget counts as consumed. An unknown limit
//!    is an exhausted budget.
//! 3. If a reported count and the listed attempts disagree, the larger wins
//!    and the disagreement is an unexplained difference that blocks handoff.
//! 4. A contamination mark is carried forward. Unknown contamination is
//!    never clean.
//! 5. Independence is one of the three legacy values, verbatim, or the
//!    scope is refused. No value maps to "independent", and a claim of
//!    organizational independence is refused.
//! 6. A locator that looks like a local path, or names protected material,
//!    refuses the whole extract.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::canonical::to_canonical_bytes;
use custodian_contracts::common::{
    EvaluationDomain, IndependenceClaim, OrganisationalIndependence,
};
use custodian_contracts::public::ScopeKind;
use custodian_contracts::types::{ArtifactDigest, DocumentDigest, Timestamp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::model::*;
use super::report::{
    DifferenceCode, DryRunReport, GateStatus, RefusalCode, RefusedScope, ScopeReport, Totals,
};

pub const IMPORT_SCHEMA: &str = "private-custodian.legacy-import/1";
pub const IMPORT_DOMAIN: &str = "private-custodian/v1/legacy-import";
pub const EXTRACT_DOMAIN: &str = "private-custodian/v1/legacy-extract";

/// Why an extract as a whole was refused. Fieldless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExtractRefusal {
    /// Over the size bound.
    Oversized,
    /// Not valid JSON for the extract type: unknown field, bad label, a
    /// locator shaped like a local path or naming protected material, a
    /// number out of range, an unknown value.
    Malformed,
    /// A schema tag other than the one this importer reads.
    WrongSchema,
    /// More scopes, attempts or sources than the bounds allow.
    TooLarge,
}

impl ExtractRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::Oversized => "extract_oversized",
            Self::Malformed => "extract_malformed",
            Self::WrongSchema => "extract_wrong_schema",
            Self::TooLarge => "extract_too_large",
        }
    }
}

impl core::fmt::Display for ExtractRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ExtractRefusal {}

/// Stable identity of an import record: `lgi_` plus 32 hex characters of the
/// domain-separated digest of its facts (the body without provenance).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImportId(String);

impl ImportId {
    pub fn parse(s: &str) -> Result<Self, InvalidFormat> {
        let ok = s.len() == 36
            && s.starts_with("lgi_")
            && s[4..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidFormat)
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ImportId {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).map_err(|_| "import_id")
    }
}
impl From<ImportId> for String {
    fn from(i: ImportId) -> String {
        i.0
    }
}

/// Deterministic text key of a legacy scope.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ScopeKey(String);

impl ScopeKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn of(lifecycle: Lifecycle, domain: EvaluationDomain, scope: &ScopeSpec) -> Self {
        let l = match lifecycle {
            Lifecycle::Holdout => "holdout",
            Lifecycle::PiiProtected => "pii-protected",
            Lifecycle::Blind => "blind",
        };
        let d = match domain {
            EvaluationDomain::Credential => "credential",
            EvaluationDomain::Pii => "pii",
        };
        let s = match scope {
            ScopeSpec::PopulationEpoch {
                population,
                epoch,
                family,
            } => format!(
                "pop={}/epoch={}/family={}",
                population.as_str(),
                epoch.as_str(),
                family.as_ref().map_or("-", Label::as_str)
            ),
            ScopeSpec::CandidateEpoch { candidate, epoch } => {
                format!("cand={}/epoch={}", candidate.as_str(), epoch.as_str())
            }
        };
        Self(format!("{l}|{d}|{s}"))
    }
}

impl TryFrom<String> for ScopeKey {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty()
            || s.len() > 600
            || !s
                .bytes()
                .all(|b| (0x21..=0x7e).contains(&b) && b != b'"' && b != b'\\')
        {
            return Err("scope_key");
        }
        Ok(Self(s))
    }
}
impl From<ScopeKey> for String {
    fn from(k: ScopeKey) -> String {
        k.0
    }
}

/// Why a unit of budget was counted the way it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumptionBasis {
    /// From the listed attempts.
    Attempts,
    /// From a reported legacy count, larger than or equal to the attempts.
    ReportedCount,
    /// A cited unspent attestation and nothing contradicting it.
    UnspentAttested,
    /// No evidence either way: the whole budget counts as consumed.
    NoEvidenceAssumedConsumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedBudget {
    /// Which custodian budget semantics this maps to. Never merged.
    pub scope_kind: ScopeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    pub consumed: u32,
    pub remaining: u32,
    pub exhausted: bool,
    pub basis: ConsumptionBasis,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedAttempt {
    pub run: Label,
    pub legacy_state: LegacyAttemptState,
    /// Whether the attempt counts as a consumed unit.
    pub counted: bool,
}

/// The legacy independence statement, preserved. The claim keeps its legacy
/// spelling; organizational independence has one representable value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedIndependence {
    pub claim: IndependenceClaim,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organisational_independence: Option<OrganisationalIndependence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<Label>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_sha256: Option<ArtifactDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "standing", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContaminationStanding {
    /// Marked in the legacy lifecycle. Stays contaminated.
    Contaminated { reason: Label },
    /// A reviewer states no mark was recorded.
    NoneRecorded {},
    /// Not determinable. Never clean; blocks handoff until reviewed.
    Unknown {},
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ambiguity {
    /// No attempt, count or attestation: whole budget counted as consumed.
    NoSpendEvidence,
    /// The limit is not stated: treated as exhausted.
    LimitUnknown,
    /// An attempt in a state the reviewer could not classify.
    UnknownAttemptState,
    /// A refusal-before-exposure was claimed without a supporting source.
    RefusalUnsupported,
    /// A cited attestation says unspent while an attempt or count says spent.
    AttestationContradicted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportProvenance {
    pub extracted_at: Timestamp,
    pub review: ReviewStatement,
    /// Domain-separated digest of the extract bytes this came from.
    pub extract_digest: DocumentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportBody {
    pub scope_key: ScopeKey,
    pub lifecycle: Lifecycle,
    pub domain: EvaluationDomain,
    pub scope: ScopeSpec,
    pub budget: ImportedBudget,
    pub attempts: Vec<ImportedAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence: Option<ImportedIndependence>,
    pub contamination: ContaminationStanding,
    pub receipt_count: u32,
    pub ambiguities: Vec<Ambiguity>,
    pub sources: Vec<ExtractSource>,
    pub provenance: ImportProvenance,
}

/// One immutable import record. Never edited; a later import that adds
/// information is a new record that supersedes it in a store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyImportRecord {
    pub schema: String,
    pub import_id: ImportId,
    pub body: ImportBody,
}

impl LegacyImportRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExtractRefusal> {
        to_canonical_bytes(self).map_err(|_| ExtractRefusal::TooLarge)
    }
}

/// The result of a dry run: the records that would be imported and the
/// report. Nothing was written anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DryRun {
    pub records: Vec<LegacyImportRecord>,
    pub report: DryRunReport,
}

fn digest_with(domain: &str, bytes: &[u8]) -> DocumentDigest {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0u8]);
    h.update(bytes);
    DocumentDigest::from_raw(h.finalize().into())
}

/// Digest of the extract bytes, as recorded in provenance.
pub fn extract_digest(bytes: &[u8]) -> DocumentDigest {
    digest_with(EXTRACT_DOMAIN, bytes)
}

/// Parse an extract strictly.
pub fn decode_extract(bytes: &[u8]) -> Result<LegacyExtract, ExtractRefusal> {
    if bytes.len() > MAX_EXTRACT_BYTES {
        return Err(ExtractRefusal::Oversized);
    }
    let ex: LegacyExtract = serde_json::from_slice(bytes).map_err(|_| ExtractRefusal::Malformed)?;
    if ex.schema != EXTRACT_SCHEMA {
        return Err(ExtractRefusal::WrongSchema);
    }
    if ex.scopes.len() > MAX_SCOPES
        || ex.scopes.iter().any(|s| {
            s.attempts.len() > MAX_ATTEMPTS_PER_SCOPE || s.sources.len() > MAX_SOURCES_PER_SCOPE
        })
    {
        return Err(ExtractRefusal::TooLarge);
    }
    Ok(ex)
}

/// Compute the records and the report for an extract. Whole-extract problems
/// are an `Err`; a problem with one scope refuses that scope and is listed in
/// the report, and the scope is not imported.
pub fn dry_run(extract_bytes: &[u8]) -> Result<DryRun, ExtractRefusal> {
    let ex = decode_extract(extract_bytes)?;
    let digest = extract_digest(extract_bytes);

    // Duplicate scope keys refuse every scope that shares one: two
    // statements about the same budget cannot both be right.
    let keys: Vec<ScopeKey> = ex
        .scopes
        .iter()
        .map(|s| ScopeKey::of(s.lifecycle, s.domain, &s.scope))
        .collect();
    let mut count: BTreeMap<&ScopeKey, u32> = BTreeMap::new();
    for k in &keys {
        *count.entry(k).or_default() += 1;
    }

    let mut records = Vec::new();
    let mut scope_reports = Vec::new();
    let mut refused = Vec::new();
    for (i, (scope, key)) in ex.scopes.iter().zip(keys.iter()).enumerate() {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        if count.get(key).copied().unwrap_or(0) > 1 {
            refused.push(RefusedScope {
                index,
                code: RefusalCode::DuplicateScope,
            });
            continue;
        }
        match import_scope(scope, key, &ex, &digest) {
            Ok((record, report)) => {
                records.push(record);
                scope_reports.push(report);
            }
            Err(code) => refused.push(RefusedScope { index, code }),
        }
    }
    // Deterministic order, independent of input order.
    records.sort_by(|a, b| a.body.scope_key.cmp(&b.body.scope_key));
    scope_reports.sort_by(|a, b| a.scope_key.cmp(&b.scope_key));

    let unexplained: u32 = scope_reports
        .iter()
        .map(|r| u32::try_from(r.unexplained.len()).unwrap_or(u32::MAX))
        .sum();
    let unknown_contamination = u32::try_from(
        records
            .iter()
            .filter(|r| r.body.contamination == ContaminationStanding::Unknown {})
            .count(),
    )
    .unwrap_or(u32::MAX);
    let refused_count = u32::try_from(refused.len()).unwrap_or(u32::MAX);
    let totals = Totals {
        scopes_in_extract: u32::try_from(ex.scopes.len()).unwrap_or(u32::MAX),
        imported: u32::try_from(records.len()).unwrap_or(u32::MAX),
        refused: refused_count,
        consumed_units: records.iter().map(|r| r.body.budget.consumed).sum(),
        exhausted_scopes: u32::try_from(records.iter().filter(|r| r.body.budget.exhausted).count())
            .unwrap_or(u32::MAX),
        receipts: records.iter().map(|r| r.body.receipt_count).sum(),
        contaminated_scopes: u32::try_from(
            records
                .iter()
                .filter(|r| {
                    matches!(
                        r.body.contamination,
                        ContaminationStanding::Contaminated { .. }
                    )
                })
                .count(),
        )
        .unwrap_or(u32::MAX),
        ambiguous_scopes: u32::try_from(
            records
                .iter()
                .filter(|r| !r.body.ambiguities.is_empty())
                .count(),
        )
        .unwrap_or(u32::MAX),
    };
    let ready = unexplained == 0 && refused_count == 0 && unknown_contamination == 0;
    let report = DryRunReport {
        schema: super::report::REPORT_SCHEMA.to_owned(),
        extract_digest: digest,
        totals,
        scopes: scope_reports,
        refused,
        gate: GateStatus {
            unexplained_differences: unexplained,
            refused_scopes: refused_count,
            unknown_contamination,
            ready_for_review: ready,
        },
        executed: super::report::Executed::Nothing,
    };
    Ok(DryRun { records, report })
}

fn import_scope(
    s: &ExtractScope,
    key: &ScopeKey,
    ex: &LegacyExtract,
    extract_digest: &DocumentDigest,
) -> Result<(LegacyImportRecord, ScopeReport), RefusalCode> {
    // Scope shape must match the lifecycle's budget semantics.
    let scope_kind = match (&s.scope, s.lifecycle) {
        (ScopeSpec::PopulationEpoch { .. }, Lifecycle::Holdout | Lifecycle::PiiProtected) => {
            ScopeKind::PopulationEpoch
        }
        (ScopeSpec::CandidateEpoch { .. }, Lifecycle::Blind) => ScopeKind::CandidateLineageEpoch,
        _ => return Err(RefusalCode::ScopeMismatch),
    };
    if s.declared_limit == Some(0) {
        return Err(RefusalCode::LimitInvalid);
    }

    // Sources: digests required except for reviewed statements, which are
    // logical labels only.
    for src in &s.sources {
        match (src.kind, &src.sha256) {
            (SourceKind::CustodianStatement, Some(_)) => return Err(RefusalCode::SourceInvalid),
            (SourceKind::CustodianStatement, None) if !src.locator.is_logical_label() => {
                return Err(RefusalCode::SourceInvalid)
            }
            (SourceKind::CustodianStatement, None) => {}
            (_, None) => return Err(RefusalCode::SourceInvalid),
            (_, Some(_)) => {}
        }
    }
    let nsrc = s.sources.len();
    let valid_ref = |i: u32| usize::try_from(i).is_ok_and(|i| i < nsrc);
    if s.attempts
        .iter()
        .any(|a| a.source.is_some_and(|i| !valid_ref(i)))
    {
        return Err(RefusalCode::SourceInvalid);
    }

    // Independence: legacy vocabulary only.
    let independence = match &s.independence {
        None => None,
        Some(i) => {
            let claim: IndependenceClaim =
                serde_json::from_value(serde_json::Value::String(i.claim.clone()))
                    .map_err(|_| RefusalCode::IndependenceUnrepresentable)?;
            if i.organisational_independence_claimed == Some(true) {
                return Err(RefusalCode::OrganisationalIndependenceClaimed);
            }
            Some(ImportedIndependence {
                claim,
                organisational_independence: i
                    .organisational_independence_claimed
                    .map(|_| OrganisationalIndependence::NotClaimed),
                evidence_class: i.evidence_class.clone(),
                statement_sha256: i.statement_sha256.clone(),
            })
        }
    };

    let contamination = match &s.contamination {
        ExtractContamination::Marked { reason, source } => {
            if !valid_ref(*source) {
                return Err(RefusalCode::SourceInvalid);
            }
            ContaminationStanding::Contaminated {
                reason: reason.clone(),
            }
        }
        ExtractContamination::NoneRecorded { source } => {
            if !valid_ref(*source) {
                return Err(RefusalCode::SourceInvalid);
            }
            ContaminationStanding::NoneRecorded {}
        }
        ExtractContamination::Unknown {} => ContaminationStanding::Unknown {},
    };

    // Attempts. Spent unless positively shown not to have been.
    let mut ambiguities = BTreeSet::new();
    let mut attempts = Vec::new();
    for a in &s.attempts {
        let counted = match a.state {
            LegacyAttemptState::RefusedBeforeExposure => {
                if a.source.is_some() {
                    false
                } else {
                    ambiguities.insert(Ambiguity::RefusalUnsupported);
                    true
                }
            }
            LegacyAttemptState::Unknown => {
                ambiguities.insert(Ambiguity::UnknownAttemptState);
                true
            }
            _ => true,
        };
        attempts.push(ImportedAttempt {
            run: a.run.clone(),
            legacy_state: a.state,
            counted,
        });
    }
    attempts.sort_by(|a, b| a.run.cmp(&b.run));
    let counted_attempts = u32::try_from(attempts.iter().filter(|a| a.counted).count())
        .map_err(|_| RefusalCode::LimitInvalid)?;
    let attested_unspent = s
        .sources
        .iter()
        .any(|x| x.kind == SourceKind::UnspentAttestation);

    let mut explained = Vec::new();
    let mut unexplained = Vec::new();
    let consumed;
    let basis;
    if attempts.is_empty() && s.reported_consumed.is_none() {
        if attested_unspent {
            consumed = 0;
            basis = ConsumptionBasis::UnspentAttested;
        } else {
            // Ambiguous: the whole budget is treated as consumed.
            consumed = s.declared_limit.unwrap_or(0);
            basis = ConsumptionBasis::NoEvidenceAssumedConsumed;
            ambiguities.insert(Ambiguity::NoSpendEvidence);
            explained.push(DifferenceCode::ConservativeAmbiguity);
        }
    } else {
        match s.reported_consumed {
            Some(r) if r > counted_attempts => {
                consumed = r;
                basis = ConsumptionBasis::ReportedCount;
                if !attempts.is_empty() {
                    unexplained.push(DifferenceCode::ReportedCountDisagrees);
                }
            }
            Some(r) if r < counted_attempts => {
                consumed = counted_attempts;
                basis = ConsumptionBasis::Attempts;
                unexplained.push(DifferenceCode::ReportedCountDisagrees);
            }
            _ => {
                consumed = counted_attempts;
                basis = ConsumptionBasis::Attempts;
            }
        }
        if attested_unspent && consumed > 0 {
            ambiguities.insert(Ambiguity::AttestationContradicted);
            unexplained.push(DifferenceCode::AttestationContradictsSpend);
        }
    }
    if s.declared_limit.is_none() {
        ambiguities.insert(Ambiguity::LimitUnknown);
        explained.push(DifferenceCode::ConservativeAmbiguity);
    }
    let limit = s.declared_limit;
    // An unknown limit is an exhausted budget; a spent budget never goes
    // back below its limit.
    let remaining = limit.map_or(0, |l| l.saturating_sub(consumed));
    let exhausted = limit.is_none_or(|l| consumed >= l);
    if exhausted && limit.is_some() && consumed > limit.unwrap_or(0) {
        explained.push(DifferenceCode::ConsumedAboveLimit);
    }

    // Receipts.
    let receipt_count = u32::try_from(s.sources.iter().filter(|x| x.kind.is_receipt()).count())
        .map_err(|_| RefusalCode::SourceInvalid)?;
    if s.reported_receipts.is_some_and(|r| r != receipt_count) {
        unexplained.push(DifferenceCode::ReceiptCountDisagrees);
    }

    let mut sources = s.sources.clone();
    sources.sort();
    sources.dedup();

    let body = ImportBody {
        scope_key: key.clone(),
        lifecycle: s.lifecycle,
        domain: s.domain,
        scope: s.scope.clone(),
        budget: ImportedBudget {
            scope_kind,
            limit,
            consumed,
            remaining,
            exhausted,
            basis,
        },
        attempts,
        independence,
        contamination,
        receipt_count,
        ambiguities: ambiguities.into_iter().collect(),
        sources,
        provenance: ImportProvenance {
            extracted_at: ex.extracted_at,
            review: ex.review.clone(),
            extract_digest: extract_digest.clone(),
        },
    };
    // Identity is the facts: the same facts re-imported from a re-read or
    // re-reviewed extract are the same record, not a new one. Provenance
    // travels with the record but is not part of its identity.
    let mut facts = serde_json::to_value(&body).map_err(|_| RefusalCode::TooLarge)?;
    if let Some(o) = facts.as_object_mut() {
        o.remove("provenance");
    }
    let body_bytes = to_canonical_bytes(&facts).map_err(|_| RefusalCode::TooLarge)?;
    let id_digest = digest_with(IMPORT_DOMAIN, &body_bytes);
    let import_id = ImportId::parse(&format!("lgi_{}", &id_digest.as_str()[7..39]))
        .map_err(|_| RefusalCode::TooLarge)?;
    let record = LegacyImportRecord {
        schema: IMPORT_SCHEMA.to_owned(),
        import_id,
        body,
    };
    // The whole record must itself be canonical and bounded.
    record
        .canonical_bytes()
        .map_err(|_| RefusalCode::TooLarge)?;

    explained.sort();
    explained.dedup();
    unexplained.sort();
    unexplained.dedup();
    let report = ScopeReport {
        scope_key: key.clone(),
        lifecycle: s.lifecycle,
        reported_consumed: s.reported_consumed,
        imported_consumed: record.body.budget.consumed,
        reported_receipts: s.reported_receipts,
        imported_receipts: receipt_count,
        explained,
        unexplained,
    };
    Ok((record, report))
}
