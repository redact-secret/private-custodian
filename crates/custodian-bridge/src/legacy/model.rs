//! The reviewed legacy metadata extract (input) and its vocabulary.
//!
//! An extract is a document a maintainer prepares from the public, committed
//! metadata of the existing protected lifecycles (manifests, seals,
//! aggregates, receipts, resolutions, unspent attestations, blind aggregates)
//! plus reviewed statements about state the legacy runner keeps privately
//! (for example how many runs its protected state recorded). It carries
//! counts, labels, digests of the public files and dates. It never carries a
//! corpus, a seed, a fixture, a run input or a private path, and the importer
//! rejects anything shaped like one.
//!
//! The vocabulary below follows the legacy records so a reviewer can compare
//! them one to one; no value is renamed or reinterpreted.

use custodian_contracts::common::EvaluationDomain;
use custodian_contracts::types::{ArtifactDigest, Timestamp};
use serde::{Deserialize, Serialize};

/// Schema tag of the extract.
pub const EXTRACT_SCHEMA: &str = "private-custodian.legacy-extract/1";
/// Largest extract accepted, in bytes.
pub const MAX_EXTRACT_BYTES: usize = 1_048_576;
pub const MAX_SCOPES: usize = 256;
pub const MAX_ATTEMPTS_PER_SCOPE: usize = 64;
pub const MAX_SOURCES_PER_SCOPE: usize = 64;

/// A value did not have the required shape. Fieldless: the value is never
/// echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFormat;

fn is_label_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'+' | b'-')
}

/// A bounded printable label: `[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}`. No slash,
/// no space, no quote: it cannot be a path, a command or free text.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Label(String);

impl Label {
    pub fn parse(s: &str) -> Result<Self, InvalidFormat> {
        let ok = !s.is_empty()
            && s.len() <= 128
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes().all(is_label_byte);
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

impl TryFrom<String> for Label {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).map_err(|_| "label")
    }
}

impl From<Label> for String {
    fn from(l: Label) -> String {
        l.0
    }
}

/// Segments that name protected or private legacy material. A locator that
/// contains one is refused even when it is otherwise a clean relative path.
const PROTECTED_SEGMENTS: &[&str] = &[
    "generated",
    "private",
    "corpus.json",
    "fixtures.json",
    "state.json",
    "ledger.json",
    "archive",
    "runs",
    "seed",
    "seeds",
    "secrets",
    ".lock",
];

/// A repository-relative locator of a public metadata file, or a one-segment
/// logical label for a reviewed statement. Never absolute, never `..`, never
/// a home or drive path, never a protected segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Locator(String);

/// Why a locator was refused. Fieldless: the value is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocatorRefusal {
    Shape,
    PathLike,
    Protected,
}

impl Locator {
    pub fn parse(s: &str) -> Result<Self, LocatorRefusal> {
        if s.is_empty() || s.len() > 200 {
            return Err(LocatorRefusal::Shape);
        }
        // Anything that could be an absolute, home-relative, drive or
        // traversal path is a local-path leak, whatever else it contains.
        if s.starts_with('/')
            || s.starts_with('~')
            || s.starts_with('\\')
            || s.contains('\\')
            || s.contains("..")
            || s.as_bytes().get(1) == Some(&b':')
        {
            return Err(LocatorRefusal::PathLike);
        }
        let mut segments = 0;
        for seg in s.split('/') {
            segments += 1;
            if seg.is_empty() || seg == "." || !seg.bytes().all(|b| is_label_byte(b) && b != b':') {
                return Err(LocatorRefusal::Shape);
            }
            if PROTECTED_SEGMENTS.contains(&seg.to_ascii_lowercase().as_str()) {
                return Err(LocatorRefusal::Protected);
            }
        }
        if segments > 12 {
            return Err(LocatorRefusal::Shape);
        }
        Ok(Self(s.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn is_logical_label(&self) -> bool {
        !self.0.contains('/')
    }
}

impl TryFrom<String> for Locator {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).map_err(|_| "locator")
    }
}

impl From<Locator> for String {
    fn from(l: Locator) -> String {
        l.0
    }
}

/// Which legacy lifecycle a scope belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Lifecycle {
    /// In-repo holdout (credential, credential-policy, PII conformance and
    /// protected manifests).
    #[serde(rename = "holdout")]
    Holdout,
    /// The six-family PII protected corpus.
    #[serde(rename = "pii-protected")]
    PiiProtected,
    /// Custodian-held blind evaluation.
    #[serde(rename = "blind")]
    Blind,
}

/// The two legacy budget scopes, kept distinct (ADR 0003).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeSpec {
    /// Holdout and PII: attempts per population (and family) epoch.
    PopulationEpoch {
        population: Label,
        epoch: Label,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        family: Option<Label>,
    },
    /// Blind: attempts per candidate identity per epoch.
    CandidateEpoch { candidate: Label, epoch: Label },
}

/// What the legacy record says happened to one attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyAttemptState {
    /// Blind `reserved`, or a holdout run recorded in `runs` without an
    /// outcome: spent at reservation.
    Reserved,
    Complete,
    Incomplete,
    Failed,
    /// PII flow only: refused because public gates were unmet, before any
    /// protected input was read. Not spent, and only on cited evidence.
    RefusedBeforeExposure,
    /// A state the reviewer cannot classify. Counts as consumed.
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractAttempt {
    /// The legacy run identity (an opaque run id).
    pub run: Label,
    pub state: LegacyAttemptState,
    /// Index into the scope's `sources` that supports this attempt's state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SourceKind {
    #[serde(rename = "manifest")]
    Manifest,
    #[serde(rename = "seal")]
    Seal,
    /// A holdout or PII aggregate (a receipt).
    #[serde(rename = "aggregate")]
    Aggregate,
    /// A credential-policy holdout receipt (a receipt).
    #[serde(rename = "policy-receipt")]
    PolicyReceipt,
    /// A released blind aggregate (a receipt).
    #[serde(rename = "blind-aggregate")]
    BlindAggregate,
    #[serde(rename = "trust-resolution")]
    TrustResolution,
    #[serde(rename = "disposition")]
    Disposition,
    /// A committed attestation that an epoch is unspent.
    #[serde(rename = "unspent-attestation")]
    UnspentAttestation,
    /// A blind carry-over record. Evidence only; it consumes nothing here.
    #[serde(rename = "carry-over")]
    CarryOver,
    /// A reviewed statement about state the legacy runner keeps privately.
    /// Has no digest and no path: the private file is not read.
    #[serde(rename = "custodian-statement")]
    CustodianStatement,
}

impl SourceKind {
    /// Whether a source of this kind is a legacy receipt for the
    /// receipt-count comparison.
    pub fn is_receipt(self) -> bool {
        matches!(
            self,
            Self::Aggregate | Self::PolicyReceipt | Self::BlindAggregate
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractSource {
    pub kind: SourceKind,
    pub locator: Locator,
    /// SHA-256 of the public metadata file's bytes. Required for every kind
    /// except `custodian-statement`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<ArtifactDigest>,
    pub observed_at: Timestamp,
    /// Source repository revision the file was read at, as a label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<Label>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractIndependence {
    /// The legacy value, verbatim: `public-control`, `custodian-declared` or
    /// `procedural-separation`. Anything else is refused.
    pub claim: String,
    /// The legacy `organisationalIndependence` flag where the record has one.
    /// Only `false` is representable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organisational_independence_claimed: Option<bool>,
    /// The legacy `evidenceClass` (for example `custodian-blind`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_class: Option<Label>,
    /// SHA-256 of the original statement text, kept in the cited source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_sha256: Option<ArtifactDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtractContamination {
    /// A legacy mark (`exposed`, `used-for-tuning`, `unreviewed-change`, or a
    /// retirement for disclosure or rotation).
    Marked { reason: Label, source: u32 },
    /// A reviewer states the legacy runner recorded no mark.
    NoneRecorded { source: u32 },
    /// Not determinable from metadata (blind contamination is procedural and
    /// has no machine-readable field). Never treated as clean.
    Unknown {},
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractScope {
    pub lifecycle: Lifecycle,
    pub domain: EvaluationDomain,
    pub scope: ScopeSpec,
    /// The legacy limit (`maxRuns`, or one per candidate per epoch for blind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_limit: Option<u32>,
    pub attempts: Vec<ExtractAttempt>,
    /// The legacy summary count of consumed attempts, where one exists (for
    /// example `runs: "1/1"` in a resolution, or the length of the legacy
    /// state's run list as reviewed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_consumed: Option<u32>,
    /// The legacy count of receipts for this scope, where one is stated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_receipts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub independence: Option<ExtractIndependence>,
    pub contamination: ExtractContamination,
    pub sources: Vec<ExtractSource>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStatement {
    /// A role label such as `maintainer`; never a personal name or contact.
    pub reviewer_role: Label,
    /// A reference to the recorded review (a pull request or a document),
    /// as a label.
    pub review_ref: Label,
    pub reviewed_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyExtract {
    pub schema: String,
    /// When the extract was read from the public metadata (observed-at).
    pub extracted_at: Timestamp,
    pub review: ReviewStatement,
    pub scopes: Vec<ExtractScope>,
}
