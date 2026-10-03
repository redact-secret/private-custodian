//! Ledger record layout (ADR 0051).
//!
//! A ledger record is a closed, bounded, canonical document. It carries
//! identities, digests, counters and fixed vocabulary only: no corpus, no
//! secrets, no raw fields, no worker text, no database contents. Record ids
//! are deterministic functions of the record's natural key, so a retry of the
//! same logical record always targets the same path. A correction is a new
//! record that names the one it supersedes; nothing is ever edited.

use custodian_contracts::canonical::{to_canonical_bytes, MAX_DOCUMENT_BYTES};
use custodian_contracts::common::{ActivationRef, ActorKind, PolicyKind, PolicyRef, Signature};
use custodian_contracts::types::{
    ActorRef, ApprovalId, DestinationId, DocumentDigest, ExecutionId, KeyId, ProjectionDigest,
    ProjectionId, ReceiptId, Timestamp, MAX_SAFE_INT,
};
use custodian_store::{Checkpoint, OutboxEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::b64::hex;
use crate::domain::SignDomain;

pub const LEDGER_SCHEMA: &str = "private-custodian.ledger-record/1";

const MAX_PAYLOAD_ENTRIES: usize = 32;
const MAX_VALUE_LEN: usize = 128;
const MAX_PURPOSES: usize = 16;

/// Fixed-vocabulary record errors. None carries input text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordError {
    Oversized,
    Malformed,
    /// The `schema` tag is not the one this build understands.
    SchemaMismatch,
    FieldRejected,
    NonCanonical,
    /// Cross-field or identity-derivation check failed.
    Inconsistent,
    /// An outbox payload contains a key, value or shape outside the export
    /// allowlist. Nothing is repaired or truncated.
    PayloadNotExportable,
    /// The outbox event does not match its own recorded digest.
    EventInconsistent,
}

impl RecordError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Oversized => "record_oversized",
            Self::Malformed => "record_malformed",
            Self::SchemaMismatch => "record_schema_mismatch",
            Self::FieldRejected => "record_field_rejected",
            Self::NonCanonical => "record_non_canonical",
            Self::Inconsistent => "record_inconsistent",
            Self::PayloadNotExportable => "record_payload_not_exportable",
            Self::EventInconsistent => "record_event_inconsistent",
        }
    }
}

impl core::fmt::Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RecordError {}

/// Keys an exported outbox payload may contain. Every value must be a bounded
/// integer or a bounded identifier-shaped string. Unknown keys are refused,
/// never dropped, so a new store field cannot leak by accident.
pub const PAYLOAD_KEY_ALLOWLIST: &[&str] = &[
    "event",
    "at",
    "request_id",
    "attempt_id",
    "attempt_no",
    "reservation_id",
    "approval_id",
    "plan_digest",
    "scope_key",
    "kind",
    "units",
    "limit",
    "previous_limit",
    "state",
    "prior_state",
    "outcome",
    "reason",
    "exposure",
    "settlement",
    "actor",
    "authorization_ref",
    "lease_token",
    // C9 (ADR 0073): epoch standing and revocation feed events.
    "actor_kind",
    "retired",
    "target_kind",
    "successor_epoch",
    "feed_sequence",
    "document_digest",
    "destination",
];

fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_VALUE_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

// --- Record kinds -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RecordKind {
    AuditEvent,
    StoreCheckpoint,
    RegistryCheckpoint,
    Policy,
    Publication,
    Reconciliation,
    KeyEvent,
}

impl RecordKind {
    pub const ALL: [RecordKind; 7] = [
        Self::AuditEvent,
        Self::StoreCheckpoint,
        Self::RegistryCheckpoint,
        Self::Policy,
        Self::Publication,
        Self::Reconciliation,
        Self::KeyEvent,
    ];

    /// Directory name and id infix.
    pub fn dir(self) -> &'static str {
        match self {
            Self::AuditEvent => "audit",
            Self::StoreCheckpoint => "store-checkpoint",
            Self::RegistryCheckpoint => "registry-checkpoint",
            Self::Policy => "policy",
            Self::Publication => "publication",
            Self::Reconciliation => "reconciliation",
            Self::KeyEvent => "key-event",
        }
    }

    pub fn domain(self) -> SignDomain {
        match self {
            Self::AuditEvent => SignDomain::LedgerAuditEvent,
            Self::StoreCheckpoint => SignDomain::LedgerStoreCheckpoint,
            Self::RegistryCheckpoint => SignDomain::LedgerRegistryCheckpoint,
            Self::Policy => SignDomain::LedgerPolicy,
            Self::Publication => SignDomain::LedgerPublication,
            Self::Reconciliation => SignDomain::LedgerReconciliation,
            Self::KeyEvent => SignDomain::LedgerKeyEvent,
        }
    }

    /// Kind of a well-formed record id (`rec-<dir>-<32 hex>`), if any.
    pub fn of_id(id: &str) -> Option<Self> {
        let rest = id.strip_prefix("rec-")?;
        Self::ALL.into_iter().find(|k| {
            rest.strip_prefix(k.dir())
                .and_then(|r| r.strip_prefix('-'))
                .is_some_and(|h| {
                    h.len() == 32 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                })
        })
    }
}

fn derive_id(kind: RecordKind, natural: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/v1/ledger/id\0");
    h.update(kind.dir().as_bytes());
    for part in natural {
        h.update([0]);
        h.update(part.as_bytes());
    }
    format!("rec-{}-{}", kind.dir(), hex(&h.finalize()[..16]))
}

// --- Bodies -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEventBody {
    /// Outbox sequence number.
    pub seq: u64,
    /// Deterministic store event id (`terminal:<attempt>`, ...). The
    /// idempotency key of the export.
    pub event_id: String,
    pub kind: String,
    /// Outbox chain value at `seq` (64 lowercase hex).
    pub chain: String,
    /// SHA-256 of the store's payload text (64 lowercase hex).
    pub payload_digest: String,
    /// True when `payload_digest` is also the SHA-256 of this record's
    /// canonical `payload`. False when null members of the store payload were
    /// omitted (canonical JSON has no null).
    pub payload_exact: bool,
    /// Allowlisted keys with integer or identifier-shaped string values.
    pub payload: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCheckpointBody {
    pub seq: u64,
    pub chain: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryCheckpointBody {
    /// Corpus registry head digest (`custodian-corpus` `RegistryView::head`).
    pub head: DocumentDigest,
    /// Number of registry events the head covers.
    pub event_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBody {
    pub activation: ActivationRef,
    /// Domain-separated digest of the reviewed policy document.
    pub document_digest: DocumentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationBody {
    pub projection_id: ProjectionId,
    pub receipt_id: ReceiptId,
    pub projection_digest: ProjectionDigest,
    /// Key that signed the published projection.
    pub signature_key_id: KeyId,
    /// The publication decision (C8, ADR 0063): where, under which disclosure
    /// policy, by whose release approval. Optional so records written before
    /// C8 keep their bytes and ids; every C8 release writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<PublicationDecision>,
}

/// Who authorized releasing this projection, to which destination, under
/// which disclosure policy. Written to the ledger before any signed bytes
/// leave the private boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationDecision {
    pub destination: DestinationId,
    pub disclosure_policy: PolicyRef,
    pub execution_id: ExecutionId,
    pub approval_id: ApprovalId,
    pub approver: ActorRef,
    pub approver_kind: ActorKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileOutcome {
    Consistent,
    Repaired,
    Divergent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationBody {
    pub outcome: ReconcileOutcome,
    pub store_events: u64,
    pub ledger_records: u64,
    pub missing_in_ledger: u64,
    pub unacked_in_ledger: u64,
    pub conflicting: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAction {
    Published,
    Retired,
    Revoked,
}

impl KeyAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEventBody {
    pub key_id: KeyId,
    pub action: KeyAction,
    /// Ed25519 public key, 64 lowercase hex. Present exactly for `published`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Domains the key may sign. Non-empty exactly for `published`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purposes: Vec<SignDomain>,
    /// `published`: first instant the key may sign. `retired`: no signature
    /// issued at or after this time is valid. `revoked`: informational; every
    /// signature by the key is rejected.
    pub effective_at: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordBody {
    AuditEvent(AuditEventBody),
    StoreCheckpoint(StoreCheckpointBody),
    RegistryCheckpoint(RegistryCheckpointBody),
    Policy(PolicyBody),
    Publication(PublicationBody),
    Reconciliation(ReconciliationBody),
    KeyEvent(KeyEventBody),
}

impl RecordBody {
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::AuditEvent(_) => RecordKind::AuditEvent,
            Self::StoreCheckpoint(_) => RecordKind::StoreCheckpoint,
            Self::RegistryCheckpoint(_) => RecordKind::RegistryCheckpoint,
            Self::Policy(_) => RecordKind::Policy,
            Self::Publication(_) => RecordKind::Publication,
            Self::Reconciliation(_) => RecordKind::Reconciliation,
            Self::KeyEvent(_) => RecordKind::KeyEvent,
        }
    }
}

// --- Record -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    pub schema: String,
    pub record_id: String,
    /// Deterministic per record: the event's creation time for audit events,
    /// the observation time passed by the caller for checkpoints. Never the
    /// time of the export attempt, so a retry produces identical bytes.
    pub issued_at: Timestamp,
    /// The record this one corrects. Absent for first records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    pub body: RecordBody,
}

fn ts(secs: u64) -> Result<Timestamp, RecordError> {
    Timestamp::new(secs).map_err(|_| RecordError::FieldRejected)
}

impl LedgerRecord {
    fn build(issued_at: u64, body: RecordBody) -> Result<Self, RecordError> {
        let mut r = Self {
            schema: LEDGER_SCHEMA.to_owned(),
            record_id: String::new(),
            issued_at: ts(issued_at)?,
            supersedes: None,
            body,
        };
        r.record_id = r.expected_id()?;
        r.validate()?;
        Ok(r)
    }

    /// Record the export of one outbox event. `issued_at` is the event's own
    /// creation time.
    pub fn audit_event(event: &OutboxEvent) -> Result<Self, RecordError> {
        // The store must agree with its own digest before anything is signed.
        if sha_hex(event.payload.as_bytes()) != event.payload_digest {
            return Err(RecordError::EventInconsistent);
        }
        let parsed: Value =
            serde_json::from_str(&event.payload).map_err(|_| RecordError::PayloadNotExportable)?;
        let Value::Object(mut payload) = parsed else {
            return Err(RecordError::PayloadNotExportable);
        };
        payload.retain(|_, v| !v.is_null());
        check_payload(&payload)?;
        let canonical = to_canonical_bytes(&payload).map_err(|_| RecordError::NonCanonical)?;
        let exact = sha_hex(&canonical) == event.payload_digest;
        Self::build(
            event.created_at,
            RecordBody::AuditEvent(AuditEventBody {
                seq: event.seq,
                event_id: event.event_id.clone(),
                kind: event.kind.clone(),
                chain: event.chain.clone(),
                payload_digest: event.payload_digest.clone(),
                payload_exact: exact,
                payload,
            }),
        )
    }

    pub fn store_checkpoint(cp: &Checkpoint, observed_at: u64) -> Result<Self, RecordError> {
        Self::build(
            observed_at,
            RecordBody::StoreCheckpoint(StoreCheckpointBody {
                seq: cp.seq,
                chain: cp.chain.clone(),
            }),
        )
    }

    pub fn registry_checkpoint(
        head: &DocumentDigest,
        event_count: u64,
        observed_at: u64,
    ) -> Result<Self, RecordError> {
        Self::build(
            observed_at,
            RecordBody::RegistryCheckpoint(RegistryCheckpointBody {
                head: head.clone(),
                event_count,
            }),
        )
    }

    pub fn policy(
        activation: ActivationRef,
        document_digest: DocumentDigest,
        issued_at: u64,
    ) -> Result<Self, RecordError> {
        Self::build(
            issued_at,
            RecordBody::Policy(PolicyBody {
                activation,
                document_digest,
            }),
        )
    }

    pub fn publication(body: PublicationBody, published_at: u64) -> Result<Self, RecordError> {
        Self::build(published_at, RecordBody::Publication(body))
    }

    pub fn reconciliation(body: ReconciliationBody, at: u64) -> Result<Self, RecordError> {
        Self::build(at, RecordBody::Reconciliation(body))
    }

    pub fn key_event(body: KeyEventBody, issued_at: u64) -> Result<Self, RecordError> {
        Self::build(issued_at, RecordBody::KeyEvent(body))
    }

    /// Turn this record into a correction of `prior` (an existing record id of
    /// the same kind). The id is re-derived, so the correction lands at a new
    /// path and the original is never touched.
    pub fn superseding(mut self, prior: &str) -> Result<Self, RecordError> {
        self.supersedes = Some(prior.to_owned());
        self.record_id = self.expected_id()?;
        self.validate()?;
        Ok(self)
    }

    pub fn kind(&self) -> RecordKind {
        self.body.kind()
    }

    pub fn domain(&self) -> SignDomain {
        self.kind().domain()
    }

    /// Ledger path: `records/<kind>/<record_id>.json`.
    pub fn path(&self) -> String {
        record_path(self.kind(), &self.record_id)
    }

    fn natural_key(&self) -> Vec<String> {
        match &self.body {
            RecordBody::AuditEvent(b) => vec![b.event_id.clone()],
            RecordBody::StoreCheckpoint(b) => vec![
                b.seq.to_string(),
                b.chain.clone(),
                self.issued_at.secs().to_string(),
            ],
            RecordBody::RegistryCheckpoint(b) => vec![
                b.head.as_str().to_owned(),
                b.event_count.to_string(),
                self.issued_at.secs().to_string(),
            ],
            RecordBody::Policy(b) => vec![b.document_digest.as_str().to_owned()],
            RecordBody::Publication(b) => match &b.decision {
                None => vec![b.projection_digest.as_str().to_owned()],
                Some(d) => vec![
                    b.projection_digest.as_str().to_owned(),
                    d.destination.as_str().to_owned(),
                    d.approval_id.as_str().to_owned(),
                ],
            },
            RecordBody::Reconciliation(b) => vec![
                self.issued_at.secs().to_string(),
                format!(
                    "{:?}:{}:{}:{}:{}:{}",
                    b.outcome,
                    b.store_events,
                    b.ledger_records,
                    b.missing_in_ledger,
                    b.unacked_in_ledger,
                    b.conflicting
                ),
            ],
            RecordBody::KeyEvent(b) => {
                vec![b.key_id.as_str().to_owned(), b.action.as_str().to_owned()]
            }
        }
    }

    /// The id this record must carry. Identity is derived from content, so a
    /// record cannot claim another record's path.
    pub fn expected_id(&self) -> Result<String, RecordError> {
        let kind = self.kind();
        let natural = self.natural_key();
        let refs: Vec<&str> = natural.iter().map(String::as_str).collect();
        let base = derive_id(kind, &refs);
        match &self.supersedes {
            None => Ok(base),
            Some(prior) => {
                if RecordKind::of_id(prior) != Some(kind) {
                    return Err(RecordError::Inconsistent);
                }
                Ok(derive_id(kind, &[&base, "supersedes", prior]))
            }
        }
    }

    pub fn validate(&self) -> Result<(), RecordError> {
        if self.schema != LEDGER_SCHEMA {
            return Err(RecordError::SchemaMismatch);
        }
        match &self.body {
            RecordBody::AuditEvent(b) => {
                if b.seq == 0
                    || b.seq > MAX_SAFE_INT
                    || !safe_token(&b.event_id)
                    || !safe_token(&b.kind)
                    || !is_hex64(&b.chain)
                    || !is_hex64(&b.payload_digest)
                {
                    return Err(RecordError::FieldRejected);
                }
                check_payload(&b.payload)?;
                if b.payload_exact {
                    let c =
                        to_canonical_bytes(&b.payload).map_err(|_| RecordError::NonCanonical)?;
                    if sha_hex(&c) != b.payload_digest {
                        return Err(RecordError::Inconsistent);
                    }
                }
            }
            RecordBody::StoreCheckpoint(b) => {
                if b.seq == 0 || b.seq > MAX_SAFE_INT || !is_hex64(&b.chain) {
                    return Err(RecordError::FieldRejected);
                }
            }
            RecordBody::RegistryCheckpoint(b) => {
                if b.event_count == 0 || b.event_count > MAX_SAFE_INT {
                    return Err(RecordError::FieldRejected);
                }
            }
            RecordBody::Policy(_) => {}
            RecordBody::Publication(b) => {
                if let Some(d) = &b.decision {
                    if d.disclosure_policy.kind != PolicyKind::Disclosure
                        || d.approver_kind == ActorKind::Agent
                    {
                        return Err(RecordError::Inconsistent);
                    }
                }
            }
            RecordBody::Reconciliation(b) => {
                let all = [
                    b.store_events,
                    b.ledger_records,
                    b.missing_in_ledger,
                    b.unacked_in_ledger,
                    b.conflicting,
                ];
                if all.iter().any(|n| *n > MAX_SAFE_INT) {
                    return Err(RecordError::FieldRejected);
                }
            }
            RecordBody::KeyEvent(b) => {
                let published = b.action == KeyAction::Published;
                let key_ok = match &b.public_key {
                    Some(k) => published && is_hex64(k),
                    None => !published,
                };
                let sorted_unique = b.purposes.windows(2).all(|w| w[0] < w[1]);
                if !key_ok
                    || published == b.purposes.is_empty()
                    || b.purposes.len() > MAX_PURPOSES
                    || !sorted_unique
                {
                    return Err(RecordError::Inconsistent);
                }
            }
        }
        if self.record_id != self.expected_id()? {
            return Err(RecordError::Inconsistent);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordError> {
        to_canonical_bytes(self).map_err(|_| RecordError::NonCanonical)
    }

    /// Strict parse of canonical bytes: size cap, closed schema, validation,
    /// and byte equality with the canonical encoding.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(RecordError::Oversized);
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| RecordError::Malformed)?;
        r.validate()?;
        if r.canonical_bytes()? != bytes {
            return Err(RecordError::NonCanonical);
        }
        Ok(r)
    }
}

pub fn record_path(kind: RecordKind, id: &str) -> String {
    format!("records/{}/{}.json", kind.dir(), id)
}

fn check_payload(payload: &Map<String, Value>) -> Result<(), RecordError> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_ENTRIES {
        return Err(RecordError::PayloadNotExportable);
    }
    for (k, v) in payload {
        if !PAYLOAD_KEY_ALLOWLIST.contains(&k.as_str()) {
            return Err(RecordError::PayloadNotExportable);
        }
        let ok = match v {
            Value::Number(n) => n.as_u64().is_some_and(|u| u <= MAX_SAFE_INT),
            Value::String(s) => safe_token(s),
            _ => false,
        };
        if !ok {
            return Err(RecordError::PayloadNotExportable);
        }
    }
    Ok(())
}

// --- Signed record ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLedgerRecord {
    pub payload: LedgerRecord,
    pub signature: Signature,
}

impl SignedLedgerRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RecordError> {
        to_canonical_bytes(self).map_err(|_| RecordError::NonCanonical)
    }

    /// Strict parse of an untrusted stored file. Signature verification is
    /// separate (`Verifier::verify_ledger_record`).
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_DOCUMENT_BYTES * 2 {
            return Err(RecordError::Oversized);
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| RecordError::Malformed)?;
        r.payload.validate()?;
        if r.canonical_bytes()? != bytes {
            return Err(RecordError::NonCanonical);
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_ids_have_a_recognizable_kind() {
        let id = derive_id(RecordKind::AuditEvent, &["terminal:x"]);
        assert_eq!(RecordKind::of_id(&id), Some(RecordKind::AuditEvent));
        assert_eq!(RecordKind::of_id("rec-audit-zz"), None);
        assert_eq!(RecordKind::of_id("evil"), None);
    }

    #[test]
    fn payload_allowlist_is_closed() {
        let mut m = Map::new();
        m.insert("event".into(), Value::String("attempt.terminal".into()));
        assert!(check_payload(&m).is_ok());
        m.insert("note".into(), Value::String("x".into()));
        assert_eq!(check_payload(&m), Err(RecordError::PayloadNotExportable));
        m.remove("note");
        m.insert("reason".into(), Value::String("free text here".into()));
        assert_eq!(check_payload(&m), Err(RecordError::PayloadNotExportable));
    }
}
