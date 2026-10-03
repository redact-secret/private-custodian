//! Ledger re-issue after a signing-key revocation (R-4, ADR 0131).
//!
//! Revoking a key rejects every signature it ever made, so the ledger walk
//! reports findings and the control plane refuses to start. This module
//! re-attests that history under a new key **without rewriting or deleting
//! anything**:
//!
//! * the new key publishes nothing about the old key except a signed
//!   `revoked` key event; it must already be trusted (a pinned root);
//! * every record signed by the revoked key is re-attested by a *superseding*
//!   record with the same body and the same issue time, signed by the new
//!   key, at a new path. The old file stays exactly where it is: it is the
//!   marked old lineage, reported by the walker as `RevokedSuperseded`;
//! * an audit record or checkpoint is re-attested only if the store (or the
//!   registry) corroborates it. A revoked-key record that contradicts the
//!   store is never re-attested, so a forgery made with a stolen key keeps
//!   the ledger untrusted instead of being laundered;
//! * policy, publication, reconciliation and key-event records cannot be
//!   corroborated by the store. They are re-attested only when the operator
//!   confirms the exact plan digest, which covers every record id.
//!
//! The procedure constraints that earlier issues recorded are enforced here
//! instead of being left to the operator: the new key must be valid from at
//! or before the oldest record it re-attests (R-6), the revoking key event
//! must not share a second with another key event (R-5), and the finished
//! ledger must walk clean (post-check). The module holds no key; signing goes
//! through the caller's [`Signer`]. Synthetic data and test keys only in the
//! tests; project-maintained, not independent validation.

use std::collections::BTreeSet;

use custodian_contracts::types::{KeyId, Timestamp};
use custodian_corpus::registry::RegistryView;
use custodian_store::{Checkpoint, SqliteStore, StoreError};
use sha2::{Digest, Sha256};

use crate::b64::hex;
use crate::backend::{BackendError, LedgerBackend};
use crate::exporter::{ExportError, Exporter, WriteOutcome};
use crate::keys::Verifier;
use crate::record::{
    KeyAction, KeyEventBody, LedgerRecord, ReconcileOutcome, ReconciliationBody, RecordBody,
    RecordKind,
};
use crate::signer::{SignRefusal, Signer};
use crate::walk::{walk_ledger, FindingCode, WalkReport};

/// What the store can vouch for. The control plane passes its own store.
pub trait Corroboration {
    /// The store holds exactly this audit event at `seq`.
    fn audit_matches(
        &self,
        seq: u64,
        event_id: &str,
        kind: &str,
        chain: &str,
        payload_digest: &str,
    ) -> Result<bool, StoreError>;
    /// The store's outbox chain contains this checkpoint.
    fn checkpoint_contained(&self, cp: &Checkpoint) -> Result<bool, StoreError>;
}

impl Corroboration for SqliteStore {
    fn audit_matches(
        &self,
        seq: u64,
        event_id: &str,
        kind: &str,
        chain: &str,
        payload_digest: &str,
    ) -> Result<bool, StoreError> {
        Ok(self.outbox_event(seq)?.is_some_and(|e| {
            e.event_id == event_id
                && e.kind == kind
                && e.chain == chain
                && e.payload_digest == payload_digest
        }))
    }

    fn checkpoint_contained(&self, cp: &Checkpoint) -> Result<bool, StoreError> {
        self.contains_checkpoint(cp)
    }
}

/// Why a plan or an execution was refused. Fixed vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReissueRefusal {
    LedgerUnavailable,
    StoreUnavailable,
    /// The walk has a finding that re-issue cannot fix (malformed or
    /// misplaced files, bad signatures other than revocation, forks, rejected
    /// key events). Investigate as an incident.
    OtherFindings,
    /// Nothing is signed by a revoked key, or the named key is not revoked
    /// and not the signer of any record.
    NothingToReissue,
    /// More than one revoked key signed records; re-issue one lineage at a time.
    MoreThanOneRevokedKey,
    /// A revoked-key record contradicts the store (or the registry).
    Contradicted,
    /// A revoked-key record is itself a correction; re-attesting it would
    /// lose the link to the record it corrects.
    CorrectionChain,
    /// The new signer's key is unknown to the walked keyring, revoked, or not
    /// authorized for a domain it must sign.
    NewKeyNotTrusted,
    /// The new key is valid only from a time after the oldest record it must
    /// re-attest (R-6). Pin it with an earlier `valid_from`.
    NewKeyNotValidForHistory,
    /// The new key is the revoked key.
    SameKey,
    /// Another key event shares the second of the revoking key event (R-5).
    SameSecondKeyEvent,
    ConfirmationMismatch,
    Sign(SignRefusal),
    Backend(BackendError),
    /// A re-attested record was not written (conflict, deferral, record error).
    WriteFailed,
    /// After re-issue the ledger still does not walk clean.
    PostCheckFailed,
}

impl ReissueRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::LedgerUnavailable => "reissue_ledger_unavailable",
            Self::StoreUnavailable => "reissue_store_unavailable",
            Self::OtherFindings => "reissue_other_findings",
            Self::NothingToReissue => "reissue_nothing_to_reissue",
            Self::MoreThanOneRevokedKey => "reissue_more_than_one_revoked_key",
            Self::Contradicted => "reissue_contradicted_by_store",
            Self::CorrectionChain => "reissue_correction_chain",
            Self::NewKeyNotTrusted => "reissue_new_key_not_trusted",
            Self::NewKeyNotValidForHistory => "reissue_new_key_not_valid_for_history",
            Self::SameKey => "reissue_same_key",
            Self::SameSecondKeyEvent => "reissue_same_second_key_event",
            Self::ConfirmationMismatch => "reissue_confirmation_mismatch",
            Self::Sign(r) => r.code(),
            Self::Backend(b) => b.code(),
            Self::WriteFailed => "reissue_write_failed",
            Self::PostCheckFailed => "reissue_post_check_failed",
        }
    }
}

impl core::fmt::Display for ReissueRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ReissueRefusal {}

/// One record the plan would re-attest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedRecord {
    pub record_id: String,
    pub kind: RecordKind,
    pub issued_at: u64,
    /// The store (or registry) confirmed the body.
    pub corroborated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReissuePlan {
    /// The one revoked key whose records are re-attested.
    pub revoked_key: KeyId,
    pub to_reissue: Vec<PlannedRecord>,
    /// Revoked-key records that already have a valid re-attestation.
    pub already_reattested: usize,
    pub corroborated: usize,
    pub uncorroborated: usize,
    pub earliest_issued_at: Option<u64>,
    pub latest_issued_at: Option<u64>,
    /// `sha256:` digest over the revoked key and every planned record id: the exact object the operator confirms.
    pub digest: String,
}

fn plan_digest(revoked: &KeyId, records: &[PlannedRecord]) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/ledger/reissue-plan/v1\0");
    h.update(revoked.as_str().as_bytes());
    for r in records {
        h.update([0]);
        h.update(r.record_id.as_bytes());
        h.update([u8::from(r.corroborated)]);
    }
    format!("sha256:{}", hex(&h.finalize()))
}

fn only_recoverable_findings(walk: &WalkReport) -> bool {
    walk.findings.iter().all(|f| match f.code {
        // The revoked records themselves, and what their absence from the
        // valid set causes in the chain walk. Both disappear once
        // re-attested; the post-check proves it.
        FindingCode::BadSignature(crate::keys::VerifyError::KeyRevoked)
        | FindingCode::SeqGap
        | FindingCode::ChainMismatch => true,
        c => c.is_informational(),
    })
}

/// Work out what re-issue would do. Reads the ledger and the store; writes
/// nothing.
pub fn plan_reissue(
    backend: &dyn LedgerBackend,
    roots: &crate::keys::Keyring,
    store: &dyn Corroboration,
    registry: Option<&RegistryView>,
) -> Result<ReissuePlan, ReissueRefusal> {
    let walk = walk_ledger(backend, roots).map_err(|_| ReissueRefusal::LedgerUnavailable)?;
    plan_from_walk(&walk, store, registry)
}

fn plan_from_walk(
    walk: &WalkReport,
    store: &dyn Corroboration,
    registry: Option<&RegistryView>,
) -> Result<ReissuePlan, ReissueRefusal> {
    if !only_recoverable_findings(walk) {
        return Err(ReissueRefusal::OtherFindings);
    }
    let signers: BTreeSet<&KeyId> = walk
        .revoked
        .iter()
        .map(|r| &r.record.signature.key_id)
        .collect();
    let revoked_key = match signers.len() {
        0 => return Err(ReissueRefusal::NothingToReissue),
        1 => (*signers
            .iter()
            .next()
            .ok_or(ReissueRefusal::NothingToReissue)?)
        .clone(),
        _ => return Err(ReissueRefusal::MoreThanOneRevokedKey),
    };
    let already = walk.revoked.iter().filter(|r| r.reattested).count();
    let mut planned = Vec::new();
    for r in walk.revoked.iter().filter(|r| !r.reattested) {
        let rec = &r.record.payload;
        if rec.supersedes.is_some() {
            return Err(ReissueRefusal::CorrectionChain);
        }
        let corroborated = match &rec.body {
            RecordBody::AuditEvent(b) => {
                if !store
                    .audit_matches(b.seq, &b.event_id, &b.kind, &b.chain, &b.payload_digest)
                    .map_err(|_| ReissueRefusal::StoreUnavailable)?
                {
                    return Err(ReissueRefusal::Contradicted);
                }
                true
            }
            RecordBody::StoreCheckpoint(b) => {
                let cp = Checkpoint {
                    seq: b.seq,
                    chain: b.chain.clone(),
                };
                if !store
                    .checkpoint_contained(&cp)
                    .map_err(|_| ReissueRefusal::StoreUnavailable)?
                {
                    return Err(ReissueRefusal::Contradicted);
                }
                true
            }
            RecordBody::RegistryCheckpoint(b) => match registry {
                Some(view) => {
                    if view.event_count() < b.event_count
                        || view.head_after(b.event_count).as_ref() != Some(&b.head)
                    {
                        return Err(ReissueRefusal::Contradicted);
                    }
                    true
                }
                None => false,
            },
            RecordBody::Policy(_)
            | RecordBody::Publication(_)
            | RecordBody::Reconciliation(_)
            | RecordBody::KeyEvent(_) => false,
        };
        planned.push(PlannedRecord {
            record_id: rec.record_id.clone(),
            kind: rec.kind(),
            issued_at: rec.issued_at.secs(),
            corroborated,
        });
    }
    if planned.is_empty() {
        return Err(ReissueRefusal::NothingToReissue);
    }
    planned.sort_by(|a, b| a.record_id.cmp(&b.record_id));
    let corroborated = planned.iter().filter(|p| p.corroborated).count();
    let digest = plan_digest(&revoked_key, &planned);
    Ok(ReissuePlan {
        earliest_issued_at: planned.iter().map(|p| p.issued_at).min(),
        latest_issued_at: planned.iter().map(|p| p.issued_at).max(),
        uncorroborated: planned.len() - corroborated,
        corroborated,
        already_reattested: already,
        revoked_key,
        to_reissue: planned,
        digest,
    })
}

/// The operator's exact confirmations.
#[derive(Clone, Debug)]
pub struct ReissueRequest<'a> {
    pub confirm_revoked_key: &'a KeyId,
    pub confirm_new_key: &'a KeyId,
    pub confirm_plan_digest: &'a str,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReissueReport {
    pub revoked_key: KeyId,
    pub new_key: KeyId,
    pub reissued: usize,
    pub already_present: usize,
    pub ledger_records_after: usize,
}

fn export_refusal(e: ExportError) -> ReissueRefusal {
    match e {
        ExportError::Sign(r) => ReissueRefusal::Sign(r),
        ExportError::Backend(b) => ReissueRefusal::Backend(b),
        ExportError::SelfCheck(_) => ReissueRefusal::NewKeyNotTrusted,
        _ => ReissueRefusal::WriteFailed,
    }
}

/// Check that the signing key can sign the revoking key event and, when a
/// `plan` is given, every record in it (R-6).
fn check_new_key(
    walk: &WalkReport,
    plan: Option<&ReissuePlan>,
    revoked: &KeyId,
    new_key: &KeyId,
    now: u64,
) -> Result<(), ReissueRefusal> {
    if new_key == revoked {
        return Err(ReissueRefusal::SameKey);
    }
    let entry = walk
        .keyring
        .get(new_key)
        .ok_or(ReissueRefusal::NewKeyNotTrusted)?;
    if entry.revoked_at.is_some() {
        return Err(ReissueRefusal::NewKeyNotTrusted);
    }
    let mut domains: BTreeSet<_> = BTreeSet::new();
    domains.insert(RecordKind::KeyEvent.domain());
    if let Some(plan) = plan {
        domains.extend(plan.to_reissue.iter().map(|p| p.kind.domain()));
        domains.insert(RecordKind::Reconciliation.domain());
    }
    if !domains.iter().all(|d| entry.purposes.contains(d)) {
        return Err(ReissueRefusal::NewKeyNotTrusted);
    }
    let earliest = plan
        .and_then(|p| p.earliest_issued_at)
        .map_or(now, |e| e.min(now));
    if entry.valid_from.secs() > earliest {
        return Err(ReissueRefusal::NewKeyNotValidForHistory);
    }
    let latest = plan
        .and_then(|p| p.latest_issued_at)
        .map_or(now, |l| l.max(now));
    if entry.retired_at.is_some_and(|t| t.secs() <= latest) {
        return Err(ReissueRefusal::NewKeyNotTrusted);
    }
    Ok(())
}

/// Step 1 of the compromise procedure: record, in the ledger and signed by
/// the new (already pinned) key, that `revoked` is revoked. After this the
/// old lineage is untrusted until [`execute_reissue`] has run; the control
/// plane will refuse to start meanwhile, which is the intended containment.
///
/// Refuses when the signer is the revoked key (a key cannot revoke itself),
/// when the signing key is not trusted for key events or not yet valid, when
/// the key is unknown, and when another key event shares the second of this
/// one (R-5: events apply in `(issued_at, id)` order and a same-second pair
/// is ambiguous). Returns `Ok(false)` when the key is already revoked.
pub fn revoke_key(
    backend: &dyn LedgerBackend,
    roots: &crate::keys::Keyring,
    signer: &dyn Signer,
    revoked: &KeyId,
    confirm_revoked: &KeyId,
    now: u64,
) -> Result<bool, ReissueRefusal> {
    if revoked != confirm_revoked {
        return Err(ReissueRefusal::ConfirmationMismatch);
    }
    let walk = walk_ledger(backend, roots).map_err(|_| ReissueRefusal::LedgerUnavailable)?;
    let target = walk
        .keyring
        .get(revoked)
        .ok_or(ReissueRefusal::NothingToReissue)?;
    if target.revoked_at.is_some() {
        return Ok(false);
    }
    check_new_key(&walk, None, revoked, signer.key_id(), now)?;
    if walk.key_event_times.contains(&now) {
        return Err(ReissueRefusal::SameSecondKeyEvent);
    }
    let ev = LedgerRecord::key_event(
        KeyEventBody {
            key_id: revoked.clone(),
            action: KeyAction::Revoked,
            public_key: None,
            purposes: Vec::new(),
            effective_at: Timestamp::new(now).map_err(|_| ReissueRefusal::WriteFailed)?,
        },
        now,
    )
    .map_err(|_| ReissueRefusal::WriteFailed)?;
    let verifier = Verifier::new(walk.keyring.clone());
    match Exporter::new(backend, signer, &verifier)
        .write_record(&ev)
        .map_err(export_refusal)?
    {
        WriteOutcome::Created | WriteOutcome::Identical => Ok(true),
        _ => Err(ReissueRefusal::WriteFailed),
    }
}

/// Step 2: re-attest every unattested revoked-key record, write one marker
/// record, and prove the ledger now walks clean.
///
/// `signer` must sign as the new key. Nothing is overwritten or deleted. A
/// second call after success finds everything attested and returns
/// `NothingToReissue`.
pub fn execute_reissue(
    backend: &dyn LedgerBackend,
    roots: &crate::keys::Keyring,
    signer: &dyn Signer,
    store: &dyn Corroboration,
    registry: Option<&RegistryView>,
    req: &ReissueRequest<'_>,
) -> Result<ReissueReport, ReissueRefusal> {
    let walk = walk_ledger(backend, roots).map_err(|_| ReissueRefusal::LedgerUnavailable)?;
    let plan = plan_from_walk(&walk, store, registry)?;
    if plan.revoked_key != *req.confirm_revoked_key
        || signer.key_id() != req.confirm_new_key
        || plan.digest != req.confirm_plan_digest
    {
        return Err(ReissueRefusal::ConfirmationMismatch);
    }
    check_new_key(
        &walk,
        Some(&plan),
        &plan.revoked_key,
        req.confirm_new_key,
        req.now,
    )?;
    let verifier = Verifier::new(walk.keyring.clone());
    let ex = Exporter::new(backend, signer, &verifier);
    let mut reissued = 0usize;
    let mut present = 0usize;
    for r in walk.revoked.iter().filter(|r| !r.reattested) {
        let new = r
            .record
            .payload
            .clone()
            .superseding(&r.record.payload.record_id)
            .map_err(|_| ReissueRefusal::WriteFailed)?;
        match ex.write_record(&new).map_err(export_refusal)? {
            WriteOutcome::Created => reissued += 1,
            WriteOutcome::Identical => present += 1,
            _ => return Err(ReissueRefusal::WriteFailed),
        }
    }
    if reissued > 0 {
        let marker = LedgerRecord::reconciliation(
            ReconciliationBody {
                outcome: ReconcileOutcome::Repaired,
                store_events: 0,
                ledger_records: reissued as u64,
                missing_in_ledger: 0,
                unacked_in_ledger: 0,
                conflicting: 0,
            },
            req.now,
        )
        .map_err(|_| ReissueRefusal::WriteFailed)?;
        match ex.write_record(&marker).map_err(export_refusal)? {
            WriteOutcome::Created | WriteOutcome::Identical => {}
            _ => return Err(ReissueRefusal::WriteFailed),
        }
    }
    let after = walk_ledger(backend, roots).map_err(|_| ReissueRefusal::LedgerUnavailable)?;
    if !after.is_trustworthy() {
        return Err(ReissueRefusal::PostCheckFailed);
    }
    Ok(ReissueReport {
        revoked_key: plan.revoked_key,
        new_key: req.confirm_new_key.clone(),
        reissued,
        already_present: present,
        ledger_records_after: after.records,
    })
}
