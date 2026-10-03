//! Epoch standing, contamination events, rotation links and the revocation
//! feed (C9, ADR 0070 to 0073).
//!
//! The store does not decide what contamination means; `custodian_core::standing`
//! does, and every method here calls it inside the transaction that persists
//! the result. What the store adds is atomicity and ordering:
//!
//! * **Standing changes** are one `BEGIN IMMEDIATE` transaction that writes the
//!   event row, updates the standing row, records any feed obligation the
//!   change causes, and writes the audit outbox event. A contamination can
//!   never be committed without its feed consequence or its audit event.
//! * **The gate.** `reserve`, `retry`, `start` and `record_exposure` (in
//!   `ops.rs`) read the epoch's standing in their own write transaction. Writers
//!   are serialized, so a contamination commit is either before the gate (the
//!   operation is refused with [`StoreError::EpochBlocked`]) or after it (the
//!   operation already took effect and is re-evaluated at the next gate).
//! * **The feed.** Envelopes are appended contiguously with a matching
//!   `previous` link, by code and by trigger. Two publishers racing for the
//!   same sequence cannot both commit.

use custodian_core::standing::{apply, evidence_effect, EvidenceEffect, StandingRefusal};
use custodian_core::{Contamination, EpochChange, EpochStanding};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::migrations::hex;
use crate::outbox::outbox_append;
use crate::store::*;

const MAX_ID_LEN: usize = 128;
/// Largest signed envelope the store keeps (the contract's document cap).
const MAX_DOCUMENT_BYTES: usize = 65_536;

fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

fn check_ids(ids: &[&str]) -> Result<(), StoreError> {
    if ids.iter().all(|s| safe_id(s)) {
        Ok(())
    } else {
        Err(StoreError::InvalidInput)
    }
}

// ---- standing ----------------------------------------------------------------

/// Standing of one epoch as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochStandingRecord {
    pub epoch_id: String,
    pub corpus_id: String,
    pub family_id: Option<String>,
    pub standing: EpochStanding,
    /// Number of standing changes applied (1 for the first).
    pub version: u64,
    pub updated_at: u64,
}

/// A requested standing change with everything the audit trail records.
#[derive(Clone, Debug)]
pub struct EpochEventCommand<'a> {
    pub epoch_id: &'a str,
    pub corpus_id: &'a str,
    pub family_id: Option<&'a str>,
    /// A repeat with the same key and content replays the recorded outcome.
    pub idempotency_key: &'a str,
    pub change: EpochChange,
    /// Fixed reason vocabulary (checked by the caller; shape-checked here).
    pub reason: &'a str,
    pub actor: &'a str,
    /// `human`, `service` or `agent`.
    pub actor_kind: &'a str,
    /// Reference to the authorization or review that permitted the change.
    pub authorization_ref: &'a str,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochEventOutcome {
    /// Global event sequence.
    pub event_seq: u64,
    pub prior: EpochStanding,
    pub new: EpochStanding,
    pub changed: bool,
    /// Standing version after the event.
    pub version: u64,
    /// True when this was a repeat of an already recorded event.
    pub replay: bool,
    /// The feed obligation the change created, if any.
    pub obligation_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochEventRecord {
    pub seq: u64,
    pub epoch_id: String,
    pub change: String,
    pub reported: Option<String>,
    pub prior: EpochStanding,
    pub new: EpochStanding,
    pub changed: bool,
    pub version_after: u64,
    pub actor: String,
    pub actor_kind: String,
    pub reason: String,
    pub authorization_ref: String,
    pub at: u64,
}

fn parse_standing(c: &str, r: i64) -> Result<EpochStanding, StoreError> {
    Ok(EpochStanding {
        contamination: Contamination::parse(c).ok_or(StoreError::Corrupt)?,
        retired: r != 0,
    })
}

type StandingRow = (String, String, Option<String>, String, i64, i64, i64);

pub(crate) fn load_standing(
    tx: &Connection,
    epoch_id: &str,
) -> Result<Option<EpochStandingRecord>, StoreError> {
    let row: Option<StandingRow> = tx
        .query_row(
            "SELECT epoch_id, corpus_id, family_id, contamination, retired, version, updated_at \
             FROM epoch_standing WHERE epoch_id = ?1",
            [epoch_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?;
    row.map(|(e, c, f, cont, ret, v, u)| {
        Ok(EpochStandingRecord {
            epoch_id: e,
            corpus_id: c,
            family_id: f,
            standing: parse_standing(&cont, ret)?,
            version: from_sql(v),
            updated_at: from_sql(u),
        })
    })
    .transpose()
}

/// The gate: refuse new use of a contaminated, possibly-changed or retired
/// epoch. Absence of a row means nothing was recorded, which is usable.
pub(crate) fn gate_epoch(tx: &Connection, epoch_id: &str) -> Result<(), StoreError> {
    match load_standing(tx, epoch_id)? {
        Some(r) if !r.standing.usable() => Err(StoreError::EpochBlocked),
        _ => Ok(()),
    }
}

/// The epoch a stored request draws on: the plan's population epoch for a
/// contract request, the opaque population identity for a port request.
pub(crate) fn epoch_key(
    origin: &str,
    subject: Option<&str>,
    document: Option<&str>,
) -> Result<String, StoreError> {
    if origin == "port" {
        return subject.map(str::to_owned).ok_or(StoreError::Corrupt);
    }
    let doc: serde_json::Value =
        serde_json::from_str(document.ok_or(StoreError::Corrupt)?).map_err(|_| StoreError::Corrupt)?;
    doc.pointer("/plan/population/epoch_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(StoreError::Corrupt)
}

/// Gate by stored request id (used at start and exposure).
pub(crate) fn gate_request(tx: &Connection, request_id: &str) -> Result<(), StoreError> {
    let (origin, subject, document): (String, Option<String>, Option<String>) = tx.query_row(
        "SELECT origin, subject, document FROM requests WHERE request_id = ?1",
        [request_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let key = epoch_key(&origin, subject.as_deref(), document.as_deref())?;
    gate_epoch(tx, &key)
}

fn event_digest(c: &EpochEventCommand<'_>) -> String {
    let reported = match c.change {
        EpochChange::Report(k) => k.as_str(),
        _ => "-",
    };
    let mut h = Sha256::new();
    h.update(b"private-custodian/store/epoch-event/v1");
    for p in [
        c.epoch_id,
        c.corpus_id,
        c.family_id.unwrap_or("-"),
        c.change.as_str(),
        reported,
        c.reason,
        c.actor,
        c.actor_kind,
        c.authorization_ref,
    ] {
        h.update([0]);
        h.update(p.as_bytes());
    }
    hex(&h.finalize())
}

fn obligation_id_for(epoch_id: &str, version: i64, effect: EvidenceEffect) -> String {
    let tag = match effect {
        EvidenceEffect::Contaminated => "contaminated",
        EvidenceEffect::EpochEnded => "ended",
    };
    format!("epoch:{epoch_id}:{version}:{tag}")
}

// ---- obligations -------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObligationTarget {
    Projection,
    Receipt,
    Candidate,
    Population,
    Policy,
}

impl ObligationTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Projection => "projection",
            Self::Receipt => "receipt",
            Self::Candidate => "candidate",
            Self::Population => "population",
            Self::Policy => "policy",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Projection,
            Self::Receipt,
            Self::Candidate,
            Self::Population,
            Self::Policy,
        ]
        .into_iter()
        .find(|t| t.as_str() == s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObligationAction {
    Revoked,
    Contaminated,
    Superseded,
}

impl ObligationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Contaminated => "contaminated",
            Self::Superseded => "superseded",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        [Self::Revoked, Self::Contaminated, Self::Superseded]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

/// The fixed public reasons (`PublicRevocationReason`), by wire name.
pub const PUBLIC_REASONS: [&str; 6] = [
    "contamination",
    "epoch_rotation",
    "key_compromise",
    "policy_revoked",
    "error_correction",
    "newer_evidence",
];

#[derive(Clone, Debug)]
pub struct ObligationCommand<'a> {
    /// Deterministic identity; a repeat is a no-op.
    pub obligation_id: &'a str,
    pub target: ObligationTarget,
    /// Internal reference: epoch id, candidate digest, projection or receipt
    /// id, or the canonical policy reference.
    pub target_ref: &'a str,
    pub action: ObligationAction,
    pub superseded_by: Option<&'a str>,
    pub reason: &'a str,
    pub effective_at: u64,
    pub actor: &'a str,
    pub authorization_ref: &'a str,
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObligationRecord {
    pub seq: u64,
    pub obligation_id: String,
    pub target: ObligationTarget,
    pub target_ref: String,
    pub action: ObligationAction,
    pub superseded_by: Option<String>,
    pub reason: String,
    pub effective_at: u64,
    pub actor: String,
    pub authorization_ref: String,
    pub created_at: u64,
    pub published_seq: Option<u64>,
}

const OBLIGATION_COLS: &str = "seq, obligation_id, target_kind, target_ref, action, superseded_by, \
     reason, effective_at, actor, authorization_ref, created_at, published_seq";

fn map_obligation(r: &rusqlite::Row<'_>) -> rusqlite::Result<ObligationRecord> {
    let kind: String = r.get(2)?;
    let action: String = r.get(4)?;
    Ok(ObligationRecord {
        seq: from_sql(r.get(0)?),
        obligation_id: r.get(1)?,
        target: ObligationTarget::parse(&kind).ok_or(rusqlite::Error::InvalidQuery)?,
        target_ref: r.get(3)?,
        action: ObligationAction::parse(&action).ok_or(rusqlite::Error::InvalidQuery)?,
        superseded_by: r.get(5)?,
        reason: r.get(6)?,
        effective_at: from_sql(r.get(7)?),
        actor: r.get(8)?,
        authorization_ref: r.get(9)?,
        created_at: from_sql(r.get(10)?),
        published_seq: r.get::<_, Option<i64>>(11)?.map(from_sql),
    })
}

fn insert_obligation(
    tx: &Connection,
    c: &ObligationCommand<'_>,
) -> Result<Option<ObligationRecord>, StoreError> {
    check_ids(&[
        c.obligation_id,
        c.target_ref,
        c.actor,
        c.authorization_ref,
        c.reason,
    ])?;
    if let Some(s) = c.superseded_by {
        check_ids(&[s])?;
    }
    if !PUBLIC_REASONS.contains(&c.reason)
        || (c.action == ObligationAction::Superseded) != c.superseded_by.is_some()
    {
        return Err(StoreError::InvalidInput);
    }
    let existing: Option<ObligationRecord> = tx
        .query_row(
            &format!("SELECT {OBLIGATION_COLS} FROM feed_obligations WHERE obligation_id = ?1"),
            [c.obligation_id],
            map_obligation,
        )
        .optional()?;
    if let Some(e) = existing {
        let same = e.target == c.target
            && e.target_ref == c.target_ref
            && e.action == c.action
            && e.superseded_by.as_deref() == c.superseded_by
            && e.reason == c.reason;
        return if same {
            Ok(None)
        } else {
            Err(StoreError::IdentityConflict)
        };
    }
    let eff = sql_time(c.effective_at)?;
    let now = sql_time(c.now)?;
    tx.execute(
        "INSERT INTO feed_obligations (obligation_id, target_kind, target_ref, action, \
         superseded_by, reason, effective_at, actor, authorization_ref, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        (
            c.obligation_id,
            c.target.as_str(),
            c.target_ref,
            c.action.as_str(),
            c.superseded_by,
            c.reason,
            eff,
            c.actor,
            c.authorization_ref,
            now,
        ),
    )?;
    let rec = tx.query_row(
        &format!("SELECT {OBLIGATION_COLS} FROM feed_obligations WHERE obligation_id = ?1"),
        [c.obligation_id],
        map_obligation,
    )?;
    outbox_append(
        tx,
        &format!("obligation:{}", c.obligation_id),
        "feed.obligation",
        None,
        None,
        &json!({
            "event": "feed.obligation", "target_kind": c.target.as_str(),
            "kind": c.action.as_str(), "reason": c.reason,
            "scope_key": c.obligation_id, "actor": c.actor,
            "authorization_ref": c.authorization_ref, "at": now,
        }),
        now,
    )?;
    Ok(Some(rec))
}

// ---- feed ----------------------------------------------------------------------

/// The newest committed envelope of a feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedHead {
    pub sequence: u64,
    pub digest: String,
    pub issued_at: u64,
    pub fresh_until: u64,
}

#[derive(Clone, Debug)]
pub struct FeedAppend<'a> {
    pub feed_id: &'a str,
    pub sequence: u64,
    pub previous_digest: Option<&'a str>,
    /// Domain-separated document digest of the envelope payload.
    pub digest: &'a str,
    /// Canonical bytes of the signed envelope, exactly as published.
    pub document: &'a str,
    pub issued_at: u64,
    pub fresh_until: u64,
    /// Obligations this envelope publishes; each is stamped once.
    pub obligation_ids: &'a [String],
    pub now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedEnvelopeRecord {
    pub sequence: u64,
    pub digest: String,
    pub document: String,
    pub issued_at: u64,
    pub fresh_until: u64,
    pub delivered: bool,
}

// ---- rotation ------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct RotationCommand<'a> {
    pub predecessor: &'a str,
    pub successor: &'a str,
    pub corpus_id: &'a str,
    pub family_id: Option<&'a str>,
    pub actor: &'a str,
    pub authorization_ref: &'a str,
    pub now: u64,
}

impl SqliteStore {
    /// Standing of an epoch; `None` when nothing was ever recorded (usable).
    pub fn epoch_standing(&self, epoch_id: &str) -> Result<Option<EpochStandingRecord>, StoreError> {
        check_ids(&[epoch_id])?;
        self.read(|tx| load_standing(tx, epoch_id))
    }

    /// Read-only form of the gate: `Err(EpochBlocked)` unless the epoch may
    /// be used. The same rule `reserve`, `retry`, `start` and
    /// `record_exposure` apply inside their own transactions.
    pub fn check_epoch_usable(&self, epoch_id: &str) -> Result<(), StoreError> {
        check_ids(&[epoch_id])?;
        self.read(|tx| gate_epoch(tx, epoch_id))
    }

    /// Apply a standing change atomically with its audit event and any feed
    /// obligation it causes. A repeat of the same key and content replays the
    /// recorded outcome; the same key with different content is
    /// `IdempotencyConflict`. A refused change (for example clearing a
    /// permanent contamination) writes nothing.
    pub fn apply_epoch_change(
        &self,
        cmd: &EpochEventCommand<'_>,
    ) -> Result<EpochEventOutcome, StoreError> {
        check_ids(&[
            cmd.epoch_id,
            cmd.corpus_id,
            cmd.idempotency_key,
            cmd.reason,
            cmd.actor,
            cmd.authorization_ref,
        ])?;
        if let Some(f) = cmd.family_id {
            check_ids(&[f])?;
        }
        if !matches!(cmd.actor_kind, "human" | "service" | "agent") {
            return Err(StoreError::InvalidInput);
        }
        let now = sql_time(cmd.now)?;
        let digest = event_digest(cmd);
        self.write(FaultOp::EpochChange, |tx| {
            // Replay.
            let prior_event: Option<(i64, String)> = tx
                .query_row(
                    "SELECT seq, request_digest FROM epoch_events WHERE idempotency_key = ?1",
                    [cmd.idempotency_key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((seq, stored)) = prior_event {
                if stored != digest {
                    return Err(StoreError::IdempotencyConflict);
                }
                return replay_event(tx, seq);
            }

            let cur = load_standing(tx, cmd.epoch_id)?;
            if let Some(c) = &cur {
                if c.corpus_id != cmd.corpus_id || c.family_id.as_deref() != cmd.family_id {
                    return Err(StoreError::IdentityConflict);
                }
            }
            let current = cur.as_ref().map_or(EpochStanding::CLEAN, |c| c.standing);
            let t = apply(current, cmd.change).map_err(|e| match e {
                StandingRefusal::NothingToReport => StoreError::InvalidInput,
                StandingRefusal::NotClearable => StoreError::InvalidTransition,
            })?;
            let version = match &cur {
                None => {
                    // The first event creates the row at its post-change value.
                    tx.execute(
                        "INSERT INTO epoch_standing (epoch_id, corpus_id, family_id, \
                         contamination, retired, version, updated_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                        (
                            cmd.epoch_id,
                            cmd.corpus_id,
                            cmd.family_id,
                            t.new.contamination.as_str(),
                            i64::from(t.new.retired),
                            now,
                        ),
                    )?;
                    1
                }
                Some(c) if t.changed() => {
                    let v = sql_time(c.version)? + 1;
                    tx.execute(
                        "UPDATE epoch_standing SET contamination = ?1, retired = ?2, \
                         version = ?3, updated_at = ?4 WHERE epoch_id = ?5",
                        (
                            t.new.contamination.as_str(),
                            i64::from(t.new.retired),
                            v,
                            now,
                            cmd.epoch_id,
                        ),
                    )?;
                    v
                }
                Some(c) => sql_time(c.version)?,
            };
            let reported = match cmd.change {
                EpochChange::Report(k) => Some(k.as_str()),
                _ => None,
            };
            tx.execute(
                "INSERT INTO epoch_events (epoch_id, idempotency_key, request_digest, change, \
                 reported, prior_contamination, prior_retired, new_contamination, new_retired, \
                 changed, version_after, actor, actor_kind, reason, authorization_ref, at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                (
                    cmd.epoch_id,
                    cmd.idempotency_key,
                    &digest,
                    cmd.change.as_str(),
                    reported,
                    t.prior.contamination.as_str(),
                    i64::from(t.prior.retired),
                    t.new.contamination.as_str(),
                    i64::from(t.new.retired),
                    i64::from(t.changed()),
                    version,
                    cmd.actor,
                    cmd.actor_kind,
                    cmd.reason,
                    cmd.authorization_ref,
                    now,
                ),
            )?;
            let event_seq = tx.last_insert_rowid();

            // The public consequence is part of the same transaction.
            let mut obligation_id = None;
            if t.changed() {
                if let Some(effect) = evidence_effect(&t) {
                    let id = obligation_id_for(cmd.epoch_id, version, effect);
                    let (action, reason) = match effect {
                        EvidenceEffect::Contaminated => {
                            (ObligationAction::Contaminated, "contamination")
                        }
                        EvidenceEffect::EpochEnded => (ObligationAction::Revoked, "epoch_rotation"),
                    };
                    insert_obligation(
                        tx,
                        &ObligationCommand {
                            obligation_id: &id,
                            target: ObligationTarget::Population,
                            target_ref: cmd.epoch_id,
                            action,
                            superseded_by: None,
                            reason,
                            effective_at: cmd.now,
                            actor: cmd.actor,
                            authorization_ref: cmd.authorization_ref,
                            now: cmd.now,
                        },
                    )?;
                    obligation_id = Some(id);
                }
            }

            outbox_append(
                tx,
                &format!("epoch-event:{event_seq}"),
                "epoch.standing",
                None,
                None,
                &json!({
                    "event": "epoch.standing", "scope_key": cmd.epoch_id,
                    "kind": cmd.change.as_str(),
                    "prior_state": t.prior.contamination.as_str(),
                    "state": t.new.contamination.as_str(),
                    "retired": i64::from(t.new.retired),
                    "reason": cmd.reason, "actor": cmd.actor, "actor_kind": cmd.actor_kind,
                    "authorization_ref": cmd.authorization_ref, "at": now,
                }),
                now,
            )?;
            Ok(EpochEventOutcome {
                event_seq: from_sql(event_seq),
                prior: t.prior,
                new: t.new,
                changed: t.changed(),
                version: from_sql(version),
                replay: false,
                obligation_id,
            })
        })
    }

    /// Every event of an epoch, oldest first.
    pub fn epoch_events(&self, epoch_id: &str) -> Result<Vec<EpochEventRecord>, StoreError> {
        check_ids(&[epoch_id])?;
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT seq, epoch_id, change, reported, prior_contamination, prior_retired, \
                 new_contamination, new_retired, changed, version_after, actor, actor_kind, \
                 reason, authorization_ref, at FROM epoch_events WHERE epoch_id = ?1 ORDER BY seq",
            )?;
            let rows = stmt.query_map([epoch_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                    r.get::<_, i64>(8)?,
                    r.get::<_, i64>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, String>(13)?,
                    r.get::<_, i64>(14)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (seq, epoch, change, reported, pc, pr, nc, nr, changed, ver, actor, kind, reason, auth, at) =
                    row?;
                out.push(EpochEventRecord {
                    seq: from_sql(seq),
                    epoch_id: epoch,
                    change,
                    reported,
                    prior: parse_standing(&pc, pr)?,
                    new: parse_standing(&nc, nr)?,
                    changed: changed != 0,
                    version_after: from_sql(ver),
                    actor,
                    actor_kind: kind,
                    reason,
                    authorization_ref: auth,
                    at: from_sql(at),
                });
            }
            Ok(out)
        })
    }

    // ---- obligations -----------------------------------------------------------

    /// Record an operator-originated revocation, supersession or
    /// contamination entry the feed must carry. Idempotent per
    /// `obligation_id`. Returns true when it was newly recorded.
    pub fn enqueue_obligation(&self, cmd: &ObligationCommand<'_>) -> Result<bool, StoreError> {
        self.write(FaultOp::ObligationEnqueue, |tx| {
            Ok(insert_obligation(tx, cmd)?.is_some())
        })
    }

    /// Unpublished obligations in order, at most `limit` (1..=128).
    pub fn pending_obligations(&self, limit: u32) -> Result<Vec<ObligationRecord>, StoreError> {
        let limit = i64::from(limit.clamp(1, 128));
        self.read(|tx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {OBLIGATION_COLS} FROM feed_obligations WHERE published_seq IS NULL \
                 ORDER BY seq LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], map_obligation)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    pub fn pending_obligation_count(&self) -> Result<u64, StoreError> {
        self.read(|tx| {
            let n: i64 = tx.query_row(
                "SELECT COUNT(*) FROM feed_obligations WHERE published_seq IS NULL",
                [],
                |r| r.get(0),
            )?;
            Ok(from_sql(n))
        })
    }

    /// Every obligation (published or not) that names one of `targets`. This
    /// is the custodian's own authoritative revocation set: an entry counts
    /// the moment it is recorded, before the feed carries it.
    pub fn obligation_hits(
        &self,
        targets: &[(ObligationTarget, &str)],
    ) -> Result<Vec<ObligationRecord>, StoreError> {
        self.read(|tx| {
            let mut out = Vec::new();
            for (kind, target_ref) in targets {
                let mut stmt = tx.prepare(&format!(
                    "SELECT {OBLIGATION_COLS} FROM feed_obligations \
                     WHERE target_kind = ?1 AND target_ref = ?2 ORDER BY seq"
                ))?;
                let rows = stmt.query_map((kind.as_str(), *target_ref), map_obligation)?;
                for r in rows {
                    out.push(r?);
                }
            }
            Ok(out)
        })
    }

    // ---- feed ------------------------------------------------------------------

    pub fn feed_head(&self, feed_id: &str) -> Result<Option<FeedHead>, StoreError> {
        check_ids(&[feed_id])?;
        self.read(|tx| load_head(tx, feed_id))
    }

    /// Append the next envelope and stamp the obligations it publishes, in
    /// one transaction. `Conflict` when the head moved (another publisher
    /// won the sequence) or an obligation was already published; nothing is
    /// written then. A byte-identical repeat is accepted.
    pub fn append_feed_envelope(&self, cmd: &FeedAppend<'_>) -> Result<(), StoreError> {
        check_ids(&[cmd.feed_id, cmd.digest])?;
        if let Some(p) = cmd.previous_digest {
            check_ids(&[p])?;
        }
        if cmd.document.len() > MAX_DOCUMENT_BYTES
            || cmd.sequence == 0
            || cmd.fresh_until <= cmd.issued_at
            || cmd.obligation_ids.len() > 128
        {
            return Err(StoreError::InvalidInput);
        }
        let seq = sql_time(cmd.sequence)?;
        let issued = sql_time(cmd.issued_at)?;
        let fresh = sql_time(cmd.fresh_until)?;
        let now = sql_time(cmd.now)?;
        self.write(FaultOp::FeedAppend, |tx| {
            let stored: Option<(String, String)> = tx
                .query_row(
                    "SELECT digest, document FROM feed_envelopes \
                     WHERE feed_id = ?1 AND sequence = ?2",
                    (cmd.feed_id, seq),
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((d, doc)) = stored {
                return if d == cmd.digest && doc == cmd.document {
                    Ok(())
                } else {
                    Err(StoreError::Conflict)
                };
            }
            let head = load_head(tx, cmd.feed_id)?;
            let (want_seq, want_prev) = match &head {
                None => (1, None),
                Some(h) => (h.sequence + 1, Some(h.digest.as_str())),
            };
            if cmd.sequence != want_seq || cmd.previous_digest != want_prev {
                return Err(StoreError::Conflict);
            }
            tx.execute(
                "INSERT INTO feed_envelopes (feed_id, sequence, previous_digest, digest, \
                 document, issued_at, fresh_until, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (
                    cmd.feed_id,
                    seq,
                    cmd.previous_digest,
                    cmd.digest,
                    cmd.document,
                    issued,
                    fresh,
                    now,
                ),
            )?;
            for id in cmd.obligation_ids {
                let n = tx.execute(
                    "UPDATE feed_obligations SET published_seq = ?1 \
                     WHERE obligation_id = ?2 AND published_seq IS NULL",
                    (seq, id),
                )?;
                if n != 1 {
                    return Err(StoreError::Conflict);
                }
            }
            outbox_append(
                tx,
                &format!("feed:{}:{}", cmd.feed_id, cmd.sequence),
                "feed.published",
                None,
                None,
                &json!({
                    "event": "feed.published", "scope_key": cmd.feed_id,
                    "feed_sequence": seq, "document_digest": cmd.digest,
                    "units": cmd.obligation_ids.len(), "at": now,
                }),
                now,
            )?;
            Ok(())
        })
    }

    /// Envelopes from `from_sequence` (inclusive) in order, with delivery state.
    pub fn feed_envelopes(
        &self,
        feed_id: &str,
        from_sequence: u64,
    ) -> Result<Vec<FeedEnvelopeRecord>, StoreError> {
        check_ids(&[feed_id])?;
        let from = sql_time(from_sequence.max(1))?;
        self.read(|tx| {
            let mut stmt = tx.prepare(
                "SELECT e.sequence, e.digest, e.document, e.issued_at, e.fresh_until, \
                 d.sequence IS NOT NULL FROM feed_envelopes e \
                 LEFT JOIN feed_deliveries d ON d.feed_id = e.feed_id AND d.sequence = e.sequence \
                 WHERE e.feed_id = ?1 AND e.sequence >= ?2 ORDER BY e.sequence",
            )?;
            let rows = stmt.query_map((feed_id, from), |r| {
                Ok(FeedEnvelopeRecord {
                    sequence: from_sql(r.get(0)?),
                    digest: r.get(1)?,
                    document: r.get(2)?,
                    issued_at: from_sql(r.get(3)?),
                    fresh_until: from_sql(r.get(4)?),
                    delivered: r.get::<_, i64>(5)? != 0,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// Record that the destination confirmed envelope `sequence`. Idempotent.
    /// Deliveries must be in order: sequence N needs N-1 delivered first, so
    /// a consumer never sees a gap the publisher created.
    pub fn mark_feed_delivered(
        &self,
        feed_id: &str,
        sequence: u64,
        destination: &str,
        now: u64,
    ) -> Result<(), StoreError> {
        check_ids(&[feed_id, destination])?;
        let seq = sql_time(sequence)?;
        let now = sql_time(now)?;
        self.write(FaultOp::FeedDelivered, |tx| {
            let exists: i64 = tx.query_row(
                "SELECT COUNT(*) FROM feed_envelopes WHERE feed_id = ?1 AND sequence = ?2",
                (feed_id, seq),
                |r| r.get(0),
            )?;
            if exists != 1 {
                return Err(StoreError::NotFound);
            }
            let done: i64 = tx.query_row(
                "SELECT COUNT(*) FROM feed_deliveries WHERE feed_id = ?1 AND sequence = ?2",
                (feed_id, seq),
                |r| r.get(0),
            )?;
            if done == 1 {
                return Ok(());
            }
            if seq > 1 {
                let prev: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM feed_deliveries WHERE feed_id = ?1 AND sequence = ?2",
                    (feed_id, seq - 1),
                    |r| r.get(0),
                )?;
                if prev != 1 {
                    return Err(StoreError::InvalidTransition);
                }
            }
            tx.execute(
                "INSERT INTO feed_deliveries (feed_id, sequence, destination, delivered_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                (feed_id, seq, destination, now),
            )?;
            outbox_append(
                tx,
                &format!("feed-delivered:{feed_id}:{sequence}"),
                "feed.delivered",
                None,
                None,
                &json!({
                    "event": "feed.delivered", "scope_key": feed_id,
                    "feed_sequence": seq, "destination": destination, "at": now,
                }),
                now,
            )?;
            Ok(())
        })
    }

    // ---- rotation --------------------------------------------------------------

    /// Link a retired epoch to its successor. Never edits either epoch and
    /// never touches a budget: the successor's budget scope key is its own.
    /// The predecessor must already be retired in the store; the successor
    /// must not be blocked. Returns true when newly recorded, false for an
    /// identical repeat; a different link for either epoch is
    /// `IdentityConflict`.
    pub fn record_rotation(&self, cmd: &RotationCommand<'_>) -> Result<bool, StoreError> {
        check_ids(&[
            cmd.predecessor,
            cmd.successor,
            cmd.corpus_id,
            cmd.actor,
            cmd.authorization_ref,
        ])?;
        if let Some(f) = cmd.family_id {
            check_ids(&[f])?;
        }
        if cmd.predecessor == cmd.successor {
            return Err(StoreError::InvalidInput);
        }
        let now = sql_time(cmd.now)?;
        self.write(FaultOp::RecordRotation, |tx| {
            let pred = load_standing(tx, cmd.predecessor)?.ok_or(StoreError::InvalidTransition)?;
            if !pred.standing.retired
                || pred.corpus_id != cmd.corpus_id
                || pred.family_id.as_deref() != cmd.family_id
            {
                return Err(StoreError::InvalidTransition);
            }
            if let Some(s) = load_standing(tx, cmd.successor)? {
                if !s.standing.usable() {
                    return Err(StoreError::EpochBlocked);
                }
            }
            let existing: Option<(String, String)> = tx
                .query_row(
                    "SELECT successor_epoch, predecessor_epoch FROM epoch_rotations \
                     WHERE successor_epoch = ?1 OR predecessor_epoch = ?2",
                    (cmd.successor, cmd.predecessor),
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((s, p)) = existing {
                return if s == cmd.successor && p == cmd.predecessor {
                    Ok(false)
                } else {
                    Err(StoreError::IdentityConflict)
                };
            }
            tx.execute(
                "INSERT INTO epoch_rotations (successor_epoch, predecessor_epoch, corpus_id, \
                 family_id, actor, authorization_ref, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    cmd.successor,
                    cmd.predecessor,
                    cmd.corpus_id,
                    cmd.family_id,
                    cmd.actor,
                    cmd.authorization_ref,
                    now,
                ),
            )?;
            outbox_append(
                tx,
                &format!("epoch-rotated:{}", cmd.successor),
                "epoch.rotated",
                None,
                None,
                &json!({
                    "event": "epoch.rotated", "scope_key": cmd.predecessor,
                    "successor_epoch": cmd.successor, "actor": cmd.actor,
                    "authorization_ref": cmd.authorization_ref, "at": now,
                }),
                now,
            )?;
            Ok(true)
        })
    }

    /// The successor of a retired epoch, if a rotation was recorded.
    pub fn successor_of(&self, predecessor: &str) -> Result<Option<String>, StoreError> {
        check_ids(&[predecessor])?;
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT successor_epoch FROM epoch_rotations WHERE predecessor_epoch = ?1",
                    [predecessor],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// Consistency checks for the C9 tables, in addition to
    /// [`SqliteStore::verify_invariants`]: every standing row equals the
    /// fold of its events, every event has its audit outbox event, the feed
    /// is contiguous, and every published obligation names an existing
    /// envelope.
    pub fn verify_lifecycle_invariants(&self) -> Result<(), StoreError> {
        self.read(|tx| {
            let skewed: i64 = tx.query_row(
                "SELECT COUNT(*) FROM epoch_standing s WHERE s.version <> \
                 (SELECT COUNT(*) FROM epoch_events e WHERE e.epoch_id = s.epoch_id AND e.changed = 1)",
                [],
                |r| r.get(0),
            )?;
            if skewed != 0 {
                return Err(StoreError::Invariant("epoch_version_counts_changes"));
            }
            let mismatched: i64 = tx.query_row(
                "SELECT COUNT(*) FROM epoch_standing s WHERE \
                 s.contamination <> COALESCE((SELECT e.new_contamination FROM epoch_events e \
                   WHERE e.epoch_id = s.epoch_id ORDER BY e.seq DESC LIMIT 1), '') \
                 OR s.retired <> COALESCE((SELECT e.new_retired FROM epoch_events e \
                   WHERE e.epoch_id = s.epoch_id ORDER BY e.seq DESC LIMIT 1), -1)",
                [],
                |r| r.get(0),
            )?;
            if mismatched != 0 {
                return Err(StoreError::Invariant("epoch_standing_matches_events"));
            }
            let unaudited: i64 = tx.query_row(
                "SELECT COUNT(*) FROM epoch_events e WHERE NOT EXISTS \
                 (SELECT 1 FROM outbox o WHERE o.event_id = 'epoch-event:' || e.seq)",
                [],
                |r| r.get(0),
            )?;
            if unaudited != 0 {
                return Err(StoreError::Invariant("epoch_event_audited"));
            }
            let unaudited_obl: i64 = tx.query_row(
                "SELECT COUNT(*) FROM feed_obligations f WHERE NOT EXISTS \
                 (SELECT 1 FROM outbox o WHERE o.event_id = 'obligation:' || f.obligation_id)",
                [],
                |r| r.get(0),
            )?;
            if unaudited_obl != 0 {
                return Err(StoreError::Invariant("obligation_audited"));
            }
            let dangling: i64 = tx.query_row(
                "SELECT COUNT(*) FROM feed_obligations f WHERE f.published_seq IS NOT NULL AND \
                 NOT EXISTS (SELECT 1 FROM feed_envelopes e WHERE e.sequence = f.published_seq)",
                [],
                |r| r.get(0),
            )?;
            if dangling != 0 {
                return Err(StoreError::Invariant("obligation_published_in_envelope"));
            }
            let gaps: i64 = tx.query_row(
                "SELECT COUNT(*) FROM (SELECT feed_id, COUNT(*) AS n, MAX(sequence) AS m \
                 FROM feed_envelopes GROUP BY feed_id) WHERE n <> m",
                [],
                |r| r.get(0),
            )?;
            if gaps != 0 {
                return Err(StoreError::Invariant("feed_contiguous"));
            }
            Ok(())
        })
    }
}

fn load_head(tx: &Connection, feed_id: &str) -> Result<Option<FeedHead>, StoreError> {
    Ok(tx
        .query_row(
            "SELECT sequence, digest, issued_at, fresh_until FROM feed_envelopes \
             WHERE feed_id = ?1 ORDER BY sequence DESC LIMIT 1",
            [feed_id],
            |r| {
                Ok(FeedHead {
                    sequence: from_sql(r.get(0)?),
                    digest: r.get(1)?,
                    issued_at: from_sql(r.get(2)?),
                    fresh_until: from_sql(r.get(3)?),
                })
            },
        )
        .optional()?)
}

fn replay_event(tx: &Connection, seq: i64) -> Result<EpochEventOutcome, StoreError> {
    let (epoch, pc, pr, nc, nr, changed, version): (String, String, i64, String, i64, i64, i64) =
        tx.query_row(
            "SELECT epoch_id, prior_contamination, prior_retired, new_contamination, new_retired, \
             changed, version_after FROM epoch_events WHERE seq = ?1",
            [seq],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )?;
    let prior = parse_standing(&pc, pr)?;
    let new = parse_standing(&nc, nr)?;
    let t = custodian_core::standing::Transition { prior, new };
    let obligation_id = evidence_effect(&t)
        .filter(|_| changed != 0)
        .map(|e| obligation_id_for(&epoch, version, e));
    Ok(EpochEventOutcome {
        event_seq: from_sql(seq),
        prior,
        new,
        changed: changed != 0,
        version: from_sql(version),
        replay: true,
        obligation_id,
    })
}
