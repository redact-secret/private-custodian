//! Audit outbox: durable export intents written in the same transaction as the
//! state they describe, with a hash chain and an idempotent acknowledgement.
//!
//! The outbox is the producer side only. C7 owns signing and the private
//! ledger write; it reads [`SqliteStore::outbox_pending`], exports, and calls
//! [`SqliteStore::outbox_ack`]. A failed or missing export leaves the row
//! pending; nothing in the store treats "export not done" as permission to
//! disclose (see [`SqliteStore::check_disclosure_precondition`]).

use custodian_core::ports::Refusal;
use custodian_core::{ActorId, ReasonCode, RunId, RunState};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::StoreError;
use crate::fault::FaultOp;
use crate::migrations::hex;
use crate::model::{AckOutcome, Checkpoint, OutboxEvent};
use crate::store::{from_sql, reconcile_flag, sql_time, SqliteStore};

pub(crate) const GENESIS_CHAIN: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub(crate) fn chain_of(prev: &str, seq: i64, payload_digest: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/store/outbox-chain/v1\0");
    h.update(prev.as_bytes());
    h.update([0]);
    h.update(seq.to_string().as_bytes());
    h.update([0]);
    h.update(payload_digest.as_bytes());
    hex(&h.finalize())
}

/// Append an event, or return the sequence of the event already stored under
/// `event_id` (deterministic ids make re-delivery harmless). Runs inside the
/// caller's write transaction, so the row commits with the state it describes.
pub(crate) fn outbox_append(
    tx: &Connection,
    event_id: &str,
    kind: &str,
    request_id: Option<&str>,
    attempt_id: Option<&str>,
    payload: &Value,
    now: i64,
) -> Result<i64, StoreError> {
    if let Some(seq) = tx
        .query_row(
            "SELECT seq FROM outbox WHERE event_id = ?1",
            [event_id],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
    {
        return Ok(seq);
    }
    let (prev_seq, prev_chain): (i64, String) = tx
        .query_row(
            "SELECT seq, chain FROM outbox ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((0, GENESIS_CHAIN.to_owned()));
    let seq = prev_seq + 1;
    let body = payload.to_string();
    let digest = hex(&Sha256::digest(body.as_bytes()));
    let chain = chain_of(&prev_chain, seq, &digest);
    tx.execute(
        "INSERT INTO outbox (seq, event_id, kind, request_id, attempt_id, payload, \
         payload_digest, chain, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        (
            seq, event_id, kind, request_id, attempt_id, &body, &digest, &chain, now,
        ),
    )?;
    Ok(seq)
}

const OUTBOX_COLS: &str = "seq, event_id, kind, request_id, attempt_id, payload, payload_digest, \
     chain, created_at, exported_at, export_ref";

fn map_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<OutboxEvent> {
    Ok(OutboxEvent {
        seq: from_sql(r.get(0)?),
        event_id: r.get(1)?,
        kind: r.get(2)?,
        request_id: r.get(3)?,
        attempt_id: r.get(4)?,
        payload: r.get(5)?,
        payload_digest: r.get(6)?,
        chain: r.get(7)?,
        created_at: from_sql(r.get(8)?),
        exported_at: r.get::<_, Option<i64>>(9)?.map(from_sql),
        export_ref: r.get(10)?,
    })
}

fn valid_export_ref(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
}

impl SqliteStore {
    /// Unacknowledged events in sequence order, at most `limit` (clamped to
    /// 1..=1000). Reading never changes anything.
    pub fn outbox_pending(&self, limit: u32) -> Result<Vec<OutboxEvent>, StoreError> {
        let limit = i64::from(limit.clamp(1, 1000));
        self.read(|tx| {
            let mut stmt = tx.prepare(&format!(
                "SELECT {OUTBOX_COLS} FROM outbox WHERE exported_at IS NULL \
                 ORDER BY seq LIMIT ?1"
            ))?;
            let rows = stmt.query_map([limit], map_event)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    pub fn outbox_event(&self, seq: u64) -> Result<Option<OutboxEvent>, StoreError> {
        let seq = sql_time(seq)?;
        self.read(|tx| {
            Ok(tx
                .query_row(
                    &format!("SELECT {OUTBOX_COLS} FROM outbox WHERE seq = ?1"),
                    [seq],
                    map_event,
                )
                .optional()?)
        })
    }

    /// Acknowledge a durable export of event `seq` under `export_ref` (an
    /// opaque reference to the signed ledger entry). Idempotent: repeating the
    /// same ack is `AlreadyAcked`; acknowledging with a different reference is
    /// refused rather than overwritten.
    pub fn outbox_ack(
        &self,
        seq: u64,
        export_ref: &str,
        now: u64,
    ) -> Result<AckOutcome, StoreError> {
        if !valid_export_ref(export_ref) {
            return Err(StoreError::InvalidInput);
        }
        let seq_i = sql_time(seq)?;
        let now_i = sql_time(now)?;
        self.write(FaultOp::OutboxAck, |tx| {
            let current: Option<Option<String>> = tx
                .query_row(
                    "SELECT export_ref FROM outbox WHERE seq = ?1",
                    [seq_i],
                    |r| r.get(0),
                )
                .optional()?;
            match current {
                None => Err(StoreError::NotFound),
                Some(Some(existing)) if existing == export_ref => Ok(AckOutcome::AlreadyAcked),
                Some(Some(_)) => Err(StoreError::IdentityConflict),
                Some(None) => {
                    tx.execute(
                        "UPDATE outbox SET exported_at = ?1, export_ref = ?2 WHERE seq = ?3",
                        (now_i, export_ref, seq_i),
                    )?;
                    Ok(AckOutcome::Acked)
                }
            }
        })
    }

    /// Position of the newest outbox event. Record this in the private
    /// ledger with each export; compare it after a restore.
    pub fn latest_checkpoint(&self) -> Result<Option<Checkpoint>, StoreError> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT seq, chain FROM outbox ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| {
                        Ok(Checkpoint {
                            seq: from_sql(r.get(0)?),
                            chain: r.get(1)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    /// Compare this database to a checkpoint held outside it (the private
    /// ledger). If the checkpoint's event is absent or its chain value
    /// differs, this database is older than, or diverged from, what was
    /// already exported: consumed budget may be understated. The store then
    /// persists a `needs_reconcile` block that refuses every write until
    /// [`SqliteStore::clear_reconcile`] is called by an operator.
    pub fn verify_external_checkpoint(&self, cp: &Checkpoint) -> Result<(), StoreError> {
        let seq = sql_time(cp.seq)?;
        let mut guard = self.lock();
        let tx = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let chain: Option<String> = tx
            .query_row("SELECT chain FROM outbox WHERE seq = ?1", [seq], |r| {
                r.get(0)
            })
            .optional()?;
        if chain.as_deref() == Some(cp.chain.as_str()) {
            let blocked = reconcile_flag(&tx)?;
            tx.commit()?;
            return if blocked {
                Err(StoreError::NeedsReconcile)
            } else {
                Ok(())
            };
        }
        tx.execute(
            "UPDATE meta SET value = '1' WHERE key = 'needs_reconcile'",
            [],
        )?;
        tx.commit()?;
        Err(StoreError::NeedsReconcile)
    }

    pub fn needs_reconcile(&self) -> Result<bool, StoreError> {
        self.read(|tx| reconcile_flag(tx))
    }

    /// Operator acknowledgement that a restored database was reconciled with
    /// the ledger (consumed budget raised to at least the exported figures by
    /// a reviewed procedure). Recorded in the outbox.
    pub fn clear_reconcile(&self, actor: &ActorId, now: u64) -> Result<(), StoreError> {
        let now_i = sql_time(now)?;
        self.write(FaultOp::Reconcile, |tx| {
            tx.execute(
                "UPDATE meta SET value = '0' WHERE key = 'needs_reconcile'",
                [],
            )?;
            let n: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM outbox", [], |r| {
                r.get(0)
            })?;
            outbox_append(
                tx,
                &format!("reconcile-cleared:{n}"),
                "store.reconciled",
                None,
                None,
                &json!({"event": "store.reconciled", "actor": actor.as_str(), "at": now_i}),
                now_i,
            )?;
            Ok(())
        })
    }

    /// Precondition a disclosure step must check before preparing or
    /// releasing anything from this attempt: it completed, settled, and its
    /// terminal audit event was durably exported. Export failure keeps the
    /// event pending, so this stays closed. It is necessary, never
    /// sufficient: approval and disclosure policy (C8) still apply.
    pub fn check_disclosure_precondition(&self, attempt: &RunId) -> Result<(), Refusal> {
        let refuse = Refusal(ReasonCode::DisclosureNotPermitted);
        let ok = self
            .read(|tx| {
                let state: Option<String> = tx
                    .query_row(
                        "SELECT state FROM attempts WHERE attempt_id = ?1",
                        [attempt.as_str()],
                        |r| r.get(0),
                    )
                    .optional()?;
                if state.as_deref() != Some(crate::model::state_str(RunState::Completed)) {
                    return Ok(false);
                }
                let settled: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM settlements WHERE attempt_id = ?1",
                    [attempt.as_str()],
                    |r| r.get(0),
                )?;
                let exported: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM outbox WHERE event_id = ?1 AND exported_at IS NOT NULL",
                    [format!("terminal:{}", attempt.as_str())],
                    |r| r.get(0),
                )?;
                Ok(settled == 1 && exported == 1 && !reconcile_flag(tx)?)
            })
            .map_err(|_| refuse)?;
        if ok {
            Ok(())
        } else {
            Err(refuse)
        }
    }
}
