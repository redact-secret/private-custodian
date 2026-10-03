//! Ledger walker: verifies a whole ledger from public keys and pinned roots
//! (ADR 0051, ADR 0054). It needs no private key, no database and no
//! scanner. A clean walk means every record is well formed, canonical,
//! correctly identified and validly signed, audit events form a gap-free
//! hash chain, and corrections reference real records exactly once. It does
//! not prove the ledger is complete or that history was not rewritten.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::types::DocumentDigest;
use custodian_store::Checkpoint;
use sha2::{Digest, Sha256};

use crate::b64::hex;
use crate::backend::{BackendError, LedgerBackend};
use crate::keys::{Keyring, KeyringError, Verifier, VerifyError};
use crate::record::{RecordBody, RecordKind, SignedLedgerRecord};

const GENESIS_CHAIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Outbox chain step. Must equal `custodian-store`'s construction (ADR 0022);
/// `tests/exporter.rs` (a clean walk of a real store export) checks it.
pub fn outbox_chain_step(prev: &str, seq: u64, payload_digest: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/store/outbox-chain/v1\0");
    h.update(prev.as_bytes());
    h.update([0]);
    h.update(seq.to_string().as_bytes());
    h.update([0]);
    h.update(payload_digest.as_bytes());
    hex(&h.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FindingCode {
    Malformed,
    PathMismatch,
    BadSignature(VerifyError),
    KeyEventRejected(KeyringError),
    SeqGap,
    ChainMismatch,
    /// Two valid records disagree about the same sequence or event count.
    CheckpointFork,
    SupersedesMissing,
    SupersessionFork,
    /// A correction of an audit event changed its sequence or chain value.
    SupersessionChangedChain,
    /// Records exist under `quarantine/`: an export conflict awaits review.
    /// Not an integrity failure of the records themselves.
    QuarantinePresent,
    /// The record is signed by a revoked key, and a record signed by a
    /// currently trusted key re-attests exactly the same body (R-4, ADR 0131).
    /// The old record stays in the ledger as the marked, superseded lineage;
    /// it is not an integrity failure. A revoked-key record with no such
    /// re-attestation is `BadSignature(KeyRevoked)` and stays blocking.
    RevokedSuperseded,
}

impl FindingCode {
    /// Findings that do not make the ledger untrustworthy.
    pub fn is_informational(self) -> bool {
        matches!(self, Self::QuarantinePresent | Self::RevokedSuperseded)
    }
}

/// One effective (valid, not superseded) audit record, in the shape the
/// recovery tools need (R-1, R-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: u64,
    pub record_id: String,
    pub event_id: String,
    pub kind: String,
    pub chain: String,
    pub payload_digest: String,
    pub payload_exact: bool,
    pub issued_at: u64,
    pub payload: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub code: FindingCode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryPoint {
    pub head: DocumentDigest,
    pub event_count: u64,
}

#[derive(Clone, Debug)]
pub struct WalkReport {
    pub records: usize,
    pub findings: Vec<Finding>,
    pub quarantined: Vec<String>,
    /// Newest valid (seq, chain) from audit and store-checkpoint records.
    pub store_checkpoint: Option<Checkpoint>,
    pub registry_checkpoint: Option<RegistryPoint>,
    /// Roots plus every key event that verified.
    pub keyring: Keyring,
    /// Effective audit records in sequence order (valid and not superseded).
    pub audit: Vec<AuditEntry>,
    /// Records signed by a revoked key, whether or not they were re-attested.
    pub revoked: Vec<RevokedRecord>,
    /// Issue times (seconds) of every decoded key event, for the same-second
    /// rule (R-5).
    pub key_event_times: BTreeSet<u64>,
}

/// A record whose signing key is revoked (R-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokedRecord {
    pub path: String,
    pub record: SignedLedgerRecord,
    /// A valid record re-attests exactly this body (the marked old lineage).
    pub reattested: bool,
}

impl WalkReport {
    /// No integrity finding. Quarantined records alone do not make the
    /// ledger untrustworthy; they need review.
    pub fn is_trustworthy(&self) -> bool {
        self.findings.iter().all(|f| f.code.is_informational())
    }
}

fn republishes_same_key(keyring: &Keyring, body: &RecordBody) -> bool {
    let RecordBody::KeyEvent(ev) = body else {
        return false;
    };
    let Some(existing) = keyring.get(&ev.key_id) else {
        return false;
    };
    ev.public_key
        .as_deref()
        .and_then(crate::b64::unhex32)
        .is_some_and(|pk| pk == existing.public_key)
}

fn parse_record_path(path: &str) -> Option<(RecordKind, &str)> {
    let rest = path.strip_prefix("records/")?;
    let (dir, file) = rest.split_once('/')?;
    let id = file.strip_suffix(".json")?;
    let kind = RecordKind::ALL.into_iter().find(|k| k.dir() == dir)?;
    (RecordKind::of_id(id) == Some(kind)).then_some((kind, id))
}

/// Walk and verify the whole ledger. `Err` only when the backend cannot be
/// read; all content problems are findings.
pub fn walk_ledger(
    backend: &dyn LedgerBackend,
    roots: &Keyring,
) -> Result<WalkReport, BackendError> {
    backend.refresh()?;
    let mut findings: Vec<Finding> = Vec::new();
    let mut find = |path: &str, code: FindingCode| {
        findings.push(Finding {
            path: path.to_owned(),
            code,
        })
    };

    // 1. Load and decode.
    let mut decoded: Vec<(String, SignedLedgerRecord)> = Vec::new();
    for path in backend.list("records")? {
        let p = path.as_str().to_owned();
        let Some((kind, id)) = parse_record_path(&p) else {
            find(&p, FindingCode::PathMismatch);
            continue;
        };
        let Some(bytes) = backend.get(&path)? else {
            find(&p, FindingCode::Malformed);
            continue;
        };
        match SignedLedgerRecord::decode_canonical(&bytes) {
            Ok(rec) if rec.payload.kind() == kind && rec.payload.record_id == id => {
                decoded.push((p, rec));
            }
            Ok(_) => find(&p, FindingCode::PathMismatch),
            Err(_) => find(&p, FindingCode::Malformed),
        }
    }

    // 2. Build the keyring from pinned roots and verified key events.
    let mut keyring = roots.clone();
    let mut key_events: Vec<&(String, SignedLedgerRecord)> = decoded
        .iter()
        .filter(|(_, r)| r.payload.kind() == RecordKind::KeyEvent)
        .collect();
    key_events.sort_by(|a, b| {
        (a.1.payload.issued_at, &a.1.payload.record_id)
            .cmp(&(b.1.payload.issued_at, &b.1.payload.record_id))
    });
    let key_event_times: BTreeSet<u64> = key_events
        .iter()
        .map(|(_, r)| r.payload.issued_at.secs())
        .collect();
    for (p, rec) in key_events {
        if let Err(e) = keyring.apply_key_event(rec) {
            // A key pinned as a root and also published in the ledger (the
            // recovery case, R-4) re-announces the same public key: that
            // changes nothing and is not a rejection. A different key under
            // a known id still is.
            if e == KeyringError::KeyAlreadyKnown
                && republishes_same_key(&keyring, &rec.payload.body)
            {
                continue;
            }
            find(p, FindingCode::KeyEventRejected(e));
        }
    }

    // 3. Verify every signature against the final keyring.
    let verifier = Verifier::new(keyring.clone());
    let mut valid: Vec<&(String, SignedLedgerRecord)> = Vec::new();
    // Records whose only problem is a revoked signing key: judged after
    // supersession is known (R-4).
    let mut revoked: Vec<&(String, SignedLedgerRecord)> = Vec::new();
    for item in &decoded {
        match verifier.verify_ledger_record(&item.1) {
            Ok(()) => valid.push(item),
            Err(VerifyError::KeyRevoked) => revoked.push(item),
            Err(e) => find(&item.0, FindingCode::BadSignature(e)),
        }
    }

    // 4. Supersession: targets exist, exactly one correction per target.
    let all_ids: BTreeSet<&str> = decoded
        .iter()
        .map(|(_, r)| r.payload.record_id.as_str())
        .collect();
    let by_id: BTreeMap<&str, &SignedLedgerRecord> = decoded
        .iter()
        .map(|(_, r)| (r.payload.record_id.as_str(), r))
        .collect();
    let mut superseded: BTreeSet<&str> = BTreeSet::new();
    let mut superseder_of: BTreeMap<&str, &SignedLedgerRecord> = BTreeMap::new();
    for (p, rec) in &valid {
        if let Some(target) = rec.payload.supersedes.as_deref() {
            if !all_ids.contains(target) {
                find(p, FindingCode::SupersedesMissing);
            } else if !superseded.insert(target) {
                find(p, FindingCode::SupersessionFork);
            } else {
                superseder_of.insert(target, rec);
                if let (RecordBody::AuditEvent(new), Some(old)) =
                    (&rec.payload.body, by_id.get(target))
                {
                    if let RecordBody::AuditEvent(old) = &old.payload.body {
                        if old.seq != new.seq || old.chain != new.chain {
                            find(p, FindingCode::SupersessionChangedChain);
                        }
                    }
                }
            }
        }
    }

    // 4b. Revoked-key records: re-attested exactly (same issue time, same
    // body) by a valid superseding record are the marked old lineage;
    // everything else stays a blocking finding.
    let mut revoked_out: Vec<RevokedRecord> = Vec::new();
    for (p, rec) in &revoked {
        let reattested = superseder_of
            .get(rec.payload.record_id.as_str())
            .is_some_and(|s| {
                s.payload.body == rec.payload.body && s.payload.issued_at == rec.payload.issued_at
            });
        revoked_out.push(RevokedRecord {
            path: p.clone(),
            record: rec.clone(),
            reattested,
        });
        find(
            p,
            if reattested {
                FindingCode::RevokedSuperseded
            } else {
                FindingCode::BadSignature(VerifyError::KeyRevoked)
            },
        );
    }

    // 5. Audit chain over effective (not superseded) valid audit records.
    let mut audit: Vec<(&str, u64, &str, &str)> = valid
        .iter()
        .filter_map(|(p, r)| match &r.payload.body {
            RecordBody::AuditEvent(b) if !superseded.contains(r.payload.record_id.as_str()) => {
                Some((
                    p.as_str(),
                    b.seq,
                    b.chain.as_str(),
                    b.payload_digest.as_str(),
                ))
            }
            _ => None,
        })
        .collect();
    audit.sort_by_key(|a| (a.1, a.0));
    let mut prev_chain = GENESIS_CHAIN.to_owned();
    let mut expected = 1u64;
    let mut last_seq: Option<u64> = None;
    for (p, seq, chain, digest) in audit {
        if last_seq == Some(seq) {
            find(p, FindingCode::CheckpointFork);
            continue;
        }
        last_seq = Some(seq);
        if seq != expected {
            find(p, FindingCode::SeqGap);
            // Cannot recompute across a gap; resynchronize on the record.
            prev_chain = chain.to_owned();
            expected = seq + 1;
            continue;
        }
        if outbox_chain_step(&prev_chain, seq, digest) != chain {
            find(p, FindingCode::ChainMismatch);
        }
        prev_chain = chain.to_owned();
        expected = seq + 1;
    }

    // 6. Checkpoints: newest valid position, and no two records disagreeing.
    let mut store_points: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    let mut registry_points: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
    for (_, r) in &valid {
        match &r.payload.body {
            RecordBody::AuditEvent(b) => {
                store_points.entry(b.seq).or_default().insert(&b.chain);
            }
            RecordBody::StoreCheckpoint(b) => {
                store_points.entry(b.seq).or_default().insert(&b.chain);
            }
            RecordBody::RegistryCheckpoint(b) => {
                registry_points
                    .entry(b.event_count)
                    .or_default()
                    .insert(b.head.as_str());
            }
            _ => {}
        }
    }
    for (seq, chains) in &store_points {
        if chains.len() > 1 {
            find(&format!("seq:{seq}"), FindingCode::CheckpointFork);
        }
    }
    for (count, heads) in &registry_points {
        if heads.len() > 1 {
            find(&format!("registry:{count}"), FindingCode::CheckpointFork);
        }
    }
    let store_checkpoint = store_points.iter().next_back().and_then(|(seq, chains)| {
        (chains.len() == 1).then(|| Checkpoint {
            seq: *seq,
            chain: chains
                .iter()
                .next()
                .map(|c| (*c).to_owned())
                .unwrap_or_default(),
        })
    });
    let registry_checkpoint = registry_points
        .iter()
        .next_back()
        .and_then(|(count, heads)| {
            if heads.len() != 1 {
                return None;
            }
            let head = heads.iter().next()?;
            valid.iter().find_map(|(_, r)| match &r.payload.body {
                RecordBody::RegistryCheckpoint(b)
                    if b.event_count == *count && b.head.as_str() == *head =>
                {
                    Some(RegistryPoint {
                        head: b.head.clone(),
                        event_count: b.event_count,
                    })
                }
                _ => None,
            })
        });

    // 7. Quarantine listing.
    let mut quarantined = BTreeSet::new();
    for path in backend.list("quarantine")? {
        if let Some(id) = path.as_str().split('/').nth(1) {
            quarantined.insert(id.to_owned());
        }
    }
    for id in &quarantined {
        find(&format!("quarantine/{id}"), FindingCode::QuarantinePresent);
    }

    let mut audit_entries: Vec<AuditEntry> = valid
        .iter()
        .filter_map(|(_, r)| match &r.payload.body {
            RecordBody::AuditEvent(b) if !superseded.contains(r.payload.record_id.as_str()) => {
                Some(AuditEntry {
                    seq: b.seq,
                    record_id: r.payload.record_id.clone(),
                    event_id: b.event_id.clone(),
                    kind: b.kind.clone(),
                    chain: b.chain.clone(),
                    payload_digest: b.payload_digest.clone(),
                    payload_exact: b.payload_exact,
                    issued_at: r.payload.issued_at.secs(),
                    payload: b.payload.clone(),
                })
            }
            _ => None,
        })
        .collect();
    audit_entries.sort_by(|a, b| (a.seq, &a.record_id).cmp(&(b.seq, &b.record_id)));

    let records = decoded.len();
    Ok(WalkReport {
        records,
        findings,
        quarantined: quarantined.into_iter().collect(),
        store_checkpoint,
        registry_checkpoint,
        keyring,
        audit: audit_entries,
        revoked: revoked_out,
        key_event_times,
    })
}
