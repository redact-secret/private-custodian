//! The public revocation feed: building, signing, persisting and delivering
//! envelopes, and the destination contract (ADR 0072).
//!
//! # Public feed shape
//!
//! A feed is a sequence of `SignedRevocationEnvelope` documents (the C2
//! contract, schema `private-custodian.revocation-envelope/1`), one per file:
//!
//! ```text
//! <feed_id>/0000000001.json      canonical JSON bytes, nothing else
//! <feed_id>/0000000002.json
//! ...
//! ```
//!
//! Sequences are 1-based, contiguous and zero-padded to ten digits. A file is
//! written once and never changed or removed. There is no index and no mutable
//! "latest" pointer: a consumer asks for `known + 1`, then `known + 2`, until
//! a sequence is absent. The newest envelope's `fresh_until` bounds how long
//! the consumer may trust "nothing else is revoked"; the publisher renews it
//! with an empty envelope. Entries carry public identifiers only (projection,
//! receipt, candidate digest, public population reference, policy reference),
//! a fixed action, a fixed reason and a time. No corpus detail, epoch or
//! family identity, case identity, budget or actor appears.
//!
//! # Destination contract
//!
//! A [`FeedDestination`] stores bytes under `(feed_id, sequence)` with
//! create-if-absent semantics: an identical repeat succeeds, different bytes
//! for an existing sequence are refused. It must be readable by consumers
//! without access to the private ledger or the runtime store, and it must not
//! hold anything but these documents. Writes are made in order; the publisher
//! never writes sequence N+1 before N is confirmed.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use custodian_contracts::canonical::{to_canonical_bytes, Contract};
use custodian_contracts::common::PolicyRef;
use custodian_contracts::public::{FeedRef, PublicPopulationRef};
use custodian_contracts::revocation::{
    PublicRevocationReason, RevocationAction, RevocationEntry, RevocationEnvelope,
    RevocationSchema, RevocationTarget, SignedRevocationEnvelope,
};
use custodian_contracts::types::{
    BoundedVec, CandidateDigest, Count, DestinationId, DocumentDigest, EpochId, FeedId,
    ProjectionId, ReceiptId, Timestamp,
};
use custodian_corpus::Registry as CorpusRegistry;
use custodian_disclosure::PublicPopulationNames;
use custodian_ledger::{ApprovedPayload, SignRefusal, Signer};
use custodian_store::{
    FeedAppend, ObligationAction, ObligationCommand, ObligationRecord, ObligationTarget,
    SqliteStore, StoreError,
};

use crate::authority::{authorize, OperatorAction, OperatorAuthority, OperatorAuthorization};
use crate::eligibility::{parse_policy_key, policy_ref_key};
use crate::fault::{LifecycleFault, LifecyclePoint};
use crate::reason::{from_store, LifecycleReason as R, Result};

/// File name of a sequence at a destination.
pub fn envelope_file_name(sequence: u64) -> String {
    format!("{sequence:010}.json")
}

// ---- destination and source ----------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    /// The destination already held exactly these bytes.
    Identical,
}

/// Where signed envelopes are published (write side).
pub trait FeedDestination: Send + Sync {
    fn put(&self, feed: &FeedId, sequence: u64, bytes: &[u8]) -> Result<PutOutcome>;
}

/// Where a consumer fetches envelopes (read side). `None` when absent.
pub trait FeedSource: Send + Sync {
    fn get(&self, feed: &FeedId, sequence: u64) -> Result<Option<Vec<u8>>>;
}

/// In-memory destination and source, for tests and examples.
#[derive(Default)]
pub struct MemoryFeed {
    files: Mutex<BTreeMap<(String, u64), Vec<u8>>>,
    fail_puts: Mutex<bool>,
}

impl MemoryFeed {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make every `put` fail (destination outage).
    pub fn set_unavailable(&self, down: bool) {
        if let Ok(mut g) = self.fail_puts.lock() {
            *g = down;
        }
    }

    pub fn sequences(&self, feed: &FeedId) -> Vec<u64> {
        self.files
            .lock()
            .map(|g| {
                g.keys()
                    .filter(|(f, _)| f == feed.as_str())
                    .map(|(_, s)| *s)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Insert bytes directly, as an attacker or a broken publisher might.
    pub fn force(&self, feed: &FeedId, sequence: u64, bytes: Vec<u8>) {
        if let Ok(mut g) = self.files.lock() {
            g.insert((feed.as_str().to_owned(), sequence), bytes);
        }
    }

    /// Remove a sequence, as a gap-producing fault would.
    pub fn remove(&self, feed: &FeedId, sequence: u64) {
        if let Ok(mut g) = self.files.lock() {
            g.remove(&(feed.as_str().to_owned(), sequence));
        }
    }
}

impl FeedDestination for MemoryFeed {
    fn put(&self, feed: &FeedId, sequence: u64, bytes: &[u8]) -> Result<PutOutcome> {
        if *self
            .fail_puts
            .lock()
            .map_err(|_| R::DestinationUnavailable)?
        {
            return Err(R::DestinationUnavailable);
        }
        let mut g = self.files.lock().map_err(|_| R::DestinationUnavailable)?;
        match g.get(&(feed.as_str().to_owned(), sequence)) {
            None => {
                g.insert((feed.as_str().to_owned(), sequence), bytes.to_vec());
                Ok(PutOutcome::Created)
            }
            Some(existing) if existing == bytes => Ok(PutOutcome::Identical),
            Some(_) => Err(R::DestinationConflict),
        }
    }
}

impl FeedSource for MemoryFeed {
    fn get(&self, feed: &FeedId, sequence: u64) -> Result<Option<Vec<u8>>> {
        let g = self.files.lock().map_err(|_| R::DestinationUnavailable)?;
        Ok(g.get(&(feed.as_str().to_owned(), sequence)).cloned())
    }
}

/// A local directory laid out as the public feed (for static hosting). Files
/// are written to a temporary name and linked into place, so a reader never
/// sees a partial file and an existing sequence is never replaced.
pub struct DirFeed {
    root: PathBuf,
}

impl DirFeed {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn dir(&self, feed: &FeedId) -> PathBuf {
        self.root.join(feed.as_str())
    }

    fn path(&self, feed: &FeedId, sequence: u64) -> PathBuf {
        self.dir(feed).join(envelope_file_name(sequence))
    }
}

impl FeedDestination for DirFeed {
    fn put(&self, feed: &FeedId, sequence: u64, bytes: &[u8]) -> Result<PutOutcome> {
        let dir = self.dir(feed);
        fs::create_dir_all(&dir).map_err(|_| R::DestinationUnavailable)?;
        let target = self.path(feed, sequence);
        if let Ok(existing) = fs::read(&target) {
            return if existing == bytes {
                Ok(PutOutcome::Identical)
            } else {
                Err(R::DestinationConflict)
            };
        }
        let tmp = dir.join(format!(".{}.tmp", envelope_file_name(sequence)));
        let _ = fs::remove_file(&tmp);
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|_| R::DestinationUnavailable)?;
            f.write_all(bytes).map_err(|_| R::DestinationUnavailable)?;
            f.sync_all().map_err(|_| R::DestinationUnavailable)?;
        }
        let linked = fs::hard_link(&tmp, &target);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(PutOutcome::Created),
            Err(_) => match fs::read(&target) {
                Ok(existing) if existing == bytes => Ok(PutOutcome::Identical),
                Ok(_) => Err(R::DestinationConflict),
                Err(_) => Err(R::DestinationUnavailable),
            },
        }
    }
}

impl FeedSource for DirFeed {
    fn get(&self, feed: &FeedId, sequence: u64) -> Result<Option<Vec<u8>>> {
        match fs::read(self.path(feed, sequence)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(R::DestinationUnavailable),
        }
    }
}

// ---- publisher -------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FeedConfig {
    pub feed_id: FeedId,
    pub destination_label: DestinationId,
    /// How long each envelope keeps the feed fresh. Consumers treat the feed
    /// as stale after this.
    pub ttl_secs: u64,
    /// Renew when the head would expire within this many seconds.
    pub renew_margin_secs: u64,
}

/// An operator-originated entry (everything except the contamination and
/// retirement entries standing changes record themselves).
#[derive(Clone, Debug)]
pub struct RevocationSpec {
    pub target: RevocationTarget,
    pub action: RevocationAction,
    pub reason: PublicRevocationReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishReport {
    /// Sequence of the envelope this call appended, if it appended one.
    pub appended: Option<u64>,
    pub entries: usize,
    /// Envelopes this call delivered to the destination (including earlier
    /// ones a crash left undelivered).
    pub delivered: usize,
}

/// Translates an internal epoch to the public population reference
/// projections carry. It must be the same mapping the disclosure service uses
/// (`PublicPopulationNames`), or a population entry would not match the
/// projections it must revoke.
pub trait PublicPopulations: Send + Sync {
    fn public_ref(&self, epoch: &EpochId) -> Option<PublicPopulationRef>;
}

/// The deployment mapping: epoch to registry row to the disclosure naming
/// object (opaque reference or keyed commitment).
pub struct RegistryPopulations<'a> {
    pub registry: &'a CorpusRegistry,
    pub names: &'a dyn PublicPopulationNames,
}

impl PublicPopulations for RegistryPopulations<'_> {
    fn public_ref(&self, epoch: &EpochId) -> Option<PublicPopulationRef> {
        let view = self.registry.view().ok()?;
        let (row, _) = view.get(epoch)?;
        let binding = custodian_contracts::common::PopulationBinding {
            domain: row.domain,
            corpus_id: row.corpus_id.clone(),
            epoch_id: row.epoch_id.clone(),
            family_id: row.family_id.clone(),
            population_digest: row.population_digest.clone(),
            custody_version: row.custody_version,
        };
        self.names.public_ref(&binding)
    }
}

pub struct FeedPublisher<'a> {
    pub store: &'a SqliteStore,
    pub populations: &'a dyn PublicPopulations,
    pub signer: &'a dyn Signer,
    pub destination: &'a dyn FeedDestination,
    pub authority: &'a dyn OperatorAuthority,
    pub config: FeedConfig,
    pub fault: &'a dyn LifecycleFault,
}

fn secs(t: Timestamp) -> u64 {
    t.secs()
}

fn reason_wire(r: PublicRevocationReason) -> &'static str {
    match r {
        PublicRevocationReason::Contamination => "contamination",
        PublicRevocationReason::EpochRotation => "epoch_rotation",
        PublicRevocationReason::KeyCompromise => "key_compromise",
        PublicRevocationReason::PolicyRevoked => "policy_revoked",
        PublicRevocationReason::ErrorCorrection => "error_correction",
        PublicRevocationReason::NewerEvidence => "newer_evidence",
    }
}

fn parse_reason(s: &str) -> Result<PublicRevocationReason> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).map_err(|_| R::Unpublishable)
}

impl FeedPublisher<'_> {
    fn crash(&self, p: LifecyclePoint) -> Result<()> {
        if self.fault.crash_at(p) {
            Err(R::InjectedCrash)
        } else {
            Ok(())
        }
    }

    /// Record an operator-originated entry as an obligation. Idempotent per
    /// `id` (a short label the caller chooses; the same id with different
    /// content is refused). It counts for eligibility from this moment and
    /// reaches consumers with the next published envelope.
    pub fn record_revocation(
        &self,
        who: &OperatorAuthorization,
        id: &str,
        spec: &RevocationSpec,
        now: Timestamp,
    ) -> Result<bool> {
        authorize(self.authority, who, OperatorAction::RecordRevocation)?;
        let (target, target_ref) = match &spec.target {
            RevocationTarget::Projection { projection_id } => (
                ObligationTarget::Projection,
                projection_id.as_str().to_owned(),
            ),
            RevocationTarget::Receipt { receipt_id } => {
                (ObligationTarget::Receipt, receipt_id.as_str().to_owned())
            }
            RevocationTarget::Candidate { candidate } => {
                (ObligationTarget::Candidate, candidate.as_str().to_owned())
            }
            RevocationTarget::Policy { policy } => (
                ObligationTarget::Policy,
                policy_ref_key(policy).map_err(|_| R::InvalidInput)?,
            ),
            // A population is named by the public reference; the internal
            // epoch is resolved by the standing changes, not by operators.
            RevocationTarget::Population { .. } => return Err(R::InvalidInput),
        };
        let (action, superseded_by) = match &spec.action {
            RevocationAction::Revoked {} => (ObligationAction::Revoked, None),
            RevocationAction::Contaminated {} => (ObligationAction::Contaminated, None),
            RevocationAction::Superseded { superseded_by } => (
                ObligationAction::Superseded,
                Some(superseded_by.as_str().to_owned()),
            ),
        };
        let obligation_id = format!("operator:{id}");
        self.store
            .enqueue_obligation(&ObligationCommand {
                obligation_id: &obligation_id,
                target,
                target_ref: &target_ref,
                action,
                superseded_by: superseded_by.as_deref(),
                reason: reason_wire(spec.reason),
                effective_at: secs(now),
                actor: who.actor.as_str(),
                authorization_ref: who.authorization.as_str(),
                now: secs(now),
            })
            .map_err(from_store)
    }

    /// A feed reference for a projection about to be prepared: the feed and
    /// the newest sequence a consumer must have seen. Refused while any
    /// obligation is recorded but unpublished, so the reference never points
    /// at a feed that is missing a known revocation.
    pub fn feed_ref(&self) -> Result<FeedRef> {
        if self.store.pending_obligation_count().map_err(from_store)? != 0 {
            return Err(R::PendingObligations);
        }
        let head = self
            .store
            .feed_head(self.config.feed_id.as_str())
            .map_err(from_store)?
            .ok_or(R::FeedNotInitialized)?;
        Ok(FeedRef {
            feed_id: self.config.feed_id.clone(),
            min_sequence: Count::new(head.sequence).map_err(|_| R::InvalidInput)?,
        })
    }

    /// Deliver every committed envelope the destination has not confirmed,
    /// in order. Safe to repeat; an identical destination write is accepted.
    pub fn deliver_pending(&self, now: Timestamp) -> Result<usize> {
        let envs = self
            .store
            .feed_envelopes(self.config.feed_id.as_str(), 1)
            .map_err(from_store)?;
        let mut n = 0;
        for e in envs.iter().filter(|e| !e.delivered) {
            self.destination
                .put(&self.config.feed_id, e.sequence, e.document.as_bytes())?;
            self.crash(LifecyclePoint::AfterDestinationPut)?;
            self.store
                .mark_feed_delivered(
                    self.config.feed_id.as_str(),
                    e.sequence,
                    self.config.destination_label.as_str(),
                    secs(now),
                )
                .map_err(from_store)?;
            n += 1;
        }
        Ok(n)
    }

    /// Append and deliver the next envelope: every pending obligation (up to
    /// 128), or an empty envelope when the head is about to go stale.
    /// Returns without appending when there is nothing to publish and the
    /// head is fresh enough. Two publishers racing for a sequence cannot both
    /// commit; the loser re-reads and tries again.
    pub fn publish(&self, who: &OperatorAuthorization, now: Timestamp) -> Result<PublishReport> {
        authorize(self.authority, who, OperatorAction::PublishFeed)?;
        let mut delivered = self.deliver_pending(now)?;
        let feed = self.config.feed_id.as_str();
        for _ in 0..4 {
            let head = self.store.feed_head(feed).map_err(from_store)?;
            let pending = self.store.pending_obligations(128).map_err(from_store)?;
            let renew_due = head.as_ref().is_none_or(|h| {
                secs(now).saturating_add(self.config.renew_margin_secs) >= h.fresh_until
            });
            if pending.is_empty() && !renew_due {
                return Ok(PublishReport {
                    appended: None,
                    entries: 0,
                    delivered,
                });
            }
            if let Some(h) = &head {
                if secs(now) < h.issued_at {
                    return Err(R::ClockSkew);
                }
            }
            let entries = pending
                .iter()
                .map(|o| self.entry_for(o))
                .collect::<Result<Vec<_>>>()?;
            let sequence = head.as_ref().map_or(1, |h| h.sequence + 1);
            let previous = match &head {
                None => None,
                Some(h) => Some(DocumentDigest::parse(&h.digest).map_err(|_| R::InvalidInput)?),
            };
            let fresh_until = secs(now)
                .checked_add(self.config.ttl_secs)
                .ok_or(R::InvalidInput)?;
            let env = RevocationEnvelope {
                schema: RevocationSchema,
                feed_id: self.config.feed_id.clone(),
                sequence: Count::new(sequence).map_err(|_| R::InvalidInput)?,
                previous,
                issued_at: now,
                fresh_until: Timestamp::new(fresh_until).map_err(|_| R::InvalidInput)?,
                entries: BoundedVec::new(entries).map_err(|_| R::InvalidInput)?,
            };
            env.validate().map_err(|_| R::InvalidInput)?;
            let approved = ApprovedPayload::revocation(&env).map_err(|_| R::SigningRefused)?;
            let signature = self.signer.sign(&approved).map_err(|e| match e {
                SignRefusal::SignerUnavailable => R::SignerUnavailable,
                _ => R::SigningRefused,
            })?;
            let digest = env.document_digest().map_err(|_| R::InvalidInput)?;
            let signed = SignedRevocationEnvelope {
                payload: env,
                signature,
            };
            let document =
                String::from_utf8(to_canonical_bytes(&signed).map_err(|_| R::InvalidInput)?)
                    .map_err(|_| R::InvalidInput)?;
            self.crash(LifecyclePoint::BeforeFeedAppend)?;
            let ids: Vec<String> = pending.iter().map(|o| o.obligation_id.clone()).collect();
            let prev_str = signed
                .payload
                .previous
                .as_ref()
                .map(|d| d.as_str().to_owned());
            match self.store.append_feed_envelope(&FeedAppend {
                feed_id: feed,
                sequence,
                previous_digest: prev_str.as_deref(),
                digest: digest.as_str(),
                document: &document,
                issued_at: secs(now),
                fresh_until,
                obligation_ids: &ids,
                now: secs(now),
            }) {
                Ok(()) => {}
                // Another publisher took the sequence: look again.
                Err(StoreError::Conflict) => continue,
                Err(e) => return Err(from_store(e)),
            }
            self.crash(LifecyclePoint::AfterFeedAppend)?;
            delivered += self.deliver_pending(now)?;
            return Ok(PublishReport {
                appended: Some(sequence),
                entries: ids.len(),
                delivered,
            });
        }
        Err(R::FeedConflict)
    }

    /// Translate one recorded obligation to its public entry.
    fn entry_for(&self, o: &ObligationRecord) -> Result<RevocationEntry> {
        let target = match o.target {
            ObligationTarget::Population => {
                let epoch = EpochId::parse(&o.target_ref).map_err(|_| R::Unpublishable)?;
                RevocationTarget::Population {
                    population: self.public_population(&epoch)?,
                }
            }
            ObligationTarget::Candidate => RevocationTarget::Candidate {
                candidate: CandidateDigest::parse(&o.target_ref).map_err(|_| R::Unpublishable)?,
            },
            ObligationTarget::Projection => RevocationTarget::Projection {
                projection_id: ProjectionId::parse(&o.target_ref).map_err(|_| R::Unpublishable)?,
            },
            ObligationTarget::Receipt => RevocationTarget::Receipt {
                receipt_id: ReceiptId::parse(&o.target_ref).map_err(|_| R::Unpublishable)?,
            },
            ObligationTarget::Policy => {
                let policy: PolicyRef = parse_policy_key(&o.target_ref).ok_or(R::Unpublishable)?;
                RevocationTarget::Policy { policy }
            }
        };
        let action = match (o.action, &o.superseded_by) {
            (ObligationAction::Revoked, _) => RevocationAction::Revoked {},
            (ObligationAction::Contaminated, _) => RevocationAction::Contaminated {},
            (ObligationAction::Superseded, Some(by)) => RevocationAction::Superseded {
                superseded_by: ProjectionId::parse(by).map_err(|_| R::Unpublishable)?,
            },
            (ObligationAction::Superseded, None) => return Err(R::Unpublishable),
        };
        Ok(RevocationEntry {
            target,
            action,
            reason: parse_reason(&o.reason)?,
            effective_at: Timestamp::new(o.effective_at).map_err(|_| R::Unpublishable)?,
        })
    }

    fn public_population(&self, epoch: &EpochId) -> Result<PublicPopulationRef> {
        self.populations.public_ref(epoch).ok_or(R::Unpublishable)
    }
}
