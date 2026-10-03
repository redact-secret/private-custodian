//! A reference feed consumer: what a downstream system without private-ledger
//! access does with the public feed (ADR 0072, docs/lifecycle-and-revocation.md
//! "Consumer verification steps").
//!
//! It holds public information only: the pinned verification keys, the feed
//! identity and the envelopes it has accepted. It never sees an epoch, a
//! family, a case or a budget, because none is in the feed.
//!
//! The consumer is a synthetic stand-in for benchmarks (C11). Product support
//! decisions stay downstream: this type only says whether a projection may
//! still be relied on, and which projections stopped being reliable since the
//! last look, so the downstream can re-evaluate whatever support it derived
//! from them.

use std::collections::BTreeMap;

use custodian_contracts::canonical::Contract;
use custodian_contracts::public::PublicProjection;
use custodian_contracts::revocation::{RevocationLog, SignedRevocationEnvelope, Standing};
use custodian_contracts::types::{DocumentDigest, FeedId, ProjectionId, Timestamp};
use custodian_ledger::Verifier;

use crate::feed::FeedSource;

/// Why an envelope was not accepted. Fieldless.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyncError {
    /// Not a strictly valid, canonical envelope.
    Malformed,
    /// The signature does not verify under the pinned keys.
    BadSignature,
    /// An envelope of another feed.
    WrongFeed,
    /// A sequence beyond the next one: envelopes are missing.
    Gap,
    /// A sequence already accepted, with different bytes: the feed forked or
    /// was rewritten. Never resolved silently.
    Fork,
    /// The next sequence does not link to the accepted head.
    BrokenChain,
    /// The source failed.
    SourceUnavailable,
}

impl SyncError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Malformed => "feed_malformed",
            Self::BadSignature => "feed_bad_signature",
            Self::WrongFeed => "feed_wrong_feed",
            Self::Gap => "feed_gap",
            Self::Fork => "feed_fork",
            Self::BrokenChain => "feed_broken_chain",
            Self::SourceUnavailable => "feed_source_unavailable",
        }
    }
}

impl core::fmt::Display for SyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SyncError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// Appended to the log.
    Applied,
    /// Already accepted, byte for byte (a harmless replay).
    AlreadyApplied,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub applied: usize,
    pub head_sequence: u64,
}

/// A projection whose standing changed since the last evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingChange {
    pub projection: ProjectionId,
    pub from: Standing,
    pub to: Standing,
}

pub struct FeedConsumer {
    feed: FeedId,
    verifier: Verifier,
    log: RevocationLog,
    /// Canonical bytes accepted per sequence (index = sequence - 1), to tell
    /// a replay from a fork.
    accepted: Vec<Vec<u8>>,
    tracked: BTreeMap<ProjectionId, (PublicProjection, Standing)>,
}

impl FeedConsumer {
    pub fn new(feed: FeedId, verifier: Verifier) -> Self {
        Self {
            log: RevocationLog::new(feed.clone()),
            feed,
            verifier,
            accepted: Vec::new(),
            tracked: BTreeMap::new(),
        }
    }

    pub fn sequence(&self) -> u64 {
        self.log.sequence()
    }

    /// Accept one envelope given as the bytes found at the source. Steps, in
    /// order, each fail-closed: strict canonical decode; same feed; replay or
    /// fork check against what was accepted; gap check; signature under the
    /// pinned keys; chain link and sequence (`RevocationLog::apply`).
    pub fn observe(&mut self, bytes: &[u8]) -> Result<Observed, SyncError> {
        let signed = SignedRevocationEnvelope::decode(bytes).map_err(|_| SyncError::Malformed)?;
        let canonical = custodian_contracts::canonical::to_canonical_bytes(&signed)
            .map_err(|_| SyncError::Malformed)?;
        if canonical != bytes {
            return Err(SyncError::Malformed);
        }
        let env = &signed.payload;
        if env.feed_id != self.feed {
            return Err(SyncError::WrongFeed);
        }
        let seq = env.sequence.get();
        if seq <= self.log.sequence() {
            let idx = usize::try_from(seq - 1).map_err(|_| SyncError::Malformed)?;
            if self.accepted.get(idx).is_some_and(|prev| prev == bytes) {
                return Ok(Observed::AlreadyApplied);
            }
            // Different bytes for an accepted sequence: a fork, but only if
            // the other document is really signed. An unsigned imitation is
            // just a bad signature, not an alarm.
            self.verifier
                .verify_revocation(&signed)
                .map_err(|_| SyncError::BadSignature)?;
            return Err(SyncError::Fork);
        }
        self.verifier
            .verify_revocation(&signed)
            .map_err(|_| SyncError::BadSignature)?;
        if seq != self.log.sequence() + 1 {
            return Err(SyncError::Gap);
        }
        self.log.apply(env).map_err(|_| SyncError::BrokenChain)?;
        self.accepted.push(bytes.to_vec());
        Ok(Observed::Applied)
    }

    /// Fetch and accept envelopes after the current head until the source has
    /// no more. If the next sequence is absent but a later one exists the
    /// feed has a gap and nothing past it is accepted.
    pub fn sync(&mut self, source: &dyn FeedSource) -> Result<SyncReport, SyncError> {
        let mut applied = 0;
        loop {
            let next = self.log.sequence() + 1;
            match source
                .get(&self.feed, next)
                .map_err(|_| SyncError::SourceUnavailable)?
            {
                Some(bytes) => {
                    if self.observe(&bytes)? == Observed::Applied {
                        applied += 1;
                    }
                }
                None => {
                    if source
                        .get(&self.feed, next + 1)
                        .map_err(|_| SyncError::SourceUnavailable)?
                        .is_some()
                    {
                        return Err(SyncError::Gap);
                    }
                    break;
                }
            }
        }
        Ok(SyncReport {
            applied,
            head_sequence: self.log.sequence(),
        })
    }

    /// Whether `projection` may be relied on at `now`: the contract's
    /// `RevocationLog::standing`. A feed that is missing, too old, for
    /// another feed or behind the projection's `min_sequence` is `Stale`,
    /// never `Valid`; a revocation or contamination is decided from whatever
    /// feed state is held.
    pub fn standing(&self, projection: &PublicProjection, now: Timestamp) -> Standing {
        self.log.standing(projection, now)
    }

    /// Start tracking a projection for re-evaluation triggers.
    pub fn track(&mut self, projection: PublicProjection, now: Timestamp) {
        let s = self.log.standing(&projection, now);
        self.tracked
            .insert(projection.projection_id.clone(), (projection, s));
    }

    /// Re-evaluate every tracked projection at `now` and return those that
    /// stopped being usable since the previous call (or since tracking).
    /// The downstream re-evaluates the support it derived from exactly these.
    /// A projection that becomes usable again (a fresh feed after a stale
    /// one) is recorded but not reported: only losses trigger.
    pub fn reevaluate(&mut self, now: Timestamp) -> Vec<StandingChange> {
        let mut out = Vec::new();
        for (id, (p, last)) in &mut self.tracked {
            let current = self.log.standing(p, now);
            if current != *last {
                if last.is_usable() && !current.is_usable() {
                    out.push(StandingChange {
                        projection: id.clone(),
                        from: *last,
                        to: current,
                    });
                }
                *last = current;
            }
        }
        out
    }

    /// Digest of the head envelope's payload, for comparing two consumers or
    /// recording what was seen.
    pub fn head_digest(&self) -> Option<DocumentDigest> {
        let last = self.accepted.last()?;
        let signed = SignedRevocationEnvelope::decode(last).ok()?;
        signed.payload.document_digest().ok()
    }
}
