//! The signing engine the socket server runs around the key (ADR 0111).
//!
//! It adds three checks the ledger's [`SignerService`] does not own, and
//! delegates everything else to it:
//!
//! 1. request freshness: the frame's `issued_at` must be within the allowed
//!    skew of the signer's clock, so a captured frame cannot be replayed later;
//! 2. key window: the key is used only inside `[valid_from, not_after)` by the
//!    signer's own clock; outside it the signer refuses (`sign_signer_unavailable`
//!    on the wire, `key_out_of_window` in its own event stream);
//! 3. payload freshness for public documents: a projection or revocation
//!    envelope whose `fresh_until` has passed, or whose `issued_at` is in the
//!    future beyond the skew, is refused as `sign_not_approved`.
//!
//! `SignerService` still re-decodes every payload with
//! `ApprovedPayload::from_wire` and `SoftwareSigner` still enforces the key's
//! purposes. The engine never signs bytes the client supplied directly.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use custodian_contracts::canonical::Contract;
use custodian_contracts::common::Signature;
use custodian_contracts::public::PublicProjection;
use custodian_contracts::public_v2::PublicProjectionV2;
use custodian_contracts::revocation::RevocationEnvelope;
use custodian_contracts::types::KeyId;
use custodian_ledger::{
    ApprovedPayload, SignDomain, SignRefusal, Signer, SignerService, SoftwareSigner,
};
use serde::Deserialize;

use crate::frame::{Reject, Request};
use crate::provider::{KeyProvider, KeyProviderError};

/// Wall-clock seconds. Injected so tests control time.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock a test moves by hand.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(secs: u64) -> Self {
        Self(AtomicU64::new(secs))
    }
    pub fn set(&self, secs: u64) {
        self.0.store(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Receives fixed event codes (never payloads, keys or paths).
pub type EventSink = Arc<dyn Fn(&'static str) + Send + Sync>;

/// Drops events.
pub fn silent_sink() -> EventSink {
    Arc::new(|_| {})
}

#[derive(Debug, Default)]
pub struct Stats {
    signed: AtomicU64,
    refused: AtomicU64,
    key_out_of_window: AtomicU64,
    stale_payload: AtomicU64,
    rejected_frames: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub signed: u64,
    pub refused: u64,
    pub key_out_of_window: u64,
    pub stale_payload: u64,
    pub rejected_frames: u64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            signed: self.signed.load(Ordering::SeqCst),
            refused: self.refused.load(Ordering::SeqCst),
            key_out_of_window: self.key_out_of_window.load(Ordering::SeqCst),
            stale_payload: self.stale_payload.load(Ordering::SeqCst),
            rejected_frames: self.rejected_frames.load(Ordering::SeqCst),
        }
    }

    pub(crate) fn rejected_frame(&self) {
        self.rejected_frames.fetch_add(1, Ordering::SeqCst);
    }
}

/// What the signer is allowed to do with its one key.
#[derive(Clone, Debug)]
pub struct SignerSetup {
    pub key_id: KeyId,
    pub purposes: BTreeSet<SignDomain>,
    /// First second the key may sign.
    pub valid_from: u64,
    /// First second the key may no longer sign; `None` for no end.
    pub not_after: Option<u64>,
    /// Allowed distance between the client's `issued_at` and this clock.
    pub max_request_skew_secs: u64,
}

struct WindowedSigner {
    inner: SoftwareSigner,
    valid_from: u64,
    not_after: Option<u64>,
    skew: u64,
    clock: Arc<dyn Clock>,
    stats: Arc<Stats>,
    events: EventSink,
}

impl WindowedSigner {
    fn payload_is_stale(&self, payload: &ApprovedPayload, now: u64) -> bool {
        let (issued, fresh_until) = match payload.domain() {
            SignDomain::PublicProjection => {
                match PublicProjection::decode_canonical(payload.canonical_bytes()) {
                    Ok(p) => (p.issued_at.secs(), p.fresh_until.secs()),
                    Err(_) => return true,
                }
            }
            SignDomain::PublicProjectionV2 => {
                match PublicProjectionV2::decode_canonical(payload.canonical_bytes()) {
                    Ok(p) => (p.issued_at.secs(), p.fresh_until.secs()),
                    Err(_) => return true,
                }
            }
            SignDomain::RevocationEnvelope => {
                match RevocationEnvelope::decode_canonical(payload.canonical_bytes()) {
                    Ok(e) => (e.issued_at.secs(), e.fresh_until.secs()),
                    Err(_) => return true,
                }
            }
            _ => return false,
        };
        fresh_until <= now || issued > now.saturating_add(self.skew)
    }
}

impl Signer for WindowedSigner {
    fn key_id(&self) -> &KeyId {
        self.inner.key_id()
    }

    fn sign(&self, payload: &ApprovedPayload) -> Result<Signature, SignRefusal> {
        let now = self.clock.now_secs();
        if now < self.valid_from || self.not_after.is_some_and(|end| now >= end) {
            self.stats.key_out_of_window.fetch_add(1, Ordering::SeqCst);
            (self.events)("key_out_of_window");
            return Err(SignRefusal::SignerUnavailable);
        }
        if self.payload_is_stale(payload, now) {
            self.stats.stale_payload.fetch_add(1, Ordering::SeqCst);
            (self.events)("payload_stale");
            return Err(SignRefusal::NotApproved);
        }
        self.inner.sign(payload)
    }
}

#[derive(Deserialize)]
struct ResponseProbe {
    #[serde(default)]
    refused: Option<String>,
}

pub struct SigningEngine {
    service: SignerService<WindowedSigner>,
    clock: Arc<dyn Clock>,
    max_skew: u64,
    stats: Arc<Stats>,
    events: EventSink,
    public_key_hex: String,
}

impl core::fmt::Debug for SigningEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SigningEngine(<redacted>)")
    }
}

impl SigningEngine {
    /// Load the key from `provider` and build the engine. The seed is copied
    /// into the signing key and the provider's copy is dropped (zeroized)
    /// before this returns.
    pub fn new(
        provider: &dyn KeyProvider,
        setup: SignerSetup,
        clock: Arc<dyn Clock>,
        events: EventSink,
    ) -> Result<Self, KeyProviderError> {
        let seed = provider.load_seed()?;
        let inner = SoftwareSigner::from_seed(
            setup.key_id.clone(),
            seed.expose(),
            setup.purposes.iter().copied(),
        );
        drop(seed);
        let public_key_hex = inner.public_key_hex();
        let stats = Arc::new(Stats::default());
        let windowed = WindowedSigner {
            inner,
            valid_from: setup.valid_from,
            not_after: setup.not_after,
            skew: setup.max_request_skew_secs,
            clock: clock.clone(),
            stats: stats.clone(),
            events: events.clone(),
        };
        Ok(Self {
            service: SignerService::new(windowed),
            clock,
            max_skew: setup.max_request_skew_secs,
            stats,
            events,
            public_key_hex,
        })
    }

    /// The public half, for pinning in a verifier's roots. Public by design.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    pub(crate) fn emit(&self, code: &'static str) {
        (self.events)(code);
    }

    /// Handle one parsed request: freshness, then the ledger service.
    pub fn handle(&self, req: &Request) -> Result<Vec<u8>, Reject> {
        let now = self.clock.now_secs();
        if req.issued_at.abs_diff(now) > self.max_skew {
            return Err(Reject::StaleRequest);
        }
        let resp = self.service.handle(&req.body);
        let refused = serde_json::from_slice::<ResponseProbe>(&resp)
            .ok()
            .and_then(|p| p.refused);
        match refused {
            None => {
                self.stats.signed.fetch_add(1, Ordering::SeqCst);
                self.emit("signed");
            }
            Some(code) => {
                self.stats.refused.fetch_add(1, Ordering::SeqCst);
                self.emit(SignRefusal::from_code(&code).map_or("refused", SignRefusal::code));
            }
        }
        Ok(resp)
    }
}
