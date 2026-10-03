//! Offline doubles and an in-test fake signing key.
//!
//! Nothing here reads a file, an environment variable or the network, and no
//! key material is committed anywhere: [`FakeSigningKey::generate`] makes
//! fresh random bytes on every call. The fake signs with HMAC-SHA256, not
//! RSA, so it can never produce a signature GitHub would accept even if it
//! leaked; it exists only to exercise the JWT-building and token-exchange
//! logic offline.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::app_auth::{AccessTokenRequest, AppApiTransport};
use crate::credentials::AppJwtSigner;
use crate::ids::{InstallationId, RepositoryId};
use crate::reason::IntakeReason;

/// `n` unpredictable bytes for throwaway test secrets (not cryptographic
/// guarantees; test use only).
pub fn random_bytes(n: usize) -> Vec<u8> {
    let state = RandomState::new();
    let mut out = Vec::with_capacity(n);
    let mut counter = 0u64;
    while out.len() < n {
        out.extend_from_slice(&state.hash_one(counter).to_le_bytes());
        counter += 1;
    }
    out.truncate(n);
    out
}

/// A freshly generated fake signing key. Not RSA; never a real credential.
#[derive(Clone)]
pub struct FakeSigningKey {
    bytes: Vec<u8>,
}

impl FakeSigningKey {
    pub fn generate() -> Self {
        Self {
            bytes: random_bytes(32),
        }
    }

    pub fn tag(&self, input: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.bytes).unwrap_or_else(|_| {
            // Unreachable: HMAC accepts any key length.
            Hmac::<Sha256>::new_from_slice(&[0u8; 32]).expect("fixed key")
        });
        mac.update(input);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        self.tag(input) == signature
    }
}

impl core::fmt::Debug for FakeSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FakeSigningKey(<redacted>)")
    }
}

impl AppJwtSigner for FakeSigningKey {
    fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, IntakeReason> {
        Ok(self.tag(signing_input))
    }
}

/// A signer that always fails, for the failure path.
#[derive(Debug)]
pub struct FailingSigner;

impl AppJwtSigner for FailingSigner {
    fn sign_rs256(&self, _signing_input: &[u8]) -> Result<Vec<u8>, IntakeReason> {
        Err(IntakeReason::AppAuthFailed)
    }
}

/// One recorded token request.
#[derive(Clone, Debug)]
pub struct RecordedTokenRequest {
    pub jwt: String,
    pub installation: InstallationId,
    pub repository: RepositoryId,
    pub body: String,
}

/// Offline stand-in for the GitHub App API. Returns a preset response body.
#[derive(Debug)]
pub struct FakeAppApi {
    response: Mutex<Result<Vec<u8>, IntakeReason>>,
    requests: Mutex<Vec<RecordedTokenRequest>>,
}

impl FakeAppApi {
    pub fn responding(body: impl Into<Vec<u8>>) -> Self {
        Self {
            response: Mutex::new(Ok(body.into())),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn failing(reason: IntakeReason) -> Self {
        Self {
            response: Mutex::new(Err(reason)),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn requests(&self) -> Vec<RecordedTokenRequest> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

impl AppApiTransport for FakeAppApi {
    fn create_installation_token(
        &self,
        request: &AccessTokenRequest<'_>,
    ) -> Result<Vec<u8>, IntakeReason> {
        if let Ok(mut r) = self.requests.lock() {
            r.push(RecordedTokenRequest {
                jwt: request.jwt.expose_secret().to_owned(),
                installation: request.installation,
                repository: request.repository,
                body: request.body(),
            });
        }
        self.response
            .lock()
            .map_err(|_| IntakeReason::AppAuthFailed)?
            .clone()
    }
}
