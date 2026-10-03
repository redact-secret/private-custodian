//! Credential roles and the rule that keeps them apart (ADR 0002, ADR 0010).
//!
//! Three credentials exist in the system and they are different types:
//!
//! - [`RequestFacingAppCredential`]: the request-facing App. It can sign an
//!   App JWT and nothing else. Defined here.
//! - [`LedgerWriterCredential`]: write access to the private ledger (C7).
//! - [`DbAdminCredential`]: runtime database administration (C4).
//!
//! The last two are declared here only as distinct, non-constructible role
//! types so no function can accept one where another is expected. Their real
//! providers belong to C7 and C4.
//!
//! Isolated workers and requesting-project CI hold none of them. That is
//! enforced as configuration: [`validate_assignments`] rejects any deployment
//! description that gives a worker or CI a credential, or gives any holder a
//! credential outside its single permitted role, and
//! [`validate_worker_environment`] rejects environment names that would carry
//! one into a worker.

use crate::ids::AppId;
use crate::reason::IntakeReason;

/// What a credential is for. One role per credential type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CredentialRole {
    RequestFacingApp,
    LedgerWriter,
    DbAdmin,
}

/// Implemented by the distinct credential types, so a role can be named at
/// compile time and compared in tests.
pub trait Credential {
    const ROLE: CredentialRole;
}

/// Signs the App JWT with the App's private key. The key lives behind this
/// trait in the deployment adapter (a restricted file or a key service); this
/// crate never reads, stores or prints key material. Production signs
/// RS256 (RSASSA-PKCS1-v1_5 with SHA-256) as GitHub requires.
pub trait AppJwtSigner: Send + Sync {
    /// Sign `signing_input` (`base64url(header) "." base64url(claims)`).
    fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>, IntakeReason>;
}

/// The request-facing App identity (Z1). Not `Clone`, redacted `Debug`.
pub struct RequestFacingAppCredential {
    app_id: AppId,
    signer: Box<dyn AppJwtSigner>,
}

impl RequestFacingAppCredential {
    pub fn new(app_id: AppId, signer: Box<dyn AppJwtSigner>) -> Self {
        Self { app_id, signer }
    }
    pub fn app_id(&self) -> AppId {
        self.app_id
    }
    pub(crate) fn sign(&self, input: &[u8]) -> Result<Vec<u8>, IntakeReason> {
        self.signer.sign_rs256(input)
    }
}

impl Credential for RequestFacingAppCredential {
    const ROLE: CredentialRole = CredentialRole::RequestFacingApp;
}

impl core::fmt::Debug for RequestFacingAppCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RequestFacingAppCredential(<redacted>)")
    }
}

/// Role type for the ledger-writer credential (C7). No constructor here.
#[derive(Debug)]
pub struct LedgerWriterCredential {
    _sealed: (),
}

impl Credential for LedgerWriterCredential {
    const ROLE: CredentialRole = CredentialRole::LedgerWriter;
}

/// Role type for the runtime-database administration credential (C4). No
/// constructor here.
#[derive(Debug)]
pub struct DbAdminCredential {
    _sealed: (),
}

impl Credential for DbAdminCredential {
    const ROLE: CredentialRole = CredentialRole::DbAdmin;
}

/// Who might be handed a credential in a deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Holder {
    RequestFacingAppAdapter,
    ControlService,
    LedgerWriterService,
    DbAdministrator,
    IsolatedWorker,
    RequestingProjectCi,
}

/// One line of a deployment's credential manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assignment {
    pub holder: Holder,
    pub role: CredentialRole,
}

fn permitted(holder: Holder, role: CredentialRole) -> bool {
    matches!(
        (holder, role),
        (
            Holder::RequestFacingAppAdapter,
            CredentialRole::RequestFacingApp
        ) | (Holder::LedgerWriterService, CredentialRole::LedgerWriter)
            | (Holder::DbAdministrator, CredentialRole::DbAdmin)
    )
}

/// Reject any manifest that crosses credential roles. Each credential has
/// exactly one permitted holder; the control service holds none of the three
/// (it has database write access through its own OS user, which is not an
/// App or admin credential); workers and requesting-project CI hold nothing.
pub fn validate_assignments(manifest: &[Assignment]) -> Result<(), IntakeReason> {
    if manifest.iter().all(|a| permitted(a.holder, a.role)) {
        Ok(())
    } else {
        Err(IntakeReason::CredentialBoundaryViolation)
    }
}

/// Substrings (case-insensitive) that mark an environment variable name as
/// credential-bearing. A worker environment containing any is rejected.
const FORBIDDEN_ENV_MARKERS: [&str; 12] = [
    "github",
    "token",
    "secret",
    "private_key",
    "app_id",
    "installation",
    "webhook",
    "ledger",
    "database",
    "db_",
    "password",
    "credential",
];

/// Validate the environment names a worker (or requesting-project CI) would
/// receive. A name check is a guard against configuration mistakes, not the
/// isolation boundary itself (C6 proves that).
pub fn validate_worker_environment<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), IntakeReason> {
    for name in names {
        let lower = name.to_ascii_lowercase();
        if FORBIDDEN_ENV_MARKERS.iter().any(|m| lower.contains(m)) {
            return Err(IntakeReason::CredentialBoundaryViolation);
        }
    }
    Ok(())
}
