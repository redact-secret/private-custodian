//! Authenticated roles and the real `OperatorAuthority` (C10, ADR 0081).
//!
//! The reviewed operator policy file lists identities, their kind (`human`,
//! `service`, `agent`), their roles and the SHA-256 digest of each identity's
//! credential. The file holds no credential. A caller proves an identity by
//! presenting the credential; [`PolicyAuthority::authenticate`] is the only
//! way to obtain a [`Principal`], and every permission check is a method on a
//! `Principal`. A request document, a flag or an environment variable can
//! name an identity but never grant a role.
//!
//! Structural rules, enforced when the policy is loaded and again at every
//! check, whatever the policy file says:
//!
//! * an `agent` identity may hold only `requester`;
//! * a `service` identity may hold only `requester` and `auditor`;
//! * only a `human` may approve, clear, retire, rotate, publish, repair,
//!   import a policy activation or cancel another principal's request;
//! * nobody approves their own request (checked by the control plane and by
//!   the store).

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::approval::MAX_APPROVAL_TTL_SECS;
use custodian_contracts::common::ActorKind;
use custodian_contracts::policy::MAX_STATE_AGE_SECS;
use custodian_contracts::types::{ActorRef, ApprovalId, Timestamp};
use custodian_lifecycle::{OperatorAction, OperatorAuthority, OperatorAuthorization};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::reason::CliReason;

pub const OPERATOR_POLICY_SCHEMA: &str = "private-custodian.operator-policy/1";
/// Largest operator policy file accepted.
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
/// Credentials shorter than this many bytes are refused outright.
pub const MIN_CREDENTIAL_BYTES: usize = 32;
const MAX_IDENTITIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// May submit requests and see or cancel its own.
    Requester,
    /// May approve another principal's request. Holding the role approves
    /// nothing by itself.
    Approver,
    /// May run lifecycle, feed, repair and policy-activation commands.
    Operator,
    /// May read status and run verification. Cannot change anything.
    Auditor,
}

impl Role {
    pub fn code(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Approver => "approver",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }
}

/// What a command needs. Every command maps to exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    RequestSubmit,
    RequestViewOwn,
    RequestViewAny,
    RequestApprove,
    RequestCancelOwn,
    RequestCancelAny,
    Verify,
    Diagnose,
    Repair,
    Lifecycle(OperatorAction),
    PolicyImport,
    PolicyValidate,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityEntry {
    actor: ActorRef,
    kind: ActorKind,
    roles: Vec<Role>,
    credential_sha256: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsFile {
    approval_ttl_secs: Option<u64>,
    max_state_age_secs: Option<u64>,
    reservation_window_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    schema: String,
    policy_version: u64,
    issued_at: u64,
    expires_at: u64,
    identities: Vec<IdentityEntry>,
    #[serde(default)]
    limits: LimitsFile,
}

/// Limits the control plane applies. Defaults are the strictest sensible
/// values; a policy may lower them, never raise them past the contract caps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub approval_ttl_secs: u64,
    pub max_state_age_secs: u64,
    pub reservation_window_secs: u64,
}

#[derive(Clone, Debug)]
struct Identity {
    kind: ActorKind,
    roles: BTreeSet<Role>,
    credential: String,
}

/// `sha256` of the domain-separated credential, lowercase hex. This is the
/// value an operator puts in the policy file; the credential itself is never
/// written down by this repository.
pub fn credential_digest(credential: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"private-custodian/cli/credential/v1\0");
    h.update(credential);
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    for b in d {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
    }
    s
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The validated, reviewed operator policy.
#[derive(Clone, Debug)]
pub struct OperatorPolicy {
    digest: String,
    version: u64,
    issued_at: u64,
    expires_at: u64,
    identities: BTreeMap<ActorRef, Identity>,
    limits: Limits,
}

impl OperatorPolicy {
    /// Parse and validate. Fails closed: unknown fields, duplicates,
    /// malformed digests and any role an identity kind may not hold are
    /// refused.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CliReason> {
        if bytes.len() > MAX_POLICY_BYTES {
            return Err(CliReason::OperatorPolicyInvalid);
        }
        let file: PolicyFile =
            serde_json::from_slice(bytes).map_err(|_| CliReason::OperatorPolicyInvalid)?;
        if file.schema != OPERATOR_POLICY_SCHEMA
            || file.policy_version == 0
            || file.expires_at <= file.issued_at
            || file.identities.is_empty()
            || file.identities.len() > MAX_IDENTITIES
        {
            return Err(CliReason::OperatorPolicyInvalid);
        }
        let mut identities = BTreeMap::new();
        let mut credentials = BTreeSet::new();
        for e in file.identities {
            if e.roles.is_empty() || !is_hex64(&e.credential_sha256) {
                return Err(CliReason::OperatorPolicyInvalid);
            }
            let roles: BTreeSet<Role> = e.roles.iter().copied().collect();
            if roles.len() != e.roles.len() {
                return Err(CliReason::OperatorPolicyInvalid);
            }
            if !kind_may_hold(e.kind, &roles) {
                return Err(CliReason::OperatorPolicyInvalid);
            }
            // One credential, one identity: a shared credential would make
            // two principals indistinguishable.
            if !credentials.insert(e.credential_sha256.clone()) {
                return Err(CliReason::OperatorPolicyInvalid);
            }
            let id = Identity {
                kind: e.kind,
                roles,
                credential: e.credential_sha256,
            };
            if identities.insert(e.actor, id).is_some() {
                return Err(CliReason::OperatorPolicyInvalid);
            }
        }
        let l = file.limits;
        let limits = Limits {
            approval_ttl_secs: l.approval_ttl_secs.unwrap_or(3600),
            max_state_age_secs: l.max_state_age_secs.unwrap_or(MAX_STATE_AGE_SECS),
            reservation_window_secs: l.reservation_window_secs.unwrap_or(600),
        };
        if limits.approval_ttl_secs == 0
            || limits.approval_ttl_secs > MAX_APPROVAL_TTL_SECS
            || limits.max_state_age_secs == 0
            || limits.max_state_age_secs > MAX_STATE_AGE_SECS
            || limits.reservation_window_secs == 0
            || limits.reservation_window_secs > 86_400
        {
            return Err(CliReason::OperatorPolicyInvalid);
        }
        Ok(Self {
            digest: credential_digest(bytes),
            version: file.policy_version,
            issued_at: file.issued_at,
            expires_at: file.expires_at,
            identities,
            limits,
        })
    }

    /// Digest of the exact policy bytes. It is what authorization references
    /// recorded in the audit trail are derived from, so each recorded act is
    /// traceable to the reviewed policy revision that permitted it.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn identity_count(&self) -> usize {
        self.identities.len()
    }

    /// The policy is within its validity window at `now`. A policy outside it
    /// authenticates nobody (fail closed).
    pub fn is_current(&self, now: Timestamp) -> bool {
        now.secs() >= self.issued_at && now.secs() < self.expires_at
    }
}

/// The structural role rule, shared by loading and checking.
fn kind_may_hold(kind: ActorKind, roles: &BTreeSet<Role>) -> bool {
    match kind {
        ActorKind::Human => true,
        ActorKind::Service => roles
            .iter()
            .all(|r| matches!(r, Role::Requester | Role::Auditor)),
        ActorKind::Agent => roles.iter().all(|r| *r == Role::Requester),
    }
}

/// An authenticated principal. Only [`PolicyAuthority::authenticate`] builds
/// one, so holding one is proof that the credential matched the policy that
/// was current at that moment.
#[derive(Clone, Debug)]
pub struct Principal {
    actor: ActorRef,
    kind: ActorKind,
    roles: BTreeSet<Role>,
    policy_digest: String,
}

impl Principal {
    pub fn actor(&self) -> &ActorRef {
        &self.actor
    }

    pub fn kind(&self) -> ActorKind {
        self.kind
    }

    pub fn roles(&self) -> impl Iterator<Item = Role> + '_ {
        self.roles.iter().copied()
    }

    pub fn has_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }

    /// Check `permission`. The kind rules come first and hold whatever roles
    /// the policy file granted.
    pub fn check(&self, permission: Permission) -> Result<(), CliReason> {
        use Permission::*;
        let agent_ok = matches!(
            permission,
            RequestSubmit | RequestViewOwn | RequestCancelOwn | PolicyValidate
        );
        let human_only = matches!(
            permission,
            RequestApprove | RequestCancelAny | Repair | Lifecycle(_) | PolicyImport
        );
        match self.kind {
            ActorKind::Agent if !agent_ok => return Err(CliReason::AgentNotPermitted),
            ActorKind::Service if human_only => return Err(CliReason::AutomationNotPermitted),
            _ => {}
        }
        let role = match permission {
            RequestSubmit | RequestViewOwn | RequestCancelOwn => Role::Requester,
            RequestApprove => Role::Approver,
            RequestViewAny => {
                if self.roles.iter().any(|r| *r != Role::Requester) {
                    return Ok(());
                }
                return Err(CliReason::Forbidden);
            }
            RequestCancelAny | Repair | Lifecycle(_) | PolicyImport => Role::Operator,
            Verify | Diagnose => {
                if self.roles.contains(&Role::Auditor) || self.roles.contains(&Role::Operator) {
                    return Ok(());
                }
                return Err(CliReason::Forbidden);
            }
            PolicyValidate => return Ok(()),
        };
        if self.roles.contains(&role) {
            Ok(())
        } else {
            Err(CliReason::Forbidden)
        }
    }

    /// The authorization reference recorded with an operator act: a stable
    /// `apr_` identity derived from the policy revision that permitted it,
    /// the actor, the action and the act's idempotency key. It names no
    /// secret and is the same on a retry.
    pub fn authorization_ref(&self, action: &str, key: &str) -> Result<ApprovalId, CliReason> {
        let mut h = Sha256::new();
        h.update(b"private-custodian/cli/authorization/v1\0");
        for part in [
            self.policy_digest.as_str(),
            self.actor.as_str(),
            action,
            key,
        ] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        let d = h.finalize();
        let mut s = String::from("apr_");
        for b in d.iter().take(16) {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
        }
        ApprovalId::parse(&s).map_err(|_| CliReason::Internal)
    }

    /// The `OperatorAuthorization` the lifecycle library takes.
    pub fn operator_authorization(
        &self,
        action: &str,
        key: &str,
    ) -> Result<OperatorAuthorization, CliReason> {
        Ok(OperatorAuthorization {
            actor: self.actor.clone(),
            kind: self.kind,
            authorization: self.authorization_ref(action, key)?,
        })
    }
}

/// The deployment authority: roles from the reviewed policy file.
#[derive(Clone, Debug)]
pub struct PolicyAuthority {
    policy: OperatorPolicy,
}

impl PolicyAuthority {
    pub fn new(policy: OperatorPolicy) -> Self {
        Self { policy }
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, CliReason> {
        Ok(Self::new(OperatorPolicy::from_json(bytes)?))
    }

    pub fn policy(&self) -> &OperatorPolicy {
        &self.policy
    }

    /// Prove an identity. One failure code for an unknown identity, a wrong
    /// credential and a short credential, so the result is no oracle for
    /// which identities exist. A policy outside its validity window
    /// authenticates nobody.
    pub fn authenticate(
        &self,
        identity: &str,
        credential: &[u8],
        now: Timestamp,
    ) -> Result<Principal, CliReason> {
        if !self.policy.is_current(now) {
            return Err(CliReason::OperatorPolicyExpired);
        }
        let digest = credential_digest(credential);
        let entry = ActorRef::parse(identity)
            .ok()
            .and_then(|a| self.policy.identities.get(&a).map(|i| (a, i)));
        let zero = "0".repeat(64);
        let (stored, found) = match &entry {
            Some((_, i)) => (i.credential.as_str(), true),
            None => (zero.as_str(), false),
        };
        let matched = ct_eq(&digest, stored);
        if !(found && matched) || credential.len() < MIN_CREDENTIAL_BYTES {
            return Err(CliReason::Unauthenticated);
        }
        let (actor, i) = entry.ok_or(CliReason::Unauthenticated)?;
        Ok(Principal {
            actor,
            kind: i.kind,
            roles: i.roles.clone(),
            policy_digest: self.policy.digest.clone(),
        })
    }
}

impl OperatorAuthority for PolicyAuthority {
    /// Re-derives everything from the policy: the caller's claimed `kind` is
    /// not trusted, and only a human holding `operator` is permitted any
    /// lifecycle action.
    fn permits(&self, who: &OperatorAuthorization, _action: OperatorAction) -> bool {
        match self.policy.identities.get(&who.actor) {
            Some(i) => {
                i.kind == who.kind
                    && i.kind == ActorKind::Human
                    && i.roles.contains(&Role::Operator)
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authorization_reference_grammar_holds() {
        assert!(ApprovalId::parse(&format!("apr_{}", "0".repeat(32))).is_ok());
    }

    #[test]
    fn constant_time_compare_handles_length_differences() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "a"));
    }
}
