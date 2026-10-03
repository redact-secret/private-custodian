//! GitHub-facing identity types. Numeric GitHub identities are used, never
//! mutable names (logins, repository full names, branch names): a name can be
//! renamed or recycled, a numeric id cannot. Every constructor validates, so a
//! value of these types is always well formed.

use serde::{Deserialize, Deserializer, Serialize};

use crate::reason::IntakeReason;

/// Largest numeric id accepted (2^53 - 1, as in the contracts).
const MAX_ID: u64 = (1u64 << 53) - 1;

macro_rules! numeric_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
        pub struct $name(u64);

        impl $name {
            /// Zero and values above 2^53 - 1 are rejected.
            pub fn new(value: u64) -> Option<Self> {
                (1..=MAX_ID).contains(&value).then_some(Self(value))
            }
            pub fn get(self) -> u64 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v = u64::deserialize(d)?;
                Self::new(v).ok_or_else(|| serde::de::Error::custom("id_rejected"))
            }
        }
    };
}

numeric_id!(
    /// GitHub App id (deployment configuration, never committed).
    AppId
);
numeric_id!(
    /// GitHub App installation id.
    InstallationId
);
numeric_id!(
    /// GitHub repository id (stable across rename and transfer).
    RepositoryId
);
numeric_id!(
    /// GitHub user id of the sender (stable across rename).
    GithubUserId
);
numeric_id!(
    /// Pull request number within one repository.
    PullRequestNumber
);

/// `X-GitHub-Delivery`: a UUID. Normalized to lowercase.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeliveryId(String);

impl DeliveryId {
    pub fn parse(value: &str) -> Result<Self, IntakeReason> {
        let b = value.as_bytes();
        if b.len() != 36 {
            return Err(IntakeReason::DeliveryIdInvalid);
        }
        for (i, c) in b.iter().enumerate() {
            let ok = if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            };
            if !ok {
                return Err(IntakeReason::DeliveryIdInvalid);
            }
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A git commit id: 40 (SHA-1) or 64 (SHA-256) lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct HeadSha(String);

impl HeadSha {
    pub fn parse(value: &str) -> Result<Self, IntakeReason> {
        let ok_len = value.len() == 40 || value.len() == 64;
        if !ok_len
            || !value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(IntakeReason::PayloadMalformed);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HeadSha {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(|_| serde::de::Error::custom("sha_rejected"))
    }
}

/// Webhook event name (`X-GitHub-Event`): `[a-z_]{1,40}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventName(String);

impl EventName {
    pub fn parse(value: &str) -> Result<Self, IntakeReason> {
        if value.is_empty()
            || value.len() > 40
            || !value.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
        {
            return Err(IntakeReason::EventNotAllowed);
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
