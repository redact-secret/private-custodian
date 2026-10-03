//! Bounded, validated leaf types. Every string in a contract is one of these
//! (or a closed enum), so every field has an allowlisted shape and a maximum
//! size, enforced at deserialization and mirrored in the JSON Schemas.

use std::borrow::Cow;

use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ContractError;

/// Largest integer that survives every JSON implementation (2^53 - 1).
pub const MAX_SAFE_INT: u64 = (1u64 << 53) - 1;

fn all(s: &str, f: impl Fn(u8) -> bool) -> bool {
    s.bytes().all(f)
}

fn lower_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn label_char(b: u8) -> bool {
    lower_alnum(b) || matches!(b, b'.' | b'_' | b'-')
}

fn hex_char(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn b64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

/// Declares a validated string newtype with serde and schema support.
macro_rules! string_type {
    (
        $(#[$m:meta])* $name:ident,
        pattern = $pattern:expr, min = $min:expr, max = $max:expr,
        check = $check:expr
    ) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub const PATTERN: &'static str = $pattern;
            pub const MAX_LEN: usize = $max;

            /// Parse and validate. The only way to construct a value.
            pub fn parse(value: &str) -> Result<Self, ContractError> {
                let check: fn(&str) -> bool = $check;
                if value.len() < $min || value.len() > $max || !check(value) {
                    return Err(ContractError::FieldRejected);
                }
                Ok(Self(value.to_owned()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::parse(&s).map_err(de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed(stringify!($name))
            }
            fn inline_schema() -> bool {
                true
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "minLength": $min,
                    "maxLength": $max,
                    "pattern": $pattern
                })
            }
        }
    };
}

/// Random opaque identity with a fixed prefix: `<prefix>[a-z0-9]{16,64}`.
macro_rules! prefixed_id {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        string_type!(
            $(#[$m])* $name,
            pattern = concat!("^", $prefix, "[a-z0-9]{16,64}$"),
            min = $prefix.len() + 16, max = $prefix.len() + 64,
            check = |s| s.strip_prefix($prefix).is_some_and(|r| all(r, lower_alnum))
        );
    };
}

/// Bounded lowercase label: `[a-z0-9][a-z0-9._-]{0,63}`.
macro_rules! label_type {
    ($(#[$m:meta])* $name:ident) => {
        string_type!(
            $(#[$m])* $name,
            pattern = "^[a-z0-9][a-z0-9._-]{0,63}$", min = 1, max = 64,
            check = |s| s.as_bytes().first().is_some_and(|b| lower_alnum(*b)) && all(s, label_char)
        );
    };
}

/// `sha256:` + 64 lowercase hex characters. Distinct Rust types keep digests
/// of different things from being interchanged.
macro_rules! digest_type {
    ($(#[$m:meta])* $name:ident) => {
        string_type!(
            $(#[$m])* $name,
            pattern = "^sha256:[0-9a-f]{64}$", min = 71, max = 71,
            check = |s| s.strip_prefix("sha256:").is_some_and(|r| r.len() == 64 && all(r, hex_char))
        );

        impl $name {
            /// Wrap raw SHA-256 output.
            pub fn from_raw(digest: [u8; 32]) -> Self {
                let mut out = String::with_capacity(71);
                out.push_str("sha256:");
                for b in digest {
                    out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
                    out.push(char::from_digit(u32::from(b & 0xf), 16).unwrap_or('0'));
                }
                Self(out)
            }
        }
    };
}

// --- Internal identities (never public) ---------------------------------

prefixed_id!(
    /// Identity of one request (one proposed plan).
    RequestId, "req_"
);
prefixed_id!(
    /// Caller-supplied key making a mutating request replay-safe.
    IdempotencyKey, "idk_"
);
prefixed_id!(
    /// Identity of an issued approval record.
    ApprovalId, "apr_"
);
prefixed_id!(
    /// Identity of a budget reservation.
    ReservationId, "rsv_"
);
prefixed_id!(
    /// Identity of one execution attempt.
    ExecutionId, "exe_"
);
prefixed_id!(
    /// Identity of an internal or public receipt.
    ReceiptId, "rcp_"
);
prefixed_id!(
    /// Identity of an approved public projection.
    ProjectionId, "prj_"
);
prefixed_id!(
    /// Authenticated actor reference. Never an agent message or a label.
    ActorRef, "act_"
);
prefixed_id!(
    /// Internal corpus custody identity. Never public.
    CorpusId, "cor_"
);
prefixed_id!(
    /// Internal population epoch identity. Never public.
    EpochId, "epo_"
);
prefixed_id!(
    /// Internal population family identity (for example a PII family). Never public.
    FamilyId, "fam_"
);
prefixed_id!(
    /// Candidate lineage: the budget identity under which tuned copies of a
    /// candidate share one budget. A new digest alone is not a fresh budget.
    LineageId, "lin_"
);
prefixed_id!(
    /// Identity of one policy activation record.
    ActivationId, "pac_"
);
prefixed_id!(
    /// Opaque public population reference. Randomly assigned, not derived
    /// from population content.
    PublicPopulationId, "ppr_"
);
prefixed_id!(
    /// Identity of a public revocation feed.
    FeedId, "fed_"
);
prefixed_id!(
    /// Signing key identifier (a name, never key material).
    KeyId, "key_"
);

label_type!(
    /// Component, engine, adapter or scanner name.
    ComponentName
);
label_type!(
    /// Version label of a component, protocol or policy.
    VersionLabel
);
label_type!(
    /// Name of a measurement or evaluation protocol.
    ProtocolName
);
label_type!(
    /// Name of a policy.
    PolicyName
);
label_type!(
    /// Policy-defined stratum label. Allowlisted by the disclosure policy.
    StratumId
);
label_type!(
    /// Policy-defined metric label. Allowlisted by the disclosure policy.
    MetricId
);

// --- Digests -------------------------------------------------------------

digest_type!(
    /// SHA-256 of the exact staged candidate bytes (no domain prefix, so it
    /// can be checked with any SHA-256 tool).
    CandidateDigest
);
impl CandidateDigest {
    /// Digest of exact candidate bytes (plain SHA-256).
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self::from_raw(crate::canonical::raw_digest(bytes))
    }
}

digest_type!(
    /// Domain-separated digest of a canonical `EvaluationPlan`.
    PlanDigest
);
digest_type!(
    /// Digest of the frozen activation/configuration bytes.
    ConfigDigest
);
digest_type!(
    /// Digest of an engine, adapter or scanner artifact.
    ArtifactDigest
);
digest_type!(
    /// Internal sealed-population digest. Never public.
    PopulationDigest
);
digest_type!(
    /// Digest of a private result artifact. Never public.
    ResultDigest
);
digest_type!(
    /// Domain-separated digest of a canonical public projection payload.
    ProjectionDigest
);
digest_type!(
    /// Domain-separated digest of any other canonical document.
    DocumentDigest
);

// --- Signature and commitment ------------------------------------------------

string_type!(
    /// Base64url (no padding) 64-byte signature value. Verification is C7.
    SignatureValue,
    pattern = "^[A-Za-z0-9_-]{86}$", min = 86, max = 86,
    check = |s| all(s, b64url_char)
);

string_type!(
    /// Keyed population commitment: `hmac-sha256:` + 64 hex characters.
    /// The key is held by the custodian and never published, so the value is
    /// not a guessable hash of population content.
    KeyedCommitment,
    pattern = "^hmac-sha256:[0-9a-f]{64}$", min = 76, max = 76,
    check = |s| s.strip_prefix("hmac-sha256:").is_some_and(|r| r.len() == 64 && all(r, hex_char))
);

// --- Bounded numbers and collections ---------------------------------------

/// Seconds since the Unix epoch (UTC), as a JSON integer. Contracts carry no
/// clock: the control service supplies `now`. The core's logical `expires_at`
/// `u64` maps to this type (ADR 0004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const ZERO: Self = Self(0);

    pub fn new(secs: u64) -> Result<Self, ContractError> {
        if secs > MAX_SAFE_INT {
            return Err(ContractError::FieldRejected);
        }
        Ok(Self(secs))
    }
    pub fn secs(self) -> u64 {
        self.0
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl JsonSchema for Timestamp {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Timestamp")
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INT})
    }
}

/// Unsigned integer with an inclusive maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Count<const MAX: u64>(u64);

impl<const MAX: u64> Count<MAX> {
    pub fn new(v: u64) -> Result<Self, ContractError> {
        if v > MAX || v > MAX_SAFE_INT {
            return Err(ContractError::FieldRejected);
        }
        Ok(Self(v))
    }
    pub fn get(self) -> u64 {
        self.0
    }
}

impl<const MAX: u64> Serialize for Count<MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

impl<'de, const MAX: u64> Deserialize<'de> for Count<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl<const MAX: u64> JsonSchema for Count<MAX> {
    fn schema_name() -> Cow<'static, str> {
        Cow::Owned(format!("Count{MAX}"))
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "integer", "minimum": 0, "maximum": MAX})
    }
}

/// A sequence number or version counter.
pub type Seq = Count<MAX_SAFE_INT>;
/// A policy or protocol version number.
pub type Version = Count<1_000_000>;

/// A vector with a maximum length, enforced at deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoundedVec<T, N> {
    pub fn new(items: Vec<T>) -> Result<Self, ContractError> {
        if items.len() > N {
            return Err(ContractError::FieldRejected);
        }
        Ok(Self(items))
    }
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: Serialize, const N: usize> Serialize for BoundedVec<T, N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(Vec::<T>::deserialize(d)?).map_err(de::Error::custom)
    }
}

impl<T: JsonSchema, const N: usize> JsonSchema for BoundedVec<T, N> {
    fn schema_name() -> Cow<'static, str> {
        Cow::Owned(format!("BoundedVec{N}Of{}", T::schema_name()))
    }
    fn inline_schema() -> bool {
        true
    }
    fn json_schema(g: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "array", "maxItems": N, "items": g.subschema_for::<T>()})
    }
}

/// Declares a zero-sized schema tag that serializes to a fixed string and
/// rejects every other value, so a document of another type or version never
/// deserializes as this one.
macro_rules! schema_tag {
    ($(#[$m:meta])* $name:ident, $value:literal) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
        pub struct $name;

        impl $name {
            pub const VALUE: &'static str = $value;
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> ::core::result::Result<S::Ok, S::Error> {
                s.serialize_str($value)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> ::core::result::Result<Self, D::Error> {
                let s = <String as ::serde::Deserialize>::deserialize(d)?;
                if s == $value {
                    Ok(Self)
                } else {
                    Err(<D::Error as ::serde::de::Error>::custom($crate::error::ContractError::Malformed))
                }
            }
        }

        impl ::schemars::JsonSchema for $name {
            fn schema_name() -> ::std::borrow::Cow<'static, str> {
                ::std::borrow::Cow::Borrowed(stringify!($name))
            }
            fn inline_schema() -> bool {
                true
            }
            fn json_schema(_: &mut ::schemars::SchemaGenerator) -> ::schemars::Schema {
                ::schemars::json_schema!({"const": $value})
            }
        }
    };
}
pub(crate) use schema_tag;

/// `deserialize_with` for optional fields: absent is `None`, but an explicit
/// `null` is rejected (canonical form omits absent fields; there is no
/// absent-versus-null ambiguity).
pub fn some_only<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}
