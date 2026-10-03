//! Distinct identity types. They are separate Rust types so they cannot be
//! interchanged by accident (see CONVENTIONS.md, "Identity and transitions").
//!
//! The inner representation is an opaque string. Wire encodings, canonical
//! serialization and digests are defined in `custodian-contracts` (ADR 0004);
//! adapters convert between these and the validated contract types.

macro_rules! opaque_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_id!(
    /// Authenticated actor reference (never a model or an agent message).
    ActorId
);
opaque_id!(
    /// Digest of an exact frozen evaluation plan (wire form: `custodian_contracts::types::PlanDigest`).
    PlanDigest
);
opaque_id!(
    /// Internal corpus custody identity. Never a public identifier.
    PopulationId
);
opaque_id!(
    /// Unique run identity.
    RunId
);
opaque_id!(
    /// Caller-supplied key making a mutating request replay-safe.
    IdempotencyKey
);
opaque_id!(
    /// Identity of an issued authorization record.
    AuthorizationId
);
