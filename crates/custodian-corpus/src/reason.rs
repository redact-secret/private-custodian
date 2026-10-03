//! Fixed reason codes. No variant carries a path, name, byte or free-form
//! text, so an error can be logged, returned or exported without leaking
//! protected material (CONVENTIONS.md, "Execution and logging").

use core::fmt;

use custodian_core::lifecycle::ReasonCode;
use custodian_core::ports::Refusal;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageReason {
    /// Storage root missing, not absolute, a symlink or not a directory.
    RootInvalid,
    /// Storage root (or an ancestor) is inside a Git working tree.
    RootInsideGitTree,
    /// A path component resolves outside the storage layout.
    PathEscape,
    /// An entry or epoch name is outside the allowlisted shape.
    NameInvalid,
    SymlinkRefused,
    HardlinkRefused,
    SpecialFileRefused,
    /// Mode bits differ from the required 0700/0600 (staging) or 0500/0400 (sealed).
    PermissionViolation,
    /// File or directory is not owned by the storage owner.
    OwnerMismatch,
    AlreadyExists,
    NotFound,
    /// Unexpected or missing file in the storage layout.
    LayoutInvalid,
    /// Mutation attempted on a sealed epoch.
    EpochSealed,
    /// Read of sealed material attempted on an unsealed epoch.
    EpochNotSealed,
    /// The epoch on disk, in the seal or in the request does not match.
    WrongEpoch,
    UnknownEpoch,
    /// The epoch is not in the `active` registry state.
    NotActive,
    /// Stored bytes do not match the sealed commitment (tamper or corruption).
    IntegrityMismatch,
    SealInvalid,
    ManifestInvalid,
    ReviewMissing,
    BindingMismatch,
    EmptyCorpus,
    TooLarge,
    RegistryInvalid,
    InvalidTransition,
    InvalidHandle,
    KeyInvalid,
    /// Adapter I/O failure or unavailable backend. Always fail closed.
    Io,
}

impl StorageReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::RootInvalid => "root_invalid",
            Self::RootInsideGitTree => "root_inside_git_tree",
            Self::PathEscape => "path_escape",
            Self::NameInvalid => "name_invalid",
            Self::SymlinkRefused => "symlink_refused",
            Self::HardlinkRefused => "hardlink_refused",
            Self::SpecialFileRefused => "special_file_refused",
            Self::PermissionViolation => "permission_violation",
            Self::OwnerMismatch => "owner_mismatch",
            Self::AlreadyExists => "already_exists",
            Self::NotFound => "not_found",
            Self::LayoutInvalid => "layout_invalid",
            Self::EpochSealed => "epoch_sealed",
            Self::EpochNotSealed => "epoch_not_sealed",
            Self::WrongEpoch => "wrong_epoch",
            Self::UnknownEpoch => "unknown_epoch",
            Self::NotActive => "not_active",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::SealInvalid => "seal_invalid",
            Self::ManifestInvalid => "manifest_invalid",
            Self::ReviewMissing => "review_missing",
            Self::BindingMismatch => "binding_mismatch",
            Self::EmptyCorpus => "empty_corpus",
            Self::TooLarge => "too_large",
            Self::RegistryInvalid => "registry_invalid",
            Self::InvalidTransition => "invalid_transition",
            Self::InvalidHandle => "invalid_handle",
            Self::KeyInvalid => "key_invalid",
            Self::Io => "io_failure",
        }
    }
}

impl fmt::Display for StorageReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for StorageReason {}

pub type Result<T> = core::result::Result<T, StorageReason>;

impl From<StorageReason> for Refusal {
    /// Core ports carry only core reason codes. Backend failure maps to
    /// `StoreUnavailable`; every other refusal is `CorpusUnavailable`.
    fn from(r: StorageReason) -> Self {
        Refusal(match r {
            StorageReason::Io => ReasonCode::StoreUnavailable,
            _ => ReasonCode::CorpusUnavailable,
        })
    }
}
