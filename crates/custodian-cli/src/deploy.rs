//! The file-based deployment the `custodian` binary opens.
//!
//! A deployment config names the locations of the runtime store, the
//! operator policy, the protected-population root, the local clone of the
//! private ledger, the pinned verification roots and the feed directory. It
//! contains paths and public identifiers only; it holds no credential, key or
//! token and is not committed. Paths never appear in output.
//!
//! What is deliberately not here: a signing key. When `signer_socket_path` is
//! configured the deployment's signer is a `RemoteSigner` over the isolated
//! signer's Unix socket (`custodian-signer`, ADR 0111); it holds a key id and
//! a socket path, never a key. When it is absent, or the socket is down, slow
//! or refuses, signing fails with `signer_unavailable` ([`UnavailableSigner`]
//! for the absent case), so commands that must sign (export, feed publication)
//! report `signer_unavailable` rather than silently skipping their audit step.

use std::path::{Path, PathBuf};

use custodian_contracts::common::{PopulationBinding, Signature};
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::types::{DestinationId, EpochId, FeedId, KeyId, Timestamp};
use custodian_corpus::{FsEpochStore, ProtectedPopulations};
use custodian_disclosure::PublicPopulationNames;
use custodian_ledger::{
    ApprovedPayload, GitBackend, GitConfig, KeyEntry, Keyring, RemoteSigner, SignDomain,
    SignRefusal, Signer,
};
use custodian_lifecycle::{DirFeed, FeedConfig, NoFault, PublicPopulations};
use custodian_signer::UnixSocketTransport;
use custodian_store::{SqliteStore, StoreConfig, SystemClock};
use serde::Deserialize;

use crate::authority::PolicyAuthority;
use crate::control::Parts;
use crate::reason::CliReason;

pub const CONFIG_SCHEMA: &str = "private-custodian.cli-config/1";
const MAX_CONFIG_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    schema: String,
    store_path: PathBuf,
    operator_policy_path: PathBuf,
    corpus_root: PathBuf,
    ledger_dir: PathBuf,
    #[serde(default = "default_remote")]
    ledger_remote: String,
    #[serde(default = "default_branch")]
    ledger_branch: String,
    pinned_roots_path: PathBuf,
    feed_dir: PathBuf,
    feed_id: FeedId,
    feed_destination_label: DestinationId,
    #[serde(default = "default_ttl")]
    feed_ttl_secs: u64,
    #[serde(default = "default_margin")]
    feed_renew_margin_secs: u64,
    /// Public key identifier used to name the keyed population commitment.
    commitment_key_id: KeyId,
    /// Identifier of the signing key the isolated signer holds.
    signer_key_id: KeyId,
    /// Absolute path of the isolated signer's Unix socket (ADR 0111). Absent
    /// means no signer is configured and signing fails closed.
    #[serde(default)]
    signer_socket_path: Option<PathBuf>,
    /// If set, only a signer process running as this uid is trusted.
    #[serde(default)]
    signer_uid: Option<u32>,
    #[serde(default = "default_signer_timeout")]
    signer_timeout_secs: u64,
}

fn default_signer_timeout() -> u64 {
    10
}

fn default_remote() -> String {
    "origin".to_owned()
}
fn default_branch() -> String {
    "main".to_owned()
}
fn default_ttl() -> u64 {
    3600
}
fn default_margin() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootEntry {
    key_id: KeyId,
    public_key_hex: String,
    purposes: Vec<SignDomain>,
    valid_from: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootsFile {
    roots: Vec<RootEntry>,
}

/// Parse the pinned verification roots. Public keys only.
pub fn parse_roots(bytes: &[u8]) -> Result<Keyring, CliReason> {
    let f: RootsFile = serde_json::from_slice(bytes).map_err(|_| CliReason::NotConfigured)?;
    if f.roots.is_empty() {
        return Err(CliReason::NotConfigured);
    }
    let mut ring = Keyring::new();
    for r in f.roots {
        let entry = KeyEntry::root(
            r.key_id,
            &r.public_key_hex,
            r.purposes,
            Timestamp::new(r.valid_from).map_err(|_| CliReason::NotConfigured)?,
        )
        .ok_or(CliReason::NotConfigured)?;
        ring = ring.with_root(entry);
    }
    Ok(ring)
}

/// A signer that signs nothing. Used until a deployment provides an isolated
/// signer; every request is refused with a fixed code.
pub struct UnavailableSigner {
    key_id: KeyId,
}

impl UnavailableSigner {
    pub fn new(key_id: KeyId) -> Self {
        Self { key_id }
    }
}

impl Signer for UnavailableSigner {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    fn sign(&self, _payload: &ApprovedPayload) -> Result<Signature, SignRefusal> {
        Err(SignRefusal::SignerUnavailable)
    }
}

/// The deployment's signer: remote when a socket is configured, otherwise
/// the always-refusing [`UnavailableSigner`]. Neither variant holds a key.
pub enum ConfiguredSigner {
    Unavailable(UnavailableSigner),
    Remote(RemoteSigner<UnixSocketTransport>),
}

impl ConfiguredSigner {
    pub fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }
}

impl Signer for ConfiguredSigner {
    fn key_id(&self) -> &KeyId {
        match self {
            Self::Unavailable(s) => s.key_id(),
            Self::Remote(s) => s.key_id(),
        }
    }
    fn sign(&self, payload: &ApprovedPayload) -> Result<Signature, SignRefusal> {
        match self {
            Self::Unavailable(s) => s.sign(payload),
            Self::Remote(s) => s.sign(payload),
        }
    }
}

/// The deployment's public naming of populations: the keyed commitment of the
/// sealed population, the same object disclosure uses.
pub struct KeyedPopulations<'a> {
    pub populations: &'a ProtectedPopulations<FsEpochStore>,
    pub key_id: KeyId,
}

impl PublicPopulationNames for KeyedPopulations<'_> {
    fn public_ref(&self, b: &PopulationBinding) -> Option<PublicPopulationRef> {
        self.populations
            .public_commitment(&b.epoch_id)
            .ok()
            .map(|commitment| PublicPopulationRef::KeyedCommitment {
                key_id: self.key_id.clone(),
                commitment,
            })
    }
}

impl PublicPopulations for KeyedPopulations<'_> {
    fn public_ref(&self, epoch: &EpochId) -> Option<PublicPopulationRef> {
        let view = self.populations.registry().view().ok()?;
        let (row, _) = view.get(epoch)?;
        let binding = PopulationBinding {
            domain: row.domain,
            corpus_id: row.corpus_id.clone(),
            epoch_id: row.epoch_id.clone(),
            family_id: row.family_id.clone(),
            population_digest: row.population_digest.clone(),
            custody_version: row.custody_version,
        };
        PublicPopulationNames::public_ref(self, &binding)
    }
}

/// Everything opened from a deployment config. Owns the objects; borrow a
/// [`Parts`] from it with [`Deployment::parts`].
pub struct Deployment {
    pub store: SqliteStore,
    pub authority: PolicyAuthority,
    pub populations: ProtectedPopulations<FsEpochStore>,
    pub ledger: GitBackend,
    pub roots: Keyring,
    pub signer: ConfiguredSigner,
    pub feed: DirFeed,
    pub feed_config: FeedConfig,
    pub commitment_key_id: KeyId,
    pub fault: NoFault,
}

/// Read a security-relevant file only if it is a regular file (never a
/// symbolic link), no larger than `max`, and carries none of the mode bits in
/// `forbidden_mode`. A refusal does not say which check failed or name the
/// path. The operator policy and pinned roots forbid group and other write
/// (`0o022`): anyone who can write them can add an operator or a trust anchor.
/// A credential file forbids all group and other access (`0o077`), as the
/// runbook requires.
pub fn read_checked(path: &Path, max: usize, forbidden_mode: u32) -> Result<Vec<u8>, CliReason> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).map_err(|_| CliReason::NotConfigured)?;
    if !meta.file_type().is_file()
        || meta.len() > max as u64
        || meta.permissions().mode() & forbidden_mode != 0
    {
        return Err(CliReason::NotConfigured);
    }
    std::fs::read(path).map_err(|_| CliReason::NotConfigured)
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>, CliReason> {
    read_checked(path, max, 0o022)
}

impl Deployment {
    /// Open every component. Any failure is `not_configured` or a store
    /// code; none names a path.
    pub fn open(config_bytes: &[u8]) -> Result<Self, CliReason> {
        if config_bytes.len() > MAX_CONFIG_BYTES {
            return Err(CliReason::NotConfigured);
        }
        let c: ConfigFile =
            serde_json::from_slice(config_bytes).map_err(|_| CliReason::NotConfigured)?;
        if c.schema != CONFIG_SCHEMA || c.feed_ttl_secs == 0 || c.feed_renew_margin_secs == 0 {
            return Err(CliReason::NotConfigured);
        }
        let authority = PolicyAuthority::from_json(&read_bounded(
            &c.operator_policy_path,
            crate::authority::MAX_POLICY_BYTES,
        )?)?;
        // The commitment key is provisioned with the corpus root; the CLI
        // never creates one.
        if !c.corpus_root.join("keys").join("commitment.key").is_file() {
            return Err(CliReason::NotConfigured);
        }
        let populations =
            ProtectedPopulations::open_fs(&c.corpus_root).map_err(|_| CliReason::NotConfigured)?;
        // The R-2 dispatch gate is always enforced for a deployment (ADR 0116).
        let store = SqliteStore::open_with_config(&c.store_path, StoreConfig::enforced())
            .map_err(CliReason::from)?;
        let ledger = GitBackend::open(
            &c.ledger_dir,
            GitConfig {
                remote: c.ledger_remote,
                branch: c.ledger_branch,
                ..GitConfig::default()
            },
        )
        .map_err(|_| CliReason::LedgerUnavailable)?;
        let roots = parse_roots(&read_bounded(&c.pinned_roots_path, 64 * 1024)?)?;
        let signer = match c.signer_socket_path {
            None => ConfiguredSigner::Unavailable(UnavailableSigner::new(c.signer_key_id)),
            Some(path) => {
                if !path.is_absolute() || c.signer_timeout_secs == 0 || c.signer_timeout_secs > 60 {
                    return Err(CliReason::NotConfigured);
                }
                let mut transport = UnixSocketTransport::new(
                    path,
                    std::time::Duration::from_secs(c.signer_timeout_secs),
                );
                if let Some(uid) = c.signer_uid {
                    transport = transport.expecting_signer_uid(uid);
                }
                ConfiguredSigner::Remote(RemoteSigner::new(c.signer_key_id, transport))
            }
        };
        Ok(Self {
            store,
            authority,
            populations,
            ledger,
            roots,
            signer,
            feed: DirFeed::new(c.feed_dir),
            feed_config: FeedConfig {
                feed_id: c.feed_id,
                destination_label: c.feed_destination_label,
                ttl_secs: c.feed_ttl_secs,
                renew_margin_secs: c.feed_renew_margin_secs,
            },
            commitment_key_id: c.commitment_key_id,
            fault: NoFault,
        })
    }

    pub fn names(&self) -> KeyedPopulations<'_> {
        KeyedPopulations {
            populations: &self.populations,
            key_id: self.commitment_key_id.clone(),
        }
    }

    /// Wire the control plane. `names` must outlive the returned parts; build
    /// it with [`Deployment::names`] first.
    pub fn parts<'a>(&'a self, names: &'a KeyedPopulations<'a>) -> Parts<'a, FsEpochStore> {
        Parts {
            store: &self.store,
            clock: std::sync::Arc::new(SystemClock),
            authority: &self.authority,
            populations: &self.populations,
            ledger: &self.ledger,
            roots: &self.roots,
            signer: &self.signer,
            feed_destination: &self.feed,
            feed_populations: names,
            feed_config: self.feed_config.clone(),
            fault: &self.fault,
        }
    }
}
