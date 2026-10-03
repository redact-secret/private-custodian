//! The signer's own configuration file. Paths, public identifiers and numbers
//! only: it never contains key material and is not secret (ADR 0112).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use custodian_contracts::types::KeyId;
use custodian_ledger::SignDomain;
use serde::Deserialize;

use crate::engine::SignerSetup;
use crate::server::ServerConfig;

pub const CONFIG_SCHEMA: &str = "private-custodian.signer-config/1";
pub const MAX_CONFIG_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    schema: String,
    key_id: KeyId,
    key_path: PathBuf,
    socket_path: PathBuf,
    allowed_peer_uid: u32,
    /// Signing domain tags this key may sign.
    purposes: Vec<String>,
    valid_from: u64,
    #[serde(default)]
    not_after: Option<u64>,
    #[serde(default = "default_timeout")]
    io_timeout_secs: u64,
    #[serde(default = "default_concurrency")]
    max_concurrent: usize,
    #[serde(default = "default_skew")]
    max_request_skew_secs: u64,
}

fn default_timeout() -> u64 {
    5
}
fn default_concurrency() -> usize {
    4
}
fn default_skew() -> u64 {
    120
}

/// A parsed, validated signer configuration.
#[derive(Debug)]
pub struct SignerConfig {
    pub key_path: PathBuf,
    pub setup: SignerSetup,
    pub server: ServerConfig,
}

impl SignerConfig {
    pub fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError);
        }
        let c: ConfigFile = serde_json::from_slice(bytes).map_err(|_| ConfigError)?;
        let mut purposes = BTreeSet::new();
        for tag in &c.purposes {
            purposes.insert(SignDomain::from_tag(tag).ok_or(ConfigError)?);
        }
        if c.schema != CONFIG_SCHEMA
            || purposes.is_empty()
            || !c.key_path.is_absolute()
            || !c.socket_path.is_absolute()
            || c.io_timeout_secs == 0
            || c.io_timeout_secs > 60
            || c.max_concurrent == 0
            || c.max_concurrent > 64
            || c.not_after.is_some_and(|n| n <= c.valid_from)
        {
            return Err(ConfigError);
        }
        Ok(Self {
            key_path: c.key_path,
            setup: SignerSetup {
                key_id: c.key_id,
                purposes,
                valid_from: c.valid_from,
                not_after: c.not_after,
                max_request_skew_secs: c.max_request_skew_secs,
            },
            server: ServerConfig {
                socket_path: c.socket_path,
                allowed_peer_uid: c.allowed_peer_uid,
                io_timeout: Duration::from_secs(c.io_timeout_secs),
                max_concurrent: c.max_concurrent,
            },
        })
    }
}
