//! The daemon configuration (`private-custodian.daemon-config/1`).
//!
//! # Rules
//!
//! * **Strict.** Every section rejects unknown fields; a missing required
//!   field, a wrong schema tag, a value outside its range or a relative path
//!   is `config_invalid`. There is no environment-variable override and no
//!   flag that loosens a limit.
//! * **Secrets by path only.** The webhook secret and the App private key are
//!   named by path; their values never appear in the file. The loader reads
//!   such a file only if it is a regular file (never a symlink), small, and has
//!   no group or other permission bits at all (`0600`).
//! * **No inline credential, no deployment identifier in the repository.**
//!   `deploy/examples/daemon-config.example.json` holds placeholders. A path that does
//!   not exist makes the placeholder file fail to load, by design.
//! * **Nothing activates by itself.** GitHub access is `disabled` unless the
//!   file says otherwise; the listener binds loopback unless the file allows
//!   another address; a feature that needs a human or an operator (a release
//!   approval, the feed publication) has no setting that grants it.
//!
//! Paths in this file are paths on the deployment host. Errors never print
//! them.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use custodian_contracts::common::{ActivationRef, Authorship, ReviewStatus};
use custodian_contracts::types::DestinationId;
use custodian_intake::config::{IntakeConfig, WebhookSecret, MAX_CONFIG_BYTES as MAX_INTAKE_BYTES};
use serde::Deserialize;

use crate::http::ListenerConfig;
use crate::reason::DaemonReason;

pub const CONFIG_SCHEMA: &str = "private-custodian.daemon-config/1";
const MAX_CONFIG_BYTES: usize = 32 * 1024;
/// A webhook secret file is a few dozen bytes; refuse anything large.
const MAX_SECRET_BYTES: usize = 1024;
const MAX_POLICY_BYTES: usize = 128 * 1024;
const MAX_INTERVAL_SECS: u64 = 86_400;

// ---- file shape ----------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntakeSection {
    config_path: PathBuf,
    webhook_secret_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenerSection {
    bind: String,
    path: String,
    #[serde(default)]
    allow_non_loopback: bool,
    max_connections: Option<usize>,
    max_request_line_bytes: Option<usize>,
    max_head_bytes: Option<usize>,
    max_headers: Option<usize>,
    first_byte_timeout_secs: Option<u64>,
    head_timeout_secs: Option<u64>,
    body_timeout_secs: Option<u64>,
    write_timeout_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubMode {
    /// No GitHub access of any kind. The queue is not consumed, so queued
    /// deliveries wait (durably) until a deployer enables a mode.
    Disabled,
    /// Plain HTTP to a loopback address (tests and rehearsal against a fake).
    LoopbackHttp,
    /// The real HTTPS API. This repository ships only a skeleton executor, so
    /// the binary refuses this mode (ADR 0124).
    Https,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GithubSection {
    mode: GithubMode,
    app_id: Option<u64>,
    app_private_key_path: Option<PathBuf>,
    /// `127.0.0.1:port` for `loopback_http`.
    loopback_addr: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSection {
    sandbox: Sandbox,
    probe_path: Option<PathBuf>,
    staging_dir: PathBuf,
    verification_max_age_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sandbox {
    /// The Linux bubblewrap backend, accepted only after the startup
    /// self-check passes on this host.
    Bubblewrap,
    /// No worker: approved runs wait with `worker_unavailable` and nothing is
    /// executed.
    None,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyActivationSection {
    activation_id: String,
    sequence: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSection {
    disclosure_policy_path: PathBuf,
    policy_activation: PolicyActivationSection,
    destination: String,
    approvals_dir: PathBuf,
    output_dir: PathBuf,
    provision_budgets_from_policy: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationSection {
    authorship: Authorship,
    review: ReviewStatus,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueSection {
    workers: Option<usize>,
    owner: Option<String>,
    lease_secs: Option<u64>,
    max_attempts: Option<u32>,
    backoff_base_secs: Option<u64>,
    backoff_max_secs: Option<u64>,
    poll_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleSection {
    recover_secs: Option<u64>,
    reconcile_registry_secs: Option<u64>,
    deliver_pending_secs: Option<u64>,
    export_secs: Option<u64>,
    checkpoint_secs: Option<u64>,
    startup_check_secs: Option<u64>,
    signer_liveness_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PipelineSection {
    owner: Option<String>,
    worker_actor: Option<String>,
    lease_secs: Option<u64>,
    poll_ms: Option<u64>,
    shutdown_grace_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    schema: String,
    deployment_config_path: PathBuf,
    intake: IntakeSection,
    listener: ListenerSection,
    github: GithubSection,
    requests_dir: PathBuf,
    artifacts_dir: PathBuf,
    worker: WorkerSection,
    release: ReleaseSection,
    attestation: AttestationSection,
    #[serde(default)]
    required_activations: Vec<ActivationRef>,
    #[serde(default)]
    queue: QueueSection,
    #[serde(default)]
    schedule: ScheduleSection,
    #[serde(default)]
    pipeline: PipelineSection,
}

// ---- validated shape -------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GithubConfig {
    pub mode: GithubMode,
    pub app_id: Option<u64>,
    pub app_private_key_path: Option<PathBuf>,
    pub loopback_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct WorkerConfig {
    pub sandbox: Sandbox,
    pub probe_path: Option<PathBuf>,
    pub staging_dir: PathBuf,
    pub verification_max_age_secs: u64,
}

#[derive(Clone, Debug)]
pub struct ReleaseConfig {
    pub disclosure_policy_path: PathBuf,
    pub activation_id: String,
    pub activation_sequence: u64,
    pub destination: DestinationId,
    pub approvals_dir: PathBuf,
    pub output_dir: PathBuf,
    pub provision_budgets_from_policy: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct AttestationConfig {
    pub authorship: Authorship,
    pub review: ReviewStatus,
}

#[derive(Clone, Debug)]
pub struct QueueConfig {
    pub workers: usize,
    pub owner: String,
    pub lease_secs: u64,
    /// A leased item that has already been leased this many times is set
    /// aside as poison instead of being tried again.
    pub max_attempts: u32,
    pub backoff_base_secs: u64,
    pub backoff_max_secs: u64,
    pub poll: Duration,
}

impl QueueConfig {
    /// Backoff for the `n`th lease of an item (1-based): base, doubling,
    /// capped. Deterministic: no jitter, so tests assert exact schedules.
    pub fn backoff_secs(&self, attempts: u32) -> u64 {
        let shift = attempts.saturating_sub(1).min(20);
        self.backoff_base_secs
            .saturating_mul(1u64 << shift)
            .min(self.backoff_max_secs)
    }
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            owner: "custodiand".to_owned(),
            lease_secs: 120,
            max_attempts: 5,
            backoff_base_secs: 5,
            backoff_max_secs: 300,
            poll: Duration::from_millis(500),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ScheduleConfig {
    pub recover_secs: u64,
    pub reconcile_registry_secs: u64,
    pub deliver_pending_secs: u64,
    pub export_secs: u64,
    pub checkpoint_secs: u64,
    pub startup_check_secs: u64,
    pub signer_liveness_secs: u64,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            recover_secs: 60,
            reconcile_registry_secs: 300,
            deliver_pending_secs: 60,
            export_secs: 30,
            checkpoint_secs: 300,
            startup_check_secs: 300,
            signer_liveness_secs: 60,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub owner: String,
    pub worker_actor: String,
    pub lease_secs: u64,
    pub poll: Duration,
    pub shutdown_grace: Duration,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            owner: "custodiand".to_owned(),
            worker_actor: "custodiand".to_owned(),
            lease_secs: 300,
            poll: Duration::from_millis(500),
            shutdown_grace: Duration::from_secs(30),
        }
    }
}

/// A validated configuration. Only constructible through [`DaemonConfig::from_json`]
/// or [`DaemonConfig::load`].
#[derive(Clone, Debug)]
pub struct DaemonConfig {
    pub deployment_config_path: PathBuf,
    pub intake_config_path: PathBuf,
    pub webhook_secret_path: PathBuf,
    /// The listener limits. `max_body_bytes` is a placeholder here; the
    /// runtime sets it from the intake configuration's own cap.
    pub listener: ListenerConfig,
    pub github: GithubConfig,
    pub requests_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    pub worker: WorkerConfig,
    pub release: ReleaseConfig,
    pub attestation: AttestationConfig,
    pub required_activations: Vec<ActivationRef>,
    pub queue: QueueConfig,
    pub schedule: ScheduleConfig,
    pub pipeline: PipelineConfig,
}

fn bad<T>() -> Result<T, DaemonReason> {
    Err(DaemonReason::ConfigInvalid)
}

fn abs(p: &Path) -> Result<(), DaemonReason> {
    if p.is_absolute() && p.to_str().is_some_and(|s| !s.contains('\0')) {
        Ok(())
    } else {
        bad()
    }
}

fn ranged(v: Option<u64>, default: u64, lo: u64, hi: u64) -> Result<u64, DaemonReason> {
    let v = v.unwrap_or(default);
    if (lo..=hi).contains(&v) {
        Ok(v)
    } else {
        bad()
    }
}

fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl DaemonConfig {
    /// Parse and validate the file's contents. Touches no file; see
    /// [`DaemonConfig::validate_filesystem`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, DaemonReason> {
        if bytes.len() > MAX_CONFIG_BYTES {
            return bad();
        }
        let f: File = serde_json::from_slice(bytes).map_err(|_| DaemonReason::ConfigInvalid)?;
        if f.schema != CONFIG_SCHEMA {
            return bad();
        }
        for p in [
            &f.deployment_config_path,
            &f.intake.config_path,
            &f.intake.webhook_secret_path,
            &f.requests_dir,
            &f.artifacts_dir,
            &f.worker.staging_dir,
            &f.release.disclosure_policy_path,
            &f.release.approvals_dir,
            &f.release.output_dir,
        ] {
            abs(p)?;
        }
        if let Some(p) = &f.github.app_private_key_path {
            abs(p)?;
        }
        if let Some(p) = &f.worker.probe_path {
            abs(p)?;
        }

        let l = &f.listener;
        let bind: SocketAddr = l.bind.parse().map_err(|_| DaemonReason::ConfigInvalid)?;
        let mut listener = ListenerConfig::new(bind, &l.path, 1);
        listener.allow_non_loopback = l.allow_non_loopback;
        let secs = |v: Option<u64>, d: Duration| v.map(Duration::from_secs).unwrap_or(d);
        if let Some(v) = l.max_connections {
            listener.max_connections = v;
        }
        if let Some(v) = l.max_request_line_bytes {
            listener.max_request_line_bytes = v;
        }
        if let Some(v) = l.max_head_bytes {
            listener.max_head_bytes = v;
        }
        if let Some(v) = l.max_headers {
            listener.max_headers = v;
        }
        listener.first_byte_timeout = secs(l.first_byte_timeout_secs, listener.first_byte_timeout);
        listener.head_timeout = secs(l.head_timeout_secs, listener.head_timeout);
        listener.body_timeout = secs(l.body_timeout_secs, listener.body_timeout);
        listener.write_timeout = secs(l.write_timeout_secs, listener.write_timeout);
        // Validate with the body cap the runtime will use at most.
        let mut probe = listener.clone();
        probe.max_body_bytes = crate::http::MAX_BODY_BYTES_CEILING;
        probe.validate()?;

        let g = &f.github;
        let loopback_addr = match g.loopback_addr.as_deref() {
            None => None,
            Some(a) => Some(
                a.parse::<SocketAddr>()
                    .map_err(|_| DaemonReason::ConfigInvalid)?,
            ),
        };
        match g.mode {
            GithubMode::Disabled => {
                if g.app_id.is_some() || g.app_private_key_path.is_some() || loopback_addr.is_some()
                {
                    return bad();
                }
            }
            GithubMode::LoopbackHttp => {
                if !loopback_addr.is_some_and(|a| a.ip().is_loopback()) {
                    return bad();
                }
            }
            GithubMode::Https => {
                if loopback_addr.is_some() {
                    return bad();
                }
            }
        }
        if g.mode != GithubMode::Disabled
            && (g.app_id.is_none_or(|n| n == 0) || g.app_private_key_path.is_none())
        {
            return bad();
        }

        let w = &f.worker;
        if w.sandbox == Sandbox::Bubblewrap && w.probe_path.is_none() {
            return bad();
        }
        let worker = WorkerConfig {
            sandbox: w.sandbox,
            probe_path: w.probe_path.clone(),
            staging_dir: w.staging_dir.clone(),
            verification_max_age_secs: ranged(w.verification_max_age_secs, 3600, 60, 86_400)?,
        };

        let r = &f.release;
        if !label(&r.destination) || r.policy_activation.sequence == 0 {
            return bad();
        }
        let release = ReleaseConfig {
            disclosure_policy_path: r.disclosure_policy_path.clone(),
            activation_id: r.policy_activation.activation_id.clone(),
            activation_sequence: r.policy_activation.sequence,
            destination: DestinationId::parse(&r.destination)
                .map_err(|_| DaemonReason::ConfigInvalid)?,
            approvals_dir: r.approvals_dir.clone(),
            output_dir: r.output_dir.clone(),
            provision_budgets_from_policy: r.provision_budgets_from_policy.unwrap_or(true),
        };

        let q = &f.queue;
        let qd = QueueConfig::default();
        let queue = QueueConfig {
            workers: match q.workers {
                None => qd.workers,
                Some(n) if (1..=8).contains(&n) => n,
                Some(_) => return bad(),
            },
            owner: match &q.owner {
                None => qd.owner,
                Some(o) if label(o) => o.clone(),
                Some(_) => return bad(),
            },
            lease_secs: ranged(q.lease_secs, qd.lease_secs, 1, 3600)?,
            max_attempts: u32::try_from(ranged(q.max_attempts.map(u64::from), 5, 1, 50)?)
                .map_err(|_| DaemonReason::ConfigInvalid)?,
            backoff_base_secs: ranged(q.backoff_base_secs, qd.backoff_base_secs, 1, 3600)?,
            backoff_max_secs: ranged(q.backoff_max_secs, qd.backoff_max_secs, 1, 86_400)?,
            poll: Duration::from_millis(ranged(q.poll_ms, 500, 10, 60_000)?),
        };
        if queue.backoff_max_secs < queue.backoff_base_secs {
            return bad();
        }

        let s = &f.schedule;
        let sd = ScheduleConfig::default();
        let iv = |v: Option<u64>, d: u64| ranged(v, d, 1, MAX_INTERVAL_SECS);
        let schedule = ScheduleConfig {
            recover_secs: iv(s.recover_secs, sd.recover_secs)?,
            reconcile_registry_secs: iv(s.reconcile_registry_secs, sd.reconcile_registry_secs)?,
            deliver_pending_secs: iv(s.deliver_pending_secs, sd.deliver_pending_secs)?,
            export_secs: iv(s.export_secs, sd.export_secs)?,
            checkpoint_secs: iv(s.checkpoint_secs, sd.checkpoint_secs)?,
            startup_check_secs: iv(s.startup_check_secs, sd.startup_check_secs)?,
            signer_liveness_secs: iv(s.signer_liveness_secs, sd.signer_liveness_secs)?,
        };

        let p = &f.pipeline;
        let pd = PipelineConfig::default();
        let pipeline = PipelineConfig {
            owner: match &p.owner {
                None => pd.owner,
                Some(o) if label(o) => o.clone(),
                Some(_) => return bad(),
            },
            worker_actor: match &p.worker_actor {
                None => pd.worker_actor,
                Some(o) if label(o) => o.clone(),
                Some(_) => return bad(),
            },
            lease_secs: ranged(p.lease_secs, pd.lease_secs, 30, 3600)?,
            poll: Duration::from_millis(ranged(p.poll_ms, 500, 10, 60_000)?),
            shutdown_grace: Duration::from_secs(ranged(p.shutdown_grace_secs, 30, 0, 600)?),
        };

        Ok(Self {
            deployment_config_path: f.deployment_config_path,
            intake_config_path: f.intake.config_path,
            webhook_secret_path: f.intake.webhook_secret_path,
            listener,
            github: GithubConfig {
                mode: g.mode,
                app_id: g.app_id,
                app_private_key_path: f.github.app_private_key_path,
                loopback_addr,
            },
            requests_dir: f.requests_dir,
            artifacts_dir: f.artifacts_dir,
            worker,
            release,
            attestation: AttestationConfig {
                authorship: f.attestation.authorship,
                review: f.attestation.review,
            },
            required_activations: f.required_activations,
            queue,
            schedule,
            pipeline,
        })
    }

    /// Read the file (a regular file, no symlink, not group- or
    /// other-writable, at most 32 KiB) and parse it.
    pub fn load(path: &Path) -> Result<Self, DaemonReason> {
        let bytes = custodian_cli::deploy::read_checked(path, MAX_CONFIG_BYTES, 0o022)
            .map_err(|_| DaemonReason::NotConfigured)?;
        let c = Self::from_json(&bytes)?;
        c.validate_filesystem()?;
        Ok(c)
    }

    /// Check that every referenced directory exists, is a real directory (not
    /// a symlink) and is not writable by group or other, and that the
    /// secret files are acceptable. Reads no secret value.
    pub fn validate_filesystem(&self) -> Result<(), DaemonReason> {
        for d in [
            &self.requests_dir,
            &self.artifacts_dir,
            &self.worker.staging_dir,
            &self.release.approvals_dir,
            &self.release.output_dir,
        ] {
            check_dir(d)?;
        }
        // The staging and output directories hold private or released data:
        // owner-only.
        for d in [&self.worker.staging_dir, &self.release.output_dir] {
            check_owner_only_dir(d)?;
        }
        check_secret_file(&self.webhook_secret_path, MAX_SECRET_BYTES)?;
        if let Some(k) = &self.github.app_private_key_path {
            check_secret_file(k, 16 * 1024)?;
        }
        for f in [
            &self.deployment_config_path,
            &self.intake_config_path,
            &self.release.disclosure_policy_path,
        ] {
            custodian_cli::deploy::read_checked(f, MAX_POLICY_BYTES, 0o022)
                .map_err(|_| DaemonReason::NotConfigured)?;
        }
        Ok(())
    }

    /// The intake configuration (identifiers only).
    pub fn read_intake_config(&self) -> Result<IntakeConfig, DaemonReason> {
        let bytes =
            custodian_cli::deploy::read_checked(&self.intake_config_path, MAX_INTAKE_BYTES, 0o022)
                .map_err(|_| DaemonReason::NotConfigured)?;
        IntakeConfig::from_json(&bytes).map_err(|_| DaemonReason::ConfigInvalid)
    }

    /// The webhook secret, from its `0600` file. The value is returned only
    /// inside the redacting type.
    pub fn read_webhook_secret(&self) -> Result<WebhookSecret, DaemonReason> {
        use zeroize::Zeroize;
        let mut bytes =
            custodian_cli::deploy::read_checked(&self.webhook_secret_path, MAX_SECRET_BYTES, 0o077)
                .map_err(|_| DaemonReason::SecretFileRejected)?;
        // A trailing newline from `echo`/an editor is not part of the secret.
        while bytes.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
            bytes.pop();
        }
        let out = WebhookSecret::new(bytes.clone()).map_err(|_| DaemonReason::SecretFileRejected);
        bytes.zeroize();
        out
    }

    /// The disclosure policy document (public by design).
    pub fn read_policy_bytes(&self) -> Result<Vec<u8>, DaemonReason> {
        custodian_cli::deploy::read_checked(
            &self.release.disclosure_policy_path,
            MAX_POLICY_BYTES,
            0o022,
        )
        .map_err(|_| DaemonReason::NotConfigured)
    }
}

fn check_dir(p: &Path) -> Result<(), DaemonReason> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::symlink_metadata(p).map_err(|_| DaemonReason::NotConfigured)?;
    if !m.file_type().is_dir() || m.permissions().mode() & 0o022 != 0 {
        return Err(DaemonReason::NotConfigured);
    }
    Ok(())
}

fn check_owner_only_dir(p: &Path) -> Result<(), DaemonReason> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::symlink_metadata(p).map_err(|_| DaemonReason::NotConfigured)?;
    if m.permissions().mode() & 0o077 != 0 {
        return Err(DaemonReason::NotConfigured);
    }
    Ok(())
}

/// A secret file exists, is regular, small and `0600`-like. Does not read it.
fn check_secret_file(p: &Path, max: usize) -> Result<(), DaemonReason> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::symlink_metadata(p).map_err(|_| DaemonReason::SecretFileRejected)?;
    if !m.file_type().is_file() || m.len() > max as u64 || m.permissions().mode() & 0o077 != 0 {
        return Err(DaemonReason::SecretFileRejected);
    }
    Ok(())
}
