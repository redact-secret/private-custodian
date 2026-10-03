//! `custodiand`: the service daemon binary (S5).
//!
//! ```text
//! custodiand run --config <path>           start the daemon
//! custodiand check-config --config <path>  validate the configuration and the files it names
//! custodiand --version
//! ```
//!
//! The binary reads one configuration file (`docs/daemon.md`,
//! `docs/daemon-config.example.json`), opens the deployment the operator CLI
//! opens, and runs until `SIGTERM` or `SIGINT`. It prints fixed
//! `component=<word> code=<word>` lines to standard error and nothing else:
//! no body, header, signature, token, path or engine text. It is not run by
//! anything in this repository and nothing here deploys it; the GitHub
//! webhook it would serve stays inactive.
//!
//! GitHub access is `disabled` unless the configuration says otherwise, and
//! the real HTTPS client is not built (ADR 0124): `https` mode is refused at
//! startup with `github_https_not_built`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use custodian_cli::deploy::Deployment;
use custodian_daemon::config::{DaemonConfig, GithubMode};
use custodian_daemon::github::plain::PlainHttp;
use custodian_daemon::github::{GithubAdapters, GithubApi, Rs256Signer};
use custodian_daemon::log::{EventLog, StderrLog};
use custodian_daemon::pipeline::approvals::DirApprovals;
use custodian_daemon::pipeline::NoPipelineFault;
use custodian_daemon::reason::DaemonReason;
use custodian_daemon::runtime::{build_worker, run, RunInputs};
use custodian_daemon::shutdown::Shutdown;
use custodian_daemon::sink::DirSink;
use custodian_daemon::source::{DirRequestSource, DirStager};
use custodian_disclosure::DisclosurePolicy;
use custodian_intake::checks::CheckSink;
use custodian_intake::credentials::RequestFacingAppCredential;
use custodian_intake::ids::AppId;
use custodian_intake::ports::PullRequestSource;
use custodian_store::{StoreConfig, SystemClock};

fn arg_value(args: &[String], flag: &str) -> Option<PathBuf> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
}

/// Block `SIGTERM` and `SIGINT` in every thread (this runs before any thread
/// is spawned) and wait for them on one dedicated thread. No handler runs in
/// an arbitrary context and no `unsafe` is involved.
fn install_signal_thread(shutdown: &Shutdown) -> Result<(), DaemonReason> {
    use nix::sys::signal::{SigSet, Signal};
    let mut set = SigSet::empty();
    set.add(Signal::SIGTERM);
    set.add(Signal::SIGINT);
    set.thread_block().map_err(|_| DaemonReason::Degraded)?;
    let shutdown = shutdown.clone();
    std::thread::Builder::new()
        .name("signals".to_owned())
        .spawn(move || {
            if set.wait().is_ok() {
                shutdown.request();
            }
        })
        .map_err(|_| DaemonReason::Degraded)?;
    Ok(())
}

fn fail(log: &dyn EventLog, r: DaemonReason) -> ExitCode {
    log.event("daemon", r.as_str());
    ExitCode::from(match r {
        DaemonReason::NotConfigured
        | DaemonReason::ConfigInvalid
        | DaemonReason::SecretFileRejected => 7,
        DaemonReason::StartupRefused => 8,
        _ => 1,
    })
}

fn run_daemon(config_path: &std::path::Path, log: Arc<dyn EventLog>) -> Result<(), DaemonReason> {
    let cfg = DaemonConfig::load(config_path)?;
    if cfg.github.mode == GithubMode::Https {
        log.event("daemon", "github_https_not_built");
        return Err(DaemonReason::NotConfigured);
    }
    let intake = cfg.read_intake_config()?;
    let secret = cfg.read_webhook_secret()?;
    let policy_bytes = cfg.read_policy_bytes()?;
    let policy: DisclosurePolicy =
        serde_json::from_slice(&policy_bytes).map_err(|_| DaemonReason::ConfigInvalid)?;
    policy.validate().map_err(|_| DaemonReason::ConfigInvalid)?;

    let deploy_bytes =
        custodian_cli::deploy::read_checked(&cfg.deployment_config_path, 16 * 1024, 0o022)
            .map_err(|_| DaemonReason::NotConfigured)?;
    let deployment = Deployment::open(&deploy_bytes).map_err(|_| DaemonReason::NotConfigured)?;
    let names = deployment.names();
    let parts = deployment.parts(&names);

    let clock: Arc<dyn custodian_store::Clock> = Arc::new(SystemClock);
    let (pulls, checks, consume): (Arc<dyn PullRequestSource>, Option<Arc<dyn CheckSink>>, bool) =
        match cfg.github.mode {
            GithubMode::Disabled => (Arc::new(Unavailable), None, false),
            GithubMode::LoopbackHttp => {
                let key_path = cfg
                    .github
                    .app_private_key_path
                    .as_ref()
                    .ok_or(DaemonReason::ConfigInvalid)?;
                let signer = Rs256Signer::from_pem_file(key_path)
                    .map_err(|_| DaemonReason::SecretFileRejected)?;
                let app = AppId::new(cfg.github.app_id.unwrap_or(0))
                    .ok_or(DaemonReason::ConfigInvalid)?;
                let addr = cfg
                    .github
                    .loopback_addr
                    .ok_or(DaemonReason::ConfigInvalid)?;
                let http = Arc::new(
                    PlainHttp::loopback(addr, std::time::Duration::from_secs(10))
                        .ok_or(DaemonReason::ConfigInvalid)?,
                );
                let adapters = GithubAdapters::build(
                    RequestFacingAppCredential::new(app, Box::new(signer)),
                    Arc::new(GithubApi::new(http.clone())),
                    http,
                    intake.clone(),
                    clock.clone(),
                );
                (
                    adapters.pulls,
                    Some(adapters.checks as Arc<dyn CheckSink>),
                    true,
                )
            }
            GithubMode::Https => return Err(DaemonReason::NotConfigured),
        };

    let (dispatcher, worker_word) = build_worker(&cfg.worker, &cfg.artifacts_dir);
    log.event("worker", worker_word);

    let shutdown = Shutdown::new();
    install_signal_thread(&shutdown)?;
    let inputs = RunInputs {
        parts,
        store_path: deployment.store_path.clone(),
        store_config: StoreConfig::enforced(),
        intake,
        webhook_secret: secret,
        policy,
        dispatcher,
        names: &names,
        pulls,
        checks,
        consume_queue: consume,
        requests: Arc::new(DirRequestSource::new(cfg.requests_dir.clone())),
        stager: Arc::new(DirStager::new(&cfg.artifacts_dir)),
        approvals: Arc::new(DirApprovals::new(cfg.release.approvals_dir.clone())),
        sink: Arc::new(DirSink::new(cfg.release.output_dir.clone())),
        log: log.clone(),
        fault: Arc::new(NoPipelineFault),
        config: cfg,
    };
    run(inputs, &shutdown, &|_| ()).map(|_| ())
}

/// No GitHub: every lookup fails closed.
struct Unavailable;

impl PullRequestSource for Unavailable {
    fn current_head(
        &self,
        _: custodian_intake::ids::InstallationId,
        _: custodian_intake::ids::RepositoryId,
        _: custodian_intake::ids::PullRequestNumber,
    ) -> Result<custodian_intake::ids::HeadSha, custodian_intake::IntakeReason> {
        Err(custodian_intake::IntakeReason::TokenUnavailable)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let log: Arc<dyn EventLog> = Arc::new(StderrLog);
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("custodiand {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("check-config") => {
            let Some(p) = arg_value(&args, "--config") else {
                return fail(log.as_ref(), DaemonReason::NotConfigured);
            };
            match DaemonConfig::load(&p) {
                Ok(_) => {
                    log.event("daemon", "config_ok");
                    ExitCode::SUCCESS
                }
                Err(r) => fail(log.as_ref(), r),
            }
        }
        Some("run") => {
            let Some(p) = arg_value(&args, "--config") else {
                return fail(log.as_ref(), DaemonReason::NotConfigured);
            };
            match run_daemon(&p, log.clone()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(r) => fail(log.as_ref(), r),
            }
        }
        _ => {
            log.event("daemon", "usage_error");
            ExitCode::from(2)
        }
    }
}
