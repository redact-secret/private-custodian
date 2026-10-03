//! Fixed reason words of the daemon. Nothing here carries a path, a header, a
//! body, a token, a signature or any text a request, a worker or an engine
//! produced: a refusal, a log line and a Check are always one of these (or
//! one of the fixed vocabularies of the crates underneath).

use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DaemonReason {
    // Configuration and startup.
    NotConfigured,
    ConfigInvalid,
    SecretFileRejected,
    StartupRefused,
    WorkerUnavailable,
    // Listener.
    BindRefused,
    // Pipeline waiting and terminal words are plain `&'static str` so the
    // store can keep them; these are the ones the runtime itself raises.
    Degraded,
    Stopped,
}

impl DaemonReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::ConfigInvalid => "config_invalid",
            Self::SecretFileRejected => "secret_file_rejected",
            Self::StartupRefused => "startup_refused",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::BindRefused => "bind_refused",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
        }
    }
}

impl fmt::Display for DaemonReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for DaemonReason {}
