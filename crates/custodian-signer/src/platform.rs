//! The few operating-system facts std does not expose, through `nix`'s safe
//! wrappers (ADR 0113): peer credentials and process hardening.
//!
//! What is enforced where (see docs/signer.md):
//!
//! * Peer uid of a Unix socket connection: Linux `SO_PEERCRED`, macOS
//!   `LOCAL_PEERCRED`. Other platforms return `None`, which the caller treats
//!   as "deny".
//! * Core dumps disabled with `setrlimit(RLIMIT_CORE, 0)`: Linux and macOS.
//! * `prctl(PR_SET_DUMPABLE, 0)` (also blocks same-uid ptrace and
//!   `/proc/<pid>/mem` reads): Linux only. macOS has no equivalent that is
//!   safe to call here; see the doc for the deployment obligation.
//! * `umask(0o077)` and environment scrubbing: both.

use std::os::unix::net::UnixStream;

/// The effective uid of the process on the other end of `stream`, or `None`
/// if the platform cannot say.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    getsockopt(stream, PeerCredentials).ok().map(|c| c.uid())
}

#[cfg(target_os = "macos")]
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::LocalPeerCred};
    getsockopt(stream, LocalPeerCred).ok().map(|c| c.uid())
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
pub fn peer_uid(_stream: &UnixStream) -> Option<u32> {
    None
}

/// What [`harden_process`] applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hardening {
    /// `RLIMIT_CORE` soft and hard limits are zero.
    pub core_dumps_disabled: bool,
    /// `PR_SET_DUMPABLE` is off (Linux only; `false` elsewhere).
    pub dumpable_off: bool,
    /// Every environment variable was removed.
    pub environment_cleared: bool,
    /// `umask` is `0o077`.
    pub umask_restricted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardenError;

/// Apply the portable process hardening. Call before the key is loaded.
/// Failure to disable core dumps is an error: the binary refuses to start.
pub fn harden_process() -> Result<Hardening, HardenError> {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|_| HardenError)?;
    let core_dumps_disabled = matches!(getrlimit(Resource::RLIMIT_CORE), Ok((0, 0)));
    if !core_dumps_disabled {
        return Err(HardenError);
    }
    #[cfg(target_os = "linux")]
    let dumpable_off = {
        nix::sys::prctl::set_dumpable(false).map_err(|_| HardenError)?;
        matches!(nix::sys::prctl::get_dumpable(), Ok(false))
    };
    #[cfg(not(target_os = "linux"))]
    let dumpable_off = false;

    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    let environment_cleared = clear_environment();
    Ok(Hardening {
        core_dumps_disabled,
        dumpable_off,
        environment_cleared,
        umask_restricted: true,
    })
}

/// Remove every environment variable so nothing inherited from a launcher
/// (proxy settings, tokens, library paths) is visible to this process or to
/// anything it could start. Returns true when none remain.
pub fn clear_environment() -> bool {
    let names: Vec<_> = std::env::vars_os().map(|(k, _)| k).collect();
    for k in names {
        std::env::remove_var(k);
    }
    std::env::vars_os().next().is_none()
}
