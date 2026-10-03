//! The Unix-socket server (ADR 0111).
//!
//! One request per connection. Before a byte is read the server checks the
//! peer's uid against the single allowed uid and refuses everything else.
//! Connections run on at most `max_concurrent` threads; a connection beyond
//! that gets a `signer_busy` frame and is closed. Every read and write is under
//! `io_timeout`, so a slow or silent client holds one slot for at most that
//! long and never blocks signing for the others.

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::engine::SigningEngine;
use crate::frame::{self, ReadOutcome, Reject};
use crate::platform::peer_uid;
use crate::provider::effective_uid;

/// Longest a refusal frame may take to write to a client we are rejecting.
const REJECT_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub socket_path: PathBuf,
    /// The only uid allowed to connect (the control service's uid).
    pub allowed_peer_uid: u32,
    pub io_timeout: Duration,
    pub max_concurrent: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerError {
    /// The socket's directory is a symlink, not a directory, not owned by the
    /// signer's uid, or accessible to group or other.
    SocketDirectoryInsecure,
    /// A live signer already listens on the path.
    AlreadyRunning,
    /// Something other than a stale socket exists at the path.
    SocketPathOccupied,
    BindFailed,
    InvalidConfig,
}

impl ServerError {
    pub fn code(self) -> &'static str {
        match self {
            Self::SocketDirectoryInsecure => "socket_directory_insecure",
            Self::AlreadyRunning => "signer_already_running",
            Self::SocketPathOccupied => "socket_path_occupied",
            Self::BindFailed => "socket_bind_failed",
            Self::InvalidConfig => "server_config_invalid",
        }
    }
}

impl core::fmt::Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ServerError {}

fn check_socket_dir(path: &Path) -> Result<(), ServerError> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(ServerError::SocketDirectoryInsecure)?;
    let m = std::fs::symlink_metadata(dir).map_err(|_| ServerError::SocketDirectoryInsecure)?;
    if !m.file_type().is_dir() || m.uid() != effective_uid() || m.mode() & 0o077 != 0 {
        return Err(ServerError::SocketDirectoryInsecure);
    }
    Ok(())
}

/// Remove a stale socket left by a crashed signer; refuse a live one or any
/// other kind of file.
fn clear_stale_socket(path: &Path) -> Result<(), ServerError> {
    match std::fs::symlink_metadata(path) {
        Err(_) => Ok(()),
        Ok(m) => {
            if !m.file_type().is_socket() || m.uid() != effective_uid() {
                return Err(ServerError::SocketPathOccupied);
            }
            if UnixStream::connect(path).is_ok() {
                return Err(ServerError::AlreadyRunning);
            }
            std::fs::remove_file(path).map_err(|_| ServerError::SocketPathOccupied)
        }
    }
}

pub struct RunningServer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    engine: Arc<SigningEngine>,
}

impl core::fmt::Debug for RunningServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RunningServer(<redacted>)")
    }
}

struct SlotGuard(Arc<AtomicUsize>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve_connection(mut s: UnixStream, engine: &SigningEngine, cfg: &ServerConfig) {
    match peer_uid(&s) {
        Some(uid) if uid == cfg.allowed_peer_uid => {}
        _ => {
            engine.stats().rejected_frame();
            engine.emit(Reject::PeerDenied.code());
            let _ = frame::write_response(&mut s, Err(Reject::PeerDenied), REJECT_WRITE_TIMEOUT);
            return;
        }
    }
    if frame::arm(&s, cfg.io_timeout).is_err() {
        engine.stats().rejected_frame();
        return;
    }
    match frame::read_request(&mut s, cfg.io_timeout) {
        ReadOutcome::Request(req) => match engine.handle(&req) {
            Ok(body) => {
                let _ = frame::write_response(&mut s, Ok(&body), cfg.io_timeout);
            }
            Err(rej) => {
                engine.stats().rejected_frame();
                engine.emit(rej.code());
                let _ = frame::write_response(&mut s, Err(rej), REJECT_WRITE_TIMEOUT);
            }
        },
        ReadOutcome::Reject(rej) => {
            engine.stats().rejected_frame();
            engine.emit(rej.code());
            let _ = frame::write_response(&mut s, Err(rej), REJECT_WRITE_TIMEOUT);
        }
        ReadOutcome::Drop(_) => {
            engine.stats().rejected_frame();
            engine.emit("client_gone");
        }
    }
}

/// Bind the socket and serve on a background thread.
pub fn start(cfg: ServerConfig, engine: Arc<SigningEngine>) -> Result<RunningServer, ServerError> {
    if cfg.max_concurrent == 0 || cfg.io_timeout.is_zero() {
        return Err(ServerError::InvalidConfig);
    }
    check_socket_dir(&cfg.socket_path)?;
    clear_stale_socket(&cfg.socket_path)?;
    let listener = UnixListener::bind(&cfg.socket_path).map_err(|_| ServerError::BindFailed)?;
    // The directory is owner-only, so the window before this call exposes
    // nothing; the explicit mode keeps the socket owner-only on its own.
    std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| ServerError::BindFailed)?;
    let stop = Arc::new(AtomicBool::new(false));
    let path = cfg.socket_path.clone();
    let thread = {
        let stop = stop.clone();
        let engine = engine.clone();
        std::thread::spawn(move || accept_loop(listener, engine, cfg, stop))
    };
    engine.emit("listening");
    Ok(RunningServer {
        path,
        stop,
        thread: Some(thread),
        engine,
    })
}

fn accept_loop(
    listener: UnixListener,
    engine: Arc<SigningEngine>,
    cfg: ServerConfig,
    stop: Arc<AtomicBool>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let cfg = Arc::new(cfg);
    for conn in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(mut s) = conn else {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= cfg.max_concurrent {
            active.fetch_sub(1, Ordering::SeqCst);
            engine.stats().rejected_frame();
            engine.emit(Reject::Busy.code());
            let _ = frame::write_response(&mut s, Err(Reject::Busy), REJECT_WRITE_TIMEOUT);
            continue;
        }
        let guard = SlotGuard(active.clone());
        let engine = engine.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let _guard = guard;
            serve_connection(s, &engine, &cfg);
        });
    }
}

impl RunningServer {
    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    pub fn engine(&self) -> &Arc<SigningEngine> {
        &self.engine
    }

    /// Block until the server thread ends (the binary's main loop).
    pub fn wait(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    /// Stop accepting, remove the socket and join the accept thread.
    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocking accept; the loop sees the flag and exits.
        let _ = UnixStream::connect(&self.path);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stop_inner();
        }
    }
}
