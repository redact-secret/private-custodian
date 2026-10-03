//! Git-backed ledger writer (ADR 0052).
//!
//! Operates on a dedicated local working clone of the ledger repository
//! through structured `git` argv (never a shell). Writes are serialized
//! in-process by a mutex and across processes by compare-and-swap on the
//! remote branch: every write is `fetch`, reset to the remote tip, check
//! the target path, commit, then a plain (never forced) `push`. A rejected
//! push means another writer advanced the branch; the local commit is
//! discarded and the whole step is re-evaluated on the new tip, so a record
//! another writer created with different bytes is seen as a conflict rather
//! than overwritten.
//!
//! The working clone is owned by this backend: it is reset and cleaned at
//! the start of every write. Git history is mutable by anyone who can force
//! push; this backend never does, and `audit_history` flags history that
//! modifies or deletes a ledger file. It is not a tamper-proof archive.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use crate::backend::{BackendError, LedgerBackend, LedgerPath, PutOutcome};

#[derive(Clone, Debug)]
pub struct GitConfig {
    pub remote: String,
    pub branch: String,
    /// Identity recorded on ledger commits. Not an authentication secret.
    pub author_name: String,
    pub author_email: String,
    /// Lost compare-and-swap rounds tolerated per write before `Busy`.
    pub max_cas_rounds: u32,
    /// Extra environment for git (for example `GIT_SSH_COMMAND` selecting the
    /// dedicated ledger deploy identity). Never logged.
    pub env: Vec<(String, String)>,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            remote: "origin".to_owned(),
            branch: "main".to_owned(),
            author_name: "custodian-ledger-writer".to_owned(),
            author_email: "ledger-writer@invalid".to_owned(),
            max_cas_rounds: 8,
            env: Vec::new(),
        }
    }
}

pub struct GitBackend {
    dir: PathBuf,
    cfg: GitConfig,
    lock: Mutex<()>,
}

impl core::fmt::Debug for GitBackend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GitBackend(<redacted>)")
    }
}

/// A commit that changed ledger history in a way an append-only writer never does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryViolation {
    pub commit: String,
    pub status: char,
    pub path: String,
}

/// Environment variables that change which repository git operates on or
/// inject configuration, removed from every git child process.
const AMBIENT_GIT_ENV: [&str; 14] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_EXEC_PATH",
    "GIT_ASKPASS",
];

/// A remote URL that git would treat as a transport helper command
/// (`ext::`, `fd::` and similar `<transport>::<address>` forms) is refused
/// outright, whatever git's own protocol policy says.
fn url_uses_transport_helper(url: &str) -> bool {
    let head = url.split('/').next().unwrap_or("");
    head.contains("::") && !head.starts_with('[')
}

fn safe_ref_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
        && !s.contains("..")
}

impl GitBackend {
    /// Initialize an empty working clone at `dir` (which must exist) that
    /// tracks `remote_url`. For provisioning and tests; production clones the
    /// real ledger with the dedicated deploy identity.
    pub fn init(dir: &Path, remote_url: &str, cfg: GitConfig) -> Result<Self, BackendError> {
        if remote_url.starts_with('-')
            || url_uses_transport_helper(remote_url)
            || !safe_ref_component(&cfg.branch)
            || !safe_ref_component(&cfg.remote)
        {
            return Err(BackendError::InvalidPath);
        }
        let b = Self::open_unchecked(dir, cfg);
        b.git(&["init", "-q"])?;
        b.git(&[
            "symbolic-ref",
            "HEAD",
            &format!("refs/heads/{}", b.cfg.branch),
        ])?;
        let remote = b.cfg.remote.clone();
        b.git(&["remote", "add", &remote, remote_url])
            .or_else(|_| b.git(&["remote", "set-url", &remote, remote_url]))?;
        Ok(b)
    }

    /// Open an existing working clone.
    pub fn open(dir: &Path, cfg: GitConfig) -> Result<Self, BackendError> {
        if !safe_ref_component(&cfg.branch) || !safe_ref_component(&cfg.remote) {
            return Err(BackendError::InvalidPath);
        }
        let b = Self::open_unchecked(dir, cfg);
        b.git(&["rev-parse", "--git-dir"])?;
        Ok(b)
    }

    fn open_unchecked(dir: &Path, cfg: GitConfig) -> Self {
        Self {
            dir: dir.to_path_buf(),
            cfg,
            lock: Mutex::new(()),
        }
    }

    fn command(&self) -> Command {
        let mut c = Command::new("git");
        // Ambient repository-location and config-injection variables must not
        // redirect this backend (`-C` is overridden by `GIT_DIR`, and the
        // backend runs `checkout -f` and `clean`). Only `GitConfig::env`
        // may add environment, after this.
        for var in AMBIENT_GIT_ENV {
            c.env_remove(var);
        }
        c.arg("-C")
            .arg(&self.dir)
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(["-c", "protocol.ext.allow=never"])
            .args(["-c", "commit.gpgsign=false"])
            .args(["-c", "core.autocrlf=false"])
            .args(["-c", "core.fsmonitor=false"])
            .arg("-c")
            .arg(format!("user.name={}", self.cfg.author_name))
            .arg("-c")
            .arg(format!("user.email={}", self.cfg.author_email))
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &self.cfg.env {
            c.env(k, v);
        }
        c
    }

    /// Run git; success is exit status 0. Output is never returned in errors.
    fn git(&self, args: &[&str]) -> Result<Vec<u8>, BackendError> {
        let out = self
            .command()
            .args(args)
            .output()
            .map_err(|_| BackendError::Io)?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(BackendError::Io)
        }
    }

    fn remote_ref(&self) -> String {
        format!("refs/remotes/{}/{}", self.cfg.remote, self.cfg.branch)
    }

    /// Does the remote have the branch? `Unavailable` when it cannot be reached.
    fn remote_has_branch(&self) -> Result<bool, BackendError> {
        let out = self
            .command()
            .args(["ls-remote", "--exit-code", "--heads"])
            .arg(&self.cfg.remote)
            .arg(format!("refs/heads/{}", self.cfg.branch))
            .output()
            .map_err(|_| BackendError::Io)?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(2) => Ok(false),
            _ => Err(BackendError::Unavailable),
        }
    }

    /// Fetch and make the working tree equal to the remote tip, discarding any
    /// local commit that was never pushed.
    fn sync_locked(&self) -> Result<(), BackendError> {
        if self.remote_has_branch()? {
            let refspec = format!(
                "+refs/heads/{b}:{r}",
                b = self.cfg.branch,
                r = self.remote_ref()
            );
            self.command()
                .args(["fetch", "-q", "--no-tags"])
                .arg(&self.cfg.remote)
                .arg(&refspec)
                .output()
                .map_err(|_| BackendError::Io)
                .and_then(|o| {
                    if o.status.success() {
                        Ok(())
                    } else {
                        Err(BackendError::Unavailable)
                    }
                })?;
            self.git(&[
                "checkout",
                "-q",
                "-f",
                "-B",
                &self.cfg.branch,
                &self.remote_ref(),
            ])?;
        } else {
            // Empty remote: drop any unpushed local history and start unborn.
            let _ = self.git(&[
                "update-ref",
                "-d",
                &format!("refs/heads/{}", self.cfg.branch),
            ]);
            self.git(&["read-tree", "--empty"])?;
        }
        self.git(&["clean", "-fdxq"])?;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn file_path(&self, path: &LedgerPath) -> PathBuf {
        self.dir.join(path.as_str())
    }

    fn read_file(&self, path: &LedgerPath) -> Result<Option<Vec<u8>>, BackendError> {
        let full = self.file_path(path);
        match fs::symlink_metadata(&full) {
            Ok(m) if m.is_file() => fs::read(&full).map(Some).map_err(|_| BackendError::Io),
            Ok(_) => Err(BackendError::Corrupt),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(BackendError::Io),
        }
    }

    fn walk(&self, rel: &str, out: &mut Vec<LedgerPath>) -> Result<(), BackendError> {
        let dir = self.dir.join(rel);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(BackendError::Io),
        };
        for entry in entries {
            let entry = entry.map_err(|_| BackendError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(BackendError::Corrupt);
            };
            let child = format!("{rel}/{name}");
            let ty = fs::symlink_metadata(entry.path())
                .map_err(|_| BackendError::Io)?
                .file_type();
            if ty.is_symlink() {
                return Err(BackendError::Corrupt);
            }
            if ty.is_dir() {
                self.walk(&child, out)?;
            } else {
                out.push(LedgerPath::parse(&child)?);
            }
        }
        Ok(())
    }

    /// Scan the branch history for commits that modify, delete, rename or
    /// retype a ledger file. An append-only writer produces none. This
    /// detects accidents and careless edits, not a malicious history rewrite
    /// (compare with an independently held checkpoint for that).
    pub fn audit_history(&self) -> Result<Vec<HistoryViolation>, BackendError> {
        let _g = self.lock();
        self.sync_locked()?;
        if !self.remote_has_branch()? {
            return Ok(Vec::new());
        }
        let out = self.git(&[
            "log",
            "--reverse",
            "--no-renames",
            "--name-status",
            "--format=commit:%H",
            "-m",
        ])?;
        let text = String::from_utf8(out).map_err(|_| BackendError::Corrupt)?;
        let mut commit = String::new();
        let mut violations = Vec::new();
        for line in text.lines() {
            if let Some(h) = line.strip_prefix("commit:") {
                commit = h.to_owned();
            } else if let Some((status, path)) = line.split_once('\t') {
                let s = status.chars().next().unwrap_or('?');
                let in_ledger = path.starts_with("records/") || path.starts_with("quarantine/");
                if in_ledger && s != 'A' {
                    violations.push(HistoryViolation {
                        commit: commit.clone(),
                        status: s,
                        path: path.to_owned(),
                    });
                }
            }
        }
        Ok(violations)
    }
}

impl LedgerBackend for GitBackend {
    fn refresh(&self) -> Result<(), BackendError> {
        let _g = self.lock();
        self.sync_locked()
    }

    fn get(&self, path: &LedgerPath) -> Result<Option<Vec<u8>>, BackendError> {
        let _g = self.lock();
        self.read_file(path)
    }

    fn put_new(&self, path: &LedgerPath, bytes: &[u8]) -> Result<PutOutcome, BackendError> {
        let _g = self.lock();
        for _round in 0..self.cfg.max_cas_rounds.max(1) {
            self.sync_locked()?;
            if let Some(existing) = self.read_file(path)? {
                return Ok(if existing == bytes {
                    PutOutcome::Identical
                } else {
                    PutOutcome::Conflict
                });
            }
            let full = self.file_path(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).map_err(|_| BackendError::Io)?;
            }
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&full)
                .map_err(|_| BackendError::Io)?;
            f.write_all(bytes).map_err(|_| BackendError::Io)?;
            f.sync_all().map_err(|_| BackendError::Io)?;
            drop(f);

            self.git(&["add", "--", path.as_str()])?;
            self.git(&[
                "commit",
                "-q",
                "--no-verify",
                "-m",
                &format!("ledger: add {}", path.as_str()),
            ])?;
            let push = self
                .command()
                .args(["push", "-q"])
                .arg(&self.cfg.remote)
                .arg(format!("HEAD:refs/heads/{}", self.cfg.branch))
                .output()
                .map_err(|_| BackendError::Io)?;
            if push.status.success() {
                return Ok(PutOutcome::Created);
            }
            // Rejected (someone else advanced the branch) or unreachable?
            // Reachable means a lost race: loop and re-evaluate on the new tip.
            self.remote_has_branch()
                .map_err(|_| BackendError::Unavailable)?;
        }
        // Leave no unpushed commit behind.
        let _ = self.sync_locked();
        Err(BackendError::Busy)
    }

    fn list(&self, prefix: &str) -> Result<Vec<LedgerPath>, BackendError> {
        let _g = self.lock();
        let prefix = prefix.trim_end_matches('/');
        LedgerPath::parse(prefix)?;
        let mut out = Vec::new();
        self.walk(prefix, &mut out)?;
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression for the C12 review: an ambient `GIT_DIR` (or any other
    /// repository-location or config-injection variable) must never reach the
    /// child, because it would override `-C` for a backend that runs
    /// `checkout -f` and `clean`. The test inspects the command; it does not
    /// touch the process environment.
    #[test]
    fn git_children_never_inherit_repository_location_or_config_variables() {
        let b =
            GitBackend::open_unchecked(Path::new("/nonexistent-synthetic"), GitConfig::default());
        let c = b.command();
        for var in AMBIENT_GIT_ENV {
            let entry = c.get_envs().find(|(k, _)| *k == std::ffi::OsStr::new(var));
            assert_eq!(
                entry,
                Some((std::ffi::OsStr::new(var), None)),
                "{var} must be explicitly removed"
            );
        }
        // Deployment-chosen environment is added after the removal.
        let cfg = GitConfig {
            env: vec![("GIT_SSH_COMMAND".to_owned(), "ssh -i synthetic".to_owned())],
            ..GitConfig::default()
        };
        let c = GitBackend::open_unchecked(Path::new("/nonexistent-synthetic"), cfg).command();
        assert!(c
            .get_envs()
            .any(|(k, v)| k == std::ffi::OsStr::new("GIT_SSH_COMMAND") && v.is_some()));
    }

    #[test]
    fn transport_helper_urls_and_unsafe_remote_names_are_refused_at_init() {
        for url in ["ext::sh -c touch% /tmp/x", "fd::3", "ext::x"] {
            assert!(url_uses_transport_helper(url), "{url}");
        }
        for url in [
            "file:///srv/ledger.git",
            "ssh://git@example.invalid/ledger.git",
            "https://example.invalid/ledger.git",
            "ssh://git@[::1]/ledger.git",
        ] {
            assert!(!url_uses_transport_helper(url), "{url}");
        }
        let dir = std::env::temp_dir().join(format!("custodian-git-init-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad_remote = GitConfig {
            remote: "--upload-pack=x".to_owned(),
            ..GitConfig::default()
        };
        assert_eq!(
            GitBackend::init(&dir, "file:///nonexistent-synthetic", bad_remote).unwrap_err(),
            BackendError::InvalidPath
        );
        assert_eq!(
            GitBackend::init(&dir, "ext::sh -c true", GitConfig::default()).unwrap_err(),
            BackendError::InvalidPath
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
