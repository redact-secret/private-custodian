//! The ledger storage port and an in-memory fake with fault injection.
//!
//! The port is deliberately small: create-if-absent, read, list. There is no
//! overwrite and no delete, so append-only is a property of the interface,
//! not of caller discipline.

use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BackendError {
    /// The ledger could not be reached or is temporarily refusing writes.
    /// Retryable; nothing was changed unless the operation is idempotent.
    Unavailable,
    /// Local concurrency limit reached (for example repeated lost
    /// compare-and-swap races). Retryable.
    Busy,
    Io,
    /// The stored state is not what the backend wrote (symlink, wrong type).
    Corrupt,
    InvalidPath,
}

impl BackendError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "ledger_unavailable",
            Self::Busy => "ledger_busy",
            Self::Io => "ledger_io",
            Self::Corrupt => "ledger_corrupt",
            Self::InvalidPath => "ledger_invalid_path",
        }
    }

    pub fn is_retryable(self) -> bool {
        matches!(self, Self::Unavailable | Self::Busy)
    }
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for BackendError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PutOutcome {
    /// New file, durably stored.
    Created,
    /// A file with exactly these bytes already existed; nothing changed.
    Identical,
    /// A file with different bytes exists under this path; nothing changed.
    Conflict,
}

/// A validated relative ledger path: `/`-separated segments of
/// `[a-z0-9._-]`, no empty segment, no `.` or `..`, at most 256 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LedgerPath(String);

impl LedgerPath {
    pub fn parse(s: &str) -> Result<Self, BackendError> {
        let ok = !s.is_empty()
            && s.len() <= 256
            && s.split('/').all(|seg| {
                !seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && !seg.starts_with('-')
                    && seg.bytes().all(|b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'.' | b'_' | b'-')
                    })
            });
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(BackendError::InvalidPath)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub trait LedgerBackend: Send + Sync {
    /// Make the latest remote state visible to `get` and `list`. A no-op for
    /// backends without a remote.
    fn refresh(&self) -> Result<(), BackendError> {
        Ok(())
    }

    /// Read a file from the state last made visible.
    fn get(&self, path: &LedgerPath) -> Result<Option<Vec<u8>>, BackendError>;

    /// Create `path` with `bytes` if absent and return only after the write
    /// is durable at the ledger of record (for Git: pushed). Never overwrites.
    fn put_new(&self, path: &LedgerPath, bytes: &[u8]) -> Result<PutOutcome, BackendError>;

    /// All file paths under `prefix` (a directory), recursively, sorted.
    fn list(&self, prefix: &str) -> Result<Vec<LedgerPath>, BackendError>;
}

// --- In-memory fake --------------------------------------------------------------

#[derive(Default)]
struct MemState {
    files: BTreeMap<String, Vec<u8>>,
    available: bool,
    /// Fail this many upcoming `put_new` calls with `Unavailable` before
    /// storing anything.
    fail_puts: u32,
    /// Store this many upcoming `put_new` calls, then report `Unavailable`
    /// anyway (the ambiguous "write landed, response lost" failure).
    lose_response: u32,
    puts: u64,
    reads_fail: bool,
}

/// In-memory backend for tests, with injectable unavailability.
pub struct MemoryBackend {
    state: Mutex<MemState>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemState {
                available: true,
                ..MemState::default()
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn set_available(&self, available: bool) {
        self.lock().available = available;
    }

    pub fn fail_next_puts(&self, n: u32) {
        self.lock().fail_puts = n;
    }

    pub fn lose_next_responses(&self, n: u32) {
        self.lock().lose_response = n;
    }

    pub fn fail_reads(&self, fail: bool) {
        self.lock().reads_fail = fail;
    }

    /// Number of `put_new` calls that reached the store (created or not).
    pub fn put_count(&self) -> u64 {
        self.lock().puts
    }

    pub fn file_count(&self) -> usize {
        self.lock().files.len()
    }

    /// Test hook: write bytes directly, bypassing the port (simulates a
    /// foreign or tampering writer).
    pub fn inject(&self, path: &str, bytes: &[u8]) {
        self.lock().files.insert(path.to_owned(), bytes.to_vec());
    }

    /// Test hook: delete a file, bypassing the port (simulates a history
    /// rewrite or a lost ledger).
    pub fn remove(&self, path: &str) {
        self.lock().files.remove(path);
    }

    pub fn paths(&self) -> Vec<String> {
        self.lock().files.keys().cloned().collect()
    }

    pub fn raw(&self, path: &str) -> Option<Vec<u8>> {
        self.lock().files.get(path).cloned()
    }
}

impl LedgerBackend for MemoryBackend {
    fn refresh(&self) -> Result<(), BackendError> {
        if self.lock().available {
            Ok(())
        } else {
            Err(BackendError::Unavailable)
        }
    }

    fn get(&self, path: &LedgerPath) -> Result<Option<Vec<u8>>, BackendError> {
        let s = self.lock();
        if !s.available || s.reads_fail {
            return Err(BackendError::Unavailable);
        }
        Ok(s.files.get(path.as_str()).cloned())
    }

    fn put_new(&self, path: &LedgerPath, bytes: &[u8]) -> Result<PutOutcome, BackendError> {
        let mut s = self.lock();
        if !s.available {
            return Err(BackendError::Unavailable);
        }
        if s.fail_puts > 0 {
            s.fail_puts -= 1;
            return Err(BackendError::Unavailable);
        }
        s.puts += 1;
        let outcome = match s.files.get(path.as_str()) {
            Some(existing) if existing == bytes => PutOutcome::Identical,
            Some(_) => PutOutcome::Conflict,
            None => {
                s.files.insert(path.as_str().to_owned(), bytes.to_vec());
                PutOutcome::Created
            }
        };
        if s.lose_response > 0 {
            s.lose_response -= 1;
            return Err(BackendError::Unavailable);
        }
        Ok(outcome)
    }

    fn list(&self, prefix: &str) -> Result<Vec<LedgerPath>, BackendError> {
        let s = self.lock();
        if !s.available || s.reads_fail {
            return Err(BackendError::Unavailable);
        }
        let dir = format!("{}/", prefix.trim_end_matches('/'));
        s.files
            .keys()
            .filter(|k| k.starts_with(&dir))
            .map(|k| LedgerPath::parse(k))
            .collect()
    }
}
