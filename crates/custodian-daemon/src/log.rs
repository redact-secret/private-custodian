//! Event log: component and a fixed code, nothing else.
//!
//! A log line is `component=<word> code=<word>`. There is no way to put a
//! body, a header, a signature, a token, a path or an engine message into it:
//! both arguments are `&'static str`, and the type system does not accept a
//! runtime string. A hostile request therefore cannot reach a log through
//! this interface (CONVENTIONS.md, "Execution and logging").

use std::sync::Mutex;

pub trait EventLog: Send + Sync {
    fn event(&self, component: &'static str, code: &'static str);
}

/// Writes `component=<word> code=<word>` lines to standard error.
#[derive(Debug, Default)]
pub struct StderrLog;

impl EventLog for StderrLog {
    fn event(&self, component: &'static str, code: &'static str) {
        use std::io::Write;
        let _ = writeln!(
            std::io::stderr().lock(),
            "component={component} code={code}"
        );
    }
}

/// Discards everything.
#[derive(Debug, Default)]
pub struct NullLog;

impl EventLog for NullLog {
    fn event(&self, _component: &'static str, _code: &'static str) {}
}

/// Records events for tests.
#[derive(Debug, Default)]
pub struct RecordingLog {
    events: Mutex<Vec<(&'static str, &'static str)>>,
}

impl RecordingLog {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn events(&self) -> Vec<(&'static str, &'static str)> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
    pub fn count(&self, component: &str, code: &str) -> usize {
        self.events()
            .iter()
            .filter(|(c, k)| *c == component && *k == code)
            .count()
    }
    /// Every line as it would be printed, for leakage scans.
    pub fn lines(&self) -> Vec<String> {
        self.events()
            .iter()
            .map(|(c, k)| format!("component={c} code={k}"))
            .collect()
    }
}

impl EventLog for RecordingLog {
    fn event(&self, component: &'static str, code: &'static str) {
        if let Ok(mut e) = self.events.lock() {
            e.push((component, code));
        }
    }
}
