//! The one JSON object `custodian-verify` prints, and its exit codes.
//!
//! Exit codes (stable; documented in `docs/ci-and-reusable-workflows.md`):
//!
//! | code | class              | meaning                                                         |
//! |------|--------------------|-----------------------------------------------------------------|
//! | 0    | `accepted`         | every projection verified, the feed applied cleanly             |
//! | 10   | `projection`       | a projection was rejected, or none was present                  |
//! | 11   | `feed`             | the revocation feed failed verification (gap, fork, bad chain)  |
//! | 12   | `response`         | the bundle answers another request, feed or destination         |
//! | 20   | `usage`            | the command line is wrong                                       |
//! | 21   | `input`            | an input file is unreadable, over a bound or not strictly valid |
//!
//! Precedence when several apply: 12, then 11, then 10. Reason codes are the
//! fixed vocabularies of `custodian_bridge::Rejection`,
//! `custodian_lifecycle::SyncError` and [`crate::InputError`]; nothing in the
//! object is copied from an input.

use serde::Serialize;

use crate::input::InputError;

pub const RESULT_SCHEMA: &str = "private-custodian.verify-result/1";

/// What this result is, on every result. Not an independent evaluation.
pub const SCOPE_NOTE: &str = "functional verification of public signed data against supplied pins; not an independent protected evaluation and not ground truth";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitClass {
    Accepted,
    Projection,
    Feed,
    Response,
    Usage,
    Input,
}

impl ExitClass {
    pub fn code(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::Projection => 10,
            Self::Feed => 11,
            Self::Response => 12,
            Self::Usage => 20,
            Self::Input => 21,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProjectionRejection {
    pub index: usize,
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub verdict: Verdict,
    pub exit_code: u8,
    pub reason: &'static str,
    pub projections_accepted: usize,
    pub projections_rejected: Vec<ProjectionRejection>,
    pub feed_applied: usize,
    pub feed_error: Option<&'static str>,
    pub feed_sequence: u64,
    pub now: Option<u64>,
    pub scope: &'static str,
    #[serde(skip)]
    class: ExitClass,
}

impl Report {
    fn base(verdict: Verdict, class: ExitClass, reason: &'static str, now: Option<u64>) -> Self {
        Self {
            schema: RESULT_SCHEMA,
            verdict,
            exit_code: class.code(),
            reason,
            projections_accepted: 0,
            projections_rejected: Vec::new(),
            feed_applied: 0,
            feed_error: None,
            feed_sequence: 0,
            now,
            scope: SCOPE_NOTE,
            class,
        }
    }

    /// An input or usage failure: nothing was verified.
    pub fn input_error(e: InputError, now: Option<u64>) -> Self {
        let class = if e == InputError::Usage {
            ExitClass::Usage
        } else {
            ExitClass::Input
        };
        Self::base(Verdict::Error, class, e.code(), now)
    }

    /// The whole response was refused before any projection was judged.
    pub fn response_rejected(reason: &'static str, now: u64) -> Self {
        Self::base(Verdict::Rejected, ExitClass::Response, reason, Some(now))
    }

    pub fn judged(
        accepted: usize,
        rejected: Vec<ProjectionRejection>,
        feed_applied: usize,
        feed_error: Option<&'static str>,
        feed_sequence: u64,
        now: u64,
    ) -> Self {
        let (verdict, class, reason) = if let Some(code) = feed_error {
            (Verdict::Rejected, ExitClass::Feed, code)
        } else if let Some(first) = rejected.first() {
            (Verdict::Rejected, ExitClass::Projection, first.reason)
        } else if accepted == 0 {
            (Verdict::Rejected, ExitClass::Projection, "no_projection")
        } else {
            (Verdict::Accepted, ExitClass::Accepted, "ok")
        };
        let mut r = Self::base(verdict, class, reason, Some(now));
        r.projections_accepted = accepted;
        r.projections_rejected = rejected;
        r.feed_applied = feed_applied;
        r.feed_error = feed_error;
        r.feed_sequence = feed_sequence;
        r
    }

    pub fn class(&self) -> ExitClass {
        self.class
    }

    /// One line of JSON, no trailing newline.
    pub fn render(&self) -> String {
        // Serializing plain strings, numbers and options cannot fail; the
        // fallback is itself a valid, fixed result.
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                "{{\"schema\":\"{RESULT_SCHEMA}\",\"verdict\":\"error\",\"exit_code\":21,\"reason\":\"render_failed\"}}"
            )
        })
    }
}
