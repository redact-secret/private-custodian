//! The real HTTPS client: a compile-checked skeleton, not an implementation
//! (ADR 0124).
//!
//! Implementing it needs a TLS stack and an HTTP client. This repository does
//! not take one on: the issue says "do not stall", the supply-chain cost is
//! large for something nothing here may use (nothing is deployed and the
//! webhook is inactive), and a deployer enabling the webhook has to review
//! that choice anyway. What a real executor must do is the contract of
//! `custodian_intake::app_auth::AppApiTransport`, restated here as the
//! checklist a reviewer holds it to:
//!
//! * connect only to `api.github.com:443`, verify its certificate against the
//!   system roots, and never accept another host or a downgrade;
//! * send the [`ApiRequest`] exactly (method, path, `Authorization: Bearer`,
//!   JSON body, a fixed `User-Agent` and `Accept: application/vnd.github+json`,
//!   `X-GitHub-Api-Version` pinned);
//! * follow no redirect (a 3xx is an `Ok` response the adapters reject);
//! * bound connect, request and total time, and the response size to
//!   [`MAX_RESPONSE_BYTES`](super::api::MAX_RESPONSE_BYTES);
//! * log nothing from the request or the response.
//!
//! [`NotBuiltHttps`] implements the trait so that wiring it is type-checked
//! now; every call fails closed with `token_unavailable`.

use custodian_intake::IntakeReason;

use super::api::{ApiRequest, ApiResponse, HttpExecutor};

/// The placeholder for the real HTTPS executor. It performs no I/O.
#[derive(Debug, Default)]
pub struct NotBuiltHttps;

impl HttpExecutor for NotBuiltHttps {
    fn execute(&self, _request: &ApiRequest) -> Result<ApiResponse, IntakeReason> {
        Err(IntakeReason::TokenUnavailable)
    }
}
