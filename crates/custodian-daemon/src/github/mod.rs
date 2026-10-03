//! The GitHub side of the daemon: the App's RS256 JWT signer, the API
//! transport behind a trait, and the Check and pull-request adapters (ADR
//! 0124).
//!
//! Nothing in this module contacts GitHub unless a deployer builds a
//! [`HttpExecutor`] that does and configures it explicitly. This repository
//! ships three executors:
//!
//! * [`testing::FakeGithub`], an offline scripted fake (all tests and CI);
//! * [`plain::PlainHttp`], plain HTTP/1.1 to a **loopback** address only, used
//!   to exercise the real request/response wire format against an in-process
//!   fake server;
//! * [`https::NotBuiltHttps`], the compile-checked skeleton of the real HTTPS
//!   client. It does nothing and says so. A TLS stack is deliberately not a
//!   dependency of this repository (ADR 0124); a deployer that enables the
//!   webhook supplies an executor that pins `api.github.com`, does not follow
//!   redirects and bounds time and size, as `AppApiTransport` requires.
//!
//! Secrets are never printed: the App key lives behind [`jwt::Rs256Signer`]
//! (redacted `Debug`, loaded from a `0600` regular file), tokens and JWTs are
//! the redacted types of `custodian_intake::app_auth`, and [`api::Bearer`]
//! redacts the `Authorization` value of every request.

pub mod adapters;
pub mod api;
pub mod https;
pub mod jwt;
pub mod plain;
pub mod testing;

pub use adapters::{GithubAdapters, GithubChecks, GithubPulls};
pub use api::{ApiRequest, ApiResponse, Bearer, GithubApi, HttpExecutor, Method};
pub use jwt::{KeyError, Rs256Signer};
