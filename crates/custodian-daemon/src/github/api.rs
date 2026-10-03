//! The GitHub REST calls the App needs, behind one small trait.
//!
//! [`HttpExecutor`] is the only seam to the network. It receives a fully
//! formed [`ApiRequest`] (method, path, bearer credential, optional JSON body)
//! and returns a status and a bounded body. An implementation pins the host,
//! does not follow redirects and bounds time and size
//! (`custodian_intake::app_auth::AppApiTransport` states the contract). The
//! types here carry no URL and no host: a request cannot be redirected to
//! another origin by anything a pull request says.

use custodian_intake::app_auth::{AccessTokenRequest, AppApiTransport};
use custodian_intake::IntakeReason;

/// Largest response body an executor may return and the adapters parse.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Patch,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
        }
    }
}

/// The `Authorization: Bearer` credential of one request (an App JWT or an
/// installation token). Redacted `Debug`, no `Display`, no `Clone`.
pub struct Bearer(String);

impl Bearer {
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for Bearer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Bearer(<redacted>)")
    }
}

/// One API request. `path` always starts with `/` and is built from numbers
/// and validated names only.
#[derive(Debug)]
pub struct ApiRequest {
    pub method: Method,
    pub path: String,
    pub bearer: Bearer,
    pub json_body: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The network seam. `Err` is a transport failure (timeout, refused,
/// oversized, malformed); an HTTP error status is an `Ok` response the caller
/// classifies.
pub trait HttpExecutor: Send + Sync {
    fn execute(&self, request: &ApiRequest) -> Result<ApiResponse, IntakeReason>;
}

impl<T: HttpExecutor + ?Sized> HttpExecutor for std::sync::Arc<T> {
    fn execute(&self, request: &ApiRequest) -> Result<ApiResponse, IntakeReason> {
        (**self).execute(request)
    }
}

/// `AppApiTransport` over an [`HttpExecutor`]: the installation-token call.
pub struct GithubApi<H: HttpExecutor> {
    http: H,
}

impl<H: HttpExecutor> GithubApi<H> {
    pub fn new(http: H) -> Self {
        Self { http }
    }
}

impl<H: HttpExecutor> AppApiTransport for GithubApi<H> {
    fn create_installation_token(
        &self,
        request: &AccessTokenRequest<'_>,
    ) -> Result<Vec<u8>, IntakeReason> {
        let resp = self.http.execute(&ApiRequest {
            method: Method::Post,
            path: format!(
                "/app/installations/{}/access_tokens",
                request.installation.get()
            ),
            bearer: Bearer::new(request.jwt.expose_secret()),
            json_body: Some(request.body().into_bytes()),
        })?;
        if resp.body.len() > MAX_RESPONSE_BYTES {
            return Err(IntakeReason::AppAuthFailed);
        }
        match resp.status {
            201 => Ok(resp.body),
            // The credential or the installation is not accepted: a fixed
            // refusal, never the body.
            401 | 403 | 404 | 422 => Err(IntakeReason::AppAuthFailed),
            // Rate limits, outages and anything unexpected are transient.
            _ => Err(IntakeReason::TokenUnavailable),
        }
    }
}
