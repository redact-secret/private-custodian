//! GitHub App authentication: App JWT, then a scoped installation token.
//!
//! Flow: the request-facing credential signs a short-lived App JWT; the JWT
//! authenticates one call that creates an installation access token limited
//! to one repository and the fixed minimum permission set; the token is used
//! only for the narrow reads and Check writes the adapter needs.
//!
//! Everything network-facing sits behind [`AppApiTransport`]. This crate
//! contains no HTTP client and never contacts GitHub; the deployment supplies
//! the transport, and tests supply an offline fake.
//!
//! Secrets: [`AppJwt`] and [`InstallationToken`] have redacted `Debug`, no
//! `Display`, no `Serialize` and no `Clone`. Errors are [`IntakeReason`]
//! values, which carry no text. The only way to read the value is
//! `expose_secret`, intended for the transport adapter's Authorization header.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use custodian_contracts::types::Timestamp;
use serde::Deserialize;

use crate::config::IntakeConfig;
use crate::credentials::RequestFacingAppCredential;
use crate::ids::{InstallationId, RepositoryId};
use crate::reason::IntakeReason;

/// GitHub rejects App JWTs valid for more than 10 minutes. Use less.
pub const JWT_LIFETIME_SECS: u64 = 540;
/// Back-date `iat` to tolerate clock skew (GitHub's documented practice).
pub const JWT_BACKDATE_SECS: u64 = 60;
/// A cached token is replaced when it has less than this left.
pub const TOKEN_REFRESH_MARGIN_SECS: u64 = 120;
/// Longest token string accepted from the API.
const MAX_TOKEN_LEN: usize = 512;
/// Largest API response body accepted.
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// Permission levels. Order matters: `Write` exceeds `Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Read,
    Write,
}

/// The only permissions the request-facing App is ever asked for, matching
/// the least-privilege App registration in docs/github-app.md. Changing this
/// list is a reviewed change, not configuration.
pub const REQUESTED_PERMISSIONS: [(&str, Level); 3] = [
    ("metadata", Level::Read),
    ("pull_requests", Level::Read),
    ("checks", Level::Write),
];

fn level_of(s: &str) -> Option<Level> {
    match s {
        "read" => Some(Level::Read),
        "write" => Some(Level::Write),
        _ => None, // "admin" and anything else exceed what we ask for
    }
}

/// App JWT. Secret.
pub struct AppJwt(String);

impl AppJwt {
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for AppJwt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AppJwt(<redacted>)")
    }
}

/// Installation access token. Secret.
pub struct InstallationToken {
    value: String,
    expires_at: Timestamp,
}

impl InstallationToken {
    pub fn expose_secret(&self) -> &str {
        &self.value
    }
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl core::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InstallationToken(<redacted>)")
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url.
pub fn base64url(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(B64[(n >> 18) as usize & 63]));
        out.push(char::from(B64[(n >> 12) as usize & 63]));
        if chunk.len() > 1 {
            out.push(char::from(B64[(n >> 6) as usize & 63]));
        }
        if chunk.len() > 2 {
            out.push(char::from(B64[n as usize & 63]));
        }
    }
    out
}

/// Build and sign an App JWT valid for [`JWT_LIFETIME_SECS`].
pub fn mint_app_jwt(
    credential: &RequestFacingAppCredential,
    now: Timestamp,
) -> Result<AppJwt, IntakeReason> {
    let iat = now.secs().saturating_sub(JWT_BACKDATE_SECS);
    let exp = now.secs() + JWT_LIFETIME_SECS;
    let header = base64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = base64url(
        format!(
            r#"{{"iat":{iat},"exp":{exp},"iss":"{}"}}"#,
            credential.app_id().get()
        )
        .as_bytes(),
    );
    let signing_input = format!("{header}.{claims}");
    let signature = credential.sign(signing_input.as_bytes())?;
    if signature.is_empty() {
        return Err(IntakeReason::AppAuthFailed);
    }
    Ok(AppJwt(format!("{signing_input}.{}", base64url(&signature))))
}

/// One installation-token request: a single installation, a single
/// repository, the fixed permission set.
pub struct AccessTokenRequest<'a> {
    pub jwt: &'a AppJwt,
    pub installation: InstallationId,
    pub repository: RepositoryId,
}

impl AccessTokenRequest<'_> {
    /// The JSON body the transport sends. Built from numbers and constants.
    pub fn body(&self) -> String {
        let perms: Vec<String> = REQUESTED_PERMISSIONS
            .iter()
            .map(|(name, level)| {
                let l = if *level == Level::Write {
                    "write"
                } else {
                    "read"
                };
                format!(r#""{name}":"{l}""#)
            })
            .collect();
        format!(
            r#"{{"repository_ids":[{}],"permissions":{{{}}}}}"#,
            self.repository.get(),
            perms.join(",")
        )
    }
}

/// Network seam. `create_installation_token` performs
/// `POST /app/installations/{id}/access_tokens` with the request's JWT and
/// body and returns the raw response body on HTTP 201. Any other status,
/// timeout, redirect or transport error is `Err(AppAuthFailed)` or
/// `Err(TokenUnavailable)`; the transport must not follow redirects, must
/// pin the GitHub API host, and must bound time and size.
pub trait AppApiTransport: Send + Sync {
    fn create_installation_token(
        &self,
        request: &AccessTokenRequest<'_>,
    ) -> Result<Vec<u8>, IntakeReason>;
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
}

/// Parse `YYYY-MM-DDTHH:MM:SSZ` into Unix seconds. Strict: UTC `Z` only.
pub fn parse_rfc3339_utc(s: &str) -> Option<Timestamp> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |r: core::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hh, mm, ss) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3600 + mm * 60 + ss;
    Timestamp::new(u64::try_from(secs).ok()?).ok()
}

/// Mints and caches scoped installation tokens.
pub struct InstallationTokenProvider {
    credential: RequestFacingAppCredential,
    transport: Arc<dyn AppApiTransport>,
    config: IntakeConfig,
    cache: Mutex<BTreeMap<(InstallationId, RepositoryId), Arc<InstallationToken>>>,
}

impl InstallationTokenProvider {
    pub fn new(
        credential: RequestFacingAppCredential,
        transport: Arc<dyn AppApiTransport>,
        config: IntakeConfig,
    ) -> Self {
        Self {
            credential,
            transport,
            config,
            cache: Mutex::new(BTreeMap::new()),
        }
    }

    /// A token for exactly this installation and repository. Refuses anything
    /// outside the configured allowlist before any JWT is minted.
    pub fn token_for(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
        now: Timestamp,
    ) -> Result<Arc<InstallationToken>, IntakeReason> {
        if !self.config.installation_allowed(installation) {
            return Err(IntakeReason::InstallationNotAllowed);
        }
        if !self.config.repository_allowed(installation, repository) {
            return Err(IntakeReason::RepositoryNotAllowed);
        }
        let key = (installation, repository);
        if let Some(t) = self
            .cache
            .lock()
            .map_err(|_| IntakeReason::TokenUnavailable)?
            .get(&key)
        {
            if t.expires_at.secs() > now.secs() + TOKEN_REFRESH_MARGIN_SECS {
                return Ok(Arc::clone(t));
            }
        }

        let jwt = mint_app_jwt(&self.credential, now)?;
        let raw = self
            .transport
            .create_installation_token(&AccessTokenRequest {
                jwt: &jwt,
                installation,
                repository,
            })?;
        let token = Arc::new(parse_token_response(&raw, now)?);
        self.cache
            .lock()
            .map_err(|_| IntakeReason::TokenUnavailable)?
            .insert(key, Arc::clone(&token));
        Ok(token)
    }

    /// Drop a cached token (for example after the installation was removed).
    pub fn forget(&self, installation: InstallationId, repository: RepositoryId) {
        if let Ok(mut c) = self.cache.lock() {
            c.remove(&(installation, repository));
        }
    }
}

fn parse_token_response(raw: &[u8], now: Timestamp) -> Result<InstallationToken, IntakeReason> {
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(IntakeReason::AppAuthFailed);
    }
    let r: TokenResponse = serde_json::from_slice(raw).map_err(|_| IntakeReason::AppAuthFailed)?;
    let token_ok = !r.token.is_empty()
        && r.token.len() <= MAX_TOKEN_LEN
        && r.token.bytes().all(|c| (0x21..=0x7e).contains(&c));
    if !token_ok {
        return Err(IntakeReason::AppAuthFailed);
    }
    // The granted permissions must not exceed what was asked for. A token
    // with extra or higher permissions is discarded, never used.
    for (name, granted) in &r.permissions {
        let granted = level_of(granted).ok_or(IntakeReason::PermissionsExceeded)?;
        let allowed = REQUESTED_PERMISSIONS
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, l)| *l)
            .ok_or(IntakeReason::PermissionsExceeded)?;
        if granted > allowed {
            return Err(IntakeReason::PermissionsExceeded);
        }
    }
    let expires_at = parse_rfc3339_utc(&r.expires_at).ok_or(IntakeReason::AppAuthFailed)?;
    if expires_at <= now {
        return Err(IntakeReason::AppAuthFailed);
    }
    Ok(InstallationToken {
        value: r.token,
        expires_at,
    })
}
