//! The Check sink and the pull-request head source over the API trait.
//!
//! Both need a repository's `owner/name`, which the events do not carry (they
//! carry numeric ids). The name is resolved once per repository with
//! `GET /repositories/{id}` under a token scoped to that repository, checked
//! against a strict shape before it is used in a path, and cached.
//!
//! Check text is built by `custodian_intake::checks::CheckPost` from fixed
//! strings and one fixed reason code; nothing here adds to it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use custodian_contracts::types::Timestamp;
use custodian_intake::app_auth::{AppApiTransport, InstallationToken, InstallationTokenProvider};
use custodian_intake::checks::{CheckPost, CheckSink, GithubConclusion, GithubStatus};
use custodian_intake::config::IntakeConfig;
use custodian_intake::credentials::RequestFacingAppCredential;
use custodian_intake::ids::{HeadSha, InstallationId, PullRequestNumber, RepositoryId};
use custodian_intake::ports::PullRequestSource;
use custodian_intake::IntakeReason;
use custodian_store::Clock;
use serde::Deserialize;
use serde_json::json;

use super::api::{ApiRequest, Bearer, HttpExecutor, Method};

fn name_ok(full: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p.len() <= 100
            && p != "."
            && p != ".."
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    full.len() <= 140
        && full
            .split_once('/')
            .is_some_and(|(o, n)| part(o) && part(n) && !n.contains('/'))
}

#[derive(Deserialize)]
struct Repo {
    full_name: String,
}

#[derive(Deserialize)]
struct CheckRun {
    id: u64,
}

#[derive(Deserialize)]
struct Pull {
    head: PullHead,
}

#[derive(Deserialize)]
struct PullHead {
    sha: String,
}

/// Shared by both adapters: the token provider, the executor, the clock and
/// the repository-name cache.
struct Core {
    http: Arc<dyn HttpExecutor>,
    tokens: InstallationTokenProvider,
    clock: Arc<dyn Clock>,
    names: Mutex<BTreeMap<RepositoryId, String>>,
}

impl Core {
    fn now(&self) -> Result<Timestamp, IntakeReason> {
        Timestamp::new(self.clock.now()).map_err(|_| IntakeReason::TokenUnavailable)
    }

    fn token(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
    ) -> Result<Arc<InstallationToken>, IntakeReason> {
        self.tokens.token_for(installation, repository, self.now()?)
    }

    fn call(
        &self,
        method: Method,
        path: String,
        token: &InstallationToken,
        body: Option<Vec<u8>>,
    ) -> Result<super::api::ApiResponse, IntakeReason> {
        let resp = self.http.execute(&ApiRequest {
            method,
            path,
            bearer: Bearer::new(token.expose_secret()),
            json_body: body,
        })?;
        if resp.body.len() > super::api::MAX_RESPONSE_BYTES {
            return Err(IntakeReason::CheckUpdateFailed);
        }
        Ok(resp)
    }

    fn full_name(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
        token: &InstallationToken,
    ) -> Result<String, IntakeReason> {
        if let Some(n) = self
            .names
            .lock()
            .map_err(|_| IntakeReason::TokenUnavailable)?
            .get(&repository)
        {
            return Ok(n.clone());
        }
        let _ = installation;
        let resp = self.call(
            Method::Get,
            format!("/repositories/{}", repository.get()),
            token,
            None,
        )?;
        if resp.status != 200 {
            return Err(IntakeReason::CheckUpdateFailed);
        }
        let repo: Repo =
            serde_json::from_slice(&resp.body).map_err(|_| IntakeReason::CheckUpdateFailed)?;
        if !name_ok(&repo.full_name) {
            return Err(IntakeReason::CheckUpdateFailed);
        }
        self.names
            .lock()
            .map_err(|_| IntakeReason::TokenUnavailable)?
            .insert(repository, repo.full_name.clone());
        Ok(repo.full_name)
    }
}

/// Posts a rendered Check as a GitHub check run. The first post for a
/// repository and commit creates the run; later posts update it. (After a
/// restart the run id is forgotten and a new run is created: a documented
/// duplicate, never a wrong value.)
pub struct GithubChecks {
    core: Arc<Core>,
    runs: Mutex<BTreeMap<(RepositoryId, String), u64>>,
}

fn status_word(s: GithubStatus) -> &'static str {
    match s {
        GithubStatus::Queued => "queued",
        GithubStatus::InProgress => "in_progress",
        GithubStatus::Completed => "completed",
    }
}

fn conclusion_word(c: GithubConclusion) -> &'static str {
    match c {
        GithubConclusion::Failure => "failure",
        GithubConclusion::Neutral => "neutral",
    }
}

impl CheckSink for GithubChecks {
    fn post(&self, check: &CheckPost) -> Result<(), IntakeReason> {
        let c = &self.core;
        let token = c.token(check.installation, check.repository)?;
        let full = c.full_name(check.installation, check.repository, &token)?;
        let mut body = json!({
            "name": check.name,
            "head_sha": check.head_sha.as_str(),
            "status": status_word(check.status),
            "output": {"title": check.title, "summary": check.summary},
        });
        if let (Some(conclusion), Some(obj)) = (check.conclusion, body.as_object_mut()) {
            obj.insert("conclusion".to_owned(), json!(conclusion_word(conclusion)));
        }
        let key = (check.repository, check.head_sha.as_str().to_owned());
        let known = self
            .runs
            .lock()
            .map_err(|_| IntakeReason::CheckUpdateFailed)?
            .get(&key)
            .copied();
        let bytes = serde_json::to_vec(&body).map_err(|_| IntakeReason::CheckUpdateFailed)?;
        let (method, path, ok) = match known {
            Some(id) => (Method::Patch, format!("/repos/{full}/check-runs/{id}"), 200),
            None => (Method::Post, format!("/repos/{full}/check-runs"), 201),
        };
        let resp = c.call(method, path, &token, Some(bytes))?;
        if resp.status != ok {
            return Err(IntakeReason::CheckUpdateFailed);
        }
        if known.is_none() {
            let run: CheckRun =
                serde_json::from_slice(&resp.body).map_err(|_| IntakeReason::CheckUpdateFailed)?;
            self.runs
                .lock()
                .map_err(|_| IntakeReason::CheckUpdateFailed)?
                .insert(key, run.id);
        }
        Ok(())
    }
}

/// The current head commit of a pull request, read through the App with a
/// token scoped to the repository (the stale-commit check).
pub struct GithubPulls {
    core: Arc<Core>,
}

impl PullRequestSource for GithubPulls {
    fn current_head(
        &self,
        installation: InstallationId,
        repository: RepositoryId,
        pull_request: PullRequestNumber,
    ) -> Result<HeadSha, IntakeReason> {
        let c = &self.core;
        let token = c.token(installation, repository)?;
        let full = c.full_name(installation, repository, &token)?;
        let resp = c.call(
            Method::Get,
            format!("/repos/{full}/pulls/{}", pull_request.get()),
            &token,
            None,
        )?;
        match resp.status {
            200 => {}
            // The pull request is gone or not visible: nothing to compare.
            404 | 410 => return Err(IntakeReason::StaleCommit),
            // Rate limits and outages say nothing about the commit.
            _ => return Err(IntakeReason::TokenUnavailable),
        }
        let pull: Pull =
            serde_json::from_slice(&resp.body).map_err(|_| IntakeReason::StaleCommit)?;
        HeadSha::parse(&pull.head.sha).map_err(|_| IntakeReason::StaleCommit)
    }
}

/// Both adapters over one executor and one token cache.
pub struct GithubAdapters {
    pub checks: Arc<GithubChecks>,
    pub pulls: Arc<GithubPulls>,
}

impl GithubAdapters {
    pub fn build(
        credential: RequestFacingAppCredential,
        transport: Arc<dyn AppApiTransport>,
        http: Arc<dyn HttpExecutor>,
        config: IntakeConfig,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let core = Arc::new(Core {
            http,
            tokens: InstallationTokenProvider::new(credential, transport, config),
            clock,
            names: Mutex::new(BTreeMap::new()),
        });
        Self {
            checks: Arc::new(GithubChecks {
                core: core.clone(),
                runs: Mutex::new(BTreeMap::new()),
            }),
            pulls: Arc::new(GithubPulls { core }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::name_ok;

    #[test]
    fn repository_names_are_checked_before_they_reach_a_path() {
        for ok in ["octo/repo", "a-b/c_d.e", "o/r"] {
            assert!(name_ok(ok), "{ok}");
        }
        for bad in [
            "",
            "noslash",
            "a/b/c",
            "/b",
            "a/",
            "../x",
            "a/..",
            "a/b?x=1",
            "a/b#f",
            "a b/c",
            "a/b\n",
            "a/b%2f",
            &format!("{}/x", "a".repeat(141)),
        ] {
            assert!(!name_ok(bad), "{bad}");
        }
    }
}
