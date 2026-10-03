//! App authentication (offline), Check output, and credential separation.

mod common;

use std::sync::Arc;

use common::*;
use custodian_core::ReasonCode;
use custodian_intake::app_auth::{
    base64url, mint_app_jwt, parse_rfc3339_utc, InstallationTokenProvider, JWT_LIFETIME_SECS,
};
use custodian_intake::checks::{
    CheckPost, CheckReason, CheckReporter, CheckState, CheckUpdate, GithubConclusion, GithubStatus,
    RecordingCheckSink, CHECK_NAME,
};
use custodian_intake::credentials::{
    validate_assignments, validate_worker_environment, Assignment, Credential, CredentialRole,
    DbAdminCredential, Holder, LedgerWriterCredential, RequestFacingAppCredential,
};
use custodian_intake::ids::{AppId, InstallationId, RepositoryId};
use custodian_intake::memory::MemoryRegistry;
use custodian_intake::ports::InstallationRegistry;
use custodian_intake::reason::IntakeReason;
use custodian_intake::testing::{FailingSigner, FakeAppApi, FakeSigningKey};

// A synthetic token. The "value" is obviously fake and is checked for leaks.
const FAKE_TOKEN: &str = "synthetic-installation-token-not-real";

fn credential(key: &FakeSigningKey) -> RequestFacingAppCredential {
    RequestFacingAppCredential::new(AppId::new(123_456).unwrap(), Box::new(key.clone()))
}

fn token_body(expires: &str, perms: serde_json::Value) -> String {
    serde_json::json!({
        "token": FAKE_TOKEN,
        "expires_at": expires,
        "permissions": perms,
        "repository_selection": "selected"
    })
    .to_string()
}

fn good_perms() -> serde_json::Value {
    serde_json::json!({"metadata": "read", "pull_requests": "read", "checks": "write"})
}

fn provider(api: Arc<FakeAppApi>, key: &FakeSigningKey) -> InstallationTokenProvider {
    InstallationTokenProvider::new(credential(key), api, config())
}

/// 2027-01-15T08:00:00Z is 1_800_000_000 + some; compute from the parser
/// rather than hard-coding a second source of truth.
fn expiry_after(secs: u64) -> String {
    // Civil-from-days (Hinnant) for the test's own formatting.
    let t = NOW + secs;
    let days = (t / 86_400) as i64;
    let rem = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[test]
fn rfc3339_parser_is_strict_and_correct() {
    assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z").unwrap().secs(), 0);
    assert_eq!(
        parse_rfc3339_utc("2000-03-01T00:00:00Z").unwrap().secs(),
        951_868_800
    );
    assert_eq!(
        parse_rfc3339_utc(&expiry_after(3600)).unwrap().secs(),
        NOW + 3600
    );
    for bad in [
        "",
        "2027-01-15T08:00:00",
        "2027-01-15 08:00:00Z",
        "2027-01-15T08:00:00+00:00",
        "2027-13-15T08:00:00Z",
        "2027-01-15T24:00:00Z",
        "2027-01-1xT08:00:00Z",
        "1969-12-31T23:59:59Z",
    ] {
        assert!(parse_rfc3339_utc(bad).is_none(), "{bad}");
    }
}

#[test]
fn app_jwt_is_short_lived_backdated_and_signed_by_the_credential() {
    let key = FakeSigningKey::generate();
    let jwt = mint_app_jwt(&credential(&key), ts(NOW)).unwrap();
    let parts: Vec<&str> = jwt.expose_secret().split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], base64url(br#"{"alg":"RS256","typ":"JWT"}"#));
    let claims = format!(
        r#"{{"iat":{},"exp":{},"iss":"123456"}}"#,
        NOW - 60,
        NOW + JWT_LIFETIME_SECS
    );
    assert_eq!(parts[1], base64url(claims.as_bytes()));
    const { assert!(JWT_LIFETIME_SECS < 600) }; // GitHub rejects JWTs over 10 minutes

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    assert_eq!(parts[2], base64url(&key.tag(signing_input.as_bytes())));
    // Another key produces a different signature.
    let other = FakeSigningKey::generate();
    assert_ne!(parts[2], base64url(&other.tag(signing_input.as_bytes())));
    assert_eq!(format!("{jwt:?}"), "AppJwt(<redacted>)");

    // Signer failure and empty signatures are refused.
    let failing = RequestFacingAppCredential::new(AppId::new(1).unwrap(), Box::new(FailingSigner));
    assert_eq!(
        mint_app_jwt(&failing, ts(NOW)).unwrap_err(),
        IntakeReason::AppAuthFailed
    );
}

#[test]
fn base64url_matches_known_vectors() {
    assert_eq!(base64url(b""), "");
    assert_eq!(base64url(b"f"), "Zg");
    assert_eq!(base64url(b"fo"), "Zm8");
    assert_eq!(base64url(b"foo"), "Zm9v");
    assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
}

#[test]
fn installation_token_is_scoped_cached_and_never_printed() {
    let key = FakeSigningKey::generate();
    let api = Arc::new(FakeAppApi::responding(token_body(
        &expiry_after(3600),
        good_perms(),
    )));
    let p = provider(api.clone(), &key);

    let t = p.token_for(inst(), repo(), ts(NOW)).unwrap();
    assert_eq!(t.expose_secret(), FAKE_TOKEN);
    assert_eq!(t.expires_at().secs(), NOW + 3600);
    assert_eq!(format!("{t:?}"), "InstallationToken(<redacted>)");

    // One request, for exactly one repository and the fixed permissions.
    let reqs = api.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].installation, inst());
    assert_eq!(reqs[0].repository, repo());
    assert_eq!(
        reqs[0].body,
        format!(
            r#"{{"repository_ids":[{REPO}],"permissions":{{"metadata":"read","pull_requests":"read","checks":"write"}}}}"#
        )
    );
    // The JWT sent upstream verifies under the credential's key.
    let parts: Vec<&str> = reqs[0].jwt.split('.').collect();
    assert!(key.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &decode_b64url(parts[2])
    ));

    // Cached while comfortably valid; refreshed near expiry.
    p.token_for(inst(), repo(), ts(NOW + 60)).unwrap();
    assert_eq!(api.requests().len(), 1);
    p.token_for(inst(), repo(), ts(NOW + 3600 - 30)).unwrap();
    assert_eq!(
        api.requests().len(),
        2,
        "near expiry a fresh token is requested"
    );
}

fn decode_b64url(s: &str) -> Vec<u8> {
    let table = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        _ => 63,
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        acc = (acc << 6) | u32::from(table(c));
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[test]
fn token_is_refused_outside_the_allowlist_before_any_jwt_is_minted() {
    let key = FakeSigningKey::generate();
    let api = Arc::new(FakeAppApi::responding(token_body(
        &expiry_after(3600),
        good_perms(),
    )));
    let p = provider(api.clone(), &key);
    assert_eq!(
        p.token_for(
            InstallationId::new(INSTALLATION + 1).unwrap(),
            repo(),
            ts(NOW)
        )
        .unwrap_err(),
        IntakeReason::InstallationNotAllowed
    );
    assert_eq!(
        p.token_for(inst(), RepositoryId::new(OTHER_REPO).unwrap(), ts(NOW))
            .unwrap_err(),
        IntakeReason::RepositoryNotAllowed
    );
    assert!(api.requests().is_empty());
}

#[test]
fn broader_permissions_than_requested_are_rejected() {
    let key = FakeSigningKey::generate();
    for perms in [
        serde_json::json!({"metadata": "read", "contents": "read"}),
        serde_json::json!({"metadata": "read", "checks": "admin"}),
        serde_json::json!({"metadata": "write"}),
        serde_json::json!({"pull_requests": "write"}),
        serde_json::json!({"administration": "read"}),
    ] {
        let api = Arc::new(FakeAppApi::responding(token_body(
            &expiry_after(3600),
            perms,
        )));
        let p = provider(api, &key);
        assert_eq!(
            p.token_for(inst(), repo(), ts(NOW)).unwrap_err(),
            IntakeReason::PermissionsExceeded
        );
    }
    // Fewer permissions than requested is fine.
    let api = Arc::new(FakeAppApi::responding(token_body(
        &expiry_after(3600),
        serde_json::json!({"metadata": "read"}),
    )));
    assert!(provider(api, &key)
        .token_for(inst(), repo(), ts(NOW))
        .is_ok());
}

#[test]
fn malformed_or_expired_token_responses_fail_closed_without_echo() {
    let key = FakeSigningKey::generate();
    let cases: Vec<Vec<u8>> = vec![
        b"not json".to_vec(),
        b"{}".to_vec(),
        token_body("tomorrow", good_perms()).into_bytes(),
        token_body(&expiry_after(0), good_perms()).into_bytes(), // already expired
        serde_json::json!({"token": "", "expires_at": expiry_after(3600)})
            .to_string()
            .into_bytes(),
        serde_json::json!({"token": "has space", "expires_at": expiry_after(3600)})
            .to_string()
            .into_bytes(),
        serde_json::json!({"token": "x".repeat(513), "expires_at": expiry_after(3600)})
            .to_string()
            .into_bytes(),
        vec![b' '; 20 * 1024],
    ];
    for body in cases {
        let p = provider(Arc::new(FakeAppApi::responding(body)), &key);
        let err = p.token_for(inst(), repo(), ts(NOW)).unwrap_err();
        assert_eq!(err, IntakeReason::AppAuthFailed);
        assert!(!format!("{err:?} {err}").contains("synthetic-installation-token"));
    }
    let p = provider(
        Arc::new(FakeAppApi::failing(IntakeReason::TokenUnavailable)),
        &key,
    );
    assert_eq!(
        p.token_for(inst(), repo(), ts(NOW)).unwrap_err(),
        IntakeReason::TokenUnavailable
    );
}

// --- Checks ------------------------------------------------------------------

fn reporter() -> (CheckReporter, Arc<RecordingCheckSink>, Arc<MemoryRegistry>) {
    let sink = Arc::new(RecordingCheckSink::new());
    let registry = Arc::new(MemoryRegistry::new());
    let r = CheckReporter::new(config(), registry.clone(), sink.clone());
    (r, sink, registry)
}

fn update(state: CheckState, reason: Option<CheckReason>) -> CheckUpdate {
    CheckUpdate {
        installation: inst(),
        repository: repo(),
        head_sha: head('a'),
        state,
        reason,
    }
}

#[test]
fn check_output_is_fixed_text_plus_one_reason_code() {
    let (r, sink, _) = reporter();
    let cases = [
        (CheckState::Queued, None),
        (
            CheckState::InProgress,
            Some(CheckReason::Core(ReasonCode::Authorized)),
        ),
        (
            CheckState::Denied,
            Some(CheckReason::Intake(IntakeReason::ForkDenied)),
        ),
        (
            CheckState::Failed,
            Some(CheckReason::Core(ReasonCode::ExecutionFailed)),
        ),
        (
            CheckState::Completed,
            Some(CheckReason::Core(ReasonCode::Completed)),
        ),
    ];
    for (state, reason) in cases {
        r.report(&update(state, reason)).unwrap();
    }
    let posts = sink.posts();
    assert_eq!(posts.len(), 5);
    for p in &posts {
        assert_eq!(p.name, CHECK_NAME);
        assert!(p.summary.len() < 300);
        assert!(p.summary.is_ascii());
        // Only the fixed template plus a lowercase code: nothing else varies.
        let expected_tail =
            "This check reports process state only; it is not a measurement result or approval.";
        assert!(p.summary.ends_with(expected_tail));
        assert!(p.summary.starts_with("State: "));
        assert_eq!(p.head_sha, head('a'));
    }
    assert_eq!(posts[0].status, GithubStatus::Queued);
    assert_eq!(posts[0].conclusion, None);
    assert!(posts[0].summary.contains("Reason: none."));
    assert!(posts[2].summary.contains("Reason: fork_denied."));
    assert_eq!(posts[2].conclusion, Some(GithubConclusion::Failure));
    assert!(posts[3].summary.contains("Reason: execution_failed."));
    // A finished run is neutral: never a green "success" that reads as a pass.
    assert_eq!(posts[4].conclusion, Some(GithubConclusion::Neutral));
    assert!(posts[4].summary.contains("Reason: completed."));
}

#[test]
fn every_reason_renders_as_a_bounded_lowercase_code() {
    for r in IntakeReason::ALL {
        let post = CheckPost::render(&update(CheckState::Denied, Some(CheckReason::Intake(r))));
        assert!(post.summary.contains(&format!("Reason: {}.", r.as_str())));
    }
    let core = [
        ReasonCode::Requested,
        ReasonCode::AuthorizationDenied,
        ReasonCode::PlanMismatch,
        ReasonCode::BudgetExhausted,
        ReasonCode::InvalidArtifact,
        ReasonCode::StoreUnavailable,
    ];
    for c in core {
        let code = CheckReason::Core(c).code();
        assert!(code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
    }
}

#[test]
fn checks_are_scoped_to_allowlisted_live_repositories() {
    let (r, sink, registry) = reporter();
    let mut u = update(CheckState::Queued, None);
    u.installation = InstallationId::new(INSTALLATION + 1).unwrap();
    assert_eq!(
        r.report(&u).unwrap_err(),
        IntakeReason::InstallationNotAllowed
    );
    let mut u = update(CheckState::Queued, None);
    u.repository = RepositoryId::new(OTHER_REPO).unwrap();
    assert_eq!(
        r.report(&u).unwrap_err(),
        IntakeReason::RepositoryNotAllowed
    );

    registry.mark_repository_removed(inst(), repo()).unwrap();
    assert_eq!(
        r.report(&update(CheckState::Queued, None)).unwrap_err(),
        IntakeReason::RepositoryRemoved
    );
    registry.mark_installation_removed(inst()).unwrap();
    assert_eq!(
        r.report(&update(CheckState::Queued, None)).unwrap_err(),
        IntakeReason::InstallationRemoved
    );
    assert!(sink.posts().is_empty());
}

// --- Credential separation -----------------------------------------------------

#[test]
fn request_facing_ledger_and_db_credentials_are_distinct_types() {
    let roles = [
        <RequestFacingAppCredential as Credential>::ROLE,
        <LedgerWriterCredential as Credential>::ROLE,
        <DbAdminCredential as Credential>::ROLE,
    ];
    assert_eq!(roles[0], CredentialRole::RequestFacingApp);
    assert_eq!(roles[1], CredentialRole::LedgerWriter);
    assert_eq!(roles[2], CredentialRole::DbAdmin);
    assert_eq!(
        roles
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );
    // The token provider accepts only the request-facing credential type;
    // `InstallationTokenProvider::new` has no overload for the others.
    let key = FakeSigningKey::generate();
    let c = credential(&key);
    assert_eq!(format!("{c:?}"), "RequestFacingAppCredential(<redacted>)");
}

#[test]
fn workers_and_requesting_ci_hold_no_credentials() {
    let ok = [
        Assignment {
            holder: Holder::RequestFacingAppAdapter,
            role: CredentialRole::RequestFacingApp,
        },
        Assignment {
            holder: Holder::LedgerWriterService,
            role: CredentialRole::LedgerWriter,
        },
        Assignment {
            holder: Holder::DbAdministrator,
            role: CredentialRole::DbAdmin,
        },
    ];
    assert_eq!(validate_assignments(&ok), Ok(()));
    assert_eq!(validate_assignments(&[]), Ok(()));

    for holder in [Holder::IsolatedWorker, Holder::RequestingProjectCi] {
        for role in [
            CredentialRole::RequestFacingApp,
            CredentialRole::LedgerWriter,
            CredentialRole::DbAdmin,
        ] {
            assert_eq!(
                validate_assignments(&[Assignment { holder, role }]),
                Err(IntakeReason::CredentialBoundaryViolation),
                "{holder:?} {role:?}"
            );
        }
    }
    // The App adapter cannot also hold ledger or DB authority, and the
    // control service holds none of the three.
    for (holder, role) in [
        (
            Holder::RequestFacingAppAdapter,
            CredentialRole::LedgerWriter,
        ),
        (Holder::RequestFacingAppAdapter, CredentialRole::DbAdmin),
        (
            Holder::LedgerWriterService,
            CredentialRole::RequestFacingApp,
        ),
        (Holder::DbAdministrator, CredentialRole::LedgerWriter),
        (Holder::ControlService, CredentialRole::RequestFacingApp),
        (Holder::ControlService, CredentialRole::LedgerWriter),
        (Holder::ControlService, CredentialRole::DbAdmin),
    ] {
        assert_eq!(
            validate_assignments(&[Assignment { holder, role }]),
            Err(IntakeReason::CredentialBoundaryViolation),
            "{holder:?} {role:?}"
        );
    }
    // One bad line among good ones still fails.
    let mut mixed = ok.to_vec();
    mixed.push(Assignment {
        holder: Holder::IsolatedWorker,
        role: CredentialRole::DbAdmin,
    });
    assert!(validate_assignments(&mixed).is_err());
}

#[test]
fn worker_environment_cannot_carry_credentials() {
    assert_eq!(
        validate_worker_environment(["PATH", "HOME", "LANG", "TMPDIR"]),
        Ok(())
    );
    for name in [
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "APP_PRIVATE_KEY",
        "CUSTODIAN_APP_ID",
        "INSTALLATION_ID",
        "WEBHOOK_SECRET",
        "LEDGER_WRITE_KEY",
        "DATABASE_URL",
        "custodian_db_admin",
        "AWS_SECRET_ACCESS_KEY",
        "PASSWORD",
        "SERVICE_CREDENTIALS",
    ] {
        assert_eq!(
            validate_worker_environment(["PATH", name]),
            Err(IntakeReason::CredentialBoundaryViolation),
            "{name}"
        );
    }
}
