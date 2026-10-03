//! Webhook intake failure modes. Every payload is synthetic and every secret
//! is generated in-test.

mod common;

use std::sync::Arc;
use std::thread;

use common::*;
use custodian_intake::config::{IntakeConfig, WebhookSecret, DEFAULT_MAX_BODY_BYTES};
use custodian_intake::memory::{MemoryDeliveryStore, MemoryQueue};
use custodian_intake::ports::{Claim, DeliveryStore};
use custodian_intake::reason::{ConfigError, IntakeReason};
use custodian_intake::testing::random_bytes;
use custodian_intake::webhook::{response, Delivery, Outcome};
use serde_json::json;

fn pr_ok() -> serde_json::Value {
    pr_payload("opened", REQUESTER, "User")
}

#[test]
fn valid_delivery_is_queued_with_identifiers_only() {
    let h = harness();
    let out = h.deliver("pull_request", 1, &pr_ok());
    assert_eq!(out, Ok(Outcome::Queued));
    assert_eq!(response(&out), (202, "queued"));

    let q = h.queue.pop().expect("queued");
    assert_eq!(q.installation, inst());
    assert_eq!(q.repository, repo());
    assert_eq!(q.pull_request.get(), PR_NUMBER);
    assert_eq!(q.head_sha, head('a'));
    assert_eq!(q.actor.as_str(), id("act_", 1));
    assert_eq!(q.github_user, user(REQUESTER));

    // Nothing the PR author controls survives into the queued record.
    let dump = format!("{q:?}");
    for hostile in ["HOSTILE", "/approve", "synthetic-branch", "synthetic-user"] {
        assert!(!dump.contains(hostile), "queued record leaked payload text");
    }
}

#[test]
fn forged_signature_fails_closed_and_does_not_consume_the_delivery() {
    let h = harness();
    let body = serde_json::to_vec(&pr_ok()).unwrap();

    // Signed with a different secret.
    let other = WebhookSecret::new(random_bytes(32)).unwrap();
    let forged = custodian_intake::signature::sign_body(&other, &body);
    let d = |sig: Option<&str>, body: &[u8]| {
        h.intake.handle(
            &Delivery {
                signature: sig,
                event: Some("pull_request"),
                delivery_id: Some(&uuid(1)),
                content_type: Some("application/json"),
                body,
            },
            ts(NOW),
        )
    };
    assert_eq!(d(Some(&forged), &body), Err(IntakeReason::SignatureInvalid));
    assert_eq!(d(None, &body), Err(IntakeReason::SignatureInvalid));
    assert_eq!(d(Some(""), &body), Err(IntakeReason::SignatureInvalid));
    assert_eq!(
        d(Some("sha256="), &body),
        Err(IntakeReason::SignatureInvalid)
    );
    assert_eq!(
        d(Some(&format!("sha1={}", "0".repeat(40))), &body),
        Err(IntakeReason::SignatureInvalid)
    );
    assert_eq!(
        d(Some(&format!("sha256={}", "z".repeat(64))), &body),
        Err(IntakeReason::SignatureInvalid)
    );
    assert_eq!(
        d(Some(&format!("sha256={}", "0".repeat(63))), &body),
        Err(IntakeReason::SignatureInvalid)
    );

    // A genuine signature over different bytes (tampered body).
    let genuine = h.signature(&body);
    let mut tampered = body.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    assert_eq!(
        d(Some(&genuine), &tampered),
        Err(IntakeReason::SignatureInvalid)
    );

    assert!(h.queue.is_empty());
    // None of the forged attempts claimed the delivery id: the real
    // delivery with the same id is still accepted.
    assert_eq!(d(Some(&genuine), &body), Ok(Outcome::Queued));
}

#[test]
fn oversized_body_is_rejected_before_signature_or_parsing() {
    let h = harness();
    let body = vec![b' '; DEFAULT_MAX_BODY_BYTES + 1];
    // Valid signature over the oversized body: still refused.
    assert_eq!(
        h.deliver_raw("pull_request", &uuid(1), &body),
        Err(IntakeReason::BodyTooLarge)
    );
    // No signature at all: size is checked first, so no HMAC work is done.
    let out = h.intake.handle(
        &Delivery {
            signature: None,
            event: Some("pull_request"),
            delivery_id: Some(&uuid(2)),
            content_type: Some("application/json"),
            body: &body,
        },
        ts(NOW),
    );
    assert_eq!(out, Err(IntakeReason::BodyTooLarge));
    assert_eq!(response(&out), (413, "body_too_large"));
    // Exactly at the limit is not oversized (it fails later, as malformed).
    let at_limit = vec![b' '; DEFAULT_MAX_BODY_BYTES];
    assert_eq!(
        h.deliver_raw("pull_request", &uuid(3), &at_limit),
        Err(IntakeReason::PayloadMalformed)
    );
}

#[test]
fn replayed_delivery_is_refused_and_queued_once() {
    let h = harness();
    assert_eq!(h.deliver("pull_request", 1, &pr_ok()), Ok(Outcome::Queued));
    assert_eq!(
        h.deliver("pull_request", 1, &pr_ok()),
        Err(IntakeReason::DeliveryReplay)
    );
    assert_eq!(h.queue.len(), 1);

    // A replay of a delivery that was denied is also a replay.
    let denied = pr_payload("opened", STRANGER, "User");
    assert_eq!(
        h.deliver("pull_request", 2, &denied),
        Err(IntakeReason::ActorNotAuthorized)
    );
    assert_eq!(
        h.deliver("pull_request", 2, &denied),
        Err(IntakeReason::DeliveryReplay)
    );
    // Case variants of one id are one id.
    let upper = uuid(0xabc).to_ascii_uppercase();
    let body = serde_json::to_vec(&pr_ok()).unwrap();
    assert_eq!(
        h.deliver_raw("pull_request", &upper, &body),
        Ok(Outcome::Queued)
    );
    assert_eq!(
        h.deliver_raw("pull_request", &uuid(0xabc), &body),
        Err(IntakeReason::DeliveryReplay)
    );
}

#[test]
fn concurrent_duplicate_deliveries_queue_exactly_once() {
    let h = Arc::new(harness());
    let body = Arc::new(serde_json::to_vec(&pr_ok()).unwrap());
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let h = Arc::clone(&h);
            let body = Arc::clone(&body);
            thread::spawn(move || h.deliver_raw("pull_request", &uuid(1), &body))
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|t| t.join().unwrap()).collect();
    let queued = results
        .iter()
        .filter(|r| **r == Ok(Outcome::Queued))
        .count();
    let replays = results
        .iter()
        .filter(|r| **r == Err(IntakeReason::DeliveryReplay))
        .count();
    assert_eq!(queued, 1);
    assert_eq!(replays, 15);
    assert_eq!(h.queue.len(), 1);
}

#[test]
fn store_claim_is_atomic_under_contention() {
    let store = Arc::new(MemoryDeliveryStore::new(8));
    let id = custodian_intake::ids::DeliveryId::parse(&uuid(5)).unwrap();
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let s = Arc::clone(&store);
            let id = id.clone();
            thread::spawn(move || s.claim(&id).unwrap())
        })
        .collect();
    let new = handles
        .into_iter()
        .map(|t| t.join().unwrap())
        .filter(|c| *c == Claim::New)
        .count();
    assert_eq!(new, 1);
}

#[test]
fn queue_failure_releases_the_claim_so_redelivery_can_succeed() {
    let h = harness_with(MemoryQueue::new(0), MemoryDeliveryStore::new(8));
    assert_eq!(
        h.deliver("pull_request", 1, &pr_ok()),
        Err(IntakeReason::QueueUnavailable)
    );
    // Still full: the same id is retried, not reported as a replay.
    assert_eq!(
        h.deliver("pull_request", 1, &pr_ok()),
        Err(IntakeReason::QueueUnavailable)
    );

    let h = harness_with(MemoryQueue::new(1), MemoryDeliveryStore::new(8));
    assert_eq!(h.deliver("pull_request", 1, &pr_ok()), Ok(Outcome::Queued));
    // Queue is now full; a second delivery fails but can be redelivered
    // once the control plane drains the queue.
    assert_eq!(
        h.deliver("pull_request", 2, &pr_ok()),
        Err(IntakeReason::QueueUnavailable)
    );
    assert!(h.queue.pop().is_some());
    assert_eq!(h.deliver("pull_request", 2, &pr_ok()), Ok(Outcome::Queued));
}

#[test]
fn delivery_store_failure_fails_closed() {
    let h = harness_with(MemoryQueue::new(4), MemoryDeliveryStore::new(0));
    assert_eq!(
        h.deliver("pull_request", 1, &pr_ok()),
        Err(IntakeReason::StoreUnavailable)
    );
    assert!(h.queue.is_empty());
}

#[test]
fn removed_installation_is_refused_and_never_re_enabled() {
    let h = harness();
    assert_eq!(h.deliver("pull_request", 1, &pr_ok()), Ok(Outcome::Queued));

    let removal = json!({"action": "deleted", "installation": {"id": INSTALLATION}});
    assert_eq!(
        h.deliver("installation", 2, &removal),
        Ok(Outcome::InstallationRevoked)
    );
    assert_eq!(
        h.deliver("pull_request", 3, &pr_ok()),
        Err(IntakeReason::InstallationRemoved)
    );

    // Neither "created" nor "unsuspend" brings it back.
    for (n, action) in [
        (4, "created"),
        (5, "unsuspend"),
        (6, "new_permissions_accepted"),
    ] {
        let ev = json!({"action": action, "installation": {"id": INSTALLATION}});
        assert_eq!(
            h.deliver("installation", n, &ev),
            Err(IntakeReason::ActionNotAllowed)
        );
    }
    assert_eq!(
        h.deliver("pull_request", 7, &pr_ok()),
        Err(IntakeReason::InstallationRemoved)
    );
    assert_eq!(h.queue.len(), 1);
}

#[test]
fn suspended_installation_is_treated_as_removed() {
    let h = harness();
    let ev = json!({"action": "suspend", "installation": {"id": INSTALLATION}});
    assert_eq!(
        h.deliver("installation", 1, &ev),
        Ok(Outcome::InstallationRevoked)
    );
    assert_eq!(
        h.deliver("pull_request", 2, &pr_ok()),
        Err(IntakeReason::InstallationRemoved)
    );
}

#[test]
fn removed_repository_is_refused() {
    let h = harness();
    let ev = json!({
        "action": "removed",
        "installation": {"id": INSTALLATION},
        "repositories_removed": [{"id": REPO}]
    });
    assert_eq!(
        h.deliver("installation_repositories", 1, &ev),
        Ok(Outcome::RepositoryRevoked)
    );
    assert_eq!(
        h.deliver("pull_request", 2, &pr_ok()),
        Err(IntakeReason::RepositoryRemoved)
    );
    // Added repositories are never allowlisted automatically.
    let added = json!({
        "action": "added",
        "installation": {"id": INSTALLATION},
        "repositories_added": [{"id": OTHER_REPO}]
    });
    assert_eq!(
        h.deliver("installation_repositories", 3, &added),
        Err(IntakeReason::ActionNotAllowed)
    );
}

#[test]
fn unknown_installation_and_repository_are_refused() {
    let h = harness();
    let mut p = pr_ok();
    p["installation"]["id"] = json!(INSTALLATION + 1);
    assert_eq!(
        h.deliver("pull_request", 1, &p),
        Err(IntakeReason::InstallationNotAllowed)
    );

    let mut p = pr_ok();
    p["repository"]["id"] = json!(OTHER_REPO);
    p["pull_request"]["head"]["repo"]["id"] = json!(OTHER_REPO);
    p["pull_request"]["base"]["repo"]["id"] = json!(OTHER_REPO);
    assert_eq!(
        h.deliver("pull_request", 2, &p),
        Err(IntakeReason::RepositoryNotAllowed)
    );

    // A removal event for an installation we never allowlisted records nothing.
    let ev = json!({"action": "deleted", "installation": {"id": INSTALLATION + 1}});
    assert_eq!(
        h.deliver("installation", 3, &ev),
        Err(IntakeReason::InstallationNotAllowed)
    );
    assert!(h.queue.is_empty());
}

#[test]
fn unauthorized_actor_is_refused() {
    let h = harness();
    assert_eq!(
        h.deliver("pull_request", 1, &pr_payload("opened", STRANGER, "User")),
        Err(IntakeReason::ActorNotAuthorized)
    );
    // The login string is not an identity: only the numeric id counts.
    let mut p = pr_payload("opened", STRANGER, "User");
    p["sender"]["login"] = json!("synthetic-requester");
    assert_eq!(
        h.deliver("pull_request", 2, &p),
        Err(IntakeReason::ActorNotAuthorized)
    );
    // Bots and apps cannot request even with an allowlisted id.
    for (n, kind) in [(3, "Bot"), (4, "Organization"), (5, "Mannequin")] {
        assert_eq!(
            h.deliver("pull_request", n, &pr_payload("opened", REQUESTER, kind)),
            Err(IntakeReason::ActorKindDenied)
        );
    }
    assert!(h.queue.is_empty());
}

#[test]
fn fork_pull_requests_are_denied() {
    let h = harness();
    let mut p = pr_ok();
    p["pull_request"]["head"]["repo"] = json!({"id": OTHER_REPO, "fork": true});
    assert_eq!(
        h.deliver("pull_request", 1, &p),
        Err(IntakeReason::ForkDenied)
    );
    // Deleted fork: head repository is null.
    let mut p = pr_ok();
    p["pull_request"]["head"]["repo"] = serde_json::Value::Null;
    assert_eq!(
        h.deliver("pull_request", 2, &p),
        Err(IntakeReason::ForkDenied)
    );
    // Even the approver cannot request from a fork.
    let mut p = pr_payload("opened", APPROVER, "User");
    p["pull_request"]["head"]["repo"] = json!({"id": OTHER_REPO, "fork": true});
    assert_eq!(
        h.deliver("pull_request", 3, &p),
        Err(IntakeReason::ForkDenied)
    );
    assert!(h.queue.is_empty());
}

#[test]
fn cross_repository_pull_requests_are_denied() {
    let h = harness();
    // Head in another, non-fork repository.
    let mut p = pr_ok();
    p["pull_request"]["head"]["repo"] = json!({"id": OTHER_REPO, "fork": false});
    assert_eq!(
        h.deliver("pull_request", 1, &p),
        Err(IntakeReason::CrossRepositoryDenied)
    );
    // Base is not the repository the event (and allowlist check) is about.
    let mut p = pr_ok();
    p["pull_request"]["base"]["repo"] = json!({"id": OTHER_REPO, "fork": false});
    assert_eq!(
        h.deliver("pull_request", 2, &p),
        Err(IntakeReason::CrossRepositoryDenied)
    );
    let mut p = pr_ok();
    p["pull_request"]["base"]["repo"] = serde_json::Value::Null;
    assert_eq!(
        h.deliver("pull_request", 3, &p),
        Err(IntakeReason::CrossRepositoryDenied)
    );
    assert!(h.queue.is_empty());
}

#[test]
fn comment_triggers_are_denied_even_from_an_approver() {
    let h = harness();
    let comment = json!({
        "action": "created",
        "installation": {"id": INSTALLATION},
        "repository": {"id": REPO},
        "sender": {"id": APPROVER, "type": "User"},
        "comment": {"body": "/approve /run SYNTHETIC"}
    });
    for (n, event) in [
        (1, "issue_comment"),
        (2, "pull_request_review_comment"),
        (3, "pull_request_review"),
        (4, "commit_comment"),
        (5, "issues"),
    ] {
        assert_eq!(
            h.deliver(event, n, &comment),
            Err(IntakeReason::CommentTriggerDenied),
            "{event}"
        );
    }
    assert!(h.queue.is_empty());
}

#[test]
fn workflow_and_dispatch_triggers_are_denied() {
    let h = harness();
    let body = json!({"action": "requested", "installation": {"id": INSTALLATION}});
    for (n, event) in [
        (1, "workflow_run"),
        (2, "workflow_job"),
        (3, "workflow_dispatch"),
        (4, "repository_dispatch"),
        (5, "pull_request_target"),
        (6, "schedule"),
    ] {
        assert_eq!(
            h.deliver(event, n, &body),
            Err(IntakeReason::WorkflowTriggerDenied),
            "{event}"
        );
    }
    // Anything else not enabled is simply not allowed.
    for (n, event) in [
        (7, "push"),
        (8, "check_run"),
        (9, "check_suite"),
        (10, "release"),
    ] {
        assert_eq!(
            h.deliver(event, n, &body),
            Err(IntakeReason::EventNotAllowed),
            "{event}"
        );
    }
    assert!(h.queue.is_empty());
}

#[test]
fn only_listed_pull_request_actions_queue() {
    let h = harness();
    for (n, action) in [
        (1, "opened"),
        (2, "synchronize"),
        (3, "reopened"),
        (4, "ready_for_review"),
    ] {
        assert_eq!(
            h.deliver("pull_request", n, &pr_payload(action, REQUESTER, "User")),
            Ok(Outcome::Queued),
            "{action}"
        );
    }
    // Labels, edits and closing are not triggers; a label never approves.
    for (n, action) in [
        (5, "labeled"),
        (6, "edited"),
        (7, "closed"),
        (8, "assigned"),
        (9, ""),
    ] {
        assert_eq!(
            h.deliver("pull_request", n, &pr_payload(action, APPROVER, "User")),
            Err(IntakeReason::ActionNotAllowed),
            "{action}"
        );
    }
    assert_eq!(h.queue.len(), 4);
}

#[test]
fn headers_and_payload_shape_are_checked() {
    let h = harness();
    let body = serde_json::to_vec(&pr_ok()).unwrap();
    let sig = h.signature(&body);
    let call = |content_type: Option<&str>, delivery: Option<&str>, event: Option<&str>| {
        h.intake.handle(
            &Delivery {
                signature: Some(&sig),
                event,
                delivery_id: delivery,
                content_type,
                body: &body,
            },
            ts(NOW),
        )
    };
    let d = uuid(1);
    assert_eq!(
        call(
            Some("application/x-www-form-urlencoded"),
            Some(&d),
            Some("pull_request")
        ),
        Err(IntakeReason::ContentTypeInvalid)
    );
    assert_eq!(
        call(None, Some(&d), Some("pull_request")),
        Err(IntakeReason::ContentTypeInvalid)
    );
    assert_eq!(
        call(Some("application/json"), None, Some("pull_request")),
        Err(IntakeReason::DeliveryIdInvalid)
    );
    assert_eq!(
        call(
            Some("application/json"),
            Some("not-a-uuid"),
            Some("pull_request")
        ),
        Err(IntakeReason::DeliveryIdInvalid)
    );
    assert_eq!(
        call(Some("application/json"), Some(&d), None),
        Err(IntakeReason::EventNotAllowed)
    );
    assert_eq!(
        call(
            Some("application/json"),
            Some(&d),
            Some("Pull Request; DROP")
        ),
        Err(IntakeReason::EventNotAllowed)
    );
    assert_eq!(
        call(
            Some("application/json; charset=utf-8"),
            Some(&d),
            Some("pull_request")
        ),
        Ok(Outcome::Queued)
    );

    // Not JSON, wrong shape, missing installation, out-of-range ids.
    assert_eq!(
        h.deliver_raw("pull_request", &uuid(2), b"not json"),
        Err(IntakeReason::PayloadMalformed)
    );
    let mut p = pr_ok();
    p.as_object_mut().unwrap().remove("installation");
    assert_eq!(
        h.deliver("pull_request", 3, &p),
        Err(IntakeReason::PayloadMalformed)
    );
    let mut p = pr_ok();
    p["pull_request"]["head"]["sha"] = json!("not-a-sha");
    assert_eq!(
        h.deliver("pull_request", 4, &p),
        Err(IntakeReason::PayloadMalformed)
    );
    let mut p = pr_ok();
    p["sender"]["id"] = json!(0);
    assert_eq!(
        h.deliver("pull_request", 5, &p),
        Err(IntakeReason::PayloadMalformed)
    );
}

#[test]
fn ping_is_authenticated_and_ignored() {
    let h = harness();
    let out = h.deliver("ping", 1, &json!({"zen": "synthetic"}));
    assert_eq!(out, Ok(Outcome::Ignored));
    assert_eq!(response(&out), (200, "ignored"));
    assert!(h.queue.is_empty());
}

#[test]
fn responses_carry_only_fixed_codes() {
    let h = harness();
    let hostile = "SYNTHETIC-HOSTILE-VALUE";
    let mut p = pr_ok();
    p["pull_request"]["title"] = json!(hostile);
    p["sender"]["login"] = json!(hostile);
    p["sender"]["id"] = json!(STRANGER);

    let result = h.deliver("pull_request", 1, &p);
    let (status, code) = response(&result);
    assert_eq!((status, code), (403, "actor_not_authorized"));
    assert!(!format!("{result:?}").contains(hostile));

    // The vocabulary is closed: lowercase ASCII and underscores, unique.
    let mut seen = std::collections::BTreeSet::new();
    for r in IntakeReason::ALL {
        let s = r.as_str();
        assert!(s.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'));
        assert!(seen.insert(s), "duplicate code {s}");
        assert_eq!(r.to_string(), s);
        assert!((400..=599).contains(&r.http_status()));
        let _ = r.to_core();
    }
    assert_eq!(seen.len(), IntakeReason::ALL.len());
}

#[test]
fn config_validation_fails_closed() {
    let parse = |v: serde_json::Value| IntakeConfig::from_json(&serde_json::to_vec(&v).unwrap());
    assert!(parse(config_json()).is_ok());

    let mut c = config_json();
    c["events"] = json!([]);
    assert_eq!(parse(c).unwrap_err(), ConfigError::NoEvents);

    // Comment and workflow events cannot be enabled by configuration.
    for ev in ["issue_comment", "workflow_run", "push", "check_run"] {
        let mut c = config_json();
        c["events"] = json!(["pull_request", ev]);
        assert_eq!(parse(c).unwrap_err(), ConfigError::UnsupportedEvent, "{ev}");
    }

    let mut c = config_json();
    c["installations"] = json!([]);
    assert_eq!(parse(c).unwrap_err(), ConfigError::NoInstallations);

    let mut c = config_json();
    c["installations"][0]["repository_ids"] = json!([]);
    assert_eq!(parse(c).unwrap_err(), ConfigError::NoRepositories);

    let mut c = config_json();
    c["actors"] = json!([]);
    assert_eq!(parse(c).unwrap_err(), ConfigError::NoActors);

    let mut c = config_json();
    c["actors"][0]["roles"] = json!([]);
    assert_eq!(parse(c).unwrap_err(), ConfigError::ActorRoleMissing);

    let mut c = config_json();
    c["actors"][1]["github_user_id"] = json!(REQUESTER);
    assert_eq!(parse(c).unwrap_err(), ConfigError::Duplicate);

    let mut c = config_json();
    c["actors"][1]["actor"] = c["actors"][0]["actor"].clone();
    assert_eq!(parse(c).unwrap_err(), ConfigError::Duplicate);

    let mut c = config_json();
    c["max_body_bytes"] = json!(0);
    assert_eq!(parse(c).unwrap_err(), ConfigError::BodyLimitOutOfRange);
    let mut c = config_json();
    c["max_body_bytes"] = json!(10 * 1024 * 1024);
    assert_eq!(parse(c).unwrap_err(), ConfigError::BodyLimitOutOfRange);

    // Unknown fields (for example an inlined secret) are rejected.
    let mut c = config_json();
    c["webhook_secret"] = json!("synthetic");
    assert_eq!(parse(c).unwrap_err(), ConfigError::Malformed);

    // A bad role name or id is malformed, not silently dropped.
    let mut c = config_json();
    c["actors"][0]["roles"] = json!(["admin"]);
    assert_eq!(parse(c).unwrap_err(), ConfigError::Malformed);
    let mut c = config_json();
    c["installations"][0]["installation_id"] = json!(0);
    assert_eq!(parse(c).unwrap_err(), ConfigError::Malformed);
    assert_eq!(
        IntakeConfig::from_json(b"").unwrap_err(),
        ConfigError::Malformed
    );
}

#[test]
fn webhook_secret_must_be_long_and_is_never_printed() {
    assert_eq!(
        WebhookSecret::new(vec![1u8; 31]).unwrap_err(),
        ConfigError::SecretTooShort
    );
    let s = WebhookSecret::new(random_bytes(32)).unwrap();
    assert_eq!(format!("{s:?}"), "WebhookSecret(<redacted>)");
}
