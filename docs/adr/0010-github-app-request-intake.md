# 0010. GitHub App request intake, authentication and credential separation

- Status: accepted (design baseline)
- Date: 2026-10-02
- Deciders (by role): repository maintainer (single human operator)
- Maintenance: this repository is maintained by the Redact Secret project; decisions here are
  project-maintained, not independent validation.

## Context

ADR 0001 places the request-facing App at the request edge (Z1): it authenticates the sender, normalizes and
enqueues a request, and posts sanitized status. It holds no corpus, signing, ledger or runtime-DB write
access, and authority never flows from Z0 (GitHub events, pull request text) into Z2 by a label, comment or
message. ADR 0002 lists the request-facing App credential as one of seven runtime identities and fixes the
crate layout. C3 (#4) implements the edge. Threat assumptions: payloads, headers, branch names, titles,
comments, labels and workflow files are attacker-controlled; webhooks can be forged, replayed, redelivered,
oversized or sent for removed installations; a pull request can come from a fork or another repository; a
head commit can move between the event and the work; App access is not human approval.

## Options

| Question | Options | Choice |
| --- | --- | --- |
| Where does intake live | in `custodian-service`; in a new adapter crate; in a TypeScript GitHub App | new crate `custodian-intake` (service keeps no vendor code; ADR 0002 says adapters enter in adapter code) |
| Webhook signature | `hmac` + `sha2`; hand-rolled HMAC; GitHub SDK | `hmac` =0.12.1 with `sha2` (already pinned); `verify_slice` is the constant-time comparison |
| App JWT (RS256) | `jsonwebtoken` or `rsa` in this crate; signer trait with the key in the deployment adapter | signer trait. The `rsa` crate carries an unfixed timing advisory (RUSTSEC-2023-0071), `jsonwebtoken` pulls a large tree; the private key must not enter request-handling memory more than a key service requires. Production supplies an RS256 signer behind `AppJwtSigner` after its own dependency review |
| HTTP client | embed a client; trait | trait (`AppApiTransport`, `CheckSink`, `PullRequestSource`). No client, TLS stack or async runtime enters this crate; the whole edge is testable offline |
| Delivery replay state | in-process only; trait with durable adapter | trait (`DeliveryStore`); in-memory double now, durable adapter in C4 |
| Authority for actors | trust `asserted_actor`; derive from verified GitHub user id and an allowlist | derive; the asserted value is checked for equality, never trusted |
| Event handling | accept all, deny some; allowlist | allowlist, with named refusal codes for comment and workflow classes |

## Decision

1. **Crate** `crates/custodian-intake` depends on `custodian-core`, `custodian-contracts`, `hmac`, `sha2`,
   `serde`, `serde_json`, all exact-pinned. `hmac` is new; it adds `subtle` (constant-time primitives) to the
   lock file. `custodian-core` stays std-only.
2. **Webhook intake validates and enqueues.** Order: body size cap, `X-Hub-Signature-256` HMAC (constant time,
   exact `sha256=` + 64 hex), JSON content type, delivery id (UUID), event allowlist, atomic delivery claim,
   strict typed parse, installation/repository/fork/cross-repository/sender/actor checks, enqueue. No
   evaluation, no network call, no read of anything but identifiers from the pull request.
3. **Event allowlist** is configuration limited to `ping`, `pull_request`, `installation`,
   `installation_repositories`. Pull request actions that queue: `opened`, `synchronize`, `reopened`,
   `ready_for_review`. Comment events (`issue_comment`, review comments, `issues`, ...) and workflow/dispatch
   events (`workflow_run`, `workflow_dispatch`, `repository_dispatch`, `pull_request_target`, ...) are refused
   by name and cannot be enabled by configuration. A label or comment is never a trigger or an approval.
4. **Scope.** Identities are numeric GitHub ids (installation, repository, user), never names. Installations
   map to explicit repository lists. A removal event (`installation` deleted/suspend,
   `installation_repositories` removed) is recorded in an `InstallationRegistry` and only ever restricts
   further; creation, unsuspension, added repositories and permission changes re-enable nothing (an operator
   configuration change does).
5. **Fork and cross-repository denial.** The base repository must be the event repository and the head must be
   in that same repository. A null head repository (deleted fork) is a fork. Only `User` senders on the actor
   allowlist with the requester role can queue; bots, apps and organizations cannot.
6. **Delivery idempotency.** `DeliveryStore::claim` is an atomic check-and-insert after authentication; a
   second claim is `delivery_replay`. If the queue refuses an otherwise accepted delivery, the claim is
   released so GitHub's redelivery can succeed. The in-memory store refuses at capacity rather than evicting
   (eviction would reopen a replay window). A store that cannot answer fails closed.
7. **Execution gate** (`ExecutionGate`) is the second stage and the only way to an `AuthorizedExecution`. It
   re-checks scope and actor, decodes the request with `EvaluationRequest::decode`, requires
   `asserted_actor` to equal the derived actor, reads the current pull request head through
   `PullRequestSource` (stale-commit check) and compares the staged candidate and configuration digests with
   the plan. It then requires an `Approval` (execute scope) whose approver holds the approver role and passes
   `Approval::check_for_execution` against current policy activation state. **App access is never an input to
   approval**: absent an approval record the result is `approval_required`.
8. **Immutable binding.** `IntakeBinding` (repository, head SHA, candidate digest, configuration digest, plan
   digest, request id) has no setters and a domain-separated digest
   (`private-custodian/v1/intake-binding`, local to this crate; promoting it to a `DomainTag` is a contracts
   change with a new tag).
9. **Fixed reason codes.** `IntakeReason` is a fieldless enum; `as_str` is the only text that leaves the edge
   (HTTP body, logs, Checks). `to_core` maps each onto the closed `custodian_core::ReasonCode` set, so the
   shared core enum is not widened by the edge.
10. **Checks.** `CheckUpdate` has no string field. Text is built from fixed templates plus one reason code.
    Conclusions are `failure` or `neutral`; `success` is not representable, so a green check cannot read as
    a passed evaluation. Updates are scoped to allowlisted, non-removed repositories.
11. **App authentication.** `mint_app_jwt` (lifetime 540 s, `iat` back-dated 60 s) signs through
    `AppJwtSigner`. `InstallationTokenProvider` exchanges it, via `AppApiTransport`, for a token limited to one
    repository and the fixed permission set (`metadata:read`, `pull_requests:read`, `checks:write`); a response
    granting anything broader is discarded (`permissions_exceeded`). Tokens and JWTs have redacted `Debug`, no
    `Display`/`Serialize`/`Clone`, and errors carry no text.
12. **Credential separation.** `RequestFacingAppCredential`, `LedgerWriterCredential` and `DbAdminCredential`
    are distinct types with one `CredentialRole` each. `validate_assignments` accepts only the three permitted
    holder/role pairs, so workers, requesting-project CI and the control service hold none of them;
    `validate_worker_environment` rejects credential-bearing environment names.

## Security properties claimed

All are requirements of the implemented library, unproven until deployed and reviewed.

| Property | Test (`crates/custodian-intake/tests/`) |
| --- | --- |
| Forged, missing, malformed or wrong-scheme signatures rejected; forged attempts do not consume the delivery | `webhook.rs::forged_signature_fails_closed_and_does_not_consume_the_delivery` |
| Oversized body rejected before HMAC or parsing | `oversized_body_is_rejected_before_signature_or_parsing` |
| Replay refused; exactly one winner under contention; queue failure releases the claim | `replayed_delivery_is_refused_and_queued_once`, `concurrent_duplicate_deliveries_queue_exactly_once`, `store_claim_is_atomic_under_contention`, `queue_failure_releases_the_claim_so_redelivery_can_succeed` |
| Removed or suspended installation and removed repository refused and never re-enabled by events | `removed_installation_is_refused_and_never_re_enabled`, `suspended_installation_is_treated_as_removed`, `removed_repository_is_refused` |
| Unauthorized actors, bots refused; login names are not identity | `unauthorized_actor_is_refused` |
| Fork, deleted fork and cross-repository refused | `fork_pull_requests_are_denied`, `cross_repository_pull_requests_are_denied` |
| Comment, workflow, dispatch and unknown events refused; configuration cannot enable them | `comment_triggers_are_denied_even_from_an_approver`, `workflow_and_dispatch_triggers_are_denied`, `config_validation_fails_closed` |
| Queued record and responses carry identifiers and fixed codes only | `valid_delivery_is_queued_with_identifiers_only`, `responses_carry_only_fixed_codes` |
| Stale commit, candidate or configuration digest mismatch refused | `gate.rs::stale_commit_is_refused`, `candidate_and_config_digest_must_match_the_staged_bytes` |
| App access is not approval; approver role required; approval bindings and freshness enforced | `app_access_is_not_protected_execution_approval`, `approver_must_hold_the_approver_role`, `approval_bindings_and_freshness_are_enforced` |
| Asserted actor is checked, not trusted | `asserted_actor_is_checked_not_trusted` |
| JWT lifetime, scoped token request, permission ceiling, no secret in output | `app.rs::app_jwt_is_short_lived_backdated_and_signed_by_the_credential`, `installation_token_is_scoped_cached_and_never_printed`, `broader_permissions_than_requested_are_rejected`, `malformed_or_expired_token_responses_fail_closed_without_echo` |
| Check output is fixed text plus a reason code and is scope-limited | `check_output_is_fixed_text_plus_one_reason_code`, `checks_are_scoped_to_allowlisted_live_repositories` |
| Workers and requesting-project CI hold no credential; credential types are distinct | `workers_and_requesting_ci_hold_no_credentials`, `worker_environment_cannot_carry_credentials`, `request_facing_ledger_and_db_credentials_are_distinct_types` |

Not claimed: that a deployed listener is correctly configured, that TLS or the host is sound, that the App
private key is protected, or that the transport pins the GitHub host. Those belong to the deployment
adapter and C12.

## Adapter contract

New ports in `custodian_intake::ports`, `checks` and `app_auth`: `DeliveryStore`, `InstallationRegistry`,
`IntakeQueue`, `PullRequestSource`, `CheckSink`, `AppApiTransport`, and `credentials::AppJwtSigner`. They
name GitHub only because this crate is the GitHub adapter; none of them is imported by `custodian-core`.
C4 implements `DeliveryStore`, `InstallationRegistry` and `IntakeQueue` durably (queue entries and delivery
claims must be written in one transaction with the audit outbox). The deployment supplies the HTTP listener,
the transport (no redirects, pinned host, bounded time and size) and the RS256 signer.

## Failure and recovery

Unreadable delivery store or registry: refuse (`store_unavailable`). Full or failing queue: refuse and release
the claim. Token exchange failure: no Check, no head read; the gate refuses (`token_unavailable`,
`app_auth_failed`). Process restart with the in-memory stores forgets claims, so durable stores are required
before the webhook is enabled (C4); until then the webhook stays inactive. A crash between claim and enqueue
leaves a claimed, unqueued delivery; the durable adapter must make the pair atomic. Duplicate or stale
requests never produce a second execution: the control service still reserves idempotently (ADR 0002).

## Performance evidence plan

Measure signature verification and parse cost per delivery, claim latency and queue enqueue latency
separately from evaluation time. Bodies are capped (default 256 KiB, ceiling 1 MiB); no check is relaxed for
speed.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Signed webhook intake, allowlists, replay, fork/cross-repo/comment/workflow denial | yes | yes (library, in-memory doubles) | no |
| Execution gate, approval separation, immutable binding | yes | yes | no |
| App JWT and scoped installation token behind traits, offline fake | yes | yes (no real signer or transport) | no |
| Sanitized Check output behind a trait | yes | yes | no |
| Credential separation types and manifest validation | yes | yes | no |
| Durable delivery store, registry and queue | yes (C4) | no | no |
| HTTP listener, RS256 signer, GitHub transport, webhook enabled | yes | no | no |

## Consequences, migration, exit

The edge is replaceable: another listener only calls `Intake::handle`. A new event or action is a reviewed code
and configuration change. Changing the requested App permissions is a reviewed change to
`REQUESTED_PERMISSIONS` and `docs/github-app.md`. Approval, retention, budget, disclosure and signer policy are
unchanged. Dependency exit: replace `hmac` by another audited MAC implementation with the same tests.

## Open risks and revisit triggers

Webhook secret and App key custody are operator tasks (rotation in `docs/github-app.md`). A single human holds
requester, approver and operator roles in the first deployment, so separation is procedural (ADR 0001 T3).
Very large `installation` events (many repositories) exceed the body cap and are refused before the removal can
be recorded; removal then relies on GitHub rejecting the installation token and on removing the entry from the
configuration. GitHub does not sign with a timestamp, so replay protection depends on delivery-id retention
(bounded by the durable store) plus the stale-commit check. Revisit if a second operator joins, if events
beyond pull requests are needed, or if a Rust RS256 implementation without open advisories is adopted.
