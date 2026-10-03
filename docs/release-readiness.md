# Operational and code-only public-release readiness (C12)

Date of the review: 2026-10-03. Base: `origin/main` at C10 (`98e393a`) plus the C12 change. Reviewer: the C12
implementation, run as a report-only application of the repository's `.agents/skills` procedures
(`conformance-controls`, `run-lifecycle-review`, `isolation-verify`, `disclosure-review`, `agent-surface-review`,
`incident-triage`, `protected-asset-sweep`, `publication-readiness`, `scan-secrets-in-history`,
`dependency-audit`, `sast-sweep`, `owasp-review`, `scorecard-check`). This repository is maintained by the Redact
Secret project: this record is project-maintained evidence, **not independent validation**. A signature or a
ledger entry attests origin, binding and history of project-maintained records, never that a result was correct.
Publishing the source would not by itself disclose, or grant access to, the runtime database, the private
ledger, protected corpora, keys, credentials or operational history, provided the exclusions below hold; the
design does not rely on the source being private, and publishing code does not change authorized data use.

## 1. Verdict

| Question | Answer |
| --- | --- |
| Can the repository be made public now? | **NO-GO** |
| Can a protected run be done now (deployment)? | **NO-GO** |
| Are the C12 synthetic validation, the restore drill and the measurements done? | yes, on synthetic data, with the limits in section 3 |

Nothing here changes repository visibility, chooses a license, publishes anything or provisions anything.

### Blockers before publication, by owner role

| # | Blocker | Owner role |
| --- | --- | --- |
| P1 | **License**: none is granted and none was chosen. Options: Apache-2.0, MIT, MPL-2.0, AGPL-3.0, or stay unlicensed (all rights reserved). Each has consequences for the benchmark and engine repositories and for contributors; the choice is explicit and human | maintainer |
| P2 | **Private vulnerability reporting route and incident owner** are not configured or documented (SECURITY.md still says they must be before publication). `docs/incident-response.md` is the procedure; the route and the owner are people and settings | maintainer |
| P3 | **Isolation proof on a Linux runner for the release commit**: the `worker-isolation` CI job (`CUSTODIAN_REQUIRE_ISOLATION=1`) is the only isolation evidence; macOS skips. Its green result for the commit to be published is the evidence | maintainer (reads CI) |
| P4 | **Personal data in tracked files and history** (author email on all commits, one local home path in two tracked helper scripts) and **developer tooling in the tree** (`.claude/` helpers and settings, `.mcp.json` with a floating `@latest` package): scrub, exclude, or accept; rewriting shared history is a maintainer decision | maintainer |
| P5 | Gate items 5 to 7 re-run green on the exact commit to publish, including `dependency-audit` in CI (added here, first run pending) | maintainer / CI |

### Blockers before any protected run, by owner role

| # | Blocker | Owner role |
| --- | --- | --- |
| D1 | No service daemon, listener or queue-consumer loop; no isolated signer process; no feed destination; no ledger remote; no operator policy (HG-4, HG-7) | engineering |
| D2 | Worker engines do not yet emit `worker-result/1` and `private-custodian.aggregates/1`; no production code assembles an execution record or internal receipt from a dispatch report (HG-5, R-3) | engineering with the engine repositories |
| D3 | Restore with no newer copy has no executable procedure (R-1); a key compromise cannot be recovered from (R-4) | engineering |
| D4 | Real disclosure policy, operator policy, keys, pinned roots, ledger deploy key, independent checkpoint, encrypted storage, monitored contact: all human provisioning in `docs/deployment-runbook.md` (HG-8, HG-9) | maintainer, operations |
| D5 | Legacy consumed-budget write (HG-3) and destination binding (HG-2) designs exist; neither is implemented | engineering |

## 2. Evidence: what ran, where

| Check | Where it ran | Result |
| --- | --- | --- |
| `cargo fmt --all --check` | local (macOS arm64, rustc 1.98.1) and CI | pass locally |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | local and CI | pass locally |
| `cargo test --workspace --locked` | local and CI | see section 2.1 |
| Real bubblewrap isolation tests | **CI only** (`worker-isolation`, Linux); skipped on macOS | not assessable locally; see P3 |
| C12 suite (`crates/custodian-cli/tests/c12_*.rs`) | local and CI, deterministic, bounded | section 2.1 |
| Second-implementation golden vectors (`verify_golden.py`) | local; CI step added | 10 of 10 vectors reproduced |
| `cargo deny check` (cargo-deny 0.20.2, RustSec database fetched 2026-10-03) | local; CI job `dependency-audit` added, first run pending | advisories ok, bans ok, licenses ok, sources ok |
| `cargo audit` | not installed | not run (cargo-deny reads the same RustSec database) |
| gitleaks 8.30.1, full history, 54 commits, all refs | local, redacted | 1 finding, triaged below; 0 in the working tree (excluding untracked `target/`) |
| trufflehog 3.97.6 on a full-history patch and the tree, `--no-verification` | local | 2 unverified findings (the same synthetic constant), 0 in the tree |
| Pattern sweep (private-key headers, token prefixes, JWTs, 64-hex near key words, sensitive extensions ever committed, protected-data paths) | local | no real secret or protected path |
| OpenSSF Scorecard 5.5.0 `--local` | local | 5.1 of 10 on the checks that can run locally; remote checks **not assessable** (private repository, token and network) |
| Static review (unsafe, process execution, paths, races, panics, secrets in logs, comparisons) and OWASP review | local reading plus ripgrep | section 5 |

Findings from tools were triaged, never printed with their matched text.

### 2.1 Test results

`cargo test --workspace --locked --no-fail-fast` on macOS arm64: 629 tests passed, 0 failed, 0 ignored (unit,
integration, example and doc tests). Of these, 37 are new in C12 (36 in `crates/custodian-cli/tests/c12_*.rs`
plus the measurement example's consistency test). Nothing in the suite sleeps to wait for a race: concurrency
tests count outcomes, crash tests use deterministic fault injection. The longest new test is the crash sweep
(about 15 to 30 s in a debug build); the C12 tests use temporary directories under the system temp directory and
remove them. The C12 concurrency and intake-crash tests were repeated six times with no failure. On this macOS
host the Linux isolation tests log `ISOLATION-TEST-SKIPPED` and verify nothing; that evidence is the CI job
(P3).

## 3. Synthetic validation delivered (acceptance criterion 1)

Every test uses synthetic data and keys generated inside the test. The sandbox in the cross-layer tests is an
in-process scripted double accepted only by `Dispatcher::new_for_tests`; it proves control-plane behavior, not
isolation (ADR 0100).

| Area | Evidence (all under `crates/custodian-cli/tests/` unless stated) |
| --- | --- |
| End-to-end: intake, approval, reserve, dispatch, validate, receipt, ledger, disclosure, feed, bridge consumer, then contamination reaching the consumer | `c12_e2e.rs::intake_to_bridge_consumer_end_to_end` |
| Negative variants: hostile or partial worker output, unapproved or replayed requests, release gates, tampered or foreign-signed input | `c12_e2e.rs` (four tests) |
| Concurrent budgets, same-request races, duplicate dispatch, contamination racing approvals, concurrent export | `c12_concurrency.rs` |
| Crash at every reachable boundary of a full run, plus export, lifecycle, recover, clear, cancel and fail-before-start windows, with a rule that every `FaultOp` is swept or named | `c12_crash_windows.rs` |
| Fault points that had no injected-crash test: lease renewal, queue lease and completion, installation removal, submission cancel | `c12_crash_intake.rs` |
| Backup restore: older than the ledger, contained, the unrecoverable window | `c12_restore_drill.rs` |
| Ledger rollback, holes, forged and foreign-signed records, export and signer outages, key rotation, same-second events, backlog at switch, revocation | `c12_keys_and_ledger.rs` |
| Revocation races including the known gap; rotated key and consumer pins | `c12_revocation.rs` |
| Canary leakage on every output, log, error, ledger, feed, projection and database file; negative control; no ad-hoc logging in library code | `c12_leakage.rs` |
| Measurements (non-gating) | `examples/c12_measure.rs`, `docs/measurements.md` |
| Second canonicalization implementation | `crates/custodian-contracts/testdata/verify_golden.py` |

### 3.1 Conformance matrix (`conformance-controls`)

| Scenario | Status | Evidence |
| --- | --- | --- |
| Authorization denial, stale plan, changed plan: rejected before any reservation | tested | `tests/operator.rs`, `custodian-contracts/tests/bindings.rs`, `c12_e2e.rs` |
| Wrong candidate, engine, scanner or config identity, before and after execution | tested | `custodian-worker/tests/dispatch_fake.rs`, `c12_crash_windows.rs::identity_mismatch_before_start_refunds_and_a_cancel_crash_refunds_once` |
| Duplicate dispatch or request: one run, one charge | tested | `c12_concurrency.rs`, `tests/edge.rs` |
| Concurrent reservation of the last unit: exactly one wins | tested | `custodian-store/tests/concurrency.rs`, `c12_concurrency.rs` |
| Budget exhaustion: run and release budgets denied and recorded | tested | `tests/operator.rs`, `custodian-disclosure/tests/release.rs`, `c12_concurrency.rs` |
| Budget exhaustion: CPU, time, storage limits | tested in CI only | `custodian-worker/tests/linux_isolation.rs` |
| Lease loss and crash before exposure: safe retry, refund by policy | tested | `custodian-store/tests/crash.rs`, `c12_crash_windows.rs` |
| Crash or cancellation after exposure: no silent refund | tested | same, `c12_crash_windows.rs` |
| Cancellation cleans the process tree | tested in CI only | `custodian-worker/tests/linux_isolation.rs` |
| Malicious output: oversize, malformed, partial roster, forged counters | tested | `custodian-worker/tests/staging_result.rs`, `c12_e2e.rs` |
| Filesystem and network denial | tested in CI only | `custodian-worker/tests/linux_isolation.rs` |
| Cross-run reuse of results or authorization | tested | `custodian-disclosure/tests/release.rs`, `custodian-contracts/tests/bindings.rs` |
| Invalid bindings or receipts: the verifier rejects | tested | `custodian-ledger/tests/signing.rs`, `custodian-bridge/tests/roundtrip.rs`, `c12_e2e.rs` |
| Suppressed strata and composition | tested | `custodian-disclosure/tests/composition.rs`, `suppress.rs` unit tests |
| Signing refusal | tested | `custodian-ledger/tests/signing.rs`, `custodian-disclosure/tests/release.rs`, `c12_keys_and_ledger.rs` |
| Restart and recovery: state, budget, audit consistent; no double publication | tested | `c12_crash_windows.rs`, `c12_restore_drill.rs`, `custodian-lifecycle/tests/feed.rs` |
| Redaction: canaries never appear in logs, errors or public output | tested | `c12_leakage.rs` (operator credentials, protected bytes, hostile worker text, signing seed; every CLI role and command, `Debug` text, ledger, feed, projection, outbox and raw database files), `custodian-intake/tests/app.rs::installation_token_is_scoped_cached_and_never_printed`, `webhook.rs::webhook_secret_must_be_long_and_is_never_printed`, `custodian-disclosure/tests/leakage.rs`, `custodian-corpus/tests/canary_leakage.rs` |
| Real isolation on the production host | **not assessable** | deployment step 5 |

## 4. Public-release gate (`publication-readiness`, SECURITY.md)

| # | Gate | Result | Evidence and note |
| --- | --- | --- | --- |
| 1 | History and assets reviewed | **pass** for secrets and protected data; **open** for P4 | section 2; the only tool finding is a synthetic token constant that was replaced (`crates/custodian-intake/tests/app.rs`, commit `a30e40d3`); no sensitive extension or protected path was ever committed; personal data is P4 |
| 2 | Deployment material replaced with safe examples | **pass** | no hostnames, inventories, accounts or paths of a deployment in the tree; absolute paths in tests and docs are negative-test inputs or placeholders |
| 3 | Private reporting configured, route and owner documented | **fail** (P2) | SECURITY.md says it must be done; the procedure is `docs/incident-response.md`; the route is a human setting |
| 4 | License selected and added | **fail** (P1, human decision) | `UNLICENSED` in `Cargo.toml`, README says none is granted; not chosen here |
| 5 | Isolation demonstrated by failure tests | **not assessable locally** (P3) | CI job `worker-isolation` is the evidence |
| 6 | Concurrency and recovery tests pass | **pass** (local, synthetic) | section 3 |
| 7 | Disclosure tests pass | **pass** (local, synthetic) | `custodian-disclosure/tests/*`, `c12_revocation.rs` |
| 8 | Keys: verification needs no private key; rotation and revocation described | **pass** with stated limits | `docs/ledger.md`, `docs/backup-recovery.md` section 7, ADR 0101; limits R-4, R-5, R-6 |
| 9 | Limitations documented honestly | **pass** | README status table, this record, each document's status line |
| 10 | Authorized data use unchanged | **pass** | README "Publication and licensing", SECURITY.md |
| 11 | Supply chain: audit and Scorecard reviewed, CI holds no protected secrets | **pass** for audit and CI; Scorecard remote **not assessable** | cargo-deny clean; CI has `contents: read`, pinned checkout, no secrets, `pull_request` not `pull_request_target`; no dependency-update tool, no SAST, no fuzzing (Scorecard local 0 on those; informational) |

Exclusions that must hold at publication (protected-asset sweep): no private-ledger content, runtime database,
protected corpus, seed, raw result, key, credential or deployment inventory in the tree or history; `.gitignore`
already excludes common names but is a convenience, not a control; the operator policy, pinned roots,
deployment config and credentials stay outside the repository.

## 5. Security review results

### 5.1 Static review (`sast-sweep`)

No `unsafe` anywhere (`unsafe_code = "forbid"` at the workspace and in every crate root). All process execution
uses structured argv, never a shell, with environment allowlists. No logging framework; the only prints are the
CLI JSON object and the service scaffold (guarded by `c12_leakage.rs::library_code_has_no_ad_hoc_logging_or_printing`).

| ID | Sev | Location | Finding | Disposition |
| --- | --- | --- | --- | --- |
| S-1 | low | `custodian-ledger/src/git.rs` | ambient `GIT_DIR`, `GIT_WORK_TREE` and config-injection variables could redirect a backend that runs `checkout -f` and `clean` | **fixed here**: removed from every git child; unit test `git_children_never_inherit_repository_location_or_config_variables` |
| S-2 | low | same, `init` | remote name not validated; transport-helper URLs (`ext::`) not refused | **fixed here**: remote name validated, `ext::` forms refused, `protocol.ext.allow=never`; unit test `transport_helper_urls_and_unsafe_remote_names_are_refused_at_init` |
| S-5 | low | `custodian-cli` file reads | credential, operator policy and pinned roots read without checking regular-file, link or mode | **fixed here**: `read_checked`; credential files must have no group or other access, policy and roots must not be group or other writable; test `credential_policy_and_roots_files_must_be_regular_and_not_loosely_permissioned` |
| S-3 | low | `custodian-worker/src/sandbox.rs` | process-group kill after reap could in principle hit a recycled id | accepted: the PID namespace and `--die-with-parent` are the primary mechanism; very low likelihood |
| S-4 | low | `sandbox.rs` | `ro_mounts[].host` only required to be absolute | accepted: callers are internal; harden when a second caller exists |
| S-6 | low | `custodian-cli/src/authority.rs` | credential stored as one unsalted SHA-256 | accepted: safe only for high-entropy tokens; the 32-byte minimum and `head -c 48 /dev/urandom` instruction are the control (documented) |
| S-7 | info | `custodian-corpus/src/secret.rs` | hand-rolled HMAC although `hmac` is a dependency; pads not zeroized | accepted (tested against RFC 4231); tidy up later |
| S-8 | low | `custodian-lifecycle/src/feed.rs` | `DirFeed::put` fixed temp name and no directory fsync | accepted: public data, retry-safe; replace before a real destination uses it |
| S-9, S-10 | info | slicing of derived strings; `RemoteSigner` does not verify the returned signature | accepted: the exporter self-checks every ledger signature; consumers verify projections |

### 5.2 OWASP-style review (`owasp-review`)

| Area | Result |
| --- | --- |
| Authentication and access control | pass for the CLI (roles re-derived from the policy, single failure code, validity window, structural limits for agents and services). The App listener, signer process and network authentication do not exist: **not assessable** |
| Business logic: budgets, retries, duplicate dispatch | pass on code and C12 tests |
| Injection and unsafe execution | pass (S-1, S-2 fixed) |
| Deserialization and validation | pass: strict, size-capped, closed schemas; errors never echo input |
| Cryptography and keys | pass by design (Ed25519, domain separation); key management in production **not assessable** (no key exists); operating limits R-4, R-5, R-6 |
| Data exposure | pass: redacted `Debug`, fixed reason codes, allowlisted projections, canary tests (`c12_leakage.rs`) |
| SSRF and egress | worker egress denied in the namespace (CI evidence); the only outbound code is git to the ledger remote, operator-configured |
| Resource consumption | pass on code (quotas, bounded output, bounded queue and submissions); no cgroups or seccomp (HG-5) |
| Logging and audit | pass by design; audit is an append-only outbox with checkpoints |
| LLM and agent surface | an agent can only `request` (structural); automation cannot approve, clear, retire, rotate or publish. Tracked developer tooling is a separate hygiene finding below |
| Supply chain and CI | pass for CI and audit; no update tool, SAST or fuzzing (informational) |

| ID | Sev | Finding | Disposition |
| --- | --- | --- | --- |
| AS-1 | low | `.mcp.json` runs `npx @playwright/mcp@latest`: an unpinned package fetched into developer environments | open (P4): pin or remove before publication; maintainer |
| AS-2 | low | `.claude/settings.json` hooks run repo-resolved Node helpers (with a fallback to `<repo>/dist`), and the helpers hard-code a home path | open (P4): remove the fallback and the allow rules, or exclude `.claude/` from the published tree; maintainer |

### 5.3 Scorecard

Remote assessment: **not assessable** (private repository; needs a token and network, not requested). Local run:
Pinned-Dependencies 10, Token-Permissions 10, Dangerous-Workflow 10, Vulnerabilities 10; Security-Policy 4,
License 0, SAST 0, Dependency-Update-Tool 0, Fuzzing 0, Binary-Artifacts 0 (untracked build output only).
Informational; no remote check (branch protection, code review, signed releases, CI tests) could be assessed.

## 6. Gap register

Disposition vocabulary: **fixed here**, **accepted** (with the rationale and the compensating control), or
**blocker** (with the owner role and what closes it). IDs: `HG-n` are the gaps handed over by earlier issues;
`R-n` were found by C12.

### 6.1 Handed over

| ID | Gap | Disposition |
| --- | --- | --- |
| HG-1 | C9: a contamination recorded after the last release-time eligibility check still lets that release go out | **accepted, bounded, tested.** It cannot be closed locally (bytes cannot be un-sent). Guaranteed and asserted: the obligation is durable and blocks all later use at once; `feed_ref` refuses until it is published; the next feed envelope revokes the release for any syncing consumer; a consumer that stops syncing sees `Stale` when the feed head expires (`c12_revocation.rs`). Operating rules: publish the feed immediately after a contamination, keep `ttl_secs` short (incident-response.md section 3) |
| HG-2 | C8/C11: `PublicProjection` has no destination field, so a consumer cannot verify destination binding without catalog access | **blocker (design recorded)**: schema major 2 with a signed `destination`, new domain tag (ADR 0102). Until then destination binding is enforced by the bridge service and the signed publication decision in the private ledger, and every description says so. Owner: engineering; maintainer approves the schema |
| HG-3 | C11: nothing writes consumed legacy budget units into the runtime store | **blocker (not small, design recorded)**: migration 0005, `budget_imports`, extended invariants, `legacy apply` (ADR 0102). No legacy population may be handed off before it exists. Owner: engineering |
| HG-4 | C10: no daemon, listener or queue consumer; no isolated signer process (`signer_unavailable`); no feed destination, ledger remote or real operator policy; no retention for pending submissions and the intake queue; ADR 0081 narrowed C9 (automation cannot publish the feed) | **blocker for deployment** (not for publishing code). C12 supplies the human provisioning plan and a proposed retention schedule that needs approval (`docs/deployment-runbook.md`, `docs/backup-recovery.md` section 5). Retention deletion tooling is not implemented. The ADR 0081 narrowing is accepted: publishing the feed is a human operator act. Owner: engineering, then operations |
| HG-5 | C6: no seccomp, no cgroup controllers; no production host proven; no engine-side `worker-result/1`; verification expires after 3600 s | **seccomp and cgroups: accepted** with a recorded risk decision required at deployment (runbook step 5); **production host: human**; **engine side: blocker** (engine repositories); **expiry: blocker for a daemon** (it must re-run the self-check; documented). Owner: engineering, operations |
| HG-6 | C5: commitment key in the same root as data; single writer per root, no cross-process lock; tamper-evident not tamper-proof | **accepted** with controls: exactly one control-service instance per root (a deployment rule, runbook section 2); key backed up separately; whoever holds the storage owner account can rewrite a sealed epoch consistently, which the external checkpoints make detectable, not impossible. Owner: maintainer |
| HG-7 | C3: no HTTP transport, RS256 signer or listener; the webhook must stay inactive | **blocker for intake**; the runbook keeps the webhook Inactive until every checklist item exists; enabling is a human act. Owner: engineering, maintainer |
| HG-8 | C7: Git history is mutable; checkpoints need an independent copy; signing key and pinned roots not created (must be generated on the signer host) | **human provisioning**, specified in runbook step 3 and 4; the independent copy is demonstrated to be the thing that shows a rolled-back ledger (`c12_keys_and_ledger.rs`). Owner: maintainer |
| HG-9 | C8: policy values in tests are placeholders | **human**: a reviewed disclosure policy and activation are runbook step 8; nothing is released without them. Owner: maintainer |
| HG-10 | C2/C7: no second-language canonicalization implementation | **fixed here**: `verify_golden.py` (standard library only, written from ADR 0004, with negative controls) reproduces all 10 golden vectors and runs in CI. Not covered: Ed25519 verification by a second implementation (ledger.md documents a manual OpenSSL check; consumer-side verification is benchmarks' own) |

### 6.2 Found by C12

| ID | Finding | Evidence | Disposition |
| --- | --- | --- | --- |
| R-1 | Restore behind the ledger with **no newer copy** has no executable procedure: the runbook said to `lifecycle retire` the affected epochs, but a write-blocked store refuses that (`store_needs_reconcile`) and `clear-reconcile` refuses (`store_behind_ledger`) | `c12_restore_drill.rs` | runbook **corrected here**; **blocker** for the recovery itself: a new store and ledger lineage (ADR 0101). Owner: engineering |
| R-2 | **Unrecoverable window**: spend after the last export is invisible to the ledger; restoring a backup that predates it passes `startup_check`, and the same request can run again | `spend_after_the_last_export_is_the_documented_unrecoverable_window` | **accepted with operating rules** (export after every approval and before dispatch; backup at least as often as the accepted loss; recovery point is a maintainer decision); deferred code gate: acknowledge `reservation.created` before `start` (ADR 0101). Owner: maintainer, engineering |
| R-3 | No production code builds an `ExecutionRecord` or `InternalReceipt` from a `DispatchReport`; the worker result carries only a roster and the aggregates artifact has no producer | `c12/mod.rs::Pipe::assemble` (test-only) | **blocker** with HG-5. Owner: engineering |
| R-4 | **Key revocation makes the whole history untrusted** until it is re-issued under a new key; there is no re-issue tool, and the control plane will not start meanwhile | `revoking_the_signing_key_makes_its_history_untrusted_until_it_is_reissued` | **blocker** for compromise recovery; containment steps documented. Owner: engineering |
| R-5 | Key events with equal timestamps fail closed (ordering by issue time then record id; a retire at the publish record's own time invalidates it) | `publishing_and_retiring_in_the_same_second_fails_closed_...` | **accepted** with a procedure (distinct times, backup-recovery.md 7.2) |
| R-6 | A key signs only records issued at or after its start: a backlog exported after the switch, or the first release under an older activation, is refused (`signing_refused`); and a disclosure service built with pinned roots only cannot use a rotated key | `events_still_pending_when_the_signer_switches_...`, `rotation_with_a_key_valid_only_from_now_...`, `a_release_signed_by_a_rotated_key_...` | **accepted** with a procedure (drain first; backdate `effective_at` to the oldest record; build verifiers from the walked keyring; pin the new key in consumers first) |
| R-7 | Every state-changing command walks and verifies the whole ledger, so latency grows with ledger size (about 1 ms empty, about 30 ms at a few hundred records, with an in-memory backend); a Git backend adds a fetch | `docs/measurements.md` | **accepted** for pilot volumes; follow-up: cache a verified prefix. Owner: engineering |
| R-8 | Five store fault points had no injected-crash test (lease renewal, queue lease, queue complete, installation removal, submission cancel) | `c12_crash_intake.rs`; coverage rule in `c12_crash_windows.rs` | **fixed here** |
| R-9 | S-1, S-2, S-5 above | unit and binary tests | **fixed here** |
| R-10 | Dependency audit was not in CI and no tool config existed | `deny.toml`, `.github/workflows/ci.yml` | **fixed here** (pinned cargo-deny 0.20.2, first CI run pending) |
| R-11 | Tracked developer tooling and personal data (AS-1, AS-2, author email, home path) | section 5.2 | **blocker for publication** (P4). Owner: maintainer |
| R-12 | The AGENTS.md status line named three crates although the workspace has twelve | review | **fixed here** (one sentence) |

## 7. Human decisions required

1. License (P1): Apache-2.0, MIT, MPL-2.0, AGPL-3.0, or remain unlicensed. Consider contributors, the engine and
   benchmark repositories, patent grants and whether network-service use should be copyleft. Not chosen here.
2. Incident owner, backup and the monitored private reporting route (P2); GitHub private vulnerability
   reporting.
3. What to do about the author email, the home path and `.claude/` and `.mcp.json` before publication (P4):
   scrub history, publish from a fresh squashed export, or accept.
4. Recovery point, retention values, key backup choice, one person holding requester and approver, the isolation
   risk decision (deployment runbook section 5).
5. Whether to implement R-1, R-2's code gate, R-4 and HG-2, HG-3 before or after the first deployment.
6. Enabling the App webhook, ever (only when a server and every checklist item exist).

## 8. Results of the final checks

Run on the final change, locally (macOS arm64, rustc 1.98.1). The CI result for the merged commit, including
`worker-isolation` and the first `dependency-audit` run, is on the pull request and is the only evidence for
those two.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | pass |
| `cargo test --workspace --locked --no-fail-fast` | 629 passed, 0 failed |
| `python3 crates/custodian-contracts/testdata/verify_golden.py` | 10 of 10 vectors reproduced |
| `cargo deny --locked check` | advisories ok, bans ok, licenses ok, sources ok |
| gitleaks on the working tree (excluding `target/`) and on `origin/main..HEAD` | no leaks |
| gitleaks on full history (54 commits) | 1 finding, the synthetic constant described in section 4 |
| Diff pattern sweep for private-key headers and token prefixes | none |
