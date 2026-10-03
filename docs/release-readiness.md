# Operational and code-only public-release readiness (C12, refreshed by S6)

Date of the C12 review: 2026-10-03 (base `origin/main` at C10, `98e393a`, plus the C12 change). Refreshed on
2026-10-03 by S6 (issue 33, epic 27) on top of S1 to S5. Reviewer: the implementation, run as a report-only
application of the repository's `.agents/skills` procedures (`conformance-controls`, `run-lifecycle-review`,
`isolation-verify`, `disclosure-review`, `agent-surface-review`, `incident-triage`, `protected-asset-sweep`,
`publication-readiness`, `scan-secrets-in-history`, `dependency-audit`, `sast-sweep`, `owasp-review`,
`scorecard-check`). This repository is maintained by the Redact Secret project: this record is
project-maintained evidence, **not independent validation**. A signature or a ledger entry attests origin,
binding and history of project-maintained records, never that a result was correct. Publishing the source would
not by itself disclose, or grant access to, the runtime database, the private ledger, protected corpora, keys,
credentials or operational history, provided the exclusions below hold; the design does not rely on the source
being private, and publishing code does not change authorized data use.

> **Every claim in this record is functional verification on public synthetic data, with test-generated keys.
> None of it is an independent protected evaluation.** No server, host, cloud resource, production key, ledger
> write, webhook activation, protected corpus or protected run exists or was used.

## Completion report

Facts only, in four parts. Detail and evidence paths are in the sections that follow.

### 1. Implemented and verified (and where it ran)

| Area | Evidence | Where it ran |
| --- | --- | --- |
| Contracts, store (migrations 0001 to 0008), protected storage, worker dispatcher, ledger, disclosure, lifecycle, bridge, operator CLI, signer process, daemon | the whole test suite (see section 8 for counts) | local (macOS arm64) and CI (Linux) |
| Real bubblewrap isolation tests | `custodian-worker/tests/linux_isolation.rs`, `custodian-daemon/tests/linux_pipeline.rs` | **CI only** (`worker-isolation`, Linux); they skip locally and prove nothing there |
| The full synthetic flow: signed request, approval, reservation, engine inside the real sandbox, isolated signer over a Unix socket, local Git ledger, destination-bound v2 projection, `custodian-verify` and the bridge consumer, contamination, rejection and the downstream re-evaluation trigger | `custodian-daemon/tests/full_flow.rs`, workflow `full-synthetic-flow.yml` | unsandboxed variant: local and CI; real-sandbox variant: **CI only** |
| R-1: restore with no newer copy (loss plan and audited acceptance, ADR 0130) | `custodian-cli/tests/s6_recovery.rs`, `custodian-store/tests/loss.rs` | local and CI, against doubles for the sandbox and a local Git or in-memory ledger |
| R-4: ledger re-issue under a new key, R-5 and R-6 enforced (ADR 0131) | `custodian-ledger/tests/reissue.rs`, `custodian-cli/tests/s6_key_revocation.rs` | local and CI, test keys, in-process signer |
| Deployment examples with a placeholder scanner; units, layout and proxy examples | `custodian-daemon/tests/deploy_examples.rs` | local and CI |
| Dependency audit, workflow lint, history and tree secret scans | section 2 | local (the dependency audit also in CI) |

### 2. Not yet verified because there is no server

- Isolation on a production host (`run_self_check` on the real host and image), and the egress filtering around it.
- Any real signing key, the signer on its own uid or host, the out-of-band pin, a rehearsal of rotation or
  compromise with a real signer.
- A usable private-ledger remote with a writer deploy key, the independent checkpoint copy, and the access checks.
- Backup and restore on a host, encrypted protected storage, the retention schedule in operation.
- A feed destination and a consumer reading it over the network; TLS in front of the listener; the daemon under
  systemd with the hardening directives.
- The GitHub App, its key and webhook secret, a real delivery, a real Check; there is no HTTPS client.
- A real operator policy and credentials, a reviewed disclosure policy and its activation, a real sealed population.
- Real engines emitting `worker-result/1` and the aggregates artifact; a real protected run.
- Anything about the performance or availability of a deployment.

### 3. Manual setup and decisions needed before deployment

All of it is listed once, in dependency order, with who, evidence and the verifying document or command, in
[server-prerequisites-checklist.md](server-prerequisites-checklist.md). In short: incident owner and monitored
contact; recovery point and retention values; whether one person holds requester and approver; the isolation risk
decision; host, uids, encrypted storage and backup; the signer host, on-host key generation and the out-of-band
pin; the ledger remote (its current contents must be resolved first), the writer deploy key and the independent
checkpoint copy; operator policy and credentials; the feed destination; the disclosure policy and activation; the
first sealed population; rehearsals; private vulnerability reporting at publication; the GitHub App last; and the
explicit human approvals for the first protected run. The benchmarks authority cutover is a separate later
decision.

### 4. Remaining issues and the exact next-work order

1. **Engines** (issue 37 and the engine repositories): emit `worker-result/1` with `private-custodian.aggregates/1`
   (ADR 0127; HG-5 and R-3). Nothing real can be released before this.
2. **Decide how GitHub is reached** (HG-7): an HTTPS client behind its own ADR, or keep intake off and use the operator CLI
   path for the first deployment. The webhook stays Inactive either way until the checklist is done.
3. **Hosting feasibility** (epic 40, the Lambda MicroVM proofs of concept) informs the host choice for checklist
   section 1; it does not replace the recovery verification done here.
4. **Resolve the private-ledger repository** (checklist section 4): it is private but not empty.
5. **Publication gate** (separate from deployment): the clean one-commit snapshot excluding `.claude/` and
   `.mcp.json` (P4), enabling private vulnerability reporting at publication (P2), and re-reading the CI results
   for the exact commit to publish (P3, P5).
6. **When a server exists:** the checklist sections 0 to 12 in order, rehearsals first, the GitHub App last.
7. **Separate decision:** the benchmarks authority cutover (checklist section 13).
8. **Engineering follow-ups, none blocking:** a verified-prefix cache for the ledger walk (R-7); an operator
   command to publish and retire a key for planned rotation (today only the ledger library and tests write those
   events); a new-lineage fallback for a diverged store or an unremovable forged ledger record; replace
   `DirFeed::put` before a real destination uses it (S-8).

## 1. Verdict

| Question | Answer |
| --- | --- |
| Can the repository be made public now? | **NO-GO** |
| Can a protected run be done now (deployment)? | **NO-GO** |
| Are the C12 synthetic validation, the restore drill, the S6 recovery procedures and the full synthetic flow done? | yes, on public synthetic data, with the limits in section 3; **none is an independent protected evaluation** |

Nothing here changes repository visibility, chooses a license, publishes anything or provisions anything.

### Blockers before publication, by owner role

| # | Blocker | Owner role |
| --- | --- | --- |
| P1 | **License**: MIT, decided and added by the maintainer ([ADR 0103](adr/0103-solo-maintainer-operating-decisions-license-reporting-and-publication.md)). **Closed** | maintainer |
| P2 | **Reporting route and incident owner**: decided in ADR 0103 and documented in SECURITY.md (GitHub private vulnerability reporting, no email; owner is the maintainer). Remaining step: enable private vulnerability reporting when the repository becomes public (not available while private) | maintainer |
| P3 | **Isolation proof on a Linux runner for the release commit**: the `worker-isolation` and `full-synthetic-flow` CI jobs (`CUSTODIAN_REQUIRE_ISOLATION=1`) are the only isolation evidence; macOS skips. Their green result for the commit to be published is the evidence | maintainer (reads CI) |
| P4 | **Personal data in history and developer tooling in the tree**: decided in ADR 0103: no history rewrite; publish a clean one-commit snapshot that excludes `.claude/` and `.mcp.json` and uses the GitHub noreply address. The export itself is done at publication, so this stays a blocker until then | maintainer |
| P5 | Gate items 5 to 7 re-run green on the exact commit to publish, including `dependency-audit` in CI (added here; it passed on the pull request) | maintainer / CI |

### Blockers before any protected run, by owner role

| # | Blocker | Owner role |
| --- | --- | --- |
| D1 | The service daemon, listener, queue consumer and request-to-projection pipeline exist in code (S5, `docs/daemon.md`) but are **not deployed**; no HTTPS client is built; no signer host, feed destination, usable ledger remote or operator policy exists (HG-4, HG-7) | engineering, operations |
| D2 | Worker engines do not yet emit `worker-result/1` with `private-custodian.aggregates/1` (the synthetic fixture does); production code now assembles the execution record and internal receipt from a dispatch report (S5, R-3) (HG-5) | engineering with the engine repositories |
| D3 | **Closed in code (S6):** restore with no newer copy (R-1, ADR 0130) and key compromise (R-4, ADR 0131) have executable, audited procedures, verified on synthetic data. Still open: a rehearsal on the real host (checklist 3.5, 9.2) | operations |
| D4 | Real disclosure policy, operator policy, keys, pinned roots, ledger deploy key, independent checkpoint, encrypted storage, monitored contact: all human provisioning in `docs/deployment-runbook.md` (HG-8, HG-9) | maintainer, operations |
| D5 | Legacy consumed-budget write (HG-3) is implemented (S3, ADRs 0115 and 0118) but no real extract has been applied. Destination binding (HG-2) is implemented in code (S4, ADR 0119 to 0122) and the daemon pipeline releases the v2 projection (S5, exercised by `full_flow.rs`); what remains is benchmarks adopting `require_destination_binding()` and authorizing the signing key for the v2 domain | engineering, benchmarks owner |

## 2. Evidence: what ran, where

| Check | Where it ran | Result |
| --- | --- | --- |
| `cargo fmt --all --check` | local (macOS arm64, rustc 1.98.1) and CI | pass locally |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | local and CI | pass locally |
| `cargo test --workspace --locked --no-fail-fast` | local (macOS arm64) after S6; CI (Linux) for the pull request | 916 passed, 0 failed, 0 ignored locally; CI result in section 8 |
| Real bubblewrap isolation tests, including the engine inside the sandbox in the full flow | **CI only** (`worker-isolation` and `full-synthetic-flow`, Linux); skipped on macOS | not assessable locally; see P3 and section 8 |
| C12 suite (`crates/custodian-cli/tests/c12_*.rs`) | local and CI, deterministic, bounded | section 2.1 |
| Second-implementation golden vectors (`verify_golden.py`) | local; CI step added | 10 of 10 vectors reproduced; 11 of 11 plus the destination-binding shape check after S4 |
| `cargo deny --locked check` (cargo-deny 0.20.2, RustSec database fetched 2026-10-03) | local at C12 and again at S6; CI job `dependency-audit` | advisories ok, bans ok, licenses ok, sources ok (S6 run) |
| `actionlint` on every workflow, including `full-synthetic-flow.yml` | local | no findings |
| `cargo audit` | not installed | not run (cargo-deny reads the same RustSec database) |
| gitleaks 8.30.1, full history, all refs (95 commits at S6), redacted | local | 11 findings, all triaged as intentional synthetic fixtures (section 4); at C12 it was 54 commits and 1 finding |
| gitleaks 8.30.1 on the working tree (`--no-git`, redacted, build output excluded from the reading) | local | 5 findings in 2 tracked files, the same synthetic fixtures (section 4); the others were in untracked `target/` |
| trufflehog 3.97.6 on a full-history patch and the tree, `--no-verification` | local | 2 unverified findings (the same synthetic constant), 0 in the tree |
| Pattern sweep (private-key headers, token prefixes, JWTs, 64-hex near key words, sensitive extensions ever committed, protected-data paths) | local | no real secret or protected path |
| OpenSSF Scorecard 5.5.0 `--local` | local at C12; **not re-run at S6** | **not assessable** remotely (private repository, token and network); the C12 local score stands for the checks that run locally |
| Static review (unsafe, process execution, paths, races, panics, secrets in logs, comparisons) and OWASP review | local reading plus ripgrep | section 5 |

Findings from tools were triaged, never printed with their matched text.

### 2.1 Test results

C12: `cargo test --workspace --locked --no-fail-fast` on macOS arm64 passed 629 tests (37 new in C12). After S6 the
same command passes 916 passed, 0 failed, 0 ignored on macOS arm64 (rustc 1.98.1); the S6 additions are `custodian-store/tests/loss.rs`,
`custodian-ledger/tests/reissue.rs`, `custodian-cli/tests/{s6_recovery,s6_key_revocation}.rs`,
`custodian-daemon/tests/{full_flow,deploy_examples}.rs` and one workflow check. Nothing in the suite sleeps to wait
for a race: concurrency tests count outcomes, crash tests use deterministic fault injection. On this macOS host
the Linux isolation tests log `ISOLATION-TEST-SKIPPED` and verify nothing, and the real-sandbox variant of the
full flow does the same; that evidence is the CI jobs (P3).

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
| S6 R-1: the previously blocking restore (no newer copy), recovered by an explicit audited acceptance; diverged store, healthy store, tampered ledger | `s6_recovery.rs`, `custodian-store/tests/loss.rs` |
| S6 R-4, R-5, R-6: revoke, re-issue under a new key, the old lineage kept and marked, clear, start again; a stolen-key forgery is not laundered | `s6_key_revocation.rs`, `custodian-ledger/tests/reissue.rs` |
| S6 full flow, request to consumer rejection and re-evaluation trigger; hostile negatives at the edge and the consumer | `custodian-daemon/tests/full_flow.rs` and the `full-synthetic-flow` job |
| S6 deployment examples: no real-looking value, real parsers accept them, units keep hardening | `custodian-daemon/tests/deploy_examples.rs` |
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
| Restart and recovery: state, budget, audit consistent; no double publication | tested | `c12_crash_windows.rs`, `c12_restore_drill.rs`, `s6_recovery.rs`, `custodian-lifecycle/tests/feed.rs` |
| Recovery from a restore with no newer copy, and from a key compromise | tested (synthetic) | `s6_recovery.rs`, `s6_key_revocation.rs`; not rehearsed on a host |
| Redaction: canaries never appear in logs, errors or public output | tested | `c12_leakage.rs` (operator credentials, protected bytes, hostile worker text, signing seed; every CLI role and command, `Debug` text, ledger, feed, projection, outbox and raw database files), `custodian-intake/tests/app.rs::installation_token_is_scoped_cached_and_never_printed`, `webhook.rs::webhook_secret_must_be_long_and_is_never_printed`, `custodian-disclosure/tests/leakage.rs`, `custodian-corpus/tests/canary_leakage.rs` |
| Real isolation on the production host | **not assessable** | deployment step 5 |

## 4. Public-release gate (`publication-readiness`, SECURITY.md)

| # | Gate | Result | Evidence and note |
| --- | --- | --- | --- |
| 1 | History and assets reviewed | **pass** for secrets and protected data; **open** for P4 | section 2; every tool finding is an intentional synthetic fixture: PEM header lines with placeholder bodies used as negative inputs (`crates/custodian-daemon/src/github/jwt.rs`), a visibly synthetic App token constant (`crates/custodian-daemon/src/github/testing.rs`) and the earlier replaced constant (`crates/custodian-intake/tests/app.rs`, commit `a30e40d3`); no sensitive extension or protected path was ever committed; personal data is P4 |
| 2 | Deployment material replaced with safe examples | **pass** | no hostnames, inventories, accounts or paths of a deployment in the tree; `deploy/examples/` is placeholders only and scanned by `deploy_examples.rs`; absolute paths in tests and docs are negative-test inputs or placeholders |
| 3 | Private reporting configured, route and owner documented | **documented; setting pending** (P2) | SECURITY.md and ADR 0103 name the route and the owner; enabling the setting happens at publication |
| 4 | License selected and added | **pass** (P1) | MIT: `LICENSE`, `Cargo.toml`, README; ADR 0103 |
| 5 | Isolation demonstrated by failure tests | **not assessable locally** (P3) | CI jobs `worker-isolation` and `full-synthetic-flow` are the evidence |
| 6 | Concurrency and recovery tests pass | **pass** (local, synthetic) | section 3 |
| 7 | Disclosure tests pass | **pass** (local, synthetic) | `custodian-disclosure/tests/*`, `c12_revocation.rs` |
| 8 | Keys: verification needs no private key; rotation and revocation described | **pass** with stated limits | `docs/ledger.md`, `docs/backup-recovery.md` section 7, ADR 0101, ADR 0131; R-4 now has a tool, R-5 and R-6 are enforced by it; planned rotation has no operator command (section 6.3) |
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
| HG-2 | C8/C11: `PublicProjection` has no destination field, so a consumer cannot verify destination binding without catalog access | **fixed in code (S4, issue 31, ADR 0119 to 0122)**: public projection major 2 carries `destination` in the signed payload under the new domain tag `private-custodian/v2/public-projection`; the release approval binds the v2 digest; a consumer verifies binding from the envelope alone (`destination_mismatch`); v1 stays verifiable and is labelled `destination_unbound`. Evidence: `custodian-contracts/tests/{destination,golden,schemas}.rs`, `testdata/verify_golden.py`, `custodian-ledger/tests/destination.rs`, `custodian-disclosure/tests/destination.rs`, `custodian-bridge/tests/destination.rs`. Synthetic data and test keys; project-maintained, not independent validation. **S6 update**: the production caller of `prepare_bound` exists (the S5 daemon pipeline) and `full_flow.rs` asserts the released projection is major 2 with the destination. **Remaining (deployment, not design)**: benchmarks adopting the checks, the signing key authorized for the v2 domain. Owner: engineering, benchmarks owner, maintainer |
| HG-3 | C11: nothing writes consumed legacy budget units into the runtime store | **code complete, not exercised on real data**: migration 0005 `budget_imports`, extended invariants, `legacy apply` (ADRs 0102, 0115, 0118). Contamination marks are not carried and must be recorded with `lifecycle report`. A real extract and maintainer review are still required before any handoff. Owner: maintainer |
| HG-4 | C10: no daemon, listener or queue consumer; no isolated signer process (`signer_unavailable`); no feed destination, ledger remote or real operator policy; no retention for pending submissions and the intake queue; ADR 0081 narrowed C9 (automation cannot publish the feed) | **daemon, listener, queue consumer and pipeline: implemented in code (S5, issue 32, ADRs 0123 to 0129), not deployed**; the isolated signer process landed in S2. Evidence: `crates/custodian-daemon/tests/{e2e,listener,consumer,pipeline,crash,scheduler,process}.rs` and `custodian-store/tests/pipeline.rs`, plus `linux_pipeline.rs` in the `worker-isolation` job (the real sandbox, Linux CI only). Functional verification on public synthetic data, not independent protected evaluation. **Still a blocker for deployment** (not for publishing code): feed destination, a usable ledger remote (the GitHub repository `redact-secret/private-ledger` exists but is not empty, see HG-8), real operator policy and every human provisioning step; they are all in `docs/server-prerequisites-checklist.md`. Earlier text follows.  C12 supplies the human provisioning plan and a proposed retention schedule that needs approval (`docs/deployment-runbook.md`, `docs/backup-recovery.md` section 5). Retention deletion tooling is implemented as `repair retention` (migration 0006, ADR 0117) with hard floors; the age values still need approval. The ADR 0081 narrowing is accepted: publishing the feed is a human operator act. Owner: engineering, then operations |
| HG-5 | C6: no seccomp, no cgroup controllers; no production host proven; no engine-side `worker-result/1`; verification expires after 3600 s | **seccomp and cgroups: accepted** with a recorded risk decision required at deployment (runbook step 5); **production host: human**; **engine side: blocker** (engine repositories); **expiry: blocker for a daemon** (it must re-run the self-check; documented). Owner: engineering, operations |
| HG-6 | C5: commitment key in the same root as data; single writer per root, no cross-process lock; tamper-evident not tamper-proof | **accepted** with controls: exactly one control-service instance per root (a deployment rule, runbook section 2); key backed up separately; whoever holds the storage owner account can rewrite a sealed epoch consistently, which the external checkpoints make detectable, not impossible. Owner: maintainer |
| HG-7 | C3: no HTTP transport, RS256 signer or listener; the webhook must stay inactive | **listener and RS256 App JWT signer implemented in code (S5, ADRs 0123, 0124)**, tested over a real loopback socket and an offline GitHub fake with a throwaway key (`tests/{listener,github,e2e}.rs`); **no HTTPS client is built** (`github_https_not_built`) and TLS termination is the deployer's proxy; the webhook stays Inactive. Functional verification on public synthetic data, not independent protected evaluation. **Blocker for intake** until deployed; earlier text: the runbook keeps the webhook Inactive until every checklist item exists; enabling is a human act. Owner: engineering, maintainer |
| HG-8 | C7: Git history is mutable; checkpoints need an independent copy; signing key and pinned roots not created (must be generated on the signer host) | **human provisioning**, specified in runbook step 3 and 4 and checklist sections 3 and 4; the independent copy is demonstrated to be the thing that shows a rolled-back ledger (`c12_keys_and_ledger.rs`) and is now an input to `repair accept-loss`. **S6 finding**: a read-only check showed `redact-secret/private-ledger` is private with no deploy key but **not empty** (it holds a different code tree on `main`), contrary to the brief; it cannot be the ledger remote as it stands. Owner: maintainer |
| HG-9 | C8: policy values in tests are placeholders | **human**: a reviewed disclosure policy and activation are runbook step 8; nothing is released without them. Owner: maintainer |
| HG-10 | C2/C7: no second-language canonicalization implementation | **fixed here**: `verify_golden.py` (standard library only, written from ADR 0004, with negative controls) reproduces all golden vectors (11 after S4, including the v2 projection and its destination-binding shape check) and runs in CI. Not covered: Ed25519 verification by a second implementation (ledger.md documents a manual OpenSSL check; consumer-side verification is benchmarks' own) |

### 6.2 Found by C12

| ID | Finding | Evidence | Disposition |
| --- | --- | --- | --- |
| R-1 | Restore behind the ledger with **no newer copy** had no executable procedure: a write-blocked store refuses `lifecycle retire` (`store_needs_reconcile`) and `clear-reconcile` refuses (`store_behind_ledger`) | `c12_restore_drill.rs` (the dead ends), `s6_recovery.rs` (the way out), `custodian-store/tests/loss.rs` | **fixed in code (S6, ADR 0130), verified on synthetic data**: `repair loss-plan` and `repair accept-loss` adopt the ledger's acknowledged tail byte for byte, raise budgets to the ledger's figures (saturating, never lowering), retire affected epochs and record an explicit loss acceptance, with exact confirmations including the independent checkpoint. **Limits** (ADR 0130): spend never exported, the requests of the lost window (their cost is carried by the budgets), feed obligations (re-recorded by hand), a diverged store (`lineage_diverged`, refused); the new-lineage fallback is not implemented. **Not rehearsed on a host.** Owner: operations (rehearsal) |
| R-2 | **Unrecoverable window**: spend after the last export is invisible to the ledger; restoring a backup that predates it passes `startup_check`, and the same request can run again | `spend_after_the_last_export_is_the_documented_unrecoverable_window` | **accepted with operating rules** (export after every approval and before dispatch; backup at least as often as the accepted loss; recovery point is a maintainer decision); the code gate is implemented for dispatch (ADR 0116: `store_export_pending`, worker export barrier, exposure acknowledgement); it does not cover spend before the gate or loss of the ledger itself. Owner: maintainer, engineering |
| R-3 | No production code builds an `ExecutionRecord` or `InternalReceipt` from a `DispatchReport`; the worker result carries only a roster and the aggregates artifact has no producer | `c12/mod.rs::Pipe::assemble` (test-only) | **closed in code (S5, ADRs 0126, 0127)**: `custodian-daemon/src/pipeline/assemble.rs` builds both from the settled attempt, never a clean receipt after a crash, refuses on drift (`tests/{pipeline,crash,e2e}.rs`, against the synthetic engine fixture). **Still a blocker with HG-5**: real engines do not emit the aggregates artifact yet. Owner: engineering with the engine repositories |
| R-4 | **Key revocation makes the whole history untrusted** until it is re-issued under a new key; there was no re-issue tool, and the control plane will not start meanwhile | `revoking_the_signing_key_makes_its_history_untrusted_until_it_is_reissued` (the consequence, unchanged), `s6_key_revocation.rs`, `custodian-ledger/tests/reissue.rs` | **fixed in code (S6, ADR 0131), verified on synthetic data with test keys**: `repair revoke-key`, `reissue-plan`, `reissue-ledger` re-attest the history with superseding records signed by the new pinned key, nothing rewritten, the old lineage kept and marked (`revoked_superseded`), corroborated against the store, the walker walks both lineages, the control plane starts again after the audited `clear-reconcile`. **Limits**: a correction-chain record and a second revoked key are not re-issued; a forgery made with the stolen key stays blocking (new-lineage fallback not implemented); public projections already signed by the revoked key are not re-signed (consumers reject them, the feed carries `key_compromise`). **Not rehearsed with a real signer.** Owner: operations (rehearsal) |
| R-5 | Key events with equal timestamps fail closed (ordering by issue time then record id; a retire at the publish record's own time invalidates it) | `publishing_and_retiring_in_the_same_second_fails_closed_...`, `reissue.rs::the_procedure_constraints_are_enforced_by_the_tool` | **accepted** with a procedure (distinct times, backup-recovery.md 7.2); **enforced by the tool** for the revocation step (`reissue_same_second_key_event`). Planned rotation still has no operator command (S6-2) |
| R-6 | A key signs only records issued at or after its start: a backlog exported after the switch, or the first release under an older activation, is refused (`signing_refused`); and a disclosure service built with pinned roots only cannot use a rotated key | `events_still_pending_when_the_signer_switches_...`, `rotation_with_a_key_valid_only_from_now_...`, `a_release_signed_by_a_rotated_key_...` | **accepted** with a procedure (drain first; backdate `effective_at` to the oldest record; build verifiers from the walked keyring; pin the new key in consumers first); **enforced by the tool** for re-issue (`reissue_new_key_not_valid_for_history` when the new key starts after the oldest record to re-attest) |
| R-7 | Every state-changing command walks and verifies the whole ledger, so latency grows with ledger size (about 1 ms empty, about 30 ms at a few hundred records, with an in-memory backend); a Git backend adds a fetch | `docs/measurements.md` | **accepted** for pilot volumes; follow-up: cache a verified prefix. Owner: engineering |
| R-8 | Five store fault points had no injected-crash test (lease renewal, queue lease, queue complete, installation removal, submission cancel) | `c12_crash_intake.rs`; coverage rule in `c12_crash_windows.rs` | **fixed here** |
| R-9 | S-1, S-2, S-5 above | unit and binary tests | **fixed here** |
| R-10 | Dependency audit was not in CI and no tool config existed | `deny.toml`, `.github/workflows/ci.yml` | **fixed here** (pinned cargo-deny 0.20.2; the CI job passed on the pull request) |
| R-11 | Tracked developer tooling and personal data (AS-1, AS-2, author email, home path) | section 5.2 | **blocker for publication** (P4). Owner: maintainer |
| R-12 | The AGENTS.md status line named three crates although the workspace has twelve | review | **fixed here** (one sentence) |

### 6.3 Found or confirmed by S6

| ID | Finding | Evidence | Disposition |
| --- | --- | --- | --- |
| S6-1 | The GitHub repository `redact-secret/private-ledger` is private with no deploy key but **not empty**: `main` holds three commits and a code tree, not ledger records | read-only `gh` calls on 2026-10-03; nothing was changed | **human decision** before any ledger work (checklist section 4). Owner: maintainer |
| S6-2 | No operator command publishes or retires a signing key (planned rotation, backup-recovery.md 7.2); only the ledger library and tests write those key events. Revocation has one (`repair revoke-key`) | `custodian-ledger/tests/signing.rs`, `c12_keys_and_ledger.rs` | **gap, non-blocking** for a first deployment with one key; proposed follow-up, not covered by an existing issue (reported to the orchestrator). Owner: engineering |
| S6-3 | `repair accept-loss` trusts the operator to read the independent checkpoint honestly; a ledger rewritten consistently with that copy would be adopted | ADR 0130 | **accepted**; a second independent copy would reduce it. Owner: maintainer |
| S6-4 | gitleaks flags intentional synthetic fixtures (PEM header negatives, a synthetic App token constant) | section 2 | **accepted**; any scan of this tree must triage them as synthetic. No allowlist file was added |
| S6-5 | The migration list moved to eight; a database at an older schema opens and migrates, and `provision_tx` tolerates a missing `budget_recoveries` table only for such a database | `custodian-store/tests/{migrations,legacy_import}.rs` | **fixed here** (small compatibility check) |
| S6-7 | A timing race in an S5 test: the listener replies 503 `busy` first and logs after, and the test asserted the log immediately; it failed once on a loaded CI runner | CI run of PR 48 | **fixed here** (the test polls for the log line, 5 s; production code unchanged) |
| S6-6 | The two configuration examples that lived in `docs/` moved to `deploy/examples/`; ADR 0128 still names the old path | `deploy/examples/README.md` | **accepted**: accepted ADRs are not rewritten; the file names are unchanged |

## 7. Human decisions required

Decided by ADR 0103: license (MIT), reporting route and incident owner (P1, P2), the clean-snapshot publication
and the author-address handling (P4), and one person holding requester and approver in solo-maintainer mode.

Still open, each with its owner and place in [server-prerequisites-checklist.md](server-prerequisites-checklist.md):
recovery point, retention values, key backup choice and the isolation risk decision (section 0); what to do with
the non-empty `private-ledger` repository (section 4); whether the first deployment uses GitHub intake at all
given that no HTTPS client is built (11.5); enabling the App webhook, ever (only when a server and every other
item exist, 11.7); and the benchmarks authority cutover (section 13), which is a separate decision.

## 8. Results of the final checks

Run on the final S6 change, locally (macOS arm64, rustc 1.98.1), and on the pull request (CI, Linux). The
isolation evidence is the CI run (P3); it must be re-read for the exact commit that would ever be published.

| Check | Where | Result |
| --- | --- | --- |
| `cargo fmt --all --check` | local | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | local | pass |
| `cargo test --workspace --locked --no-fail-fast` | local | 916 passed, 0 failed, 0 ignored |
| `python3 crates/custodian-contracts/testdata/verify_golden.py` | CI step | unchanged by S6 (no contract change) |
| `cargo deny --locked check` | local | advisories ok, bans ok, licenses ok, sources ok |
| `actionlint` (all workflows) | local | no findings |
| gitleaks, full history (95 commits, all refs) | local, redacted | 11 findings, all intentional synthetic fixtures (section 4) |
| gitleaks, working tree | local, redacted | 5 findings in 2 tracked files, the same fixtures |
| OpenSSF Scorecard | not run at S6 | **not assessable** |
| CI on the pull request: `rust`, `dependency-audit`, `worker-isolation`, `synthetic-conformance` set, `full-synthetic-flow` | CI (Linux) | pull request 48 merges only when all of these pass; the real-sandbox full flow prints `FULL-FLOW-VERIFIED full_flow_real_bubblewrap` and the isolation tests print `ISOLATION-VERIFIED` on the Linux runner (the run on the final commit is the evidence; the first run of the `full-synthetic-flow` job exposed a log-after-reply race in the existing listener test `the_connection_cap_refuses_the_next_connection_and_recovers`, fixed here, test only) |
