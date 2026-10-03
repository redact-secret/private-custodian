# Server-prerequisite checklist: everything a human does after a server exists

Status: a checklist. **Nothing in it has been done**, because no server exists. The repository provisions no
host, account, key, ledger deploy key, domain, certificate, GitHub App setting, policy file, feed destination
or contact, and the follow-up work (epic #27, ADR 0110, ADR 0132) deliberately created none. This is the single
list of what a human must do once a server exists, in dependency order. It is the index; the detail lives in
the documents it points to ([deployment-runbook.md](deployment-runbook.md) for the narrative,
[operator-runbook.md](operator-runbook.md) for commands, [`deploy/examples/`](../deploy/examples/README.md) for
the shape of each configuration file).

This repository is maintained by the Redact Secret project. Every verification named below is
project-maintained evidence of functional behavior on public synthetic data, never an independent protected
evaluation, and a passing item here does not by itself authorize a protected run.

## How to use it

- Work in order. A later section assumes the evidence of the earlier ones exists. Stop at the first item that
  fails and treat it as a finding; do not look for a way around it.
- **Evidence to record** goes in the private operations log (identities, dates, fixed codes, public-key
  fingerprints; never a secret, a credential, a key, a corpus value or an address of the deployment). None of
  it is committed to this repository, CI or the private ledger.
- **Who** names a role, not a person. One person may hold several roles in solo-maintainer mode (ADR 0103); the
  separation is then procedural and the evidence says so.
- **Verified by** is the repository document or command that checks the item, so the claim is not just a tick.
- **Never** put a real value (hostname, address, key, token, credential, personal data) into this repository.
  `deploy/examples/` is scanned for that (`crates/custodian-daemon/tests/deploy_examples.rs`).
- A box is ticked only with the evidence recorded.

Roles: **maintainer** (the project maintainer and incident owner), **operations** (whoever administers the
host), **signer custodian** (whoever can reach the signer host), **second reviewer** (if one exists; otherwise
the review is recorded as procedural).

## Section 0. Decisions that need no server

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 0.1 | Name the incident owner and a backup. | maintainer | names/roles and the date, in the operations log | SECURITY.md; [incident-response.md](incident-response.md) section 1 |
| 0.2 | Decide the recovery point (the export-and-backup interval) and the accepted loss window. | maintainer | the numbers and the reasoning | [backup-recovery.md](backup-recovery.md) section 2; `deploy/examples/backup-retention.example.json` |
| 0.3 | Decide retention values (database backups, queue rows, claims, submissions, service logs). | maintainer | the approved values | backup-recovery.md section 5; `custodian repair retention` refuses ages below the code floors |
| 0.4 | Decide whether one person may hold both `requester` and `approver`. | maintainer | the decision; receipts then say the separation is procedural | operator-runbook section 8 item 9; ADR 0103 |
| 0.5 | Decide the isolation risk position for what is not provided (no seccomp filter, no cgroup controllers, a shared host with a human who is also root). | maintainer | a signed risk decision (ADR or log entry; ARCHITECTURE.md requires an ADR for privileged or shared-host execution) | [worker-isolation.md](worker-isolation.md) sections 8 and 9; deployment-runbook step 5 |
| 0.6 | Decide the key backup choice for the signing key (recommended: none). | maintainer | the decision | backup-recovery.md 7.1 |

## Section 1. Host and accounts

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 1.1 | Provision a dedicated host or account boundary for the zones that hold protected material. Linux x86_64 or aarch64, kernel 5.14 or later, unprivileged user namespaces permitted for the worker account, `bubblewrap` 0.8 or later and util-linux `prlimit` in standard locations. | operations | host class (OS, kernel, bubblewrap and util-linux versions) | worker-isolation.md section 8; `bwrap --version`, `command -v prlimit`, `uname -sr` |
| 1.2 | Create the dedicated OS users: `custodian-svc` (control service), `custodian-worker` (non-root, holds nothing), `custodian-signer`, `custodian-backup`, and the ledger-push identity. None shared with developer or CI accounts. | operations | the account list | deployment-runbook section 2; `deploy/examples/layout/custodian.tmpfiles.example` |
| 1.3 | Create the directories with the modes in the layout example (state 0700, protected 0700, policy and artifacts root-owned and not group or other writable, backups 0700). | operations | a listing of modes (no contents) | layout example; `deploy_examples.rs` checks the example's modes |
| 1.4 | Access review: no developer or CI account can read `state/`, `protected/`, `policy/`, `ledger-clone/` or the signer's directory. Disable unrelated services; log operator sessions outside the writer's control. | maintainer | the access review | deployment-runbook step 1; protected-storage.md |

## Section 2. Storage, encryption and backup

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 2.1 | Create an encrypted volume for `protected/` (full-disk or volume encryption; the repository provides none). | operations | that the volume is encrypted and where its key is held (not the key) | protected-storage.md "Retention and deletion"; deployment-runbook step 2 |
| 2.2 | Provision the protected root with the commitment key under `keys/` (the CLI never creates one). Back the commitment key up separately from corpus backups. | operations | where each backup lives | protected-storage.md; backup-recovery.md section 1 |
| 2.3 | Choose the backup target (separate disk or provider, encrypted at rest, restricted identity) and the schedule from 0.2. Install the backup wrapper and timer from the examples. | operations | target, schedule, retention | `deploy/examples/systemd/custodian-backup.*.example`; backup-recovery.md sections 1 and 5 |
| 2.4 | Choose the **independent checkpoint copy** (an offline note, or a mirror written by a different identity that neither the ledger writer nor the host root controls) and its review cadence. | maintainer | where it is and who writes it | ledger.md "Independent checkpoint and backup verification"; ADR 0054 decision 4 |
| 2.5 | Rehearse backup and restore on a copy with synthetic data: `integrity_check`, `verify_invariants`, mode 0600, `verify checkpoint`. | operations | date, backup id, the codes seen | backup-recovery.md section 3.2 |

## Section 3. Signer host and keys

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 3.1 | Prepare the signer host or namespace: a dedicated uid the control service cannot become, key and socket directories under a root-owned path whose ancestors the control uid cannot write. Install the signer unit from the example. | signer custodian | the host and uid facts | [signer.md](signer.md) "What the deployment must add"; `deploy/examples/systemd/custodian-signer.service.example` |
| 3.2 | Generate the Ed25519 root key **on the signer host** (never a developer machine or CI): 32 random bytes as 64 lowercase hex under `umask 077` into the key path, owned by the signer uid, mode 0600. Record only the public key. | signer custodian | the public-key fingerprint and the date | signer.md "Key provider contract"; `custodian-signer --config <file> --print-public-key` |
| 3.3 | **Pin the public key out of band**: the operator `roots.json`, the independent checkpoint location, and every consumer (benchmarks' own configuration). Never take a key from the ledger or the feed. | maintainer | where each pin lives | `deploy/examples/pinned-roots.example.json`; ledger.md; `deploy/examples/` parse test |
| 3.4 | Write the signer configuration (key id, socket path, `allowed_peer_uid`, purposes, `valid_from`, `not_after`) and start the signer; confirm the control service reaches it (`signer_unavailable` must not appear). | signer custodian | the configuration facts (no key) | `deploy/examples/signer-config.example.json`; `custodian-signer` fixed codes; daemon scheduler liveness |
| 3.5 | Rehearse planned rotation (backup-recovery 7.2) and the compromise procedure (7.4) on a **throwaway** key pair with synthetic data before relying on either. | maintainer | date and result | backup-recovery.md sections 7.2 and 7.4; `s6_key_revocation.rs` is the synthetic evidence, not a host rehearsal |

## Section 4. Private ledger

The GitHub repository `redact-secret/private-ledger` exists and is private. The S6 brief described it as empty with
no deploy key; a **read-only** check during S6 (2026-10-03, nothing was changed) found it private with **no deploy
keys**, but **not empty**: its default branch `main` holds three commits and a tree that looks like a different
code project (a Cargo workspace, schemas, policies, a docs tree), not ledger records. The custodian ledger
backend writes `records/...` and `quarantine/...` into the repository root and requires a clean lineage, so
**do not point `ledger_remote` at it as it stands**. Decide first (a maintainer decision, recorded): empty it or
replace it, or use another private repository, and only then continue. Verify its state yourself again at that
time; this repository does not change it.

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 4.1 | Resolve the finding above (the repository is not empty). Then confirm visibility is private and forking is disabled, and that the repository holds only an initial README stating it is project-maintained and private. | maintainer | the settings facts | ledger.md "Manual private-ledger provisioning"; `deploy/examples/ledger-remote.example.md` |
| 4.2 | Protect `main`: no force-push, no deletion, linear history, pushes only from the ledger-writer identity; alert on any other push. | maintainer | the protection facts | ledger.md checklist |
| 4.3 | Create the **writer deploy key**: scoped to this one repository, write access, not reused from the GitHub App, CI or a personal account. Store only in the ledger-writer identity's secret store. | maintainer, operations | the deploy-key id (not the key) | ledger.md item 4; the repository has no deploy key until this step |
| 4.4 | Grant read access to the minimum named operators; no benchmarks, CI or agent identity. | maintainer | the access list | ledger.md item 5 |
| 4.5 | Clone for the writer (`ledger_dir`) and record the first checkpoint in the independent copy after the first export. | operations, maintainer | the first `(seq, chain)` | `custodian verify checkpoint`; ledger.md "Independent checkpoint" |
| 4.6 | Access checks, repeated at every review: the writer cannot force-push or read other repositories; benchmarks, CI, App and agent identities cannot read the ledger; a non-writer push is rejected or alerts; the walk is clean with the pinned roots. | maintainer | the check results | `custodian verify all`; `GitBackend::audit_history`; ledger.md checklist |

## Section 5. Isolation on the production host

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 5.1 | Run the startup self-check (`run_self_check`) on the production host and image; the record must be `Verified` with every check passed. A container is not evidence; the self-check inside it is. | operations | the verification record, retained with the run audit | worker-isolation.md section 8; daemon `worker.sandbox: "bubblewrap"` (the daemon refuses to dispatch without it) |
| 5.2 | Run the isolation tests on the host with `CUSTODIAN_REQUIRE_ISOLATION=1` (`cargo test -p custodian-worker --test linux_isolation`, `-p custodian-daemon --test linux_pipeline`, `--test full_flow`); none may skip. | operations | the output markers `ISOLATION-VERIFIED`, `PIPELINE-ISOLATION-VERIFIED`, `FULL-FLOW-VERIFIED full_flow_real_bubblewrap` | `.github/workflows/ci.yml` (`worker-isolation`), `.github/workflows/full-synthetic-flow.yml` |
| 5.3 | Re-run the self-check after any change to the launcher, kernel, container runtime or allowlist, and within `verification_max_age_secs` (3600 s) in a long-running service. | operations | the schedule | daemon.md; worker-isolation.md |
| 5.4 | Apply host-level egress filtering as defense in depth (not implemented in the repository). Artifacts directory root-owned and not writable by the worker. | operations | the rule set facts | worker-isolation.md section 9 |
| 5.5 | Record the isolation risk decision of 0.5 against the actual host. | maintainer | the signed decision | deployment-runbook step 5 |

## Section 6. Operator policy, credentials and service configuration

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 6.1 | For each human, generate at least 32 random bytes into a new 0600 credential file; compute `custodian credential-digest --token-file F`. | each operator | issuance dates (not the credentials) | operator-runbook section 2.2 |
| 6.2 | Write the operator policy (identities, kinds, roles, digests, validity window) as a reviewed revision. Agents hold only `requester`; services only `requester` and `auditor`. Install it where it is not group or other writable. | maintainer, second reviewer | the policy revision and review note | `deploy/examples/operator-policy.example.json`; any `custodian` command refuses an invalid or expired policy (`operator_policy_invalid`, `operator_policy_expired`) |
| 6.3 | Write the CLI deployment configuration and the daemon configuration from the examples with real paths; keep them outside this repository. `custodiand check-config --config <file>` must pass with the GitHub mode still `disabled`. | operations | the check result (fixed codes) | `deploy/examples/cli-config.example.json`, `daemon-config.example.json`; daemon.md |
| 6.4 | Install the control-service unit from the example with the hardening directives intact. | operations | the unit diff against the example | `deploy/examples/systemd/custodiand.service.example` |

## Section 7. Feed destination

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 7.1 | Choose static hosting or an object store that meets the `FeedDestination` contract: create-if-absent, identical bytes accepted, different bytes refused, in-order writes, readable without any private access. Restrict write access to the control service's publishing identity. | maintainer, operations | the contract facts and the public URL | `deploy/examples/feed-destination.example.json`; lifecycle-and-revocation.md |
| 7.2 | Record the public URL and the feed id that consumers pin. | maintainer | the pins | benchmarks-integration.md |

## Section 8. Disclosure policy and population

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 8.1 | Replace the placeholder policy values used in tests with a reviewed disclosure policy (strata, minimum sizes, composition, budgets, destinations, freshness). | maintainer, second reviewer | the review note | [disclosure.md](disclosure.md); `custodiand check-config` parses the policy file named in the configuration |
| 8.2 | Import the approved activations (`policy import-activation` with the exact id and sequence). Set `release.policy_activation` and `required_activations` in the daemon configuration. | maintainer | activation ids and sequences | operator-runbook section 6.6 |
| 8.3 | Seal the first reviewed population (`begin_epoch`, `add_entry`, `seal`, `activate`). | maintainer | the epoch id and commitment | protected-storage.md |

## Section 9. Conformance on the production host (synthetic only)

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 9.1 | Run the full test suite with `CUSTODIAN_REQUIRE_ISOLATION=1` and one synthetic end-to-end scenario with a public conformance control, then `verify all`. | operations | the results | deployment-runbook step 9; ADR 0001 T4 |
| 9.2 | Rehearse a restore (backup-recovery 3.2) including the no-newer-copy path on a **copy** with synthetic data (`repair loss-plan`, `accept-loss`). | operations | date, codes | backup-recovery.md section 4 case C; operator-runbook 6.3 |
| 9.3 | Run the tabletop from incident-response.md section 9. | maintainer | the record | incident-response.md |

## Section 10. Reporting contact

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 10.1 | Enable GitHub private vulnerability reporting for this repository. It is not available while the repository is private; it is a step of the publication gate. | maintainer | the setting facts | SECURITY.md; ADR 0103 |
| 10.2 | Confirm the incident owner is reachable through a monitored route and that the backup owner knows the playbooks. | maintainer | the confirmation | incident-response.md |

## Section 11. The GitHub App and the webhook (last)

Only when **every** item in sections 0 to 10 is done. The webhook stays **Inactive** until then.

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 11.1 | Register the App under the intended account, not public, permissions exactly as in github-app.md section 2, subscribed to Pull request only, installed on a single repository. | maintainer | the registration facts | [github-app.md](github-app.md) section 7 checklist |
| 11.2 | Generate the App private key once and the webhook secret (at least 32 random bytes); place each only in the secret store and as the 0600 file paths the daemon configuration names (`github.app_private_key_path`, `intake.webhook_secret_path`). | maintainer | placement facts and rotation dates | github-app.md; `custodiand check-config` |
| 11.3 | Write the intake configuration from the deployment's own ids (installation, repositories, numeric GitHub user ids, roles). | maintainer | the configuration facts | `deploy/examples/intake-config.example.json`; `IntakeConfig::from_json` |
| 11.4 | Put the TLS reverse proxy in front of the loopback listener (placeholder hostname replaced by the real one); only the webhook path is forwarded; no request body, header or token is logged. | operations | the proxy facts | `deploy/examples/proxy/nginx-custodian.conf.example` |
| 11.5 | Decide how the daemon reaches GitHub: the repository builds **no HTTPS client** (`github_https_not_built`). Either an engineering change (a new ADR) or a deliberate other route exists before intake is relied on. | maintainer | the decision | [daemon.md](daemon.md); ADR 0124 |
| 11.6 | Requesting repositories' CI holds no custodian credentials; branch protection requires review. | maintainer | the review of their secrets and environments | github-app.md section 7 |
| 11.7 | **Enable the webhook.** A deliberate human act; no code path enables it. | maintainer | the date and the checklist state | github-app.md section 4 |

## Section 12. The first protected run

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 12.1 | Engines emit `worker-result/1` with the aggregates artifact (an engineering blocker in the engine repositories; HG-5, R-3). | engineering | the engine versions and a conformance run | [release-readiness.md](release-readiness.md) |
| 12.2 | The first protected run is a human-approved request with the exact plan digest typed by an approver who is not the requester, a budget no larger than needed, and the incident owner on call. | maintainer | the approval itself | `custodian request approve`; operator-runbook section 4 |
| 12.3 | Each later protected run is a separate approval. Releasing a projection is a further, distinct human approval bound to the exact projection digest and destination. | an approver | the approvals | disclosure.md; ADR 0120 |

## Section 13. Benchmarks authority cutover (a separate decision)

Not part of bringing a server up. It happens, if ever, after sections 0 to 12 and as its own recorded decision.

| # | What | Who | Evidence to record | Verified by |
| --- | --- | --- | --- | --- |
| 13.1 | Review a real legacy extract and the handoff record; every gate cited (dry-run report digest, parity, rollback rehearsed, and the rest). `legacy apply` with the exact digests; record contamination marks with `lifecycle report`. | maintainer | the digests and the review | [legacy-migration.md](legacy-migration.md) sections 3 and 4; ADRs 0115, 0118 |
| 13.2 | Benchmarks adopts `require_destination_binding()` and pins the keys and feed out of band. | benchmarks owner | their configuration change | [benchmarks-integration.md](benchmarks-integration.md); ADR 0121, 0122 |
| 13.3 | Rollback is rehearsed; the legacy runner is disabled for a population in the same change as its cutover; retirement of the legacy runner is a later, separate act after the oracle-exit period. | maintainer | the rehearsal and the change | legacy-migration.md section 4 (ADR 0092) |
| 13.4 | Nothing is cut over by this repository or its CI. | maintainer | the decision | ADR 0092 |

## What this checklist does not cover

- Making the repository public, the clean-snapshot export and the history decisions (release-readiness P-items).
- Engineering work that no human can do at a console (the engine side, the HTTPS client); those are listed in
  [release-readiness.md](release-readiness.md) with their owners.
- Cloud, hosting or cost decisions: none was made or implied.
