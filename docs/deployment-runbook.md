# Initial single-service deployment runbook and manual infrastructure checklist (C12, refreshed by S6)

> **Start with [server-prerequisites-checklist.md](server-prerequisites-checklist.md).** It is the single list,
> in dependency order, of everything a human does once a server exists, with the evidence to record and the
> document or command that verifies each item. This runbook is the narrative behind it. The shape of every
> configuration file is in [`deploy/examples/`](../deploy/examples/README.md) (placeholders only, scanned by a
> test). The GitHub App webhook is the **last** item and stays Inactive until all others are done.

Status: a plan and a checklist. **Nothing in this repository provisions anything, and C12 provisioned nothing**:
no host, account, key, repository setting, deploy key, GitHub App setting, policy file, feed destination or
monitored contact was created. Every step below that changes the outside world is a **human action** and each
approval is a **human decision**, recorded in the private operations log (identities and fixed codes, never
secrets). Related: [ADR 0001](adr/0001-trust-boundaries-and-threat-model.md) T4 (deployment prerequisites),
[operator-runbook.md](operator-runbook.md), [worker-isolation.md](worker-isolation.md), [ledger.md](ledger.md)
(private-ledger provisioning), [github-app.md](github-app.md), [protected-storage.md](protected-storage.md),
[backup-recovery.md](backup-recovery.md), [incident-response.md](incident-response.md). This repository is
maintained by the Redact Secret project; the controls are project-maintained, not independent validation.

## 1. What can and cannot be deployed today

State after S1 to S6 (functional verification on public synthetic data; none of it is deployed):

| Piece | State in the repository | Consequence for a first deployment |
| --- | --- | --- |
| Operator CLI (`custodian`), store, corpus, ledger writer (Git), lifecycle, disclosure, bridge | implemented, synthetic-tested | runs against real files once configured |
| Service daemon `custodiand`: std-only HTTP listener on loopback, durable queue consumer, scheduler, request-to-projection pipeline (S5, [daemon.md](daemon.md)) | implemented, synthetic-tested including the real sandbox on Linux CI | needs a TLS reverse proxy in front; **no HTTPS client** is built, so GitHub access stays `disabled` or loopback-only until that decision is made (checklist 11.5) |
| Isolated signer process and local-socket transport (S2, [signer.md](signer.md)) | implemented, synthetic test keys | a dedicated uid, on-host key generation and an out-of-band pin are human steps (checklist section 3) |
| Feed destination (static hosting or object store) | **absent** (`DirFeed` and `MemoryFeed` only) | nothing for a consumer to read until a destination meets the contract (checklist section 7) |
| Worker engines (`worker-result/1` and `private-custodian.aggregates/1` in credential-eval and pii-eval) | **absent engine side**; the synthetic fixture emits them | no real run can produce a releasable aggregate |
| Receipt and execution-record assembly from a dispatch report | implemented (S5, ADR 0127), exercised with the fixture engine | blocked only by the engine side |
| Isolation | bubblewrap backend, rlimits; **no seccomp, no cgroups**; Linux only, proved by self-check on the host | unsupported until the self-check passes on the production host |
| Restore with no newer copy; key compromise | executable as operator commands (S6, [ADR 0130](adr/0130-restore-loss-acceptance-with-no-newer-copy.md), [ADR 0131](adr/0131-ledger-reissue-after-key-revocation.md)) | verified on synthetic data only; rehearse on the host (checklist 3.5, 9.2) |
| Real operator policy, disclosure policy, pinned roots, keys, ledger | **none exist** | all are human provisioning |

So the honest target of this runbook is the state in which the remaining engineering blockers in
[release-readiness.md](release-readiness.md) (the engine side, the HTTPS client decision) are closed. Sections 3
and 4 say what a human prepares and in what order.

## 2. Topology (single host, single service)

One dedicated host or account boundary for the trust zones that hold protected material (ADR 0001 T4 item 1).
Separate operating-system users; none is shared with developer or CI accounts.

| Identity | Holds | Must not hold |
| --- | --- | --- |
| `custodian-svc` (control service) | runtime database, protected root, operator policy, pinned roots, staging base, feed directory writes | the signing key, the ledger deploy key, the GitHub App private key |
| `custodian-worker` (dedicated non-root) | nothing but what the sandbox mounts read-only and its own scratch | any credential, the database, the protected root, the ledger, the signer socket |
| `custodian-signer` (isolated signer process) | the signing key only; a socket or pipe reachable by `custodian-svc` | database, protected root, ledger key |
| `custodian-ledger` (ledger writer identity) | the deploy key for `redact-secret/private-ledger`, the local clone | everything else |
| `custodian-app` (request-facing App adapter, later) | App private key and webhook secret | database write access beyond the intake ports it needs, the signer |
| Human operators | their own credential file (0600) and the CLI | direct database or ledger edits |

Layout (placeholders; the real paths are deployment material and are not committed):

```
/srv/custodian/            0755 root           mount point
  state/                   0700 custodian-svc  store.db (0600), -wal, -shm
  protected/               0700 custodian-svc  sealed/ registry/ keys/   (encrypted volume)
  staging/                 0700 custodian-svc  per-run staging, emptied after each run
  artifacts/               root-owned, not writable by others   allowlist root for engines/scanners/candidates
  policy/                  0755 root           operator-policy.json, roots.json   (not group/other writable)
  feed/                    0750 custodian-svc  public feed files (until a real destination exists)
  ledger-clone/            0700 custodian-ledger
  backups/                 0700 backup identity   encrypted, separate disk or provider
```

`artifacts/` must be root-owned with no group or other write bit; the dispatcher refuses symlinks, hard-link
aliases and writable ancestors. The credential files for operators are 0600 and are read only by their owners;
the CLI now also refuses a credential file with any group or other access, a symbolic link, and an operator
policy or pinned-roots file that is group or other writable.

## 3. Ordered steps with human approvals

Each step ends with an **Approval** line: what evidence is recorded and who signs it. Do not skip ahead; a later
step assumes the earlier approval exists. Never run any of this in CI.

### Step 0. Decisions that precede everything **(human)**

- Name the incident owner and a backup, and set up the monitored private reporting contact (a monitored mailbox
  not tied to one person, plus GitHub private vulnerability reporting once configured). Record both in the
  private operations log. **Approval:** maintainer.
- Decide the recovery point (the export-and-backup interval) and the retention values marked **(decide)** in
  [backup-recovery.md](backup-recovery.md). **Approval:** maintainer.
- Decide whether one person may hold both `requester` and `approver` identities (operator-runbook section 8,
  item 9). If yes, receipts say the separation is procedural. **Approval:** maintainer.
- Decide the code license separately; it is not a deployment prerequisite (release-readiness lists the options).

### Step 1. Host and accounts

1. Provision the dedicated host or account boundary and the users in section 2. Record the host class (OS,
   kernel, bubblewrap and util-linux versions).
2. Disable unrelated services and shared access; restrict operator login; log operator sessions outside the
   writer's control (protected-storage.md).
3. Confirm no developer or CI account can read `state/`, `protected/`, `policy/` or `ledger-clone/`.
   **Approval:** maintainer records the account list and the access review.

### Step 2. Storage, encryption and backup

1. Create an encrypted volume for `protected/` (full-disk or volume encryption; the repository provides none).
   Create `state/` with mode 0700; the store creates its files 0600 and refuses wider modes and symlinks.
2. Choose the backup target (separate disk or provider, encrypted at rest, restricted identity) and the schedule
   from the recovery-point decision. Keep the commitment-key backup separate from corpus backups.
3. Configure the retention schedule from backup-recovery.md section 5 as the maintainer approved it.
4. Rehearse a backup and restore on a copy with synthetic data (backup-recovery.md section 3.2).
   **Approval:** maintainer records the target, schedule, retention and the rehearsal result.

### Step 3. Signer host and keys

1. On the signer host, never a developer machine or CI, generate the Ed25519 root key. Record only the public
   key.
2. Pin the public key out of band: the operator `roots.json`, the independent checkpoint location, and every
   consumer (benchmarks). Do not take a key from the ledger or the feed.
3. Decide key backup (recommended: none; see backup-recovery.md 7.1).
4. Run the rotation rehearsal (backup-recovery.md 7.2) and the compromise rehearsal (7.4) on a throwaway key
   pair before relying on either.
   **Approval:** maintainer records the public key fingerprint, where it is pinned and who can reach the signer.

### Step 4. Private ledger and the independent checkpoint copy

The repository `redact-secret/private-ledger` was reported as existing, private and empty, with no deploy key,
on 2026-10-03 (the C12 brief); verify this yourself before step 1 below. Then, following ledger.md
"Manual private-ledger provisioning":

1. Confirm visibility is private and forking is disabled.
2. Add an initial commit containing only a README stating it is project-maintained and private.
3. Protect `main`: no force-push, no deletion, linear history, pushes only from the ledger-writer identity;
   alert on any other push.
4. Create a deploy key scoped to this one repository with write access (or a fine-grained token limited to its
   contents). No admin scope, no workflow permission, not reused from the GitHub App, CI or a personal account.
   Store it only in `custodian-ledger`'s secret store.
5. Grant read access to the minimum named operators; no benchmarks, CI or agent identity.
6. Choose the independent checkpoint copy (an offline note or a mirror repository written by a different
   identity) and the review cadence; record the first checkpoint.
7. Access checks, repeated at each review (ledger.md list): writer cannot force-push or read other repositories;
   benchmarks, CI, App and agent identities cannot read it; a non-writer push is rejected or alerts;
   `GitBackend::audit_history` and `walk_ledger` are clean with the pinned roots.
   **Approval:** maintainer records the settings screenshot-equivalent facts (not secrets) and the first
   checkpoint.

### Step 5. Isolation on the production host

1. Install bubblewrap (0.8 or later) and util-linux `prlimit` in standard locations; kernel 5.14 or later with
   unprivileged user namespaces permitted for the worker account.
2. Run `run_self_check` on the production host and image; the record must be `Verified` with every check
   passed, and is retained with the run audit. A container is not evidence; the self-check inside it is.
3. Re-run it after any change to the launcher, kernel, container runtime or allowlist, and at least every
   `verification_max_age_secs` (3600 s) in a long-running service (a stale record is refused).
4. Apply host-level egress filtering as defense in depth (not implemented in the repository).
5. Record the explicit risk decision for what is not provided: no seccomp filter, no cgroup controllers, a
   shared host with a human who is also root (worker-isolation.md sections 8 and 9). **Approval:** maintainer
   signs the risk decision.

### Step 6. Operator policy and credentials

1. For each human, generate at least 32 random bytes into a new 0600 credential file; compute
   `custodian credential-digest --token-file F`.
2. Write the operator policy (identities, kinds, roles, digests, validity window) as a reviewed revision. Agents
   hold only `requester`; services hold only `requester` and `auditor`; only humans approve, clear, retire,
   rotate, publish, repair, import an activation or cancel others' requests (structural, not configurable).
3. Install the policy where it is not group or other writable. **Approval:** maintainer reviews the policy diff.

### Step 7. Feed destination **(a human choice; no destination exists)**

Choose static hosting or an object store that meets the `FeedDestination` contract (create-if-absent, identical
bytes accepted, different bytes refused, readable without any private access, in-order writes). Restrict
write access to `custodian-svc`'s publishing identity. Record the public URL consumers pin. **Approval:**
maintainer.

### Step 8. Disclosure policy and policy activations

1. Replace the placeholder values used in tests with a reviewed disclosure policy (strata, minimum sizes,
   composition, budgets, destinations, freshness). **Approval:** maintainer plus a second reviewer if one exists;
   the review is recorded as procedural while one person holds all roles.
2. Import the approved policy activations (`policy import-activation` with the exact id and sequence).
3. Seal the first reviewed population (C5): `begin_epoch`, `add_entry`, `seal`, `activate`.

### Step 9. Conformance on the production host (synthetic only)

Run, on the production host and image: the full test suite with `CUSTODIAN_REQUIRE_ISOLATION=1`, one
synthetic end-to-end scenario with a public conformance control, `verify all`, the restore rehearsal and the
tabletop from incident-response.md section 9. **Approval:** maintainer records the results. This is the ADR
0001 T4 evidence; until it exists no protected execution is permitted.

### Step 10. GitHub App (only when a server exists, and last)

The App webhook stays **Inactive** until every item in github-app.md section 7 is done, including: the
listener behind HTTPS exists, the durable stores are shared with the control plane, the queue consumer exists,
requesting repositories' CI holds no custodian credentials, branch protection requires review, rotation dates
are recorded, and the incident owner and reporting route are recorded. Enabling the webhook is a deliberate
human act (github-app.md section 4); there is no code path that enables it.
**Approval:** maintainer records each checklist item.

### Step 11. First protected run

Only after steps 0 to 9 (and 10 if intake is by App), and the engine-side work in the checklist (section 12): the first protected run is a human-approved request with
the exact plan digest typed by the approver, a budget no larger than needed, and the incident owner on call.
**Approval:** maintainer.

## 4. Manual infrastructure and access checklist

Tick only with evidence in the private operations log. "Verified by" is a human.

| # | Item | Needs | Verified by / date |
| --- | --- | --- | --- |
| 1 | Dedicated host or account boundary; separate OS users per identity (section 2) | step 1 | |
| 2 | No developer or CI account can read state, protected root, policy or ledger clone | step 1 | |
| 3 | Encrypted volume for the protected root; modes 0700/0600; no symlinks | step 2 | |
| 4 | Backup target, schedule, retention and a restore rehearsal | step 2 | |
| 5 | Signer host; key generated on it; public key pinned out of band (operator, checkpoint copy, consumers) | step 3 | |
| 6 | Signing key reachable only by the signer identity; no key file, variable or socket permission for the control service, workers or agents | step 3 | |
| 7 | `redact-secret/private-ledger`: private, forking off, protected `main`, deploy key scoped to it, read access minimal | step 4 | |
| 8 | Ledger writer identity separate from the GitHub App, CI and personal credentials | step 4 | |
| 9 | Independent checkpoint copy outside the ledger writer's and the host's control, with a review cadence | step 4 | |
| 10 | Isolation requirements met; self-check `Verified` on the production host and image; re-run schedule | step 5 | |
| 11 | Worker account cannot read ledger, App, signing or DB-admin credentials; engine artifacts root-owned and not writable | step 5 | |
| 12 | Operator policy reviewed and installed; credentials 0600; entropy and rotation dates recorded | step 6 | |
| 13 | Feed destination meets the contract; public URL recorded and pinned by consumers | step 7 | |
| 14 | Disclosure policy and activations reviewed and imported; first population sealed | step 8 | |
| 15 | Synthetic conformance, restore rehearsal and tabletop recorded on the production host | step 9 | |
| 16 | GitHub App registered per github-app.md; webhook **Inactive** until a server and every checklist item exist | step 10 | |
| 17 | Monitored private reporting contact and a named incident owner (and backup); GitHub private vulnerability reporting configured | step 0 | |
| 18 | Retention values approved and scheduled | step 0, 2 | |
| 19 | Recovery point decision recorded | step 0 | |
| 20 | Risk decision for the missing seccomp and cgroup controls and for a single human holding all roles | step 5 | |

## 5. Human approvals, collected

| Decision | Who | Recorded as |
| --- | --- | --- |
| Incident owner, backup, monitored contact | maintainer | operations log |
| Recovery point, retention values, key backup choice | maintainer | operations log |
| Requester and approver held by one person or not | maintainer | operations log |
| Operator policy revision | maintainer | policy file revision and review note |
| Disclosure policy and activations | maintainer (and a second reviewer if available) | policy review note |
| Isolation risk decision | maintainer | ADR or operations log (ARCHITECTURE.md requires an ADR for privileged or shared-host execution) |
| Enabling the App webhook | maintainer | github-app.md checklist |
| Making the repository public, choosing a license | maintainer (see release-readiness) | not part of deployment |
| Each protected run | a human approver other than the requester | the approval itself |

## 6. Stopping and rollback

- Stop intake: set the App webhook Inactive and remove the installation entry from the intake configuration.
- Stop dispatch: stop the service. In-flight attempts settle as consumed after their lease lapses (never
  refunded after exposure).
- Stop disclosure: stop the signer; nothing is signed, obligations stay pending, eligibility still refuses
  revoked things.
- Never: edit or delete database rows, ledger files or feed files; lower or recreate a budget; run an engine
  outside the sandbox; paste a credential into a chat or an issue.
