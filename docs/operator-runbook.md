# Operator runbook (C10)

Status: **implemented** in `crates/custodian-cli` (library and the `custodian` binary), tested with synthetic
data and test-generated keys. **Nothing is deployed.** There is no provisioned private ledger, no signer
process, no feed destination and no live GitHub App, so no procedure below has run against a real
deployment. Decisions: [ADR 0080](adr/0080-operator-cli-command-set-output-and-exit-codes.md) (commands,
output, exit codes), [ADR 0081](adr/0081-authenticated-roles-operator-authority-and-separation-of-duties.md)
(roles), [ADR 0082](adr/0082-startup-sequence-write-block-and-operational-repair.md) (startup, write block,
repair), [ADR 0083](adr/0083-store-migration-0004-durable-intake-submissions-and-activations.md) (store).

This repository is maintained by the Redact Secret project. The controls here are project-maintained, not
independent validation, and custody does not establish ground truth.

## 1. Rules that every procedure obeys

1. **Never reset, lower or "correct" a spent budget.** No command does, and no procedure below tells you to.
   Consumption only goes up, a reservation returns only if no protected byte was opened, and an exposed
   attempt is consumed even if it crashed. If a database cannot be recovered to the ledger's position, the
   answer is to **retire the affected epochs** (section 7), not to adjust a count.
2. **Never disclose protected content to diagnose a problem.** Everything the CLI prints is a fixed code, a
   number, a digest or an opaque identifier. Do not open the protected-population directory, the database or
   the ledger by hand to "see what happened"; use `verify` and `reconcile`.
3. **Fail closed.** If a command says it cannot tell (exit 7 or 8), the system has not proceeded. Do not look
   for a way around it; resolve the cause.
4. **No shortcuts to approval.** Nobody approves their own request, no agent or automation identity approves,
   and the approval is bound to the plan digest the approver typed.
5. **History is kept.** Contamination, clearing, retirement, rotation, approvals, cancellations and
   reconciliations are append-only records. Do not edit, delete or rewrite database rows, ledger files or
   feed files.
6. **One database file, one writer at a time per operation.** Do not copy a live database file; use the
   store's backup operation (section 6.3).

## 2. Setting up an operator

### 2.1 The files

| File | Holds | Never holds |
| --- | --- | --- |
| deployment config (`--config`, or `CUSTODIAN_CONFIG`) | paths to the store, operator policy, protected root, ledger clone, pinned roots, feed directory; the feed id; two public key identifiers | credentials, keys |
| operator policy (`private-custodian.operator-policy/1`) | identities (`act_...`), kind, roles, SHA-256 digest of each credential, validity window, optional limits | the credentials themselves |
| pinned roots | the ledger signing **public** keys, obtained out of band | private keys |
| credential file (`--token-file`, or `CUSTODIAN_TOKEN_FILE`) | one credential, 32 bytes or more; a regular file (not a link) with no group or other access, else `unauthenticated` | anything else |

The deployment config, policy, roots and credentials are **not committed** to this repository. The repository
contains only synthetic fixtures. The operator policy and the pinned roots are read only if they are regular
files (not links) that are not group or other writable (anyone who can write them can add an operator or a trust
anchor); otherwise the deployment is `not_configured`. Put them in a root-owned directory.

### 2.2 Creating and rotating a credential

1. Generate at least 32 bytes from the system random source into a new 0600 file (for example
   `head -c 48 /dev/urandom | base64 > token`). Do not choose it by hand; the policy stores only its digest,
   which is only safe for a high-entropy value.
2. `custodian credential-digest --token-file token` prints `credential_sha256`. Put it in the operator policy
   entry for that identity.
3. The operator policy change is a **reviewed policy revision**: raise `policy_version`, set a validity
   window, review, deploy. A lost or exposed credential is rotated the same way; replacing the file stops the
   old credential at once. An expired policy authenticates nobody (`operator_policy_expired`, exit 3).

### 2.3 Roles

| Role | May | Kinds that may hold it |
| --- | --- | --- |
| `requester` | `request submit` (its own requests only), `request status` and `request cancel` for its own requests, `policy validate` | human, service, agent |
| `approver` | `request approve` (another principal's request), `request status`/`list` for all | human |
| `operator` | `lifecycle ...`, `feed ...`, `policy import-activation`, `repair ...`, cancel any request, `verify`, `reconcile`, `request status`/`list` | human |
| `auditor` | `verify`, `reconcile`, `request status`/`list` (read-only) | human, service |

Structural limits that the policy file cannot override: an **agent** identity may hold only `requester`; a
**service** identity may hold only `requester` and `auditor`; only a **human** approves, clears, retires,
rotates, publishes, repairs, imports an activation, or cancels someone else's request. A policy file that
tries otherwise does not load (`operator_policy_invalid`). One human may hold two identities (for example
`requester` and `approver`), so the separation is by principal; one person may hold both under two separate credentials in solo-maintainer mode (ADR 0103).

## 3. Using the CLI

`custodian [--config F] [--identity ACT] [--token-file F] [--dry-run] <group> <command> [--flag value]...`

Standard output is **one JSON object**: `{"schema":"private-custodian.cli-output/1","command":...,"ok":...,
"dry_run":...,"code":...,"exit":...,"result":{...}}`. Standard error is empty. `code` is a fixed word.
`result` holds identifiers, counts and fixed words only. Paths, credentials, free text and protected values
never appear.

### 3.1 Commands

| Command | Role | What it does | Confirmation inputs |
| --- | --- | --- | --- |
| `request submit --document F` | requester | Validate the request document (its `asserted_actor` must be you) and record it as pending. Charges nothing. If the idempotency key is already reserved by any path it reports `reserved_elsewhere` and records nothing. | none |
| `request status --request-id ID` | any role | Submission status, attempt state, exposure, last reason code, budget counters. Requesters see only their own. | none |
| `request list [--limit N]` | approver, operator, auditor | Count and pending ids. | none |
| `request approve --request-id ID --confirm-plan-digest D [--ttl-secs N]` | approver (human) | Compose the approval, re-check everything and reserve the budget in one transaction. | the exact plan digest |
| `request cancel --request-id ID` | requester (own), operator (any) | Cancel a pending request, or cancel the attempt (refund if not started; consumed if running). | none |
| `verify ledger\|store\|registry\|checkpoint\|all` | auditor, operator | Walk the ledger with the pinned roots; SQLite and accounting invariants; registry head against its checkpoint; store against the ledger's checkpoint. | none |
| `reconcile store\|ledger\|feed` | auditor, operator | **Read-only** diagnosis. `reconcile store` prints the store id repair commands need. | none |
| `lifecycle report --epoch E --kind K --reason R --idempotency-key IDK` | operator (human) | Record a contamination. `exposed` and `used_for_tuning` also retire the epoch. | none (report only blocks use) |
| `lifecycle clear --epoch E --confirm-epoch E --idempotency-key IDK` | operator (human) | Clear an `unreviewed_change` after review (reason fixed to `reviewed_no_impact`). Refused for anything else. | the epoch id |
| `lifecycle retire --epoch E --confirm-epoch E --reason R --idempotency-key IDK` | operator (human) | End an epoch's use for good. | the epoch id |
| `lifecycle rotate --predecessor E1 --successor E2 --confirm-predecessor E1 --confirm-successor E2 --run-budget-limit N --reason R --idempotency-key IDK` | operator (human) | Retire E1, link E2, provision E2's own budget, activate E2. Never touches E1's budget. | both epoch ids |
| `feed record-revocation --id LABEL --kind candidate\|projection\|receipt\|policy --target T --action revoked\|contaminated\|superseded [--superseded-by P] --reason R` | operator (human) | Record a revocation obligation (counts for eligibility at once). | none |
| `feed publish` | operator (human) | Sign and publish the next feed envelope, or renew freshness. | none |
| `policy validate --document F` | any role | Read-only: the checks `submit` and `approve` run. | none |
| `policy import-activation --document F --confirm-activation-id A --confirm-sequence N` | operator (human) | Append a policy activation state (append-only, higher sequence only). | activation id and sequence |
| `repair recover --confirm-store-id S` | operator (human) | Settle lapsed leases and reservation windows. | store id |
| `repair registry-sweep --confirm-store-id S` | operator (human) | Retire registry entries for epochs the store retired. | store id |
| `repair export --confirm-store-id S` | operator (human) | Export pending audit events to the ledger and record the checkpoints. | store id |
| `repair ledger-reconcile --confirm-store-id S` | operator (human) | Re-write identical bytes for events the ledger lost and acknowledge ones it holds. A conflicting record is never repaired. | store id |
| `repair feed-deliver --confirm-feed-id F` | operator (human) | Deliver committed feed envelopes the destination lacks. | feed id |
| `repair clear-reconcile --confirm-store-id S --confirm-checkpoint-seq N` | operator (human) | Clear the restore block, **only** if the ledger is trustworthy and the store is at or past the ledger's checkpoint. | store id and local checkpoint sequence |
| `legacy apply --extract F --handoff F --confirm-handoff-digest D --confirm-report-digest D` | operator (human, `legacy_import` permission) | Write reviewed legacy consumed units into the budget store (additive, idempotent). Does **not** carry contamination marks: record those with `lifecycle report`. Refusals: `handoff_not_ready`, `import_refused` (exit 5). | handoff digest, report digest |
| `repair retention --confirm-store-id S --queue-done-min-age-secs N --claim-min-age-secs N --decided-submission-min-age-secs N --pending-submission-max-age-secs N [--batch-limit N]` | operator (human) | One retention pass over the queue, claims and submissions; ages are mandatory and below the code floors are refused. | store id |
| `credential-digest --token-file F` | none | Print the digest to put in the operator policy. | none |

Allowed `--reason` words for `lifecycle`: `results_exposed`, `tuned_on_results`, `integrity_alarm`,
`unreviewed_population_change`, `contamination_response`, `planned_rotation`, `operator_decision`
(`reviewed_no_impact` is fixed for `clear`). Feed reasons: `contamination`, `epoch_rotation`,
`key_compromise`, `policy_revoked`, `error_correction`, `newer_evidence`. Which reason fits which change is
enforced (`invalid_change` otherwise).

### 3.2 `--dry-run`

Runs authentication, authorization, input checks, confirmations, the startup check and the read-only policy
checks (activation current, epoch usable, budget available, approval binds), prints `would_*` or the refusal
the real command would give, and writes nothing. Run it before every `approve`, `retire`, `rotate` and
`clear-reconcile`.

### 3.3 Exit codes (stable)

| Exit | Class | Meaning | Typical codes |
| --- | --- | --- | --- |
| 0 | success | done (or, with `--dry-run`, would be) | `submitted`, `approved`, `verified`, `would_*` |
| 1 | internal | an internal error; the command may have taken effect: check `request status` before retrying | `internal_error` |
| 2 | usage | malformed command line or document | `usage_error`, `invalid_document`, `document_too_large`, `actor_mismatch`, `confirmation_missing` |
| 3 | unauthenticated | credential or operator policy | `unauthenticated`, `operator_policy_invalid`, `operator_policy_expired` |
| 4 | forbidden | authenticated but not permitted | `forbidden`, `agent_not_permitted`, `automation_not_permitted`, `self_approval` |
| 5 | refused | a policy or state rule said no; nothing changed (except a recorded budget denial) | `already_decided`, `budget_exhausted`, `stale_policy`, `policy_not_current`, `approval_expired`, `epoch_blocked`, `confirmation_mismatch`, `idempotency_conflict`, `not_clearable`, `invalid_change`, `rotation_invalid`, `store_behind_ledger`, `submission_limit`, `pending_obligations` |
| 6 | not found | no such object, or not visible to you | `not_found` |
| 7 | unavailable | a dependency is unavailable; nothing changed; retry may help | `store_unavailable`, `ledger_unavailable`, `signer_unavailable`, `destination_unavailable`, `feed_conflict`, `not_configured` |
| 8 | integrity | a consistency check failed; writes are refused until a human resolves it | `store_needs_reconcile`, `store_rolled_back`, `registry_rolled_back`, `ledger_untrusted`, `verification_failed`, `destination_conflict`, `unpublishable` |

## 4. Normal evaluation

1. The requester writes the request document (the frozen plan; see docs/contracts.md) and runs
   `request submit`. The result is `pending`; no budget is held.
2. The approver reviews the plan out of band, runs `--dry-run` approve, then `request approve` with
   `--confirm-plan-digest` copied from the plan. The result is `approved` with the attempt id and run state
   `reserved`, or `budget_exhausted` (exit 5, a recorded denial). Approving again is `already_decided`.
3. The same request arriving from the GitHub App with the same idempotency key is the same request: whichever
   path reserves first wins, the other path finds it and charges nothing.
4. `request status` shows progress. `request cancel` before the worker starts refunds; after exposure it never
   does.

A stale policy fails: if the policy activation the plan binds has been superseded, revoked or has expired, or
has never been recorded, `submit` and `approve` fail (`policy_not_current` or `stale_policy`). The plan binds
the activation, so a new activation means a new plan and a new request, not an edit.

## 5. Daily checks

* `verify all` (auditor): expect `verified`, `ledger_trustworthy: true`, `store_intact: true`,
  `store_checkpoint: contained`, `registry_checkpoint: matches` (or `absent` before the first export).
* `reconcile store` / `ledger` / `feed`: expect `consistent`. Anything else is a section 6 procedure.
* `repair export` after a burst of activity, so the ledger is current (an exposed run's terminal event must be
  exported before disclosure is allowed).
* `feed publish` before the feed's `fresh_until` (`reconcile feed` shows it); an expired feed makes every
  consumer treat evidence as stale. Publishing is a human operator action.

## 6. Recovery procedures

### 6.1 Crash recovery (service or CLI died mid-operation)

Every store operation is one transaction: after a crash it is entirely there or entirely absent.

1. Start normally. `Service::start` (and every state-changing CLI command) runs the startup check first, then
   settles lapsed leases (`recover`), mirrors the registry, delivers committed feed envelopes and exports.
2. To do it by hand: `reconcile store` (note `recoverable_attempts`, `store_id`), then
   `repair recover --confirm-store-id <store-id>`.
3. Read the result honestly. `expired_unstarted` attempts never opened protected bytes and are refunded.
   `failed_consumed` attempts may have opened them and are **consumed, not refunded, and not retried
   automatically**. A retry is a new, separately approved attempt that charges again.
4. If a command exited 1 or you lost the connection, run `request status --request-id <id>` before retrying;
   approve and cancel are idempotent (`already_decided` means it took effect).
5. `repair registry-sweep` and `repair feed-deliver` converge a registry or feed left half-way by a crash
   (the C9 crash table in docs/lifecycle-and-revocation.md lists the states).

### 6.2 Ledger outage or untrusted ledger

*Outage* (the clone cannot be read or the remote is down): state-changing commands exit 7
(`ledger_unavailable`) and change nothing; reads of the store still work; the audit outbox keeps events
pending, and disclosure stays closed because an exposed run's terminal event is not exported.

1. Restore the ledger access (network, remote, deploy identity). Do not work around the check.
2. `verify ledger`, then `repair export --confirm-store-id <store-id>` to drain the outbox, then
   `reconcile ledger`. If it reports missing or unacknowledged records, `repair ledger-reconcile` re-writes
   identical bytes and acknowledges.
3. A conflicting record (`conflicting` > 0, or files under `quarantine/`) is never repaired automatically: it
   needs a human (section 8) and the incident procedure in SECURITY.md.

*Dispatch gate*: in a deployment `start` and the exposure record are also refused with `store_export_pending` while
budget-affecting events are unexported (ADR 0116). During a ledger outage this keeps dispatch closed and changes
no budget. Restore the ledger, run `repair export`, then dispatch. Do not weaken the gate to proceed.

*Untrusted ledger* (`verify ledger` reports findings; commands exit 8 with `ledger_untrusted`): the store is
**write-blocked** (persisted). Do not clear the block to get going again.

1. Stop and treat it as a possible tampering or key incident (SECURITY.md, the incident-triage skill).
2. Identify the findings by their fixed codes in `ledger_finding_codes`; compare the ledger clone with its
   remote out of band. Never delete or edit ledger files; corrections are new superseding records (ADR 0051).
3. When `verify ledger` is clean again, continue with section 6.3 step 5.

### 6.3 Restore from backup, with the checkpoint check

Backups are made with the store's backup operation (`VACUUM INTO`), never by copying a live file. A restored
database may be missing spending that happened after its snapshot, which is exactly what the ledger's
checkpoint detects.

1. Stop every writer. Restore the chosen backup file into place with owner-only permissions.
2. Run any read-only command, or `verify checkpoint`. Expect either `store_checkpoint: contained` (the store
   holds the ledger's newest position) or `behind_ledger` (it does not).
3. **`behind_ledger`**: the first state-changing command or `Service::start` has persisted the write block
   (`store_rolled_back`, exit 8). The restored store **understates consumption**. `repair clear-reconcile` will
   refuse (`store_behind_ledger`, exit 5) and no flag changes that. Do this instead:
   1. Look for a newer copy that contains the ledger's checkpoint (a later backup, the original file if it
      survived). Restore that one and go back to step 2.
   2. If none exists, **do not fabricate consumption, and stop.** This is an incident
      (docs/incident-response.md, class H). The earlier text of this runbook said to `lifecycle retire` the
      epochs that may have spent budget after the snapshot; **that is not executable**: while the store is
      write-blocked every state-changing command, `lifecycle retire` and `lifecycle rotate` included, is refused
      with `store_needs_reconcile` (exit 8), and `repair clear-reconcile` is refused with `store_behind_ledger`.
      The C12 drill pins this (`c12_restore_drill.rs`). What may be done today is read-only: `verify`,
      `reconcile`, and working out from the ledger's audit records (by sequence and request id) which epochs may
      have spent budget after the snapshot. The way to continue is a new store and a new ledger lineage with new
      reviewed epochs and their own budgets; that procedure is designed but not implemented
      (ADR 0101, decision 2; register R-1 in docs/release-readiness.md), so protected execution against the
      old store does not resume.
   3. Keep the blocked copy for the incident record; do not delete the ledger.
4. **`contained`** but the store is blocked (for example the flag was set before the restore): continue.
5. Clear the block only when all of these hold: `verify all` shows a clean ledger, `store_checkpoint:
   contained`, `registry_checkpoint: matches` or `absent`. `reconcile store` prints the `store_id` and
   `store_checkpoint_seq` (the store's own newest outbox sequence) that the clear needs. Run it with
   `--dry-run` first; if it says `would_clear`, run
   `repair clear-reconcile --confirm-store-id <store-id> --confirm-checkpoint-seq <store_checkpoint_seq>`.
   The clearing is itself an audited event (`store.reconciled`) naming you.
6. Re-run `Service::start` or any state-changing command; the check runs again from scratch.
7. A restored **registry** older than its checkpoint is `registry_rolled_back`; the same rule applies: restore
   a newer registry log. Nothing edits the registry by hand.

### 6.4 Contamination response

1. As soon as protected contents or per-case detail may have reached a party outside custody, or a candidate
   was tuned on a population's results: `lifecycle report --epoch <epoch> --kind exposed|used_for_tuning
   --reason results_exposed|tuned_on_results --idempotency-key <key>`. New use stops in the same transaction
   (reserve, retry, start, exposure; prepare and release); a permanent kind also retires the epoch. If you
   only suspect a population or binding changed: `--kind unreviewed_change --reason integrity_alarm`.
2. `feed publish` **immediately**. The revocation obligation is durable and counts for eligibility from the
   moment it is recorded, but consumers only learn of it through the signed feed; a projection released
   before this point stays usable to a consumer until its next feed sync (docs/lifecycle-and-revocation.md,
   section 3). Keep the feed's freshness short. Verify with `reconcile feed` (`consistent`).
3. Do not try to "undo" it. `exposed` and `used_for_tuning` are never clearable; an attempt already running
   settles as consumed; earlier receipts stay verifiable and auditable but cannot authorize future use.
4. Only an `unreviewed_change` can be cleared, by a human, after a review that found no impact:
   `lifecycle clear --epoch <e> --confirm-epoch <e> --idempotency-key <key>` (use `--dry-run` first).
5. For replacement work, seal a new reviewed epoch (C5) and `lifecycle rotate`. The old epoch's budgets are
   never edited; the new epoch has its own.
6. Record any revocation of a specific candidate, projection, receipt or policy with `feed record-revocation`
   and publish.

### 6.5 Key and feed issues

* **Signer unavailable or refusing** (`signer_unavailable`, exit 7): nothing was signed or appended;
  obligations stay pending; eligibility still refuses revoked things. Restore the isolated signer; then
  `feed publish` and `repair export`.
* **Feed destination down** (`destination_unavailable`): the envelope is already committed. When the
  destination is back: `repair feed-deliver --confirm-feed-id <feed-id>`.
* **Destination holds other bytes** (`destination_conflict`, exit 8): never overwritten, never marked
  delivered. A human compares it with the committed envelope (section 8); do not delete files to "fix" it.
* **Obligation cannot be published** (`unpublishable`): a public naming (opaque or keyed commitment) is
  missing for a population; fix the naming, then publish. Eligibility keeps refusing meanwhile.
* **Clock skew** (`internal_error` from publish): the clock is earlier than the feed head; fix the clock.
* **Key compromise**: revoke the key with a ledger key event (C7, ADR 0050), `feed record-revocation --kind
  projection|receipt --action revoked --reason key_compromise` for each affected item, `feed publish`, and
  supersede records under a new key. Pin the new root out of band; never take a key from the ledger or feed.
* **Operator credential exposed or lost**: section 2.2; and review the audit trail for the identity.

### 6.6 Activation and policy changes

`policy import-activation` appends a new state of an existing activation id with a higher sequence (for
example `revoked`, or a new active sequence). Revocation stops new approvals, reservations and dispatch at
once. It is an operator act on a **reviewed** document with the exact id and sequence typed; it is not a way to
edit an approval or to relax a limit.

## 7. What these procedures never do

* They never reset, lower, raise or "true up" a count, a limit or a held, consumed or refunded amount.
* They never run an engine, open the protected-population directory, read raw results, or print case-level
  detail.
* They never edit or delete a row, a ledger record or a feed file.
* They never grant an agent or automation identity approval, clearance, retirement, rotation or publication
  authority, and they never approve a request on behalf of its requester.

## 8. What requires a human decision

These are not automated and not delegated to an agent:

1. Approving any execution request (a human approver other than the requester, who has read the plan).
2. Cancelling someone else's request.
3. Declaring a contamination (`exposed`, `used_for_tuning`) and retiring or rotating an epoch.
4. Clearing an `unreviewed_change`, and the review that justifies it.
5. Publishing the feed, recording a revocation, superseding evidence.
6. Importing or revoking a policy activation; any change to the operator policy file (a reviewed revision).
7. Clearing the restore block (`repair clear-reconcile`), and choosing between a newer backup and retiring
   epochs when no copy reaches the ledger's checkpoint.
8. Resolving a conflicting or quarantined ledger record, an untrusted ledger, a feed destination that holds
   other bytes, or a suspected key compromise (incident handling, SECURITY.md).
9. How credentials are stored and issued. One person may hold both `requester` and `approver` as separate
   principals with separate credential stores (solo-maintainer mode, ADR 0103); evidence is then labelled
   `procedural-separation` or `custodian-declared`, never independent.
10. Anything involving real personal data, a live protected run, or publishing code or evidence: out of scope
    for this runbook and governed by SECURITY.md and the README publication terms.

## 9. Not covered yet (unwired for deployment)

* No long-running service, HTTP listener, queue-consumer daemon or live GitHub App exists; the pieces
  (`Intake`, `ExecutionGate`, the durable queue, `Service::start`) are libraries exercised in tests.
* The `custodian` binary has no signer: `repair export` and `feed publish` report `signer_unavailable` until a
  deployment supplies an isolated signer transport.
* No private-ledger repository, key provider, feed destination or real operator policy exists.
* Everything above is exercised only against synthetic data. C12 added the cross-layer suite, the restore drill and the readiness record: [backup-recovery.md](backup-recovery.md), [incident-response.md](incident-response.md), [deployment-runbook.md](deployment-runbook.md), [release-readiness.md](release-readiness.md).

## 10. Evidence map

| Claim | Evidence |
| --- | --- |
| Roles, structural limits, three-layer self-approval refusal | `custodian-cli/tests/operator.rs`, `custodian-store/tests/intake.rs` |
| CLI and App share idempotency and accounting | `custodian-cli/tests/edge.rs`, `custodian-store/tests/intake.rs` |
| Durable intake ports | `custodian-store/tests/intake.rs` |
| Startup refusal blocks writes; clear is verified | `custodian-cli/tests/startup.rs` |
| Output hygiene and exit codes | `custodian-cli/tests/operator.rs`, `tests/binary.rs`, unit tests |
| Repair cannot reset budgets | `tests/operator.rs` (`repair_needs_the_exact_store_id...`, `an_exposed_attempt_that_lapses...`) |
