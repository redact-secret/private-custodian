# Backup, restore drill, retention and signing-key recovery (C12)

Status: procedures and an automated drill on synthetic data. **Nothing is deployed.** Since S6 the two cases
the C12 drill could not resolve are executable: a restore with no copy that reaches the ledger checkpoint
([ADR 0130](adr/0130-restore-loss-acceptance-with-no-newer-copy.md), section 4 case C) and a compromised signing
key ([ADR 0131](adr/0131-ledger-reissue-after-key-revocation.md), section 7.4). Both are verified on public
synthetic data only; neither has been rehearsed on a host. No backup target, key
provider, ledger remote or schedule exists, so none of the numbers below is an operating fact; the values that
need a human decision are marked **(decide)**. Decisions: [ADR 0101](adr/0101-restore-recovery-window-and-signing-key-operating-constraints.md);
mechanisms: [state-store.md](state-store.md), [ledger.md](ledger.md), [protected-storage.md](protected-storage.md),
[operator-runbook.md](operator-runbook.md). This repository is maintained by the Redact Secret project. The
controls here are project-maintained, not independent validation, and custody does not establish ground truth.

## 1. What is backed up, and how

| Asset | Sensitivity | How | Never |
| --- | --- | --- | --- |
| Runtime database (budgets, attempts, audit outbox, standing, feed, intake) | as sensitive as the live database | the store's own `backup_to` (`VACUUM INTO`, new 0600 file) | copy a live database file or only its main file; keep the backup beside the live file's disk only |
| Protected root: `sealed/`, `registry/` | as sensitive as the live root | one consistent snapshot, sealed directories first, registry after (protected-storage.md) | back up the commitment key with the corpus where avoidable |
| Commitment key (`keys/`) | key material | separate encrypted backup, separate access | store it in the repository, CI or the ledger |
| Operator policy file, pinned roots file, deployment config | integrity-critical, not secret | version them in the private operations log; the policy holds digests only | commit them to this repository |
| Private ledger | tamper-evident audit copy | it is its own off-host copy (remote); the independent checkpoint copy is separate (section 3) | treat it as the budget authority |
| Public feed directory | public | rebuildable from the store; the destination holds the canonical bytes | edit or delete a published file |
| Signing key | the most sensitive | section 7: not backed up by default | put it on a developer machine, in CI or in the ledger host |

A backup is restricted data: encrypted at rest, owner-only, with its own retention (section 5). The drill below
shows the backup file mode is checked (`0600`).

## 2. The recovery point is a decision, not a default **(decide)**

The ledger can only detect a rollback of what it was told. Spend recorded in the database and not yet exported
is invisible to every check, so restoring a backup that predates it is not refused, and the lost spend can be
spent again (including a second execution of an approved request). The drill measures exactly this
(`spend_after_the_last_export_is_the_documented_unrecoverable_window`): without an export the restore passes
`startup_check` and the request runs twice; with an export after the approval the same restore is refused.

The code gate now exists for dispatch (ADR 0116): with the gate enforced, `start` and the exposure record are
refused (`store_export_pending`) until the budget-affecting events are exported. The rules below still apply to
spend that predates the gate and to backups themselves. Operating rules:

1. Run `repair export` after every approval and before the worker is started for it.
2. Take a database backup at least as often as the operator accepts to lose spend. The recovery point is the
   interval since the last backup **that is also exported**, and it is a number the maintainer signs off on.
3. Record the newest `(seq, chain)` and registry `(head, event_count)` in the independent checkpoint copy after
   each export (ledger.md, "Independent checkpoint and backup verification").
4. Never restore on a schedule or on a hunch. A restore is an incident action (docs/incident-response.md).

## 3. The restore drill

### 3.1 Automated (every CI run, synthetic data)

`crates/custodian-cli/tests/c12_restore_drill.rs` and `c12_keys_and_ledger.rs` run the drill against real
components (SQLite file, protected root, ledger, feed, bridge) with test keys:

| Drill step | Expected | Test |
| --- | --- | --- |
| Restore a backup older than the ledger's checkpoint | `startup_check` refuses (`startup_check` / `store_rolled_back`), the block is persisted, nothing is written | `restoring_a_database_older_than_the_ledger_cannot_double_spend_or_republish` |
| Redeliver the already-run request, and submit a new one | refused (`store_needs_reconcile`); the engine does not run again; the restored budget is not changed | same |
| Release request 1's evidence after a contamination the restored copy does not know about | eligibility is `unknown`, so nothing is released | same |
| `repair clear-reconcile` on the behind-the-ledger copy | refused (`store_behind_ledger`, exit 5) whatever the confirmations | same |
| Epoch-level repair (`lifecycle retire`) on the blocked copy | refused (`store_needs_reconcile`, exit 8): see section 4, case C | same |
| Reopen the newer copy | not blocked; consumed is 2, held 0, refunded 0; a replay charges and runs nothing; the contamination is in force | same |
| A contained restore with a leftover block | cleared only by the human operator with the exact store id and checkpoint sequence; dry run first; the clear is an audited `store.reconciled` event; budgets unchanged | `a_contained_restore_is_cleared_only_by_the_audited_exact_confirmation` |
| Spend after the last export | the restore is not detected (the documented window) and the mitigation closes it | `spend_after_the_last_export_is_the_documented_unrecoverable_window` |
| Ledger rolled back to an older state | the walk of the remaining prefix is clean; the independent copy shows the rollback; `reconcile ledger` is not `consistent`; `repair ledger-reconcile` re-writes identical bytes | `a_ledger_rolled_back_to_an_older_state_is_found_by_the_independent_copy_and_repaired` |
| A hole, a forged record or a foreign signature in the ledger | `ledger_untrusted`, exit 8, store write-blocked | `a_hole_a_forged_record_or_a_foreign_signature_in_the_ledger_blocks_the_store` |
| Ledger or signer outage during export | events stay pending, disclosure closed, budgets untouched, one pass drains afterwards | `export_and_signer_outages_keep_events_pending_and_disclosure_closed_then_drain` |
| No copy reaches the ledger checkpoint (the previously blocking case) | `repair loss-plan`, then `repair accept-loss` with exact confirmations adopts the ledger's acknowledged tail, raises budgets to the ledger's figures, retires affected epochs and clears the block atomically; the same request does not run again; startup passes after export | `s6_recovery.rs::the_previously_blocking_restore_is_recovered_by_an_explicit_audited_acceptance` |
| A store that is not a prefix of the ledger, a healthy store, a tampered ledger | `lineage_diverged` (exit 8), `store_not_behind_ledger`, `ledger_untrusted`; nothing written | `s6_recovery.rs` (three tests) |
| Compromised signing key: revoke, re-issue under a new key, clear, start again | the old lineage is kept and marked (`revoked_superseded`), nothing rewritten, the ledger walks clean, writes resume under the new key | `s6_key_revocation.rs`, `custodian-ledger/tests/reissue.rs` |

### 3.2 Manual rehearsal on the real deployment (not yet done; human, before any protected run)

ADR 0001 T4 item 6 requires a backup and restore rehearsal. Do it on a copy, never on the live store:

1. Take a backup with `backup_to` and verify it: `integrity_check`, `verify_invariants`, mode `0600`, and
   `verify checkpoint` after opening it read-only on the rehearsal host.
2. Record the backup's `latest_checkpoint` next to the independent copy.
3. Create synthetic activity (a conformance control, never a protected run), export, and restore the older
   backup. Confirm `startup_check` refuses and nothing can be cleared. Restore the newer one and confirm start.
4. Record the date, operator, backup identifiers, observed codes and the outcome in the private operations
   log. Report the result without printing secrets.

## 4. What to do after a restore

| Case | Observed | Do |
| --- | --- | --- |
| A. Restored copy contains the ledger's checkpoint | `startup_check` passes (or only a stale block remains) | `verify all`; if blocked, `repair clear-reconcile --dry-run` then the real command (runbook 6.3 step 5) |
| B. Restored copy is behind the ledger, a newer copy exists | `store_rolled_back` | restore the newer copy and repeat; keep the blocked copy for the record |
| C. Behind the ledger and no copy reaches the checkpoint | `store_rolled_back`, clear refused, every command refused | **Treat as an incident, then decide.** The blocked store cannot be repaired from inside, but since S6 it can be continued under an explicit, audited loss acceptance (ADR 0130; operator-runbook 6.3 step 3.2): `repair loss-plan`, compare with the **independent checkpoint copy**, `repair accept-loss`, `repair export`, `verify all`, re-record the lost feed obligations the plan listed, rotate the retired epochs. It adopts the ledger's acknowledged audit tail, raises every budget to the ledger's figures (never lowers, never resets), retires the epochs with activity in the lost window and records the acceptance. It cannot recover what the ledger was never told (section 2), the requests of the lost window (their cost is carried by the budgets), or feed obligations (their targets are not in the ledger). A store that is not a prefix of the ledger (`lineage_diverged`) is not a rollback: stop. Do not edit the database, do not lower or recreate budgets, do not delete the ledger. |
| D. Restore passes but spend since the last export is lost | no signal | the documented window; compare the independent copy and the operator log with the restored store; if any approved request is missing, treat the affected epochs as retired (they may have spent budget) once the store is writable, and record the loss as an incident |

## 5. Retention and deletion schedule **(decide)**

The values are proposals for the maintainer to approve and record; the repository sets none of them. Deletion is
not secure erasure on journaling or copy-on-write filesystems or SSDs: rely on volume encryption and key
destruction (protected-storage.md).

| Data | Proposed retention | Deletion procedure |
| --- | --- | --- |
| Runtime database, live | life of the deployment; history tables are append-only and are never trimmed | none; a successor store is a new lineage |
| Database backups | the newest N plus one per week for M weeks **(decide N, M)** | delete the file, expire cloud or snapshot copies on the same day, record it; a backup is as sensitive as the database |
| Intake queue rows (`done`) | keep until the matching submission is terminal plus a short window **(decide)**; `repair retention` can delete them (ADR 0117) | `repair retention` with explicit ages; hard floor 1 day |
| Pending and cancelled submissions | the same; bounded by `MAX_PENDING_SUBMISSIONS` (1024) | `repair retention` expires stale pending ones and purges acknowledged decided ones (floors 1 and 7 days) |
| Delivery replay claims | at least as long as GitHub can redeliver **(decide)** | `repair retention` (floor 7 days; only claims with no queue row) |
| Sealed epochs (protected root) | retired is not deleted: as long as receipts, revocation or dispute handling may refer to them **(decide)** | protected-storage.md "Retention and deletion": confirm no dependency, retire, final verification record, remove the epoch directory, expire its backups on the same schedule |
| Failed or abandoned staging epochs, worker staging | removed at the end of every run; sweep leftovers weekly **(decide)** | `discard_staging`; ordinary deletion |
| Private ledger | life of the deployment | never rewritten; corrections are superseding records |
| Independent checkpoint copy | life of the deployment | append only |
| Public feed envelopes | life of the deployment (consumers depend on a contiguous log) | never edited or removed |
| Service-manager logs of the control service | short **(decide)**; the code writes no log of its own and the CLI prints only fixed codes | rotate by the service manager; never include request bodies, headers or tokens |
| Operator credentials | until rotated; the policy holds only digests | rotate by a reviewed policy revision |
| Incident records | indefinitely, restricted | not deleted to hide a failed run (SECURITY.md) |

## 6. Verification evidence to keep

For every restore or rehearsal keep, in the private operations log: who, when, which backup, the
`verify all` result, the checkpoint comparison, the codes seen and what was decided. These are identities,
digests and fixed codes; never protected content.

## 7. Signing-key recovery and rotation

Algorithm: Ed25519 (ADR 0050). Verification needs public keys only. The key is generated on the signer host,
never on a developer machine or in CI, and the control service, workers and agents never hold it. No signer
process or key exists yet.

### 7.1 Generation and pinning (human, once)

1. Generate the root key on the signer host; record only the public key (64 hex characters).
2. Pin that public key out of band: the operator's `roots.json` (a file not writable by others), the
   independent checkpoint location, and every consumer (benchmarks pins it in its own configuration). Never
   take a key from the ledger or the feed.
3. Decide **(decide)** whether the private key is backed up. Recommended default: **do not back it up**. The
   past stays verifiable with the public key; loss is recovered by section 7.3. A backup creates a second
   place to compromise. If a backup is required, it is offline, encrypted, split between two people, and listed
   in the access checklist.

### 7.2 Planned rotation (tested: `key_rotation_continues_the_chain_of_trust_from_the_one_pinned_root`)

1. Stop writers and run `repair export` until the outbox is empty. A backlog exported after the switch is
   refused by the new key (`events_still_pending_when_the_signer_switches_cannot_be_signed_by_the_new_key`).
2. On the signer host generate the new key. Publish it with a `key-event` signed by the old key
   (`published`, purposes, `effective_at`). Choose `effective_at` at or before the oldest record the new key
   must sign, **including the policy record dated by the activation change**; otherwise the first release under
   an older activation fails closed with `signing_refused`
   (`rotation_with_a_key_valid_only_from_now_refuses_the_first_release_of_an_older_policy`).
3. Switch the signer to the new key only after the publish record is durable in the ledger.
4. Retire the old key with an event signed by the new key and an effective time **at least one second after**
   the publish record's issue time. Same-second publish and retire fail closed
   (`publishing_and_retiring_in_the_same_second_fails_closed_so_rotation_needs_distinct_times`).
5. Every exporter's and disclosure service's verifier is built from the walked keyring (pinned roots plus
   verified key events), not the pinned roots alone; the control plane's own export already does this.
6. Pin the new public key in every consumer out of band before the first release under it. A consumer pinned
   only to the old key accepts nothing signed by the new one
   (`a_release_signed_by_a_rotated_key_needs_the_new_pin_at_the_consumer`).
7. `verify all` must report a trustworthy ledger with the single original pinned root.

### 7.3 Key lost, no compromise

The old signatures remain valid. Generate a new root on the signer host and pin it **as an additional root**
next to the old one (the keyring holds several roots) in the operator's roots file and in each consumer. Publish
a retire event for the old key signed by the new root. Resume after `verify all`.

### 7.4 Key compromised

Revocation rejects every signature the key ever made, so the ledger walk reports findings and the control
plane refuses to start until the history is re-attested under a new key. Since S6 that is a tool, not a
blocker (ADR 0131). Containment comes first (docs/incident-response.md, section 5). Then, in order:

1. **Stop the signer and the control service.** Preserve the ledger (and a copy of the store); do not delete
   anything.
2. **Generate the new key on the signer host** and read its public key (`custodian-signer --print-public-key`).
   Pin it **as an additional root** out of band: the operator `roots.json`, the independent checkpoint
   location and every consumer. Set its `valid_from` **at or before the oldest ledger record**
   (R-6: a key signs only records dated at or after its start; the tool refuses otherwise). Keep the old root
   pinned so its history stays readable. Authorize the new key for every ledger domain.
3. **Point the signer at the new key** and start it. Choose a time for step 4 that is not the same second as
   any existing key event (R-5; the tool refuses otherwise).
4. `custodian repair revoke-key --key-id <old> --confirm-key-id <old>`. The new key signs a `revoked` key
   event. The control plane now refuses to start on this ledger: that is the intended containment.
5. `custodian repair reissue-plan` (read-only). Read `records_to_reissue`, `corroborated` and `uncorroborated`.
   Every audit event and checkpoint must be corroborated by the store. `uncorroborated` counts policy,
   publication, reconciliation and key-event records: they hold digests and identities only, but you are
   confirming that you reviewed them by confirming the digest. A refusal
   `reissue_contradicted_by_store` means a record signed by the old key is not in the store (a forgery made
   with the stolen key): stop and treat it as an incident; the tool will not launder it.
6. `custodian repair reissue-ledger --confirm-revoked-key-id <old> --confirm-new-key-id <new>
   --confirm-plan-digest <digest>`. Each unattested record gets a **superseding** record with the same body
   and issue time, signed by the new key, at a new path; the old files are untouched and are reported as
   `revoked_superseded` (marked, informational). One `reconciliation` record marks the step. The ledger must
   walk clean afterwards or the command reports `reissue_post_check_failed`.
7. `repair clear-reconcile` with the exact confirmations (the startup refusal had persisted the write block;
   the clear is an audited `store.reconciled` event), `repair export`, `verify all`.
8. Publish `key_compromise` revocations for every affected projection and receipt (`feed record-revocation`,
   `feed publish`). Projections and revocation envelopes already signed by the old key are not re-signed;
   consumers reject them by key revocation.

Limits (ADR 0131): a revoked-key record that is itself a correction is not re-issued; one revoked key at a time;
a forged record cannot be removed, only left blocking. The procedure is verified on public synthetic data with
test keys; it has not been rehearsed with a real signer host.

### 7.5 Operator credential and webhook secret

Operator credentials are rotated by a reviewed policy revision (runbook 2.2); the GitHub App private key and
webhook secret by docs/github-app.md (key and secret rotation). None of these are stored in this repository.

The retention tool takes every age explicitly and has hard floors; the values in the table stay proposals until
the maintainer approves them. Nothing unacknowledged by the ledger is deleted.
