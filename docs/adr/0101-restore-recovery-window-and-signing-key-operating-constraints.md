# 0101. Restore recovery window and signing-key operating constraints

- Status: accepted (operating rules and deferred designs); the rules are enforced by tests that pin current
  behavior. Decision 2 (no newer copy) is resolved by [ADR 0130](0130-restore-loss-acceptance-with-no-newer-copy.md)
  and decision 4 (bulk re-issue) by [ADR 0131](0131-ledger-reissue-after-key-revocation.md); decision 3 (the
  dispatch gate) by ADR 0116. The text below is kept as written on 2026-10-03.
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The C12 restore drill (`crates/custodian-cli/tests/c12_restore_drill.rs`) and the key flow tests
(`c12_keys_and_ledger.rs`, `c12_revocation.rs`) exposed behavior that the earlier documents did not state or
stated incorrectly:

1. A database restored from a backup older than the ledger's checkpoint is write-blocked, and
   `repair clear-reconcile` is refused (`store_behind_ledger`). The operator runbook (section 6.3) said to then
   run `lifecycle retire` for the epochs that may have spent budget after the snapshot. That command is also
   refused (`store_needs_reconcile`, exit 8), because every state-changing command checks the block first. The
   documented way out was not executable. (Register entry R-1.)
2. Spend recorded in the database but not yet exported is invisible to the ledger. A backup that predates it
   restores without any refusal, and the lost spend can be spent again, including a second execution of an
   approved request. The window is exactly the time since the last successful export. (R-2.)
3. Revoking a signing key rejects every signature it ever made, so the ledger walk reports findings and the
   control plane refuses to start until the records are re-issued. No tool re-issues them. (R-4.)
4. Key events are applied in `(issued_at, record id)` order, and a retire whose effective time equals the
   publish record's own issue time invalidates that record, so publish and retire in the same second fail
   closed. (R-5.)
5. A key signs only records issued at or after its own start. Audit events keep the time they happened, and a
   release writes a policy record dated when the activation changed. After a switch, an outbox backlog or the
   first release under an older activation is refused by the exporter's self-check (`signing_refused`). (R-6.)

## Options

| Topic | Alternatives considered |
| --- | --- |
| Restore window | accept and document; export synchronously with every approval; require an acknowledged `reservation.created` before `start` |
| No newer copy | retire inside the blocked store (not possible); a new ledger lineage with a new store; a reviewed `accept-loss` command |
| Key revocation | leave as is; a bulk re-issue tool that supersedes records under a new key; revoke from a time instead of forever |
| Rotation | document the constraints; change the walker and signer so a new key may sign older-dated records |

## Decision

1. **Operating rules now** (documented in `docs/backup-recovery.md` and the runbooks, pinned by tests):
   run `repair export` after every approval and before the worker starts; take a database backup at least as
   often as the operator accepts to lose spend; the recovery point objective is a human decision and is the
   export-and-backup interval, not zero.
2. **Restore with no newer copy** is a ledger-lineage rollover, not a repair of the blocked store. The design
   (not implemented): the operator stands up a new store with a new `store_id` and a new private-ledger
   lineage (a new repository or a new branch with its own pinned checkpoint), seals new epochs, and keeps the
   old ledger and the blocked database read-only as the incident record. The old epochs are retired by
   not being carried over; old budgets are never reused. This needs an ADR of its own and a CLI step
   (`repair begin-lineage`) before it can be relied on. Until then the answer to "no copy reaches the ledger's
   checkpoint" is: stop, treat it as an incident (`docs/incident-response.md`), and do not resume protected
   execution against the old store.
3. **Deferred code change for the window:** gate `start_attempt` on the reservation's audit event being
   acknowledged by the ledger, which closes the window for double execution at the cost of one export per run
   before dispatch. It is the smallest change that makes the drill's second half (`mitigation`) automatic.
4. **Key revocation** remains "reject everything signed by the key". Until a bulk re-issue tool exists, the
   compromise procedure assumes the ledger will be unreadable to the control plane after the revocation and
   plans for re-issue under a new key before resuming (`docs/backup-recovery.md`, key recovery). Designing the
   tool is a blocker for key-compromise recovery.
5. **Rotation procedure** (the constraints become steps): drain the outbox first; publish the new key with an
   effective time at or before the oldest record it must sign, including policy records dated by activation
   change; switch the signer after the publish record is durable; retire the old key at least one second later;
   build every exporter's verifier from the walked keyring, not the pinned roots alone; pin the new public key
   in every consumer out of band before the first release under it.
6. **Lost key without compromise:** pin a second root public key next to the first (the keyring holds several
   roots), sign a retire event for the old key with the new one, update consumers' pins. Old records still verify
   under the old pinned root.

## Security properties claimed

| Property | Test |
| --- | --- |
| A restore behind the ledger blocks writes, cannot be cleared, and does not double spend or republish revoked evidence | `restoring_a_database_older_than_the_ledger_cannot_double_spend_or_republish` |
| The block set by an earlier refusal is cleared only by the audited exact confirmation | `a_contained_restore_is_cleared_only_by_the_audited_exact_confirmation` |
| The residual window and its mitigation | `spend_after_the_last_export_is_the_documented_unrecoverable_window` |
| Rotation chains trust from one pinned root; same-second events and pending backlog fail closed | `key_rotation_continues_the_chain_of_trust_from_the_one_pinned_root`, `publishing_and_retiring_in_the_same_second_fails_closed_so_rotation_needs_distinct_times`, `events_still_pending_when_the_signer_switches_cannot_be_signed_by_the_new_key` |
| A key valid only from the rotation instant cannot sign an older policy record; a backdated one can | `rotation_with_a_key_valid_only_from_now_refuses_the_first_release_of_an_older_policy`, `a_release_signed_by_a_rotated_key_needs_the_new_pin_at_the_consumer` |
| Revocation makes the ledger untrusted until re-issue | `revoking_the_signing_key_makes_its_history_untrusted_until_it_is_reissued` |

## Failure and recovery

Every case above fails closed. The ledger is tamper-evident, not tamper-proof, and it detects only what it was
told: the independent checkpoint copy (docs/ledger.md) is what shows a ledger rolled back to an older state
(`a_ledger_rolled_back_to_an_older_state_is_found_by_the_independent_copy_and_repaired`).

## Performance evidence plan

`docs/measurements.md` records that every state-changing command walks and verifies the whole ledger, so
latency grows with ledger size (register entry R-7). Exporting after every approval adds one export per run.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Operating rules, runbook correction | yes | yes (documents) | no |
| Ledger-lineage rollover, `reservation.created` acknowledgement gate, bulk re-issue | yes (future) | no | no |
| Tests pinning current behavior | yes | yes | no |

## Consequences, migration, exit

The rules cost an export per approval and a stricter rotation checklist. The deferred code changes are additive
(a CLI step, a store check, a re-issue tool) and need their own ADRs and a migration only if the store changes.
Revisit when a daemon exists: the export-before-start gate is cheaper there.
