# 0131. Ledger re-issue under a new key after a revocation (R-4, with R-5 and R-6)

- Status: accepted; implemented in `custodian-ledger` and `custodian-cli`; not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

Revoking a signing key rejects every signature it ever made ([ADR 0050](0050-receipt-signature-algorithm-keys-and-signer-isolation.md),
[ADR 0101](0101-restore-recovery-window-and-signing-key-operating-constraints.md) decision 4). The ledger walk
then reports findings and the control plane refuses to start, and no tool re-issued the history (register entry
R-4, a blocker for compromise recovery). The re-issue must not rewrite or delete anything, must leave the old
lineage visible and marked, and must keep two earlier constraints from being left to the operator: key events
are applied in `(issued_at, record id)` order, so two in the same second are ambiguous (R-5); a key signs only
records dated at or after its start, so a new key valid only from now cannot re-attest older records (R-6).

## Options

| Option | Judged against: append-only; old lineage kept and marked; verifier walks both; no laundering of a forgery; R-5 and R-6 enforced |
| --- | --- |
| A. Defer | R-4 stays a blocker |
| B. Revoke "from a time" instead of forever | Changes the key model; a thief who backdates is trusted; rejected in ADR 0101 |
| C. Rewrite the old records under the new key | Violates append-only; destroys the evidence |
| D. A new record kind or signing domain for a lineage marker | Needs the signer's key purposes extended in every deployment; larger blast radius than the need |
| E. Superseding records signed by the new key, same body and issue time, corroborated against the store; the revocation is a key event signed by the new (pinned) key; the walker marks the superseded revoked-key records instead of failing on them | Reuses the supersession mechanism of ADR 0051 and the existing domains; nothing is deleted |

## Decision

Option E, two operator steps, human operator only.

1. **Procedure precondition (backup-recovery.md 7.4).** The new key is generated on the signer host and pinned
   **as a root** out of band (roots file and every consumer), with a `valid_from` at or before the oldest
   record it must re-attest. The signer now signs as the new key. The old key may itself be a pinned root; it
   stays pinned so its history stays readable.
2. **`repair revoke-key`** records, signed by the new key, a `revoked` key event for the old key. It refuses
   when the signer is the revoked key, when the new key is unknown, revoked, not authorized for key events or
   not yet valid, when the old key is unknown, and when another key event shares the second (R-5). Idempotent.
   After it the ledger is untrusted by design (the containment) and the control plane will not start.
3. **`repair reissue-plan`** (read-only) lists the records signed by the revoked key without a valid
   re-attestation and prints a `plan_digest` over the revoked key and every record id. **`repair
   reissue-ledger`** re-attests them. It needs the revoked key id, the new key id and the plan digest, and
   checks R-6 (the new key valid from at or before the oldest record, not retired before the newest, authorized
   for every domain involved).
4. **Re-attestation is a superseding record**: the same body and the same `issued_at`, signed by the new key, at
   a new path (`LedgerRecord::superseding`). Nothing is overwritten; the old files are byte-identical afterwards.
   One `reconciliation` record (outcome `repaired`, count of re-issued records) marks the step.
5. **Corroboration against the store.** An audit event is re-attested only if the store holds exactly that
   event (sequence, event id, kind, chain value, payload digest). A store checkpoint only if the store contains
   it; a registry checkpoint only if the registry does. A revoked-key record the store does not corroborate
   (a forgery made with a stolen key) refuses the whole plan (`reissue_contradicted_by_store`) and the ledger
   stays untrusted. Policy, publication, reconciliation and key-event records cannot be corroborated by the
   store; they are re-attested only because the operator confirmed the plan digest that names every one of them.
6. **The walker marks, it does not forgive.** A record signed by a revoked key is `revoked_superseded`
   (informational, like quarantine) only if a *valid* record re-attests exactly the same body and issue time.
   Otherwise it stays `BadSignature(KeyRevoked)` and blocking. A superseding record with a different body is a
   correction, not a re-attestation, and does not clear the finding. The audit chain is computed over the
   effective records, so it is gap-free again. A key pinned as a root and also published by a ledger key event
   with the same public key is not a rejection.
7. **Starting again is audited.** The store's write block, set by the refused startup check, is cleared only
   by `repair clear-reconcile` with exact confirmations (an `store.reconciled` event naming the operator), which
   itself requires the ledger to walk clean and the store to contain the checkpoint. Then `repair export` and
   the normal startup.

## Stated limits

- A revoked-key record that is a correction of another record (it has `supersedes`) is not re-issued
  (`reissue_correction_chain`); it needs a manual decision.
- More than one revoked key with records in the ledger is re-issued one at a time (`reissue_more_than_one_revoked_key`).
- A forged record the store never produced cannot be removed; the ledger stays untrusted. The fallback is a new
  ledger lineage, which is not implemented.
- Public projections and revocation envelopes already signed by the revoked key are not re-signed. Consumers
  reject them by key revocation and the feed carries `key_compromise` revocations for the affected projections
  (incident-response.md section 5).
- The isolated signer process path for the re-issue is the same `Signer` trait as the export; the combination
  is exercised by the export tests, and re-issue tests use the in-process signer with test keys.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Revoke, re-issue, clear, start again, resume writing; both lineages walk; old files byte-identical; reconcile is consistent | `crates/custodian-cli/tests/s6_key_revocation.rs::a_compromised_key_is_revoked_reissued_and_the_control_plane_starts_again`, `crates/custodian-ledger/tests/reissue.rs::history_signed_by_a_revoked_key_is_reattested_without_rewriting_anything` |
| A forged record made with the stolen key is not laundered; a refused step writes nothing | `s6_key_revocation.rs::a_record_made_with_the_stolen_key_that_the_store_never_produced_is_not_laundered`, `reissue.rs::a_forged_record_made_with_the_stolen_key_is_never_laundered` |
| R-5 and R-6 are enforced; wrong confirmations and signers are refused | `reissue.rs::the_procedure_constraints_are_enforced_by_the_tool`, `s6_key_revocation.rs::a_new_key_valid_only_from_now_cannot_reattest_older_history` |
| A different-body superseder does not count | `reissue.rs::a_reattestation_with_a_different_body_does_not_count` |

All keys are generated in the tests; data are synthetic. Functional verification on public synthetic data, not
an independent protected evaluation.

## Failure and recovery

Writes are idempotent (identical bytes are `Identical`; different bytes are quarantined by the exporter). A
crash mid-way leaves a prefix of re-attestations; the plan recomputes and the command resumes. The post-check
walk must be clean or the command reports `reissue_post_check_failed`.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Revoke, plan, re-issue, walker marking, reconcile awareness | yes | yes (synthetic, test keys) | no |
| Rehearsal with the isolated signer on a real host | yes | no | no |

## Consequences, migration, exit

No schema change: allowlist keys for R-1 are added in the same change (additive); the new `revoked_superseded`
finding is informational. Supersedes the "bulk re-issue tool" deferral of ADR 0101 decision 4.

## Open risks and revisit triggers

Uncorroborated record kinds rest on the operator's review of the plan. Revisit with store-side corroboration
of publications and policy records if they become numerous.
