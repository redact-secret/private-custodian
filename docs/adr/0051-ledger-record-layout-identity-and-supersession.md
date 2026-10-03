# 0051. Ledger record layout, identity, append-only semantics and supersession

- Status: accepted (design); implemented in `crates/custodian-ledger` (C7); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The private ledger holds reviewed policies, registry checkpoints, signed receipts, publication and
reconciliation records, never corpus, secrets, raw fields, worker text or the live database (issue C7,
SECURITY.md). Identical retries must be idempotent, different bytes under an existing id must be
quarantined, and corrections must append superseding records. The architectural test is whether a record
would still make sense without any particular scanner or the Redact Secret product.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Layout | one file per record at a content-derived path; one append-only log file; one directory per run |
| Identity | deterministic hash of the natural key; random id; sequence number |
| Export payload | closed key allowlist with bounded values; copy the store payload as is; digest only |
| Corrections | superseding record naming the original; in-place edit; delete and rewrite |

Criteria: retry safety (same input, same bytes), conflict detection without locking, no secret-bearing
free text, easy independent verification.

## Decision

1. **One canonical file per record**, `records/<kind>/<record_id>.json`, containing
   `{payload: LedgerRecord, signature}` in `custodian-canonical-json/1` (ADR 0004). `LedgerRecord` is
   `{schema, record_id, issued_at, supersedes?, body}` with a closed, tagged `body`. Kinds: `audit_event`,
   `store_checkpoint`, `registry_checkpoint`, `policy`, `publication`, `reconciliation`, `key_event`. Strict
   decoding denies unknown fields, enforces a size cap, requires the canonical encoding, and rejects any
   other `schema` tag (`private-custodian.ledger-record/1`).
2. **Deterministic ids.** `record_id = "rec-" kind "-" hex(SHA-256(domain || kind || natural key)[..16])`.
   The natural key is the store `event_id` for audit events, the content digest for policies and publications,
   `(seq, chain, observed_at)` and `(head, count, observed_at)` for checkpoints, and `(key_id, action)` for key
   events. `validate` recomputes the id, so a record cannot claim another record's path. `issued_at` is the
   event's own creation time or the caller's observation time, never the export attempt time, so a retry
   produces identical bytes (Ed25519 is deterministic).
3. **Export payload allowlist.** An audit record embeds the store event payload only if every key is in
   `PAYLOAD_KEY_ALLOWLIST` (identities, digests, counters, fixed vocabulary, store timestamps) and every
   value is a bounded integer or an identifier-shaped string (`[A-Za-z0-9._:/-]`, at most 128 characters).
   Unknown keys, nested values, arrays, floats, spaces and non-ASCII are refused, not dropped; the event stays
   pending and the exporter reports it. Null members are omitted and flagged `payload_exact = false`. The
   store payload text must match its own recorded digest before anything is signed.
4. **Append-only by interface.** The backend port offers create-if-absent, read and list only. The exporter
   never overwrites. Identical bytes are `Identical`; different bytes are `Conflict` and the new bytes go to
   `quarantine/<record_id>/<sha256>.json`; the event is not acked. The one exception to quarantine is the same
   payload under a different, valid signature (a retry after key rotation): the existing record is kept.
5. **Corrections append.** `LedgerRecord::superseding(prior)` sets `supersedes` and re-derives the id (the
   correction lands at a new path). It must be the same kind. The walker flags a missing target, two
   corrections of one record, and an audit correction that changes sequence or chain value.
6. **Whole-ledger verification.** `walk_ledger` verifies decoding, path and id agreement, signatures against a
   keyring built from pinned roots plus key events, supersession, the audit hash chain (gap-free from
   sequence 1, recomputed with the outbox chain construction of ADR 0022) and checkpoint forks, and lists
   quarantine. It needs no private key and no database.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Unknown fields, wrong schema, non-canonical bytes and forged ids are rejected | `tests/signing.rs::ledger_record_wrong_schema_and_non_canonical_are_rejected` |
| No raw field, free text or canary enters a record; refusal leaves the event pending | `tests/exporter.rs::raw_fields_and_worker_text_never_enter_records`, `exported_ledger_contains_no_candidate_population_or_canary_text` |
| An event that disagrees with its digest is not signed | `an_event_that_disagrees_with_its_own_digest_is_not_signed` |
| Identical retry is idempotent | `identical_retry_is_idempotent`, `second_export_pass_has_nothing_to_do` |
| Differing bytes are quarantined and never overwritten | `export_conflict_is_quarantined_not_overwritten_and_event_stays_pending` |
| Corrections append; forks and missing targets are flagged | `corrections_append_superseding_records_and_forks_are_flagged` |
| Gaps, forged signatures, edited payloads and misplaced files are found by the walker | `walker_detects_forged_gapped_and_unsigned_records` |

## Adapter contract

Records are backend-neutral bytes at validated relative paths (`LedgerPath`). Any backend that provides
create-if-absent with durable-on-return semantics can host them.

## Failure and recovery

A record that cannot be built from an event is refused with a fixed `RecordError` code and the event stays
pending; the operator fixes the producer, never the record. A quarantined record needs human review; the
resolution is a superseding record or a documented decision, not an edit.

## Performance evidence plan

Records are at most a few hundred bytes plus signature; the walker is linear in record count. Measure walk
time at startup; if it becomes slow, walk from the last verified checkpoint (revisit trigger).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Record kinds, ids, allowlist, supersession, walker | yes | yes (synthetic) | no |
| Publication records produced by a disclosure service | yes | type only (C8, C9 produce them) | no |

## Consequences, migration, exit

Adding a field or kind is a new schema version and a new domain; old records stay valid and are never
reinterpreted. Moving hosting changes only the backend.

## Open risks and revisit triggers

The allowlist is a closed set maintained with the store: a new store payload key makes export fail closed
until it is reviewed and added. Revisit if payload volume or record count makes per-file Git storage slow.
