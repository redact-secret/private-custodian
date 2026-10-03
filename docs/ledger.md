# Signed receipts and private-ledger export (C7)

Status: **implemented** in `crates/custodian-ledger` and tested with synthetic data and keys generated inside
the tests; **not deployed**. The `private-ledger` repository does not exist yet, no signing key exists, and
nothing in this repository creates either.
Decisions: [ADR 0050](adr/0050-receipt-signature-algorithm-keys-and-signer-isolation.md) (algorithm, keys,
signer isolation), [ADR 0051](adr/0051-ledger-record-layout-identity-and-supersession.md) (records),
[ADR 0052](adr/0052-ledger-backend-port-and-git-writer.md) (backend and Git writer),
[ADR 0053](adr/0053-outbox-exporter-acknowledgement-and-reconciliation.md) (exporter),
[ADR 0054](adr/0054-external-checkpoints-startup-check-and-independent-verification.md) (checkpoints, startup).
This repository is maintained by the Redact Secret project. The ledger is project-maintained evidence of
origin, binding and history; it is not independent validation and it does not prove ground truth.

## What the ledger holds

Reviewed policies, registry checkpoints, store checkpoints, signed audit receipts, publication records,
reconciliation records and key events. It never holds protected corpora, seeds, raw findings, input values,
worker free text, signing keys or the runtime database. Benchmarks cannot read it; it receives signed
approved projections and signed revocation envelopes only.

```
records/<kind>/<record_id>.json        one canonical signed file per record, never edited
quarantine/<record_id>/<sha256>.json   bytes that conflicted with an existing record id
```

`<kind>` is one of `audit`, `store-checkpoint`, `registry-checkpoint`, `policy`, `publication`,
`reconciliation`, `key-event`. The file content is canonical JSON (`custodian-canonical-json/1`, ADR 0004):

```
{ "payload": { "schema": "private-custodian.ledger-record/1", "record_id": "rec-<kind>-<32 hex>",
               "issued_at": <epoch seconds>, "supersedes": "<record_id>"?, "body": { "type": "<kind>", ... } },
  "signature": { "key_id": "key_...", "algorithm": "ed25519", "value": "<86 chars base64url>" } }
```

| Body type | Fields (all bounded; identities, digests, counters, fixed vocabulary) |
| --- | --- |
| `audit_event` | `seq`, `event_id`, `kind`, `chain`, `payload_digest`, `payload_exact`, `payload` (allowlisted keys, integer or identifier-shaped string values) |
| `store_checkpoint` | `seq`, `chain` |
| `registry_checkpoint` | `head`, `event_count` |
| `policy` | `activation` (`ActivationRef`), `document_digest` |
| `publication` | `projection_id`, `receipt_id`, `projection_digest`, `signature_key_id`, optional `decision` (C8, ADR 0063: `destination`, `disclosure_policy`, `execution_id`, `approval_id`, `approver`, `approver_kind`) |
| `reconciliation` | `outcome`, `store_events`, `ledger_records`, `missing_in_ledger`, `unacked_in_ledger`, `conflicting` |
| `key_event` | `key_id`, `action` (`published`, `retired`, `revoked`), `public_key`, `purposes`, `effective_at` |

Record ids are deterministic from the natural key, so a retry of the same logical record targets the same
path with the same bytes. `issued_at` comes from the event or the caller's observation time, never from the
export attempt. An identical retry is a no-op; different bytes under an existing id go to `quarantine/` and
are never written over; a correction is a new record with `supersedes` naming the original.

Public contract documents (`PublicProjectionEnvelope`, `SignedRevocationEnvelope`) are signed with the same
scheme but are distributed to consumers; their publication is recorded by a `publication` record.

## Signing scheme

- Algorithm: Ed25519, strict verification. Signature value: 64 bytes, base64url, no padding.
- Signed bytes: `domain || 0x00 || canonical_bytes(payload)` (ADR 0004). The signature is not part of the
  signed bytes. Domains: the contract tags for `public-projection` and `revocation-envelope`, and
  `private-custodian/v1/ledger/{audit-event,store-checkpoint,registry-checkpoint,policy,publication,reconciliation,key-event}`.
- Key identifiers: `key_` identities. Each key has a set of purposes (domains) and a validity window.
- Signing only happens through an `ApprovedPayload`: decoded as the document type of its domain, validated,
  and for a projection matched to a current release approval. Refusal codes are fixed.
- The signer process holds the key; the control service holds a `RemoteSigner`; workers and agents hold
  nothing. Keys are never in the repository, CI, a worker or an agent process.

## Key lifecycle

1. **Generate** a key in the key provider or signer host, never on a developer machine or in CI. Record only
   the public key.
2. **Pin roots.** The root public keys (hex) are stored out of band from the ledger (operator password
   manager, offline note, a repository owned by a different identity). The verifier is built from them.
3. **Publish** further keys with a signed `key_event` (`published`, purposes, `effective_at`) signed by a key
   already trusted for `key-event`.
4. **Rotate:** publish the new key, switch the signer, then `retired` the old key at the switch time. Old
   signatures stay valid; the old key is not valid for later `issued_at`.
5. **Revoke** a compromised key with a `revoked` event signed by another key. Every signature by that key is
   rejected, past ones included. Re-issue affected records as superseding records under a new key, and
   publish a `PublicRevocationReason::KeyCompromise` revocation envelope for affected public projections.
6. Retirement trusts the document's own `issued_at`; use revocation, not retirement, for compromise.

## Verification

### In code

`walk_ledger(backend, pinned_roots)` verifies the whole ledger and returns findings; `Verifier` checks one
projection, revocation envelope or record with public keys only; `startup_check` adds the store and registry
comparison.

### Offline, independently

A verifier needs: a clone of the ledger, the pinned root public keys, and any Ed25519 implementation.

1. Read a record file. Re-serialize `payload` as canonical JSON (sorted keys, no whitespace, ASCII only,
   integers only). It must equal the bytes of that member.
2. Build the signing input: the domain tag for the record's `body.type` (table above), one `0x00` byte,
   then the canonical payload bytes.
3. Base64url-decode `signature.value` (64 bytes) and verify with the public key for `key_id`. With OpenSSL
   3.x: prefix the 32-byte key with the DER header `302a300506032b6570032100`, convert to PEM, and run
   `openssl pkeyutl -verify -pubin -inkey key.pem -rawin -in input.bin -sigfile sig.bin`. This was checked
   by hand against a test-generated record with OpenSSL 3.6 ("Signature Verified Successfully"); it is not an
   automated test.
4. Check `record_id` by recomputing it from the natural key (ADR 0051), the key's purposes and validity, and
   that audit records form a gap-free chain: `chain_n = SHA-256("private-custodian/store/outbox-chain/v1\0" ||
   chain_{n-1} || 0 || n || 0 || payload_digest)` with `chain_0` = 64 zeros.

### Independent checkpoint and backup verification

Git history is mutable. A person with force-push rights can rewrite the ledger and an attacker with host
root can rewrite both the database and the exporter, so Git alone is not a tamper-proof archive. To make
rollback and tail truncation detectable:

- After each review, record the newest `(seq, chain)` and registry `(head, event_count)` somewhere the
  ledger writer and the host cannot modify (offline note, or a mirror repository written by a different
  identity). Compare it with the ledger and the store at the next review.
- Keep pinned root public keys off the ledger host.
- Verify every restored backup with `startup_check` before it serves, and keep backups with the same
  sensitivity as the database.

## Recovery

| Situation | What happens |
| --- | --- |
| Ledger unreachable | Export retries with backoff, then defers; events stay pending; disclosure stays closed; startup refuses. |
| Crash between ledger write and ack | The next pass finds identical bytes and acks. `reconcile` reports and repairs the same. |
| Conflicting bytes under an id | Quarantined; event stays pending; pass is `Blocked`; review, then supersede or fix the producer. |
| Restored older database | `startup_check` refuses and the store persists `needs_reconcile`; reconcile consumed budget to at least the ledger's figures by a reviewed procedure, then `clear_reconcile`. |
| Writer clone lost | Re-clone the ledger; it holds no state absent from the remote. |
| Key compromise | Revoke, publish a new key, supersede affected records, publish revocations. |
| Signer unavailable | Export errors with `sign_signer_unavailable`; nothing is written. |

## Manual private-ledger provisioning and access-check checklist

None of this is performed by code or by C7. Each step is a human action on the real GitHub organization and
host, taken only after the readiness review in ADR 0001; do not run it in CI.

Provision (human, later):

1. Create a **private** repository `private-ledger` in the project organization with no public forks and
   forking disabled. Do not create it from this repository's automation.
2. Add an initial commit containing only a README that states it is project-maintained and private.
3. Protect `main`: block force-push and deletion, require linear history, and allow pushes only from the
   ledger-writer identity. Do not require reviews on writer pushes (the writer is automated) but alert on any
   non-writer push.
4. Create a dedicated ledger-writer identity (a deploy key scoped to this one repository with write access,
   or a fine-grained token limited to this repository's contents). No other repository, no admin scope, no
   workflow permission. Store it in the exporter host's secret store. Never reuse the GitHub App, CI or a
   personal credential.
5. Grant read access to the minimum named operators; no benchmarks identity, no CI identity, no agent
   identity.
6. Choose and record the independent checkpoint copy location and review cadence (see above).
7. Generate the signing key on the signer host, record the public root key out of band, publish it with a
   `key-event` signed by the root.

Access checks (human, repeat at each review; report results without printing secrets):

- [ ] Repository visibility is private; forking is disabled; no deploy key other than the writer's exists.
- [ ] The writer identity can push `main` and cannot force-push, delete the branch, change settings or read
      any other repository.
- [ ] The benchmarks, CI, App and agent identities cannot read or write the repository.
- [ ] A test push from a non-writer identity is rejected or alerts.
- [ ] `GitBackend::audit_history` reports no violations; `walk_ledger` is clean with the pinned roots.
- [ ] The independent checkpoint copy matches the ledger's newest checkpoint.
- [ ] The signing key is reachable only by the signer identity; the control service, workers and agents have
      no key file, environment variable or socket permission for it.

## Interfaces for downstream issues

- `Signer::sign(&ApprovedPayload)`; build payloads with `ApprovedPayload::projection` (needs the release
  `Approval`, execution id, observed activation, `now`), `::revocation`, `::ledger_record`.
- `Verifier::{verify_projection, verify_revocation, verify_ledger_record, verify_bytes}` over a `Keyring`.
- `Exporter::{export_pending, write_record, record_store_checkpoint, record_registry_checkpoint,
  reconcile}`; record constructors on `LedgerRecord` (`policy`, `publication`, `reconciliation`,
  `key_event`, `superseding`).
- `walk_ledger`, `startup_check(backend, roots, store, registry)` with `StartupRefusal` codes.
- `OutboxSource` (implemented for `SqliteStore`), `LedgerBackend` (`GitBackend`, `MemoryBackend`).
