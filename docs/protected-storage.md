# Protected storage

Operations and failure behavior for protected populations. Design rationale: ADR 0030 and ADR 0031. Code:
`crates/custodian-corpus`. Status: implemented and tested with synthetic data in temporary directories;
**nothing is provisioned or deployed**, and no protected data has been or may be used to validate it.

This repository is maintained by the Redact Secret project. Custody and sealing attest origin and binding;
they do not prove that expectations are true or that review was independent.

## What is stored where

| Item | Location | In Git, CI, logs or ledger export? |
| --- | --- | --- |
| Corpus entry bytes | `sealed/<epoch>/entries/` (0400) | Never |
| Manifest (entry names, sizes, hashes) | `sealed/<epoch>/MANIFEST` | Never |
| Seal (binding, config digest, budget scope, provenance, review) | `sealed/<epoch>/SEAL` | Never |
| Registry (IDs, digests, counts, state) | `registry/events.jsonl` | Never; export only through the C12 allowlist |
| Commitment key | `keys/commitment.key` (0600) | Never |

No case text, case IDs, seeds, labels, ranges or raw outputs appear in registry rows or errors. Entry names are
caller-chosen and are only in the protected manifest; use opaque names.

## Where private bytes can and cannot go

- The storage root must be an operator-provisioned directory owned by the service identity with mode 0700,
  outside any Git working tree. `FsEpochStore::open` refuses a root that, or whose ancestor, contains `.git`
  (directory or file), a relative path, a symlink, a wrong owner or any mode other than 0700. Do not place the
  root under a checkout, a CI workspace, a synced folder or a world-readable mount.
- Corpus bytes only exist as `ProtectedBytes`: no `Display`, `Clone` or `Serialize`, redacting `Debug`,
  zeroed on drop (best effort). Callers must keep them out of logs, traces, prompts, caches and artifacts.
- Errors are `StorageReason` fixed codes; `Debug`/`Display` of every public type in this crate is free of
  paths, names and bytes (canary test).
- Ordinary repository CI uses only synthetic data generated inside tests; the repository tracks no corpus-like
  file and `.gitignore` is a convenience only.
- Ledger export (C12) receives identities, digests and states through `LifecycleObserver`; it never receives
  entry names, bytes, seal contents or the commitment key.

## At-rest access

- One service identity owns the root; no group or other access. Sealed entries are 0400, sealed directories
  0500. Every access re-checks owner, exact mode, link count, file type and symlinks; any deviation is a
  refusal (`permission_violation`, `owner_mismatch`, `symlink_refused`, `hardlink_refused`,
  `special_file_refused`).
- The worker and scanner identities (C6) get no filesystem access to the root. The control service reads
  through `CorpusAccess` and stages the verified bytes it needs into the worker's scratch.
- Operators with root-equivalent access to the host can read or alter anything. Use full-disk or volume
  encryption for the protected volume (not provided by this crate), restrict operator access, and log
  operator sessions outside the writer's control.
- Reads need `active` registry state. Retiring an epoch blocks new opens and reads immediately.

## Sealing procedure (programmatic)

`begin_epoch` (fresh opaque ID, staging) then `add_entry`, then `seal` with config digest, budget scope,
provenance, review attestation (not `not_reviewed`) and sealer. Seal publishes atomically and registers
`sealed`; `activate` makes it usable; `retire` ends use. Sealed is immutable: a changed corpus is a new epoch,
seal and (by policy) new budget; the old epoch remains as evidence until retention allows deletion.

## Backup and restore

- Back up `sealed/`, `registry/` and `keys/` together as one consistent snapshot, to storage with the same
  access class as the primary and encryption at rest. Keep the key backup separate from corpus backups where
  possible; a backup holding both is as sensitive as the live root.
- Sealed files are immutable, so incremental backup by directory is safe. Take the registry after the sealed
  directories so it never references an epoch the backup lacks.
- Restore into a new root, then run `verify_epoch` for every registered epoch (full hash) and compare the
  registry head digest to the last externally checkpointed one. A registry older than the checkpoint, a
  missing epoch or any `integrity_mismatch` blocks activation until a human reconciles. A restored registry
  must never lower consumed budgets (budget state is separate, C4).
- Restoring modes: restore with exact modes and ownership (0700/0600, sealed 0500/0400). Anything looser is
  refused on first access.

## Retention and deletion

- Retired is not deleted. Retain a sealed epoch for as long as receipts, revocation or dispute handling can
  refer to it; the retention period is a policy decision recorded by the maintainers (not set here).
- Deletion is an operator procedure: confirm no active receipt or open dispute depends on it, retire it, take
  a final verification record, change modes and remove the epoch directory, and expire backups on the same
  schedule. Deletion is not secure erasure on journaling or copy-on-write filesystems or SSDs; rely on volume
  encryption and key destruction for that.
- Staging epochs from failed or abandoned seals are removed by `abandon`/`discard_staging`; sweep leftovers
  periodically.
- The registry log is append-only and is retained for the life of the deployment; do not edit it.

## Adapter failure behavior (fail closed)

| Situation | Result |
| --- | --- |
| Backend I/O error or unavailable | `io_failure`; port reports `StoreUnavailable`; nothing returned |
| Entry bytes differ from the sealed manifest | `integrity_mismatch`; bytes not returned |
| Seal or manifest altered | `integrity_mismatch`, `seal_invalid` or `manifest_invalid` |
| Entry added, removed or unexpected file present | `integrity_mismatch` or `layout_invalid` |
| Directory swapped between epochs | `wrong_epoch` |
| Registry unreadable or chain broken | `registry_invalid`; no epoch opens |
| Epoch not `active` (sealed only, retired, unknown) | `not_active` or `unknown_epoch` |
| Seal fails before publish | staging discarded; nothing registered |
| Seal fails after publish, before registry append | inert sealed epoch (unusable without a row); operator reconciles |
| Handle unknown or closed | `invalid_handle` |

Retries are a caller decision; the adapter never retries, falls back to another copy, or "repairs" data. A
read failure after exposure still counts as exposure for budget purposes (the budget rules live in C4).

## Commitment and key handling

`population_digest` is the internal exact commitment (never public). The public reference is either an
opaque random `ppr_` ID or `public_commitment(epoch)`, an HMAC with the custodian-held key. The key is
generated locally, stored 0600 under `keys/`, never logged or exported. Rotation and loss: see ADR 0031;
rotation changes every public commitment and is a reviewed event.

## Limitations

- **No independence proof.** Structural validation cannot show that review was independent or that labels are
  correct. The seal records declared authorship and review in the C2 vocabulary; organizational independence
  is `not_claimed` and ground truth `not_established`.
- Tamper-evident only. Whoever can write as the storage owner can rewrite a sealed epoch, its seal and the
  registry consistently. Mitigations to add: checkpoint the registry head and per-epoch seal digests in the
  private ledger (C12), separate the key provider, and host isolation.
- The key and the corpus share a root in this first adapter.
- Single writer assumed; there is no cross-process lock. Run one control-service instance per root.
- Unix only; relies on POSIX ownership, modes and link counts. Network filesystems with weak semantics are
  unsupported.
- A hostile process running as the same owner can race the lstat/open check; same-owner code is trusted.
- Zeroing memory on drop is best effort, not secure erasure.
- Contamination handling and epoch rotation are in `custodian-lifecycle` (C9,
  [lifecycle-and-revocation.md](lifecycle-and-revocation.md)): the registry mirrors retirement and a new
  reviewed population is a new epoch and seal. The disclosure projection (C8) and worker staging (C6) are
  out of scope here.
- A real storage directory, host, volume encryption, backup target and retention schedule still need to be
  provisioned and approved by a human.
