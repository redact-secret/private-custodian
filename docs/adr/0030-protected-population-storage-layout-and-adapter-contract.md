# 0030. Protected population storage layout and adapter contract

- Status: accepted (design); implemented in `custodian-corpus` against synthetic data
- Date: 2026-10-02
- Deciders (by role): custodian maintainer, security reviewer (project-maintained; not independent)
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0002 chose filesystem-first protected storage behind the corpus port and left the layout, integrity
rules, registry and future object-store contract to C5 (issue #6). Requirements: private bytes must not reach
ordinary CI, staging, logs or ledger exports; a sealed corpus is immutable; every use re-proves integrity;
storage is infrastructure, not an extra GitHub repository. Threat assumptions follow ADR 0001: the storage
owner identity and host are trusted to the degree stated in `docs/protected-storage.md`; other local users,
the worker, scanners and the model are not.

## Options

1. **Filesystem adapter behind a small trait, with an adapter conformance suite** (chosen).
2. SQLite blobs in the runtime database. Rejected: mixes protected corpus bytes with budget/audit state that
   has different access, backup and retention needs (ADR 0002), and makes immutability depend on SQL grants.
3. Object store first. Deferred: needs a deployment decision (provider, KMS, object lock) that does not exist.
   The trait is shaped so it can be added without touching sealing or access code.
4. Defer entirely. Rejected: C6, C9 and C12 depend on a concrete access path.

## Decision

New crate `custodian-corpus` (std plus the already-pinned `serde`, `serde_json`, `sha2`; no new dependency).

**Layers.** `EpochBlobStore` (adapter: staged entries, atomic immutable publish, raw reads, never trusted for
integrity) below `ProtectedPopulations` (sealing, verification, registry, `CorpusAccess`).

**Layout** under an operator-provisioned root (0700, owner = service identity, absolute, not a symlink, not
inside any Git working tree):

```
staging/<epoch>/entries/<name>     dirs 0700, files 0600
sealed/<epoch>/entries/<name>      dirs 0500, files 0400
sealed/<epoch>/MANIFEST, SEAL      files 0400
registry/events.jsonl              0600, append-only, hash-chained
keys/commitment.key                0600
```

`<epoch>` is `epo_` plus 128 random bits (opaque, from `/dev/urandom`). Entry names match
`[a-z0-9][a-z0-9._-]{0,63}` without `..`; they are opaque to the custodian and appear only in the protected
`MANIFEST`, never in the registry.

**Sealing** publishes with one directory rename `staging/ -> sealed/` after all files are read-only. Sealed
means immutable: the adapter has no write, replace or delete for a sealed epoch, files are read-only on disk,
and a changed corpus is a new epoch with a new seal. Deleting a sealed epoch is an operator retention action,
not an API.

**Registry** rows (identity, digests, counts, state only) form a hash-chained JSONL log with states
`sealed -> active -> retired` (and `sealed -> retired`). Only `active` epochs can be opened. At most one
epoch is active per corpus and family. `LifecycleObserver` is the hook C9 (contamination) and C12 (audit
export) attach to; no contamination logic exists here.

**Filesystem controls**, applied on every access: `lstat` each component (no symlink, regular file, single
link, owner, exact mode), open, then compare device and inode of the opened descriptor with the `lstat`
result; bounded reads; fixed reason codes only. The owner is learned from a probe file the process creates, so
the crate needs no `unsafe` or `libc`.

**Future object-store contract.** An object-store adapter implements `EpochBlobStore` and must pass
`custodian_corpus::conformance::run`. Equivalent controls it must document in its own ADR: private bucket with
no public ACL, per-epoch prefix, server-side encryption with a key under custodian control, no overwrite
(create-if-absent) and versioning or object lock for sealed prefixes, atomic publish (for example a single
write of a completion marker that readers require), and fail-closed behavior on any ambiguous response.
Because integrity is verified above the adapter, a misbehaving backend is detected, not trusted.

## Security properties claimed

| Property | Test |
| --- | --- |
| Sealed epoch cannot be changed through the adapter or by the process | `changed_content_is_a_new_epoch_old_state_untouched`, `sealed_files_are_read_only_on_disk` |
| Tamper of entry, length, manifest, seal, added or removed entry is detected on open and on read | `tampered_*`, `added_or_removed_entries_are_detected`, `unexpected_file_in_sealed_epoch_is_a_layout_error` |
| Names cannot traverse | `entry_names_reject_traversal_and_odd_shapes`, `population_id_cannot_traverse_out_of_the_layout` |
| Symlink, hardlink, special file refused | `symlink*`, `hardlinked_*`, `special_file_is_refused` |
| Exact modes and owner enforced | `root_must_be_mode_0700`, `loosened_permissions_are_refused_on_access`, `owner_mismatch_is_refused`, `created_files_and_dirs_have_exact_private_modes` |
| Wrong or unknown epoch, inactive epoch refused | `swapped_epoch_directories_are_a_wrong_epoch`, `unknown_unsealed_inactive_and_retired_epochs_are_refused` |
| Root inside a Git working tree refused | `root_inside_git_working_tree_is_refused` |
| Adapter failure fails closed | `backend_failure_at_any_step_fails_closed`, `backend_outage_after_activation_refuses_with_store_unavailable` |
| No protected content in errors, Debug, registry or seal | `canary_leakage.rs` |

Tamper-evident, not tamper-proof: an actor with the storage owner's write access can replace a sealed epoch,
its seal and the whole registry consistently. See limitations in `docs/protected-storage.md`.

## Adapter contract

`EpochBlobStore` (create_staging, put_entry, list_entries, read_entry, finalize, read_doc, discard_staging,
is_sealed) and, above it, `CorpusAccess::open(&Authorization) -> CorpusHandle`. The authorization's
`PopulationId` is the epoch ID string. Opening is the exposure event and performs a full verification. Typed
reads (`read_entry`, `entry_names`, `binding`) take the handle and re-verify.

## Failure and recovery

- Backend error at any step: `io_failure`, mapped to `ReasonCode::StoreUnavailable` at the port; no partial
  result is returned and nothing verified is cached as trusted.
- Failed seal before publication discards the staging epoch. Failure after publication but before
  registration leaves an inert sealed epoch (reads require a registry row); an operator reconciles it.
- Crash during `finalize` leaves a staging epoch (discardable) or a published epoch with mode 0700 for an
  instant, which readers refuse.
- Invalid registry chain: nothing opens until an operator investigates.

## Performance evidence plan

Open hashes every entry, so cost is linear in corpus size; reads re-hash one entry. Measure open latency
and read throughput separately for representative synthetic sizes before any production claim. No check is
relaxed for speed.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Filesystem adapter, sealing, registry, verified access | yes | yes (synthetic tests) | no |
| Object-store adapter | yes (contract only) | trait and conformance suite only | no |
| Provisioned protected directory, backups, retention schedule | yes | no | no |
| Encryption at rest | yes (operator, volume level) | no | no |

## Consequences, migration, exit

Layout and seal versions (`seal_version`, `manifest_version`, domain strings) are versioned; a change is a new
version, never a reinterpretation. Switching adapters requires copying epochs and re-verifying every
commitment on the destination before activation. Retention or approval policy changes need a reviewed
revision.

## Open risks and revisit triggers

Single writer process assumed (no cross-process lock). No external checkpoint of the registry head yet.
Unix only. Revisit when the object-store adapter, a second control-service instance, or multi-tenant hosts are
proposed.
