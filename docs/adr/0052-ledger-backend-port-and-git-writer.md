# 0052. Ledger backend port and conflict-aware Git writer

- Status: accepted (design); implemented in `crates/custodian-ledger` (C7); not deployed
- Date: 2026-10-02
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0002 selects a restricted private-ledger Git repository written by a dedicated ledger-writer identity.
The repository does not exist yet and this work must not create it or touch live permissions. The writer
must be serialized or optimistic and conflict-aware, and Git history is mutable, so it is a tamper-evident
outside copy, not a tamper-proof archive.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Port | a narrow trait with create-if-absent, read, list; a Git-specific writer; object storage |
| Concurrency | in-process mutex plus compare-and-swap on the remote branch; lock file; per-record branches |
| Update | fetch, reset to tip, add, commit, plain push, retry on rejection; `git pull --rebase`; force push |
| Test remote | local bare repository; mocked git; network remote |

## Decision

1. **`LedgerBackend` port**: `refresh`, `get`, `put_new` (create-if-absent, durable on return, never
   overwrites), `list`. Paths are validated (`LedgerPath`: lowercase segments, no `..`, no leading `-`, no empty
   segment). Backends: `MemoryBackend` (fake, with injectable unavailability, lost responses and direct
   writes) and `GitBackend`.
2. **`GitBackend` on a dedicated local working clone**, using structured `git` argv (no shell), with hooks
   disabled, no prompts, no global or system config, and the commit identity from configuration. Each
   `put_new` holds an in-process mutex, then: `ls-remote` the branch; `fetch`; force-checkout the branch to the
   remote tip (discarding any unpushed local commit); clean untracked files; check the target path (identical
   bytes: `Identical`; different: `Conflict`, no commit); write the file with create-new; `add`; `commit`;
   plain `push`. A rejected push (the remote moved) is a lost compare-and-swap: the local commit is discarded
   and the step restarts on the new tip, so a record another writer created with different bytes is seen as a
   conflict. After the configured rounds, `Busy` (retryable). An unreachable remote is `Unavailable`
   (retryable). The backend never force-pushes, never rebases and never merges, so history stays linear.
3. **Crash safety.** Pushed but unseen: the next call finds identical bytes. Committed but not pushed: the next
   call discards the commit and rewrites it. Neither can duplicate or corrupt a record.
4. **`audit_history`** scans branch history for any commit that modifies, deletes or retypes a file under
   `records/` or `quarantine/`. It detects careless edits and accidents; a malicious history rewrite is
   addressed by the independent checkpoint copy in ADR 0054, not by this scan.
5. **Scope of this issue.** The writer is exercised only against tempdir repositories with a local bare
   repository as remote. The private-ledger GitHub repository, its deploy identity and branch protection are a
   manual provisioning checklist in `docs/ledger.md`; nothing here calls GitHub.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Create, identical and conflict semantics; a conflicting write changes nothing | `tests/git_backend.rs::create_identical_and_conflict_against_an_empty_remote` |
| A stale clone still detects an existing record | `a_second_writer_sees_the_first_and_conflicts_are_detected_across_clones` |
| Concurrent writers serialize by compare-and-swap; exactly one wins a contested id; history stays linear | `concurrent_writers_serialize_through_compare_and_swap` |
| Unreachable remote is `Unavailable` and recovery creates no duplicate | `unreachable_remote_is_unavailable_and_recovers_without_duplicates`, `retry_after_remote_outage_does_not_duplicate_or_quarantine` |
| A push the remote rejects is never reported as created and leaks into no read | `push_rejected_by_the_remote_is_not_reported_as_created` |
| History edits and deletions are flagged | `history_audit_flags_modified_and_deleted_ledger_files` |
| The ledger survives loss of the writer clone | `exporter_writes_through_git_and_survives_loss_of_the_writer_clone` |
| Paths, branch and remote values cannot smuggle options | `ledger_paths_are_validated`, `git_backend_debug_hides_paths_and_rejects_unsafe_refs` |

## Adapter contract

The exporter, walker and startup check depend only on `LedgerBackend`. Replacing Git (object storage with
conditional puts) means providing the same create-if-absent semantics.

## Failure and recovery

Network or remote failure: retry with backoff (ADR 0053), events stay pending, disclosure stays closed.
Lost writer clone: re-clone; the working clone holds no state that is not on the remote. Branch protection
rejecting a push: surfaced as an error, never retried as a force push.

## Performance evidence plan

Each write costs a fetch and a push. Measure per-record export latency and consider batching several
records per commit only if needed; batching must keep per-record create-if-absent semantics.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Backend port, memory fake, Git writer | yes | yes (local bare remote) | no |
| Private-ledger repository, deploy identity, branch protection | yes | no | no |

## Consequences, migration, exit

The working clone is owned by the backend and is reset on every write; do not keep other work in it.

## Open risks and revisit triggers

Anyone who can force-push can rewrite history; the ledger is tamper-evident through signatures and external
checkpoints, not tamper-proof. Under heavy contention fetch can fail transiently and surface as
`Unavailable`; callers retry. Revisit if write rate approaches Git's practical limits.
