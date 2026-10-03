# 0080. Operator CLI: command set, parsing, sanitized output and exit codes

- Status: accepted (design); implemented in `custodian-cli` (C10); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The issue asks for an operator CLI that goes through the same authorization and budget control plane as the
GitHub path: request, status, approve, cancel, reconcile, verify, restricted contamination and rotation
commands, structured sanitized output, dry-run policy validation, stable exit codes, and operational repair
separate from normal evaluation. ARCHITECTURE.md and CONVENTIONS.md say agents get bounded deterministic
operations and no routine policy mutation, logs carry fixed reason codes and no free text, and a retry passes
the same budget and plan checks as any other request. The C9 library already exposes the operator-only
actions (`docs/lifecycle-and-revocation.md` section 6) but no process calls them.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Where the logic lives | a binary that talks to SQLite itself; a thin binary over a library (`custodian-cli` lib + bin) |
| How a request becomes a reservation | the CLI writes a reservation row; the CLI calls the same store transaction the request edge calls |
| Argument parsing | `clap` (new third-party dependency tree); the standard library |
| Output | human text; one JSON object per invocation built from an allowlist |
| Repair | flags on the normal commands; a separate `repair` group with exact-object confirmations |
| Exit codes | `0`/`1` only; a documented class per kind of refusal |

## Decision

1. **Library plus binary.** `crates/custodian-cli` is a library (`custodian_cli`) and a binary (`custodian`).
   All logic is in the library, parameterized by `Parts` (store, clock, authority, populations, ledger, pinned
   roots, signer, feed destination), so tests drive exactly what the binary runs. The binary only parses,
   opens the file-based `Deployment`, authenticates and prints.
2. **No SQL, no budget, no ledger writes of its own.** A request becomes a reservation only through
   `SqliteStore::approve_submission`, which calls the same `reserve_tx` as `reserve_request` (ADR 0083). The
   crate contains no command that raises, lowers or resets a count, edits history or discloses protected
   content; the only budget-changing paths are the C4 settlement paths (`cancel`, `recover`) that already
   forbid refunding an exposed attempt.
3. **Standard-library argument parser; no new third-party crate.** The grammar is
   `custodian [--config F] [--identity A] [--token-file F] [--dry-run] <group> <command> [--flag value]...`.
   Unknown, repeated or `=`-joined flags are usage errors. `clap` would add a large transitive tree to a
   binary that holds approval authority for a grammar of about twenty fixed commands; the audit surface of the
   parser is smaller than the audit surface of the dependency. The crate uses only the workspace-pinned
   `serde`, `serde_json` and `sha2`.
4. **Command groups.**
   * `request`: `submit`, `status`, `list`, `approve`, `cancel` (normal evaluation).
   * `verify`: `ledger`, `store`, `registry`, `checkpoint`, `all` (read-only).
   * `reconcile`: `store`, `ledger`, `feed` (read-only diagnosis; it changes nothing).
   * `lifecycle`: `report`, `clear`, `retire`, `rotate` (restricted, human operator).
   * `feed`: `record-revocation`, `publish` (restricted, human operator).
   * `policy`: `validate` (read-only), `import-activation` (restricted).
   * `repair`: `recover`, `registry-sweep`, `export`, `ledger-reconcile`, `feed-deliver`, `clear-reconcile`.
     A separate group that cannot be reached from a normal command. Every command needs a confirmation flag
     naming the exact object (`--confirm-store-id`, `--confirm-feed-id`, and for `clear-reconcile` also
     `--confirm-checkpoint-seq`); a missing flag is `confirmation_missing`, a wrong one
     `confirmation_mismatch`, and neither changes anything.
   * `credential-digest --token-file F` prints the digest an operator puts in the policy file.
5. **Explicit approval.** `request approve` needs `--confirm-plan-digest` equal to the plan digest of the
   stored request, so the approver names what they approve. A repeat approval is refused
   (`already_decided`, exit 5) and writes nothing.
6. **`--dry-run`** runs authentication, authorization, input validation, confirmations, the startup check and
   every read-only policy check (activation currency, epoch usable, budget available, binding of the composed
   approval) and reports `would_*` or the refusal the real command would give. It writes nothing. `policy
   validate` is the standalone, read-only form for a request document.
7. **Output.** Exactly one JSON object per invocation on standard output (schema
   `private-custodian.cli-output/1`): `command`, `ok`, `dry_run`, `code`, `exit`, `result`. `code` is a fixed
   word (`CliReason::code` or a success word). `result` is built only by `Output::{id, num, flag, word}`:
   there is no method that accepts a free string. An identifier must match `[a-z0-9_.:-]{1,128}` or it is
   replaced by `omitted_unsafe_identifier`. A failure echoes no request identifier, so a hidden request and a
   missing one look the same. Paths, credentials, worker messages and protected values have no route to the
   output.
8. **Exit codes (stable, documented in docs/operator-runbook.md).** `0` success; `1` internal; `2` usage or
   invalid document; `3` unauthenticated or operator policy invalid/expired; `4` forbidden (role, agent or
   automation identity, self-approval); `5` refused by a policy or state rule (stale policy, exhausted budget,
   already decided, blocked epoch, confirmation mismatch, store behind the ledger); `6` not found; `7`
   dependency unavailable, retry may help (store busy, ledger, signer, feed destination, not configured); `8`
   integrity or consistency failure (verification findings, startup refusal, store awaiting reconciliation).
   Every `CliReason` maps to exactly one class (unit test `codes_are_unique_snake_case_and_exit_codes_are_stable`).

## Security properties claimed

| Property | Evidence |
| --- | --- |
| Output has a fixed envelope and only allowlisted strings; no canary, path, credential or digest of a credential | `tests/operator.rs::output_carries_no_protected_canary_path_credential_or_free_text`, `output.rs` unit tests |
| Unauthorized actions fail with exit 4 and change nothing | `tests/operator.rs` (`every_role_is_limited_to_its_own_commands`, agent and automation tests) |
| Repeat approvals, exhausted budget, stale policy fail | `tests/operator.rs` (`a_repeat_approval...`, `an_exhausted_budget...`, `a_stale_superseded_revoked_or_expired_policy...`) |
| Repair needs exact IDs and cannot reset a spent budget | `command.rs` unit tests, `tests/operator.rs::repair_needs_the_exact_store_id_and_never_resets_a_spent_budget`, `an_exposed_attempt_that_lapses_is_consumed_and_never_refunded` |
| Dry run writes nothing | `tests/operator.rs::dry_run_validates_everything_and_writes_nothing` |
| Binary: one line, fixed codes, no path or credential | `tests/binary.rs` |

## Adapter contract

`Parts` is the whole dependency surface: `SqliteStore`, `Clock`, `PolicyAuthority`,
`ProtectedPopulations<S: EpochBlobStore>`, `LedgerBackend`, pinned `Keyring`, `Signer`, `FeedDestination`,
`PublicPopulations`, `FeedConfig`, `LifecycleFault`. A deployment supplies an isolated signer transport and a
real feed destination; nothing in this crate holds a key.

## Failure and recovery

A command that cannot reach a dependency exits `7` and has changed nothing. A crash inside a store
transaction is all-or-nothing (ADR 0083). An internal error (`1`) may follow a committed change: the runbook
says to run `request status` before retrying, and every state-changing command is idempotent by key or by
identity.

## Performance evidence plan

Not claimed. The startup check walks the whole ledger on every state-changing command (ADR 0082); at the
design volume (single operator, a few hundred records) that is bounded by the ledger size. A cached walk is a
future optimization that must keep the no-bypass property.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Library, binary, command set, output, exit codes | yes | yes (synthetic tests) | no |
| Real signer transport, feed destination, ledger remote | yes (C12) | no | no |

## Consequences, migration, exit

A new command or reason code is additive; changing an exit class is breaking and needs a new ADR. Replacing
the parser with a library later is an internal change if the grammar tests keep passing.

## Open risks and revisit triggers

* Each state-changing command re-walks the ledger; revisit if the ledger grows large.
* The binary is a separate process from any future service; two processes share one SQLite file. That is
  supported (WAL, `BEGIN IMMEDIATE`) and tested with two connections, but a deployment on a network
  filesystem is not supported (ADR 0020).
