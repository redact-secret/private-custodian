# 0117. Queue and submission retention: migration 0006 and repair retention

- Status: accepted; implemented; the age values are placeholders that need approval
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

Pending submissions, claims and the intake queue grew without bound (HG-4).

## Decision

1. Migration 0006 adds retention bookkeeping. `RetentionPolicy` has hard floors (queue 1 day; claims 7 days;
   decided submissions 7 days; pending submissions 1 day) that code refuses to go below.
2. A pass expires stale pending submissions, then purges finished queue rows, claims with no queue row, and
   decided submissions whose submission and decision events are both acknowledged by the ledger.
3. `custodian repair retention` takes every age explicitly. There are no defaults; the proposed schedule in
   docs/backup-recovery.md section 5 stays a placeholder until the maintainer approves it.
4. Nothing unacknowledged is ever deleted.

## Consequences

Tests: `crates/custodian-store/tests/retention.rs`, `crates/custodian-cli/tests/retention_command.rs`.
