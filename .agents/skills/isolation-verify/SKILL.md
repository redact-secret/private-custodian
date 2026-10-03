---
name: isolation-verify
description: Verify that the execution worker boundary is actually enforced and tested (egress, filesystem, credentials, resources, output bounds, artifact integrity, cleanup), not merely declared in a manifest. Use when designing, changing, or accepting the worker or runner. Read-only until probes are requested.
---

# Isolation verify

Shared rules: [_shared/README.md](../_shared/README.md). Probing method: `vulnerability-test`.

Source: `ARCHITECTURE.md` "Isolation and artifact integrity" and `CONVENTIONS.md` "Execution and logging".
A manifest flag cannot enforce isolation, and containers alone are not an assurance statement. Look for
**enforcement evidence and a failure test** for each item.

## Checklist (pass / fail / not assessable)

- **Network**: no external egress by default; denial is verified by a test, not just a config field.
- **Credentials**: no host credentials; the engine gets no storage, signing, approval, or org-wide
  credentials; scanner children get only the files and configuration they need.
- **Filesystem**: restricted writable scratch; least-privilege mounts; read-only corpus and candidate
  mounts; no access to other runs' data.
- **Materialization**: archive, path, and symlink/hardlink validation occurs before extraction.
- **Resources**: CPU, memory, process count, storage, wall-clock limits; bounded stdout/stderr; timeout and
  process-tree cleanup on completion, failure, and cancellation.
- **Identity**: least-privilege runtime user; no privileged or shared-host execution unless an explicit risk
  decision (ADR) exists.
- **Integrity**: candidate bytes staged immutably; engine, scanner, and configuration identity verified
  before and after execution; results cover the authorized input roster, versions, counters, and failure
  states; raw data stays private.
- **Enforcement record**: the runner records verification that isolation was applied (not a descriptive flag),
  and refuses to start otherwise (fail closed).
- **Exposure**: the control plane never gives case bytes to the language model.
- **Cleanup**: scratch deletion is treated as cleanup, not secure erasure; retention for failed runs,
  snapshots, and backups is defined.

Report each item with the evidence or the missing artifact. If the platform is unselected, record that an
ADR (`adr-author`) and failure tests are prerequisites before any protected run.
