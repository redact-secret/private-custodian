# 0128. Daemon configuration, process model and shutdown

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The daemon composes existing components. It must not bypass the startup check, must run with minimal
privilege, and must stop cleanly without losing or duplicating work.

## Decision

- **Start** only through `custodian_cli::Service::start`, which runs the deployment checks and
  `startup_check`. The binary `custodiand` has no flag that skips them.
- **Config** is one JSON file, strict (unknown fields refused), read with a mode check, documented in
  `docs/daemon.md` with placeholders in `docs/daemon-config.example.json`. Secrets are paths, never values.
- **Threads**: the main thread runs the scheduler and pipeline pass; listener threads accept; consumer threads
  each own an `Arc<SqliteStore>` connection; `std::thread::scope` bounds lifetimes.
- **Signals**: SIGTERM and SIGINT are blocked in all threads and received by one dedicated `sigwait` thread
  (nix, safe API, no `unsafe`). It sets the shared `Shutdown` flag.
- **Shutdown order**: stop accepting, stop claiming, release leases, let a running dispatch finish within the
  configured bound (an expired bound leaves a lapsed lease that recovery settles as consumed), final export,
  exit 0.
- **User**: the daemon runs as the service user; the signer is a separate process behind a socket (ADR 0113
  family).
- **Degraded**: a failing startup check blocks work and is retried; health still answers `ok` for liveness,
  nothing about state.

## Security properties claimed

`tests/config.rs` (strict loader), `tests/process.rs` (the real binary starts, refuses bad config, stops on
SIGTERM), `tests/scheduler.rs`, `tests/consumer.rs` (shutdown).

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Process model | yes | yes | no |

## Consequences, migration, exit

Functional verification on public synthetic data, not independent protected evaluation.

## Open risks and revisit triggers

No supervisor unit file is shipped; init integration is a deployment task.
