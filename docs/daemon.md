# Service daemon

`custodiand` (crate `custodian-daemon`, S5, issue 32, ADRs 0123 to 0129) is the process that composes the
existing components into a running service: an HTTP listener for the webhook intake, a durable queue consumer,
a scheduler for maintenance, and the request-to-projection pipeline.

**Status: implemented in code, not deployed.** Everything below was verified as *functional verification on
public synthetic data, not independent protected evaluation*, with doubles for GitHub and for the engine, test
keys and a temporary ledger. This repository is maintained by the Redact Secret project; the tests are
project-maintained. The webhook stays Inactive (`docs/github-app.md`); no protected run, real ledger write,
production key or cutover has happened.

## Commands

```
custodiand --version
custodiand check-config --config <path>     # parse and validate; touches no store
custodiand run --config <path>              # start the service
```

`run` starts only through `custodian_cli::Service::start` (deployment checks and `startup_check`); there is no
bypass. SIGTERM and SIGINT stop it gracefully (ADR 0128). Log lines are fixed event codes on stderr; request
bodies, signatures, tokens, paths of protected inputs and result contents are never logged.

## Process model and trust boundaries

```
internet --> [deployer's TLS proxy] --> listener threads --> Intake::handle --> durable queue
                                                                                   |
                      consumer threads (lease, fencing, backoff, poison) <---------+
                                |  submit_request (App channel; never approves)
                                v
  main thread: scheduler + pipeline pass --> worker sandbox --> custodian-signer (separate process, socket)
                                |                                  |
                                v                                  v
                   store (SQLite)  ledger (Git)         feed destination (directory, human publishes the feed)
```

- The listener sees untrusted bytes only. The signing key lives in the signer process; the daemon holds none
  (it holds the optional GitHub App key, read from a 0600 file).
- Protected inputs are visible only inside the worker sandbox. The daemon passes names and counts, never
  contents, and the sandbox returns one bounded result document.
- Human acts stay human: release approval files, feed publication, enabling the webhook.

## Listener

Std-only HTTP/1.1 (ADR 0123). One POST path, `GET /healthz`. Limits (all configurable, defaults in the example):
request line, head, header count, body size (`Content-Length` required and checked before reading), first-byte,
head and body deadlines, a connection cap answering 503. Rejected: `Transfer-Encoding`, `Expect`, content
encodings, duplicate security headers. Loopback bind unless `allow_non_loopback` is set. TLS is the deployer's
reverse proxy; the daemon does not terminate it.

## Queue consumer and scheduler

See ADR 0125. Backoff is 5 s doubling to 300 s; a message that exhausts `max_attempts` leases is set aside as
`poison_message` with an audit event and no budget effect. Scheduler tasks: `recover`, `reconcile_registry`,
`deliver_pending`, `export`, `checkpoint`, `startup_check`, `signer_liveness`. A failing startup check puts the
daemon in a degraded state (no work starts) and is retried every 2 seconds.

## Pipeline

```
enrolled -> dispatched -> assembled -> prepared -> released
    \___________\____________\___________\______> closed (fixed reason)
```

Each step is idempotent and resumable from `pipeline_runs` (ADR 0126). Dispatch runs only after the startup
check and the export-drain preflight. The receipt is assembled from the settled attempt (ADR 0127): `Partial`
only if fewer items were observed than expected; a crash, drift in population or roster, or a missing aggregates
artifact closes the run and never yields a clean receipt. Release needs a distinct human approval file
`<approvals_dir>/<request_id>.json`; the daemon never writes one. Budgets are provisioned from the disclosure
policy unless `provision_budgets_from_policy` is false. If an installation or repository is removed while a
run is approved, the run is cancelled and refunded (scope guard).

## Configuration

One strict JSON document (`private-custodian.daemon-config/1`; unknown fields refused; the file must not be
group or world writable). `deploy/examples/daemon-config.example.json` contains placeholders only. Sections:

| Section | Purpose |
| --- | --- |
| `deployment_config_path` | the existing CLI deployment config (store, ledger, signer, corpus, feed) |
| `intake` | intake config and webhook secret paths |
| `listener` | bind address, path, limits and timeouts |
| `github` | `mode`: `disabled` (default: the queue is not consumed, deliveries stay queued), `loopback_http`, `https` (refused by the binary: `github_https_not_built`); `app_id`, `app_private_key_path` |
| `requests_dir`, `artifacts_dir` | request documents and the worker artifact allowlist |
| `worker` | `sandbox` (`none` refuses to dispatch, or `bubblewrap`), staging directory, verification age |
| `release` | disclosure policy path and activation, destination, approvals and output directories |
| `attestation` | declared authorship and review for the internal receipt |
| `required_activations` | policy activations the startup check requires |
| `queue`, `schedule`, `pipeline` | counts, leases and intervals |

Secrets are paths to 0600 files, never inline values.

## What is verified, and how

| Claim | Evidence | Where it ran |
| --- | --- | --- |
| Real listener to verified release, hostile requests, crash windows, poison, shutdown, threads, canary scans | `crates/custodian-daemon/tests/{e2e,listener,consumer,pipeline,crash,scheduler,config,process,github,engine}.rs` | CI and local |
| Engine inside real bubblewrap | `tests/linux_pipeline.rs`, `worker-isolation` job | Linux CI only (skips elsewhere, proves nothing there) |
| Store migration 0007 | `custodian-store/tests/{pipeline,migrations}.rs` | CI and local |

## What is not verified, or not built

- Real engines do not emit `worker-result/1` with aggregates (the fixture `custodian-synthetic-engine` does).
- No HTTPS client (`NotBuiltHttps` skeleton), no real GitHub call, no real App key.
- No deployment: no host, signer key, ledger remote, policy, feed destination or monitored contact.
- R-1 (restore with no newer copy) and R-4 (key revocation re-issue) remain open.
- Feed publication remains a human operator action.

## Hand-over for the next work

Tests start the whole synthetic stack with `common::stack::with_stack` (listener, signer socket, Git ledger,
directory feed, fake GitHub with a throwaway RS256 key). A synthetic config is in
`deploy/examples/daemon-config.example.json`; operating steps are in `docs/deployment-runbook.md`.
