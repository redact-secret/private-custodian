# 0123. A std-only HTTP/1.1 listener for the service daemon

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The webhook intake (`custodian_cli::Intake::handle`, ADR 0042 family) takes raw body bytes and headers and
returns a typed result that `webhook::response()` maps to a fixed status and code. Nothing accepted network
bytes (HG-7). The listener is the first code to read untrusted bytes from a socket, so every limit must be
explicit and testable, and the dependency surface should stay small (the intake is reached by any host that
can send a TCP connection to the port).

## Options

1. A general server stack (hyper, axum, tiny_http). Mature parsing, but a large transitive set, features that
   the service never uses (chunked bodies, keep-alive, upgrades, HTTP/2) and behaviour that is harder to bound.
2. A std-only listener that speaks the one request shape the service needs.
3. Defer: leave the daemon without a listener (HG-7 stays open).

## Decision

Option 2. `crates/custodian-daemon/src/http.rs` uses `std::net::TcpListener` and threads only.

- Accepts `POST` on exactly one configured path (to the intake) and `GET /healthz` (answers
  `{"code":"ok"}`, nothing about the store). Everything else gets a fixed 404 or 405.
- HTTP/1.1 only, `Connection: close`, no pipelining (extra bytes are ignored and the socket is closed).
- Strict, configured limits: request line, whole head, header count, body size (`Content-Length` is required
  for `POST` and is checked **before** any body byte is read), a first-byte timeout, a total head deadline (not
  a per-read timeout, so a slow-loris sender cannot extend it), a body deadline, and a connection cap that
  answers `503 busy` rather than queueing.
- Rejects `Transfer-Encoding`, `Expect`, non-identity `Content-Encoding`, duplicate security-relevant headers
  (`Content-Length`, the delivery id, the event, the signature) and obsolete line folding.
- Binds loopback by default. A non-loopback address needs `allow_non_loopback: true` in the config.
- Never logs request bodies, signature headers or tokens; the event log carries fixed codes and counts only.
- TLS is not terminated here. Production exposure is behind the deployer's reverse proxy or tunnel, which is
  a human provisioning step (`docs/deployment-runbook.md`).

## Security properties claimed

Each is a test in `crates/custodian-daemon/tests/listener.rs` (oversize, slow, duplicate and smuggling
headers, bad methods, bad framing, connection cap, no body in the log) or `e2e.rs` (real socket to the
intake). Functional verification on public synthetic data, not independent protected evaluation.

## Adapter contract

The listener only calls `Intake::handle(body, headers)` and `webhook::response()`; it owns no policy.

## Failure and recovery

A malformed request is closed with a fixed code and counted. A panic in a connection thread is meant to be
contained to that connection (not separately tested). Shutdown stops accepting, lets in-flight requests finish within a bound, then closes.

## Performance evidence plan

None claimed. Throughput is not a property of this listener; limits are.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Std-only listener with limits | yes | yes | no |
| TLS termination | no (deployer's proxy) | no | no |
| Public exposure | no | no | no |

## Consequences, migration, exit

A parser of our own is a liability; the limits and the test list are the control. A later move to a mature
stack replaces `http.rs` behind the same two calls, with its own ADR.

## Open risks and revisit triggers

A parser bug is possible despite the tests: fuzzing the request head is a follow-up. Revisit if a second
endpoint is needed or if HTTP/1.1 keep-alive becomes necessary.
