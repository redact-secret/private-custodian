# 0111. Isolated signer process, local-socket transport and framed protocol

- Status: accepted (design); implemented in `crates/custodian-signer` (S2); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

ADR 0050 decided that the receipt signing key lives only in a separate signer process and that the control
service holds a `RemoteSigner` and no key, but it left the process and the transport to deployment (C12).
HG-4 still listed "no isolated signer process" as a blocker. Issue #29 asks for the process, a transport the
control service can use, and tests of the failure modes, using only synthetic test keys. The signer is
reachable by whatever can open its socket, so the protocol must not let a client read the key, make the
signer sign bytes it has not validated, or hold it up.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Transport | Unix domain socket in an owner-only directory; TCP on loopback; stdin/stdout of a child the control service spawns; inherited file descriptor; defer |
| Framing | Fixed binary header plus the existing ledger JSON body; newline-delimited JSON; HTTP; gRPC |
| Concurrency | One request at a time; bounded concurrent threads; async runtime |
| Peer authentication | Peer credentials (`SO_PEERCRED`, `LOCAL_PEERCRED`); shared secret token; none, filesystem permissions only |

Criteria: no network exposure, authentication that does not depend on a secret the control service stores,
std-only code, bounded memory and time per client, and a protocol small enough to fuzz by hand.

## Decision

1. **Process.** `custodian-signer` is a separate binary. It is started by the operator (or the host's service
   manager) under its own uid, never by the control service, so a child of the control service cannot inherit
   its memory or file descriptors. The control service connects to a socket path in its configuration.
2. **Transport: a Unix domain socket** in a directory owned by the signer's uid with no group or other access.
   The socket file is created with mode 0600. A stale socket left by a crashed signer is removed at start only
   if it is a socket owned by the signer's uid that nobody answers on; a live signer or any other file at the
   path stops the start.
3. **Peer check before any read.** The server asks the kernel for the connecting process's uid and serves only
   the single configured uid. A missing answer (platform without peer credentials) denies. The client may
   additionally require the server to run as an expected uid, so a process that can bind the path is not
   mistaken for the signer.
4. **Framing.** A request is an 18-byte header (magic `PCSG`, version `1`, kind `1`, `issued_at`, body length)
   and a body that is the ledger crate's existing `WireRequest` JSON. A response is a 10-byte header (magic
   `PCSR`, version, status, length) and the existing `WireResponse` JSON, or a status-only rejection. The
   length is checked against 262,144 bytes (the ledger's limit) before any body byte is read or allocated.
   Rejections use a fixed vocabulary: `frame_malformed`, `frame_version_unsupported`, `frame_too_large`,
   `frame_timeout`, `signer_busy`, `peer_denied`, `request_stale`. A version bump is a new magic-compatible
   version number; the server refuses versions it does not know.
5. **Deadlines and concurrency.** One request per connection. Every read and write runs under one overall
   deadline (default 5 s, at most 60 s), so a client that sends a byte at a time cannot extend it. At most
   `max_concurrent` (default 4, at most 64) connections are served at once; the next one gets `signer_busy` and
   is closed. A slow client therefore holds one slot for at most the deadline and never blocks signing for the
   others.
6. **Re-validation.** The signer feeds the body to `SignerService`, which rebuilds the payload with
   `ApprovedPayload::from_wire` (domain tag known, canonical bytes decode as the document type of the domain,
   validation passes, projection digest equals the supplied release digest). The client never supplies bytes
   that are signed as-is; the signature is over `domain || 0x00 || canonical` of a payload the signer decoded
   itself. The key's purposes are enforced by `SoftwareSigner`.
7. **Freshness.** The frame's `issued_at` must be within a configured skew (default 120 s) of the signer's
   clock, so a captured request cannot be replayed later. A public projection or revocation envelope whose
   `fresh_until` has passed is refused as `sign_not_approved`. Neither check replaces the control plane's
   approval check (see "Open risks").
8. **Failure.** Every client-side failure (no socket, refused connection, wrong server uid, timeout, a
   response that violates the framing, a rejection frame) maps to `sign_signer_unavailable`; the exporter then
   writes nothing and acknowledges nothing (ADR 0053).

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Signatures over the socket verify under the signer's public key | `tests/signer.rs::signatures_over_the_socket_verify_under_the_public_key` |
| The signer re-validates and refuses wrong domain, wrong key purpose, unapproved and stale payloads | `the_signer_revalidates_and_refuses_wrong_domain_and_unapproved_payloads`, `a_key_without_the_purpose_refuses_with_wrong_domain`, `stale_payloads_and_stale_requests_are_refused` |
| Malformed, oversize, wrong-version, truncated and vanishing clients are rejected without effect | `malformed_oversize_and_wrong_version_frames_are_rejected_with_fixed_codes`, `truncated_requests_and_vanishing_clients_do_not_hurt_the_signer` |
| Slow and trickling clients are cut off and do not block others; concurrency is bounded | `a_slow_client_times_out_and_does_not_block_others`, `concurrency_is_bounded_and_overflow_fails_closed_without_blocking`, `concurrent_clients_all_get_valid_signatures` |
| A slow, silent or hostile signer fails the client closed within its timeout | `a_slow_or_silent_signer_fails_the_client_closed_within_its_timeout`, `a_hostile_signer_cannot_feed_the_client_garbage_or_oversize_frames` |
| Only the allowed uid is served; the client can require the signer's uid | `only_the_allowed_peer_uid_is_served`, `the_client_refuses_a_server_running_as_another_uid` |
| Socket and directory permissions are enforced; a stale socket is reclaimed, a live one is not | `socket_and_directory_permissions_are_enforced`, `signer_crash_and_restart_fail_closed_then_recover` |
| A killed signer process fails closed and a restart signs identically | `tests/process.rs::the_binary_signs_survives_kill_and_restart_and_logs_only_fixed_codes` |
| An unreachable signer makes export fail with `signer_unavailable`, writing nothing, then drain on recovery | `crates/custodian-cli/tests/s2_remote_signer.rs::an_unreachable_signer_makes_export_fail_closed_with_nothing_written_then_it_drains` |

## Adapter contract

`custodian_ledger::SignerTransport` (`call(request) -> response`) is unchanged. `UnixSocketTransport`
implements it; `RemoteSigner<UnixSocketTransport>` is the control service's `Signer`. A different transport
(a vsock or a network-namespace socket) is another implementation of the same trait and the same frame.

## Failure and recovery

Signer down, slow, busy, refusing or answering garbage: `sign_signer_unavailable` or the signer's fixed
`sign_*` refusal; the outbox keeps its events and a later pass drains them. Signer crash leaves a stale socket
the next start reclaims. No fallback key and no fallback signer exist.

## Performance evidence plan

Signing is one Ed25519 operation plus a socket round trip per ledger record. Measure it inside export latency
(docs/measurements.md) before choosing batch sizes; do not skip the exporter's self-verification.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| Signer process, Unix-socket server and client, framed protocol | yes | yes (synthetic test keys) | no |
| Dedicated uid, separate host or namespace, service manager unit | yes | no | no |
| Production key | yes | no | no |

## Consequences, migration, exit

The frame carries a version; an incompatible change is version 2 with both ends upgraded together. Moving the
signer to another host means a different `SignerTransport`, not a different signing contract. Policy impact
(who may be the control uid, key purposes, windows) is a reviewed configuration change.

## Open risks and revisit triggers

- The signer checks shape, validity, digest binding and freshness. It does not see the release approval
  itself, and it does not authorize a revocation decision. A compromised control service can therefore obtain
  a signature on any well-formed ledger record, and on a projection whose digest it claims is approved.
  Mitigation today: external checkpoints (ADR 0054) and verifier-side checks. Revisit: pass the signed
  approval to the signer and have it verify the approver and scope.
- Same-uid separation is not isolation. The deployment must run the signer under a uid the control service
  cannot become (docs/signer.md).
