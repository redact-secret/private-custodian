# The isolated signer

Status: implemented and tested with synthetic, test-generated keys; **not deployed**. No production key
exists, and this repository never contains one. Decisions: ADR 0050 (algorithm, domains, key lifecycle),
ADR 0111 (process, socket, protocol), ADR 0112 (key provider, hardening), ADR 0113 (dependencies), ADR 0114
(wiring, platform limits). The project is maintained by the Redact Secret project; tests here are functional
verification, not independent evaluation.

## Process model and trust boundary

```
 control service / CLI              signer host or namespace
 (custodian, uid A)                 (custodian-signer, uid B)
 +--------------------+  framed     +--------------------------------+
 | RemoteSigner       |  requests   | peer-uid check (uid A only)    |
 |  UnixSocketTransport|=========== > | frame + size + deadline checks |
 | holds: key id,     | owner-only  | SignerService (re-validates)   |
 |        socket path | socket      | WindowedSigner (key window)    |
 | holds NO key       | < ========= | SoftwareSigner (the key)       |
 +--------------------+  signature  +--------------------------------+
        |                                     ^ KeyProvider (0600 file in 0700 dir)
   exporter writes the ledger only after a signature is returned
```

* The signer is started by the operator or the host's service manager, under its own uid. The control
  service never starts it and shares no descriptor or memory with it.
* Workers and agents have no path to the socket and no signer configuration. Only the control service's uid
  is served.
* Trust placed in the signer: it holds the key and re-validates payload shape, domain, validity, digest
  binding and freshness. Trust **not** placed in it: it does not see the release approval or authorize a
  revocation decision. A compromised control service can obtain signatures on well-formed records. The
  defenses against that are the external checkpoint copy (ADR 0054), verifier-side checks, and the
  separation of the human approval step. Passing the signed approval to the signer is a recorded follow-up.

## Protocol (version 1)

Request: `PCSG` | version `1` | kind `1` | `issued_at` (u64, unix seconds) | body length (u32), all big
endian, 18 bytes; then the body, the ledger `WireRequest` JSON `{domain, payload (base64url), release_digest?}`.
Response: `PCSR` | version | status | body length (u32), 10 bytes; status 0 carries the ledger `WireResponse`
JSON (a signature, or a fixed `sign_*` refusal); other statuses carry no body.

| Status | Code | Meaning |
| --- | --- | --- |
| 0 | (body) | signature or `sign_wrong_domain`, `sign_unknown_domain`, `sign_payload_invalid`, `sign_schema_mismatch`, `sign_not_approved`, `sign_signer_unavailable` |
| 1 | `frame_malformed` | bad magic, kind, truncated body |
| 2 | `frame_version_unsupported` | version other than 1 |
| 3 | `frame_too_large` | declared length over 262,144 bytes (checked before reading the body) |
| 4 | `frame_timeout` | the overall deadline passed |
| 5 | `signer_busy` | `max_concurrent` connections already in service |
| 6 | `peer_denied` | peer uid is not the allowed uid, or unknown |
| 7 | `request_stale` | `issued_at` outside the allowed skew of the signer's clock |

One request per connection. Limits: body 262,144 bytes; deadline `io_timeout_secs` (default 5, at most 60) for
the whole request; `max_concurrent` (default 4, at most 64); skew `max_request_skew_secs` (default 120).
`sign_not_approved` is also returned for a projection or revocation envelope whose `fresh_until` has passed.
A key outside its `[valid_from, not_after)` window answers `sign_signer_unavailable` and the signer's event
stream says `key_out_of_window`.

The client maps every transport failure to `sign_signer_unavailable`; the exporter then errors, writes nothing
and acknowledges nothing.

## Key provider contract

`KeyProvider::load_seed()` returns a redacting `SecretSeed` or a fixed-vocabulary `KeyProviderError`.
`FileKeyProvider` requires: the immediate directory is a real directory owned by the signer's effective uid
with no group or other access; the key is a regular file (no symlink, socket or device), one hard link, owned
by that uid, mode 0600 or 0400; the opened file is the checked file (device and inode); the content is 64
lowercase hex characters plus at most one newline. Errors name no path. Ancestors above the immediate
directory are not checked: put the directory under a root-owned path whose ancestors are not writable by the
control uid.

A future KMS/HSM provider must not export the seed; it needs a signing-oriented trait and its own ADR.

## Configuration

Signer: `deploy/examples/signer-config.example.json` (placeholders only; schema `private-custodian.signer-config/1`).
Control service (CLI config, additive): `signer_socket_path` (absolute), `signer_uid` (optional, the uid the
signer must run as), `signer_timeout_secs` (1 to 60). Without `signer_socket_path` the CLI keeps its safe
default: every signature is refused with `signer_unavailable`.

Run: `custodian-signer --config <file>`; `custodian-signer --config <file> --print-public-key` prints the
public key (hex) to pin as a verifier root. Exit codes: 2 usage/config/hardening, 3 key, 4 server. Output is
fixed codes on stderr.

## What is enforced where

| Control | Linux | macOS |
| --- | --- | --- |
| Peer uid check (`SO_PEERCRED` / `LOCAL_PEERCRED`) before any byte is read | yes | yes |
| Unknown peer uid (platform cannot say) denies | yes | yes |
| Socket directory must be owner-only and owned by the signer; socket mode 0600 | yes | yes (the directory is the real barrier; some BSDs ignore socket file modes) |
| Key file checks (owner, mode, symlink, hard link, dev/ino, format) | yes | yes |
| Core dumps off (`RLIMIT_CORE` 0; start refused otherwise) | yes | yes |
| Non-dumpable (`PR_SET_DUMPABLE 0`): same-uid processes cannot read `/proc/<pid>/mem` or `environ` or ptrace | yes | **no** (not applied) |
| `umask 077`, environment scrubbed | yes | yes |
| No child processes, key files opened close-on-exec | yes | yes |
| Memory locking (no swap of key pages) | **no** | **no** |
| Ownership by another uid tested | not in CI | not locally |

What no test here can show: that the signer runs under a uid the control service cannot become, that the
signer is on another host or namespace, that disks and swap are encrypted, that nobody with root read the key.

## What the deployment must add

1. A dedicated signer uid, and a control-service uid that cannot become it or read its files. If the two share
   a uid, the peer check and file modes protect nothing.
2. For production, a separate host or network/mount/PID namespace for the signer; a root-owned path whose
   ancestors the control uid cannot write for the key and socket directories.
3. A service-manager unit that starts the signer first, restarts it on failure and gives it no environment.
4. Key generation **on the signer host only**, under `umask 077`, written once to the key path. Never copy it
   to the control host, a backup of another host, a repository or CI. Pin the public half (from
   `--print-public-key`) as a verifier root out of band, then publish key events (ADR 0050, ADR 0101).
5. Rotation and revocation per `docs/backup-recovery.md` section 7; set `not_after` so a retired key stops
   signing even if the control service is behind.
6. Optionally, an HSM or KMS provider behind the same process (future ADR).

## Tests

* `crates/custodian-signer/tests/signer.rs`: happy path verified by `Verifier`; wrong domain, wrong purpose,
  unapproved, stale payload and stale request, key window; malformed, oversize, wrong version, truncated and
  vanishing clients; slow and trickling clients; slow, silent and hostile signers; crash and restart; peer uid;
  socket and directory permissions; concurrency and its bound; canary scan for key, path and client text.
* `tests/provider.rs`: key file rules, hardening in a child process.
* `tests/process.rs`: the real binary (kill and restart, refusal to start, fixed-code stderr, Linux
  non-dumpable boundary).
* `crates/custodian-cli/tests/s2_remote_signer.rs`, `tests/binary.rs`: export through the real socket;
  unreachable signer writes nothing; configuration validation.

## Liveness (S5)

`Signer::liveness()` lets the daemon's scheduler detect a dead signer. The remote signer sends a probe under an
unknown domain and expects the refusal `sign_unknown_domain`; it never signs. A failure reports
`signer_unavailable`. [daemon.md](daemon.md).
