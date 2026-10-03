# 0113. Signer crate dependencies and the no-`unsafe` rule

- Status: accepted (design); implemented in `crates/custodian-signer` (S2)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

The workspace sets `unsafe_code = "forbid"`. The signer needs a few operating-system facts std does not offer
on stable: the connecting process's uid on a Unix socket (`SO_PEERCRED`, `LOCAL_PEERCRED`), `setrlimit`,
`prctl(PR_SET_DUMPABLE)`, `umask` and `geteuid`. Hand-written FFI would need `unsafe`. Zeroizing key bytes on
drop needs a guaranteed-not-optimized-away write.

## Options

| Choice | Alternatives considered |
| --- | --- |
| System calls | `nix` (safe wrappers over `libc`); `rustix`; direct `libc` with `unsafe`; shell out to `id`/`ulimit`; drop the features |
| Zeroizing | `zeroize` (already in the lock through `ed25519-dalek`); `write_volatile` by hand (unsafe); no zeroizing |

Criteria: keep `forbid(unsafe_code)` in every first-party crate, add as few crates as possible, keep license
compatibility with `deny.toml`, and keep the list of new code small enough to review.

## Decision

1. **`nix` `=0.31.3`**, `default-features = false`, features `socket`, `resource`, `process`, `fs`, `user`.
   It is used only in `custodian-signer`'s `platform` and `provider` modules for `getsockopt` peer
   credentials, `setrlimit`/`getrlimit`, `prctl` (Linux), `umask` and `geteuid`. It adds `nix`, `cfg_aliases`,
   `memoffset` and `autocfg` to `Cargo.lock` (`bitflags`, `cfg-if` and `libc` were already present); all are
   MIT or MIT/Apache-2.0, which `deny.toml` allows. `rustix` was not chosen because it has no macOS peer
   credential option, which the maintainer's development platform needs for the same tests.
2. **`zeroize` `=1.9.0`**, the version already locked. No derive feature.
3. **No other new third-party crate.** Framing, timeouts, the thread pool and the file checks are std.
   `serde`, `serde_json`, `custodian-contracts` and `custodian-ledger` reuse existing pins.
4. **`custodian-signer` and the binary keep `#![forbid(unsafe_code)]`.** The `unsafe` lives inside `nix`,
   a widely used crate; this ADR does not claim it is audited.
5. **`custodian-cli` depends on `custodian-signer`** for `UnixSocketTransport` only. The CLI does not link the
   key provider into any code path (it is a library item the CLI does not call) and holds no key.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| First-party crates contain no `unsafe` | the workspace lint `unsafe_code = "forbid"` and the crate-level attribute fail the build |
| The peer uid is read from the kernel on Linux and macOS | `tests/signer.rs::only_the_allowed_peer_uid_is_served` (runs on macOS locally and on Linux in CI) |
| Hardening calls succeed or the binary refuses to start | `tests/provider.rs::hardening_applies_in_a_child_process`, `tests/process.rs::the_binary_refuses_to_start_on_insecure_keys_configs_and_arguments` |

## Adapter contract

None; these are implementation dependencies behind `platform::peer_uid` and `platform::harden_process`.

## Failure and recovery

On a platform without a peer-credential option, `peer_uid` returns `None` and the server denies every
connection: it fails closed rather than skipping the check. A failed `setrlimit` stops the binary.

## Performance evidence plan

None; these calls run once per start or once per connection.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| `nix`/`zeroize` pins, no first-party `unsafe` | yes | yes | no |

## Consequences, migration, exit

If `nix` becomes a supply-chain concern, replace `platform.rs` with another safe wrapper or with a tiny
separately reviewed FFI module under an ADR that relaxes the lint for that one crate. Updating the pin is a
deliberate change with the dependency audit.

## Open risks and revisit triggers

The CI dependency audit (`cargo-deny`, `deny.toml`) runs on every change; a new advisory against `nix`, or a major release that changes the
sockopt API, is the trigger to revisit.
