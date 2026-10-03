# 0114. Control-service signer wiring, fail-closed semantics and platform limits

- Status: accepted (design); implemented in `crates/custodian-cli` and `crates/custodian-signer` (S2); not deployed
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

Until S2 the CLI deployment's signer was `UnavailableSigner`: every signature was refused with
`signer_unavailable` (ADR 0080, HG-4). With the signer process of ADR 0111 the CLI must use it when told to,
without losing the safe default, and the documentation must say plainly which protections hold on which
platform and what the deployment still has to provide.

## Options

| Choice | Alternatives considered |
| --- | --- |
| Wiring | optional socket path in the CLI config, remote signer when present, stub otherwise; always require a socket; environment variable; separate CLI flag |
| Absent or broken signer | fail closed with the existing code; fall back to a software signer; skip the audit step |
| Platform claims | claim the same guarantees everywhere; state per-platform enforcement |

## Decision

1. **CLI config** gains optional `signer_socket_path` (absolute), optional `signer_uid` (the uid the signer
   must run as) and `signer_timeout_secs` (1 to 60, default 10). All are additive; existing configs behave as
   before. A relative path or an out-of-range timeout is `not_configured`. The path never appears in output.
2. **`ConfiguredSigner`** is `Remote(RemoteSigner<UnixSocketTransport>)` when a socket is configured and
   `Unavailable(UnavailableSigner)` otherwise. Both hold a key id and no key. A configured but absent, slow,
   busy, wrong-uid or misbehaving signer yields `sign_signer_unavailable`, which the CLI reports as
   `signer_unavailable` (exit class 7), exactly as before. There is no software fallback anywhere in the CLI.
3. **No partial writes.** The exporter signs before it writes and acknowledges only after a durable write
   (ADR 0053). A signing error stops the pass with the outbox untouched.
4. **Platform statement.** `docs/signer.md` lists, per platform, what is enforced (peer uid, directory and
   file modes, core limit, environment scrub, umask, Linux non-dumpable) and what is not (macOS
   non-dumpable, memory locking, ancestors of the key directory, uid separation, host separation). Tests that
   need Linux behavior run in the CI `rust` job; the `worker-isolation` job is unchanged.
5. **Deployment must add:** a dedicated signer uid the control service cannot become, a separate host or
   namespace for production, a service-manager unit that starts the signer before the control service, key
   generation on the signer host only, backups that exclude the key from every other host, and a pinned root
   obtained out of band from `--print-public-key`.

## Security properties claimed

| Property | Failure test |
| --- | --- |
| Export through the real socket writes a ledger that verifies under the signer's public key | `crates/custodian-cli/tests/s2_remote_signer.rs::export_through_the_real_signer_socket_writes_a_ledger_that_verifies_under_its_public_key` |
| Unreachable, killed or mismatched signer: `signer_unavailable`, nothing written, outbox intact, later drain | `an_unreachable_signer_makes_export_fail_closed_with_nothing_written_then_it_drains` |
| A server running as the wrong uid is not trusted | `a_server_on_the_socket_that_runs_as_the_wrong_uid_is_not_trusted` |
| Absent configuration keeps the stub's behavior; configured and down gives the same code | `the_configured_signer_is_remote_only_when_a_socket_is_configured` |
| Bad signer settings are `not_configured` and a missing signer does not stop the deployment from opening | `crates/custodian-cli/tests/binary.rs::a_signer_socket_setting_is_validated_and_a_missing_signer_is_not_a_config_error` |

## Adapter contract

`Parts::signer` stays `&dyn Signer`. `ConfiguredSigner` is one implementation chosen by `Deployment::open`.

## Failure and recovery

See ADR 0111. The operator runbook's signer-outage procedure is unchanged: restore the signer, run
`repair export`; the pending events drain in order.

## Performance evidence plan

None beyond ADR 0111.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| CLI uses the real signer over a configured socket; stub when absent | yes | yes | no |
| Dedicated uid, separate host, service unit, production key, pinned root | yes | no | no |

## Consequences, migration, exit

Existing configs need no change. A future signer transport changes `ConfiguredSigner`, not `Parts`.

## Open risks and revisit triggers

- If the control service and signer share a uid, the peer check and file modes protect nothing. The CLI
  cannot detect that; the signer only compares against the configured uid. The deployment runbook and
  `docs/signer.md` make it a pre-start checklist item. Revisit with a startup self-check that the signer's
  uid differs from the caller's, once a deployment layout exists to define "differs" for.
- HG-4 stays open until a deployment runs the signer under its own uid with a production key.
