# Deployment configuration examples (placeholders only)

Nothing here is deployed, and nothing here is a real operational value. These files show the **shape** of
the configuration a human writes after a server exists, so that the shape is reviewed and tested before any
host does. They are written for the server-less verification phase (ADR 0110, ADR 0132): there is no host, no
account, no signing key, no ledger remote, no domain and no operator credential behind any of them.

Every value is a placeholder:

| Kind of value | How it is written here |
| --- | --- |
| Host names | `*.example.invalid` (reserved, never resolves) |
| IP addresses | loopback only, or the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Paths | `/PLACEHOLDER/...` or the conventional `/etc`, `/var`, `/run`, `/srv` locations; never a home directory |
| Keys, digests, tokens | absent, or an obviously empty digest (all zeros); never key material, never a token |
| Identities | `act_placeholder...`, `key_synthetic...` style strings; no person, no email address |
| Policy numbers | the defaults the code ships with or an obvious stand-in; real values are **(decide)** items in `docs/backup-recovery.md` and the checklist |

`crates/custodian-daemon/tests/deploy_examples.rs` scans this whole directory and fails if a real-looking value
appears (an address outside the documentation ranges, a real domain, key material, a token, an email address or
an absolute home path). It also checks that each JSON example parses with the real parser for its component and
that the systemd units keep their hardening directives. A new example must pass both.

## What each file is for

| File | Component | Real parser checked by the test |
| --- | --- | --- |
| `daemon-config.example.json` | `custodiand run --config` (docs/daemon.md) | `DaemonConfig::from_json` |
| `signer-config.example.json` | `custodian-signer --config` (docs/signer.md) | `SignerConfig::parse` |
| `cli-config.example.json` | `custodian --config` (the deployment, `deploy.rs`) | `deploy::parse_roots` for the roots file; shape for the rest |
| `operator-policy.example.json` | the reviewed operator policy (docs/operator-runbook.md) | `OperatorPolicy::from_json` |
| `pinned-roots.example.json` | the pinned verification roots (docs/ledger.md) | `deploy::parse_roots` |
| `intake-config.example.json` | the GitHub App intake allowlist (docs/github-app.md) | `IntakeConfig::from_json` |
| `backup-retention.example.json` | backup and retention decisions (docs/backup-recovery.md) | shape only; every number is a decision |
| `feed-destination.example.json` | the contract a public feed destination must meet (docs/lifecycle-and-revocation.md) | shape only |
| `arm64-sandbox-image.example.json` | the ARM64 inner-sandbox image/CI-tools-image contract (issue 54, ADR 0137); restates the existing `crates/custodian-worker` `Sandbox` privilege/mount contract for an ARM64 host | shape only; nothing parses or enforces it yet |
| `custody-topology.example.json` | the control host / signer / exporter / ephemeral worker / feed / consumer arrangement (issue 72, ADR 0146); control functions stay on a long-lived host, not serverless | JSON, all statuses PENDING, control not serverless, signer key off the control host |
| `ec2-worker-host.example.json` | per-attempt EC2 worker pins and bounds (ADRs 0142 to 0145); every sizing value DECIDE or UNMEASURED | JSON, all statuses PENDING |
| `protected-delivery.example.json` | projection and feed delivery requirements with destination binding; the transport is NOT IMPLEMENTED | JSON, all statuses PENDING |
| `activation-pins.example.json` | exact pin placeholders and owners for the restricted activation; first protected evaluation and benchmark cutover are NOT_AUTHORIZED | JSON, pins empty, approvals separate |
| `ledger-remote.example.md` | how the private ledger remote is created (docs/ledger.md) | none; commands with placeholders |
| `systemd/*.example` | service units with hardening directives | directive presence |
| `layout/custodian.tmpfiles.example` | directory and permission layout | modes match docs/deployment-runbook.md |
| `proxy/nginx-custodian.conf.example` | reverse proxy terminating TLS in front of the loopback listener | placeholders only |

## What these files are not

- They are not a deployment, a runbook, or a substitute for `docs/server-prerequisites-checklist.md`, which lists
  everything a human must do once a server exists, in order, with evidence to record.
- They are not evidence of anything. A file that parses proves the shape is accepted by the code, on public
  synthetic data. It is functional verification only; it is not an independent protected evaluation.
- They do not choose a recovery point, a retention period, a disclosure policy or an isolation risk decision.
  Those are human decisions recorded elsewhere.

## Use after a server exists

Copy a file outside this repository, replace every placeholder, and keep the result in the private operations
store (never in this repository, CI or the private ledger). Run `custodiand check-config --config <file>` and
`custodian policy validate` before starting anything. Re-read `docs/server-prerequisites-checklist.md` first.
