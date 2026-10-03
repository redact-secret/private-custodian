# 0124. RS256 App JWT with `ring`, and the GitHub adapter behind a trait with an offline fake

- Status: accepted and implemented (synthetic data and test keys; nothing deployed)
- Date: 2026-10-03
- Deciders (by role): project maintainer
- Maintenance: this repository is maintained by the Redact Secret project; its decisions are
  project-maintained, not independent validation.

## Context

To post Check Runs and read pull request facts the service authenticates as a GitHub App: it signs a short
JWT with the App's RSA private key (RS256) and exchanges it for an installation token. The repository had no
RSA signer and no HTTP client. The private key is a production secret; no real key and no network call may
exist in this work.

## Options

1. Hand-written RSA over a big-integer crate. Rejected: constant-time and padding mistakes.
2. `rsa` crate (RustCrypto). Has had a timing advisory (RUSTSEC-2023-0071) open for long.
3. `ring` 0.17 (`RsaKeyPair`, `RSA_PKCS1_SHA256`): maintained, reviewed, no advisory open for signing.
4. Shell out to `openssl`. Rejected: process boundary for a key, argv exposure.

## Decision

`ring` with the version pinned (`=0.17.14`). `AppJwtSigner` (`src/github/jwt.rs`) loads PEM PKCS#1 or PKCS#8
only, from a regular file read with `custodian_cli::deploy::read_checked` (mode must have no group or other
bits, bounded size), zeroizes the buffers, and has a redacting `Debug`. It signs `{iat, exp, iss}` with a
bounded lifetime. Tests use a throwaway key generated at test time; no key material is committed.

GitHub I/O sits behind `HttpExecutor` (one request in, one bounded response out). Implementations:

- `FakeGithub` (offline, test-only helper that can also `serve()` on loopback);
- `PlainHttp` (HTTP over loopback only, for tests and a local proxy);
- `NotBuiltHttps`: a documented skeleton that refuses with `github_https_not_built`. Linking a TLS stack
  (rustls plus a root store) is a dependency and trust decision left to the deployment ADR that enables the
  webhook; it is deliberately not taken here.

Config mode is `disabled | loopback_http | https`. `disabled` means the queue is not consumed and deliveries
stay durably queued. `https` is refused by the binary until a real client exists.

`ring` is licensed `Apache-2.0 AND ISC`; `deny.toml` gains `ISC` as a reviewed allowance for this reason.

## Security properties claimed

Tests in `crates/custodian-daemon/tests/github.rs`: the JWT verifies under the public key only (both PEM forms),
a key file that is not private, regular and a plain RSA key is refused, the check sink and pull source use the
installation token, failures map to fixed reasons never to text, HTTPS fails closed and plain HTTP is loopback
only.

## Adapter contract

`CheckSink` and `PullFacts` ports in the bridge and service crates are implemented by `GithubChecks` and
`GithubPulls`; nothing in core knows about GitHub.

## Failure and recovery

A GitHub outage defers the queue item with backoff (ADR 0125); a Check that cannot be posted never changes
any budget or approval.

## Status of the claim

| Aspect | Planned | Implemented | Deployed |
| --- | --- | --- | --- |
| RS256 JWT, offline | yes | yes | no |
| Real HTTPS client | yes (later) | no | no |
| Real App key | human | no | no |

## Consequences, migration, exit

One new native-code dependency (`ring`). Replace behind `AppJwtSigner` if policy changes.

## Open risks and revisit triggers

RSA key sizes below 2048 bits are refused by `ring`. Revisit when the HTTPS client is chosen.
