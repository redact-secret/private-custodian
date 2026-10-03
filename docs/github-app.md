# GitHub App: setup, rotation and provisioning

Maintained by the Redact Secret project. This is the operator guide for the request-facing App (zone Z1 in
[ADR 0001](adr/0001-trust-boundaries-and-threat-model.md)). Design and tests are in
[ADR 0010](adr/0010-github-app-request-intake.md) and `crates/custodian-intake`. Nothing in this repository
contacts GitHub, and no listener exists yet.

Status at the time of writing: a development App is registered with Metadata: read, Pull requests: read and
Checks: read and write, installed only on this repository. Its webhook is inactive and no server runs.
Do not enable the webhook until the readiness checklist at the end is complete.

Operational identifiers are never committed. Below, `<APP_ID>`, `<INSTALLATION_ID>`, `<REPOSITORY_ID>`,
`<USER_ID>` and `<WEBHOOK_URL>` are placeholders for values held in the deployment's configuration and secret
store.

## 1. What the App is and is not

The App is a request edge. It verifies GitHub events, enqueues identifiers, and writes sanitized Check
status. It does not run evaluations, hold protected data, sign receipts, write the ledger or approve anything.

App access is not approval. Installing the App, receiving a valid webhook, holding an installation token or
being on the requester allowlist never authorizes protected execution. Execution needs a separate `Approval`
record (execute scope) that binds the exact plan, candidate, population, budget and a current policy
activation, issued out of band by an allowlisted approver. No webhook, comment, label or Check can create one.

## 2. Least-privilege registration

Repository permissions (and nothing else; every account and organization permission stays "No access"):

| Permission | Level | Why |
| --- | --- | --- |
| Metadata | Read | Mandatory for every App; identifies repositories |
| Pull requests | Read | Read the current head commit for the stale-commit check |
| Checks | Read and write | Create and update the sanitized Check run |

Not requested, and a review finding if added: Contents, Actions, Workflows, Administration, Issues, Secrets,
Environments, Members. The adapter requests installation tokens with exactly these three permissions for a
single repository id, and discards a token that grants more (`permissions_exceeded`). The constant is
`REQUESTED_PERMISSIONS` in `crates/custodian-intake/src/app_auth.rs`. The code only writes Checks; read access is
granted because GitHub bundles it, and no code path uses it.

Subscribed events: **Pull request** only. Installation and installation-repository events are delivered to
every App automatically and are used to record removal. Do not subscribe to issue comment, pull request review,
pull request review comment, workflow run, push, check run or check suite events. The adapter refuses them by
name even if subscribed.

Webhook settings: content type `application/json` (the form-encoded type is refused), SSL verification
enabled, a secret set, webhook inactive until section 4.

Installation: "Only select repositories", the single repository that submits requests. Never "All
repositories". "Where can this App be installed": "Only on this account". Do not make the App public.

Requesting repositories must not receive the App key, webhook secret or installation token in their CI. Their
workflows have no custodian credentials and no path to the ledger or database.

## 3. Credentials and separation

| Credential | Held by | Notes |
| --- | --- | --- |
| App private key (`RequestFacingAppCredential`) | request-facing App adapter only | Signs the App JWT (RS256). Never in the repository, CI, a worker or a log |
| Webhook secret (`WebhookSecret`) | request-facing App adapter only | At least 32 random bytes. Separate from the key |
| Installation token | request-facing App adapter, in memory | Scoped to one repository, expires in about an hour |
| Ledger-writer credential (`LedgerWriterCredential`) | ledger-writer only (C7) | A different identity and secret |
| Database administration credential (`DbAdminCredential`) | the operator, not the App (C4) | A different identity and secret |

Isolated workers and requesting-project CI hold none of these. `validate_assignments` rejects a deployment
manifest that gives any holder a credential outside its single permitted role, and `validate_worker_environment`
rejects credential-shaped environment names in a worker. These checks guard configuration; the isolation
boundary itself is proven in C6.

The signing key should live where the signer adapter can use it without the process reading the key bytes
(an owner-only file under the App adapter's OS user, or a key service). Generate it only through GitHub's App
settings and move it straight to that store.

## 4. Enabling the webhook (not yet; checklist in section 7)

1. Confirm every item in section 7 is done and recorded.
2. Generate a webhook secret of at least 32 random bytes (for example `openssl rand -hex 32`) and store it in the
   secret store. Do not paste it into a shell history, ticket or chat.
3. Set the same secret in the App's webhook settings.
4. Deploy the listener behind HTTPS at `<WEBHOOK_URL>`. The listener passes the raw body, the
   `X-Hub-Signature-256`, `X-GitHub-Event`, `X-GitHub-Delivery` and `Content-Type` headers to
   `Intake::handle` and returns its `(status, code)` pair. It must not log bodies or headers.
5. In the App settings, save the URL, then mark the webhook Active.
6. Use "Redeliver" or the ping delivery to verify an authenticated `ping` returns `200 ignored`.
7. Open a pull request from the installed repository as an allowlisted requester and confirm `202 queued`
   and a Check in the "queued" state. Open one from a fork (from a second account) and confirm
   `403 fork_denied`.
8. If anything is unexpected, set the webhook Inactive. Deliveries are retained by GitHub for redelivery.

The listener must run behind a stable URL. A development tunnel is acceptable for rehearsal only, with
synthetic repositories, and must be closed afterwards.

## 5. Rotation

### App private key

GitHub allows several keys at once, which makes rotation overlap-safe.

1. In the App settings, generate a new private key. Move the downloaded file directly to the secret store;
   do not keep copies.
2. Deploy the new key to the signer adapter and configure the signer to use the new key only. The old key
   stays valid at GitHub for now, so a rollback is possible until step 4.
3. Verify: mint a JWT and exchange it for an installation token for the single repository (the Check reporter
   path); confirm the Check update succeeds.
4. Delete the old key in the App settings.
5. Delete the old key from the secret store and any backup. Record the rotation date and key fingerprint
   (GitHub displays a SHA-256 fingerprint) in the private operations log, not in this repository.
6. Rotate at least annually and immediately on suspected exposure or on a change of operator.

If the key may be exposed: delete it in the App settings first (this stops new tokens), then follow
[SECURITY.md](../SECURITY.md) incident handling. Existing installation tokens expire within about an hour;
suspend or uninstall the App to cut them off sooner.

### Webhook secret

1. Generate a new secret and store it.
2. GitHub supports one webhook secret at a time, so rotation has a short window. Set the webhook Inactive, update
   the listener's secret, update the App's secret, set Active, then verify with a ping.
3. Deliveries sent during the window are redelivered from the App's "Advanced" tab after verification.
4. Destroy the old secret. Rotate at least annually and on suspected exposure.

## 6. Removal and revocation

- Uninstall or suspend the App: GitHub sends `installation` `deleted` or `suspend`; the adapter records the
  installation as removed and refuses everything after it. Re-enabling requires an operator configuration change
  and a review; `created`, `unsuspend` and added repositories re-enable nothing.
- Remove the repository from the installation: `installation_repositories` `removed` is recorded the same way.
- To stop all intake immediately without relying on events, set the webhook Inactive or delete the
  installation's entry from the intake configuration.

## 7. Manual provisioning checklist

Record completion in the private operations log. Items marked (C6), (C12) depend on those issues.

- [ ] App registered under the intended account, not public, installable only on that account.
- [ ] Permissions exactly as in section 2; no account or organization permissions.
- [ ] Subscribed events: Pull request only.
- [ ] Installed on "Only select repositories" with the single requesting repository.
- [ ] App private key generated once, stored in the secret store, no copy on disk elsewhere.
- [ ] Webhook secret (at least 32 random bytes) generated, stored, set in the App; webhook still Inactive.
- [ ] Intake configuration written from the deployment's own values: events, installation id, repository ids,
      actor allowlist (numeric user ids, requester and approver roles). Loaded through
      `IntakeConfig::from_json`, which rejects unknown fields and empty allowlists.
- [ ] Credential manifest validated with `validate_assignments`; worker environment validated with
      `validate_worker_environment`.
- [ ] Durable `DeliveryStore`, `InstallationRegistry` and `IntakeQueue` in place (they are not provided by the C4 store as merged; see ADR 0010). Do not enable the webhook
      on the in-memory doubles.
- [ ] Transport adapter pins the GitHub API host, does not follow redirects, bounds time and response size.
- [ ] Listener serves HTTPS only, passes raw bytes, never logs bodies, headers or tokens.
- [ ] Requesting repositories' CI holds no custodian credentials (review their secrets and environments).
- [ ] Branch protection on the requesting repository requires review, so a request is not the only control on
      what reaches a protected branch.
- [ ] Deployment prerequisites in ADR 0001 T4 satisfied before any protected run (C4, C5, C6, C12).
- [ ] Key and secret rotation dates recorded; next due dates set.
- [ ] Incident owner and private reporting route recorded (C12).

## 8. Configuration file shape

Identifiers only; no secrets. Example with placeholders (not valid until each is replaced by a real positive
integer or an `act_` identity from the deployment):

```
{
  "events": ["ping", "pull_request", "installation", "installation_repositories"],
  "installations": [{"installation_id": <INSTALLATION_ID>, "repository_ids": [<REPOSITORY_ID>]}],
  "actors": [
    {"github_user_id": <USER_ID>, "actor": "act_<random 16-64 chars>", "roles": ["requester", "approver"]}
  ],
  "max_body_bytes": 262144
}
```

Actors are identified by numeric GitHub user id, not login. The `actor` value is the custodian's own
`ActorRef`. The `approver` role only makes a person eligible to be named on an `Approval`; it approves nothing
by itself. While one person holds every role, separation is procedural and approvals say so
(`single_operator_procedural`).

## 9. Reason codes

Refusals are one of the fixed codes in `custodian_intake::IntakeReason` (for example `signature_invalid`,
`body_too_large`, `delivery_replay`, `installation_removed`, `actor_not_authorized`, `fork_denied`,
`cross_repository_denied`, `comment_trigger_denied`, `stale_commit`, `approval_required`). HTTP responses and
Check summaries contain only these codes and fixed text, never payload content.
