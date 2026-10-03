-- Migration 0004: durable request intake, operator submissions and policy
-- activation state (C10, ADR 0080 to 0083).
--
-- Forward-only and checksummed like 0001 to 0003. Nothing here edits or
-- drops an existing table, lowers a counter or reinterprets a column. Budgets
-- are untouched: a submission is a request waiting for an approval, and the
-- only way it becomes a reservation is the same `reserve_tx` the GitHub path
-- uses. No statement here may contain input values, secrets or deployment
-- identifiers; rows hold identities, digests, counters and fixed vocabulary.

-- ---- GitHub request edge: delivery replay, removals, queue -------------------

-- One row per X-GitHub-Delivery id ever claimed. `enqueued = 0` means the
-- claim has not (yet) produced a queue row; such a claim lapses after the
-- claim window so a crash between claim and enqueue cannot lose the delivery
-- forever. A claim that produced a queue row is permanent: replay protection
-- never evicts.
CREATE TABLE intake_deliveries (
    delivery_id TEXT PRIMARY KEY,
    claimed_at  INTEGER NOT NULL,
    enqueued    INTEGER NOT NULL CHECK (enqueued IN (0, 1))
) STRICT;

CREATE TRIGGER intake_deliveries_guard BEFORE UPDATE ON intake_deliveries
WHEN NEW.delivery_id <> OLD.delivery_id OR (OLD.enqueued = 1 AND NEW.enqueued = 0)
BEGIN
    SELECT RAISE(ABORT, 'intake_delivery_monotonic');
END;
-- Only an un-enqueued claim may be forgotten (`release` after a refused enqueue).
CREATE TRIGGER intake_deliveries_delete_guard BEFORE DELETE ON intake_deliveries
WHEN OLD.enqueued = 1
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Installations and repositories GitHub told us were removed. `repository_id`
-- 0 means the whole installation (real ids start at 1). There is no operation
-- that re-enables anything: rows are never updated or deleted.
CREATE TABLE intake_removals (
    installation_id INTEGER NOT NULL CHECK (installation_id >= 1),
    repository_id   INTEGER NOT NULL CHECK (repository_id >= 0),
    removed_at      INTEGER NOT NULL,
    PRIMARY KEY (installation_id, repository_id)
) STRICT;

CREATE TRIGGER intake_removals_immutable BEFORE UPDATE ON intake_removals
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER intake_removals_no_delete BEFORE DELETE ON intake_removals
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Accepted requests awaiting the control plane. Identifiers only: no title,
-- body, branch, label or comment from the payload exists here. Delivery is
-- at-least-once: a leased item whose lease lapses is leased again, so the
-- consumer must be idempotent (the reservation idempotency key makes it so).
CREATE TABLE intake_queue (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id      TEXT NOT NULL UNIQUE,
    installation_id  INTEGER NOT NULL,
    repository_id    INTEGER NOT NULL,
    pull_request     INTEGER NOT NULL,
    head_sha         TEXT NOT NULL,
    actor            TEXT NOT NULL,
    github_user      INTEGER NOT NULL,
    received_at      INTEGER NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'done')),
    lease_owner      TEXT,
    lease_token      INTEGER NOT NULL DEFAULT 0,
    lease_expires_at INTEGER,
    attempts         INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL
) STRICT;

CREATE TRIGGER intake_queue_guard BEFORE UPDATE ON intake_queue
WHEN NEW.seq <> OLD.seq
  OR NEW.delivery_id <> OLD.delivery_id
  OR NEW.installation_id <> OLD.installation_id
  OR NEW.repository_id <> OLD.repository_id
  OR NEW.pull_request <> OLD.pull_request
  OR NEW.head_sha <> OLD.head_sha
  OR NEW.actor <> OLD.actor
  OR NEW.github_user <> OLD.github_user
  OR NEW.received_at <> OLD.received_at
  OR (OLD.state = 'done' AND NEW.state <> 'done')
  OR NEW.attempts < OLD.attempts
  OR NEW.lease_token < OLD.lease_token
BEGIN
    SELECT RAISE(ABORT, 'intake_queue_monotonic');
END;
CREATE TRIGGER intake_queue_no_delete BEFORE DELETE ON intake_queue
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- ---- Operator and App submissions --------------------------------------------

-- A request that passed validation and waits for an explicit approval. It is
-- not a reservation and holds no budget. The only transition out of
-- 'pending' is to 'approved' (inside the transaction that reserves, so the
-- budget charge and the status change commit together) or to 'cancelled'.
CREATE TABLE submissions (
    request_id      TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_digest  TEXT NOT NULL,
    plan_digest     TEXT NOT NULL,
    document        TEXT NOT NULL,
    requester       TEXT NOT NULL,
    submitted_by    TEXT NOT NULL,
    channel         TEXT NOT NULL CHECK (channel IN ('cli', 'app')),
    submitted_at    INTEGER NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'cancelled')),
    decided_by      TEXT,
    decided_kind    TEXT CHECK (decided_kind IS NULL OR decided_kind IN ('human', 'service', 'agent')),
    decided_at      INTEGER,
    approval_id     TEXT,
    attempt_id      TEXT,
    CHECK ((status = 'pending') = (decided_by IS NULL AND decided_at IS NULL)),
    CHECK ((status = 'approved') = (approval_id IS NOT NULL AND attempt_id IS NOT NULL)),
    -- An agent never approves, whatever any application code says.
    CHECK (NOT (status = 'approved' AND decided_kind = 'agent')),
    -- Nobody approves their own request, whatever any application code says.
    CHECK (NOT (status = 'approved' AND decided_by = requester))
) STRICT;

CREATE TRIGGER submissions_guard BEFORE UPDATE ON submissions
WHEN NEW.request_id <> OLD.request_id
  OR NEW.idempotency_key <> OLD.idempotency_key
  OR NEW.request_digest <> OLD.request_digest
  OR NEW.plan_digest <> OLD.plan_digest
  OR NEW.document <> OLD.document
  OR NEW.requester <> OLD.requester
  OR NEW.submitted_by <> OLD.submitted_by
  OR NEW.channel <> OLD.channel
  OR NEW.submitted_at <> OLD.submitted_at
  OR OLD.status <> 'pending'
BEGIN
    SELECT RAISE(ABORT, 'submission_monotonic');
END;
CREATE TRIGGER submissions_no_delete BEFORE DELETE ON submissions
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- ---- Policy activation state --------------------------------------------------

-- Append-only history of policy activation states, one row per
-- (activation, sequence). The newest sequence is the current state. A state
-- change appends a higher sequence; nothing is edited in place. `document`
-- is the canonical `PolicyActivation` contract document.
CREATE TABLE policy_activations (
    activation_id TEXT NOT NULL,
    sequence      INTEGER NOT NULL CHECK (sequence >= 1),
    policy_kind   TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'superseded')),
    document      TEXT NOT NULL,
    document_digest TEXT NOT NULL,
    recorded_by   TEXT NOT NULL,
    recorded_at   INTEGER NOT NULL,
    PRIMARY KEY (activation_id, sequence)
) STRICT;

CREATE TRIGGER policy_activations_monotonic BEFORE INSERT ON policy_activations
WHEN NEW.sequence <= COALESCE(
    (SELECT MAX(sequence) FROM policy_activations WHERE activation_id = NEW.activation_id), 0)
BEGIN
    SELECT RAISE(ABORT, 'activation_sequence_monotonic');
END;
CREATE TRIGGER policy_activations_immutable BEFORE UPDATE ON policy_activations
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER policy_activations_no_delete BEFORE DELETE ON policy_activations
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
