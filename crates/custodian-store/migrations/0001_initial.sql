-- Migration 0001: initial runtime schema (C4, ADR 0020 to 0022).
--
-- Forward-only. This file is checksummed (SHA-256 of its exact bytes) and the
-- checksum is recorded in schema_migrations; editing it after release makes
-- every database that applied it refuse to open. Add a new numbered file
-- instead. No statement here may contain input values, secrets or
-- deployment identifiers.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

INSERT INTO meta (key, value) VALUES ('store_id', lower(hex(randomblob(16))));
INSERT INTO meta (key, value) VALUES ('needs_reconcile', '0');

-- Budget counters per scope. The scope key is a digest of the kind and the
-- canonical BudgetScope, so a candidate lineage (not a candidate digest)
-- identifies a blind budget. The CHECK is the last line of defence: no bug in
-- the code can commit more units than the limit.
CREATE TABLE budgets (
    scope_key      TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('run', 'release_query')),
    scope_json     TEXT NOT NULL,
    limit_units    INTEGER NOT NULL CHECK (limit_units >= 0),
    held_units     INTEGER NOT NULL DEFAULT 0 CHECK (held_units >= 0),
    consumed_units INTEGER NOT NULL DEFAULT 0 CHECK (consumed_units >= 0),
    refunded_units INTEGER NOT NULL DEFAULT 0 CHECK (refunded_units >= 0),
    CHECK (held_units + consumed_units <= limit_units)
) STRICT;

-- A budget never shrinks, never forgets consumption and is never deleted.
CREATE TRIGGER budgets_monotonic BEFORE UPDATE ON budgets
WHEN NEW.scope_key <> OLD.scope_key
  OR NEW.kind <> OLD.kind
  OR NEW.scope_json <> OLD.scope_json
  OR NEW.limit_units < OLD.limit_units
  OR NEW.consumed_units < OLD.consumed_units
  OR NEW.refunded_units < OLD.refunded_units
BEGIN
    SELECT RAISE(ABORT, 'budget_monotonic');
END;
CREATE TRIGGER budgets_no_delete BEFORE DELETE ON budgets
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- One row per request. The idempotency key is unique: a duplicate delivery
-- finds this row instead of charging again.
CREATE TABLE requests (
    request_id      TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_digest  TEXT NOT NULL,
    plan_digest     TEXT NOT NULL,
    scope_key       TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('run', 'release_query')),
    units           INTEGER NOT NULL CHECK (units > 0),
    max_retries     INTEGER NOT NULL CHECK (max_retries >= 0),
    actor           TEXT NOT NULL,
    requested_at    INTEGER NOT NULL,
    -- 'contract': created through the contract API, `document` holds the
    -- canonical request. 'port': created through the core StateStore port,
    -- `subject` holds the opaque population identity.
    origin          TEXT NOT NULL CHECK (origin IN ('contract', 'port')),
    subject         TEXT,
    document        TEXT,
    CHECK ((origin = 'contract') = (document IS NOT NULL))
) STRICT;

CREATE TABLE approvals (
    request_id      TEXT NOT NULL REFERENCES requests (request_id),
    approval_id     TEXT NOT NULL,
    approval_digest TEXT NOT NULL,
    approver        TEXT NOT NULL,
    activation_id   TEXT NOT NULL,
    activation_seq  INTEGER NOT NULL,
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    document        TEXT,
    PRIMARY KEY (request_id, approval_id)
) STRICT;

-- One row per attempt. The attempt is the unit of the state machine and of
-- the lease; its id is the core RunId. Attempt 1 is the original request; a
-- retry is a new attempt with its own reservation.
CREATE TABLE attempts (
    attempt_id        TEXT PRIMARY KEY,
    request_id        TEXT NOT NULL REFERENCES requests (request_id),
    attempt_no        INTEGER NOT NULL CHECK (attempt_no >= 1),
    state             TEXT NOT NULL CHECK (state IN (
        'proposed', 'authorized', 'reserved', 'running', 'validating',
        'completed', 'denied', 'failed', 'cancelled', 'expired')),
    exposure          TEXT NOT NULL CHECK (exposure IN ('not_exposed', 'exposed')),
    authorization_ref TEXT NOT NULL,
    reservation_id    TEXT,
    lease_owner       TEXT,
    lease_token       INTEGER NOT NULL DEFAULT 0,
    lease_expires_at  INTEGER,
    version           INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    UNIQUE (request_id, attempt_no)
) STRICT;

-- At most one live attempt per request, whatever the callers do.
CREATE UNIQUE INDEX attempts_one_live ON attempts (request_id)
WHERE state IN ('reserved', 'running', 'validating');

CREATE TRIGGER attempts_terminal_immutable BEFORE UPDATE ON attempts
WHEN OLD.state IN ('completed', 'denied', 'failed', 'cancelled', 'expired')
BEGIN
    SELECT RAISE(ABORT, 'terminal_immutable');
END;
CREATE TRIGGER attempts_exposure_sticky BEFORE UPDATE ON attempts
WHEN OLD.exposure = 'exposed' AND NEW.exposure <> 'exposed'
BEGIN
    SELECT RAISE(ABORT, 'exposure_sticky');
END;
CREATE TRIGGER attempts_no_delete BEFORE DELETE ON attempts
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Charge-at-reservation: a reservation is created holding the units and
-- settles exactly once to consumed or refunded. Refunded with exposure is
-- unrepresentable.
CREATE TABLE reservations (
    reservation_id   TEXT PRIMARY KEY,
    attempt_id       TEXT NOT NULL UNIQUE REFERENCES attempts (attempt_id),
    request_id       TEXT NOT NULL REFERENCES requests (request_id),
    approval_id      TEXT NOT NULL,
    plan_digest      TEXT NOT NULL,
    scope_key        TEXT NOT NULL REFERENCES budgets (scope_key),
    kind             TEXT NOT NULL CHECK (kind IN ('run', 'release_query')),
    units            INTEGER NOT NULL CHECK (units > 0),
    state            TEXT NOT NULL CHECK (state IN ('held', 'consumed', 'refunded')),
    exposure         TEXT NOT NULL CHECK (exposure IN ('not_exposed', 'exposed')),
    reserved_at      INTEGER NOT NULL,
    lease_expires_at INTEGER NOT NULL,
    settled_at       INTEGER,
    CHECK (NOT (state = 'refunded' AND exposure = 'exposed')),
    CHECK ((state = 'held') = (settled_at IS NULL))
) STRICT;

CREATE TRIGGER reservations_settle_once BEFORE UPDATE ON reservations
WHEN OLD.state <> 'held'
  OR NEW.units <> OLD.units
  OR NEW.scope_key <> OLD.scope_key
  OR NEW.attempt_id <> OLD.attempt_id
BEGIN
    SELECT RAISE(ABORT, 'settle_once');
END;
CREATE TRIGGER reservations_no_delete BEFORE DELETE ON reservations
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Every state change and every exposure record: actor, reason code, prior
-- state, authorization reference. Append-only.
CREATE TABLE transitions (
    attempt_id        TEXT NOT NULL REFERENCES attempts (attempt_id),
    seq               INTEGER NOT NULL CHECK (seq >= 1),
    request_id        TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('transition', 'exposure')),
    from_state        TEXT,
    to_state          TEXT NOT NULL,
    actor             TEXT NOT NULL,
    reason            TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    at                INTEGER NOT NULL,
    PRIMARY KEY (attempt_id, seq)
) STRICT;

-- The settlement of a reservation, one row, written in the same transaction
-- as the terminal state.
CREATE TABLE settlements (
    reservation_id TEXT PRIMARY KEY REFERENCES reservations (reservation_id),
    attempt_id     TEXT NOT NULL UNIQUE REFERENCES attempts (attempt_id),
    scope_key      TEXT NOT NULL,
    units          INTEGER NOT NULL CHECK (units > 0),
    result         TEXT NOT NULL CHECK (result IN ('consumed', 'refunded')),
    exposure       TEXT NOT NULL CHECK (exposure IN ('not_exposed', 'exposed')),
    outcome        TEXT NOT NULL,
    reason         TEXT NOT NULL,
    settled_at     INTEGER NOT NULL,
    CHECK (NOT (result = 'refunded' AND exposure = 'exposed'))
) STRICT;

-- Audit export intent. A row here is written in the same transaction as the
-- state it describes; export (C7) reads pending rows and acknowledges them.
-- The hash chain makes truncation and edits detectable against a checkpoint
-- held outside this database.
CREATE TABLE outbox (
    seq            INTEGER PRIMARY KEY CHECK (seq >= 1),
    event_id       TEXT NOT NULL UNIQUE,
    kind           TEXT NOT NULL,
    request_id     TEXT,
    attempt_id     TEXT,
    payload        TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    chain          TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    exported_at    INTEGER,
    export_ref     TEXT,
    CHECK ((exported_at IS NULL) = (export_ref IS NULL))
) STRICT;

CREATE TRIGGER outbox_ack_only BEFORE UPDATE ON outbox
WHEN OLD.exported_at IS NOT NULL
  OR NEW.seq <> OLD.seq
  OR NEW.event_id <> OLD.event_id
  OR NEW.kind <> OLD.kind
  OR NEW.payload <> OLD.payload
  OR NEW.payload_digest <> OLD.payload_digest
  OR NEW.chain <> OLD.chain
  OR NEW.created_at <> OLD.created_at
  OR IFNULL(NEW.request_id, '') <> IFNULL(OLD.request_id, '')
  OR IFNULL(NEW.attempt_id, '') <> IFNULL(OLD.attempt_id, '')
BEGIN
    SELECT RAISE(ABORT, 'outbox_ack_only');
END;
CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Append-only guards for the remaining history tables.
CREATE TRIGGER requests_immutable BEFORE UPDATE ON requests
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER requests_no_delete BEFORE DELETE ON requests
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER approvals_immutable BEFORE UPDATE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER transitions_immutable BEFORE UPDATE ON transitions
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER transitions_no_delete BEFORE DELETE ON transitions
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER settlements_immutable BEFORE UPDATE ON settlements
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER settlements_no_delete BEFORE DELETE ON settlements
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
