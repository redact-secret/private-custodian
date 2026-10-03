-- Migration 0003: epoch standing, contamination events, rotation links and the
-- revocation feed (C9, ADR 0070 to 0073).
--
-- Forward-only and checksummed like 0001 and 0002. Nothing here edits or
-- drops an existing table, lowers a counter or reinterprets a column: budgets
-- are untouched, and a new epoch is a new budget scope key, never a reset.
-- Every history table is append-only by trigger. No statement here may
-- contain input values, secrets or deployment identifiers; rows hold
-- identities, digests, counters and fixed vocabulary only.

-- Current standing of one epoch (see custodian_core::standing). Absence of a
-- row means nothing has been recorded: the epoch is unaffected and not
-- retired. The guard trigger is the last line of defence behind the core
-- rule: severity never drops except the reviewed `unreviewed_change ->
-- unaffected` clearance, and retirement is one-way.
CREATE TABLE epoch_standing (
    epoch_id      TEXT PRIMARY KEY,
    corpus_id     TEXT NOT NULL,
    family_id     TEXT,
    contamination TEXT NOT NULL CHECK (contamination IN (
        'unaffected', 'unreviewed_change', 'exposed', 'used_for_tuning')),
    retired       INTEGER NOT NULL CHECK (retired IN (0, 1)),
    version       INTEGER NOT NULL CHECK (version >= 1),
    updated_at    INTEGER NOT NULL
) STRICT;

CREATE TRIGGER epoch_standing_guard BEFORE UPDATE ON epoch_standing
WHEN NEW.epoch_id <> OLD.epoch_id
  OR NEW.corpus_id <> OLD.corpus_id
  OR NEW.family_id IS NOT OLD.family_id
  OR NEW.version <> OLD.version + 1
  OR (OLD.retired = 1 AND NEW.retired = 0)
  OR ((CASE NEW.contamination WHEN 'unaffected' THEN 0 WHEN 'unreviewed_change' THEN 1
        WHEN 'exposed' THEN 2 ELSE 3 END)
      < (CASE OLD.contamination WHEN 'unaffected' THEN 0 WHEN 'unreviewed_change' THEN 1
        WHEN 'exposed' THEN 2 ELSE 3 END)
      AND NOT (OLD.contamination = 'unreviewed_change' AND NEW.contamination = 'unaffected'
               AND OLD.retired = 0))
BEGIN
    SELECT RAISE(ABORT, 'epoch_standing_monotonic');
END;
CREATE TRIGGER epoch_standing_no_delete BEFORE DELETE ON epoch_standing
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Every change request that reached the store, including repeats that
-- changed nothing: who, why, from what, under which authorization.
CREATE TABLE epoch_events (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch_id            TEXT NOT NULL REFERENCES epoch_standing (epoch_id),
    idempotency_key     TEXT NOT NULL UNIQUE,
    request_digest      TEXT NOT NULL,
    change              TEXT NOT NULL CHECK (change IN ('report', 'clear', 'retire')),
    reported            TEXT CHECK (reported IS NULL OR reported IN (
        'unreviewed_change', 'exposed', 'used_for_tuning')),
    prior_contamination TEXT NOT NULL,
    prior_retired       INTEGER NOT NULL CHECK (prior_retired IN (0, 1)),
    new_contamination   TEXT NOT NULL,
    new_retired         INTEGER NOT NULL CHECK (new_retired IN (0, 1)),
    changed             INTEGER NOT NULL CHECK (changed IN (0, 1)),
    version_after       INTEGER NOT NULL,
    actor               TEXT NOT NULL,
    actor_kind          TEXT NOT NULL CHECK (actor_kind IN ('human', 'service', 'agent')),
    reason              TEXT NOT NULL,
    authorization_ref   TEXT NOT NULL,
    at                  INTEGER NOT NULL,
    CHECK ((change = 'report') = (reported IS NOT NULL))
) STRICT;

CREATE TRIGGER epoch_events_immutable BEFORE UPDATE ON epoch_events
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER epoch_events_no_delete BEFORE DELETE ON epoch_events
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- One successor per epoch, and one predecessor per epoch: a rotation is a
-- link between two distinct epochs, never an edit of either.
CREATE TABLE epoch_rotations (
    successor_epoch   TEXT PRIMARY KEY,
    predecessor_epoch TEXT NOT NULL UNIQUE REFERENCES epoch_standing (epoch_id),
    corpus_id         TEXT NOT NULL,
    family_id         TEXT,
    actor             TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    at                INTEGER NOT NULL,
    CHECK (successor_epoch <> predecessor_epoch)
) STRICT;

CREATE TRIGGER epoch_rotations_immutable BEFORE UPDATE ON epoch_rotations
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER epoch_rotations_no_delete BEFORE DELETE ON epoch_rotations
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Revocation entries the custodian owes its public feed. An obligation is
-- written in the same transaction as the decision that causes it, so a
-- contamination can never be recorded without its feed consequence. The
-- internal target (an epoch id, a candidate digest, ...) stays here; the
-- publisher translates it to the public form. An entry is never removed;
-- publishing only stamps `published_seq` once.
CREATE TABLE feed_obligations (
    seq               INTEGER PRIMARY KEY AUTOINCREMENT,
    obligation_id     TEXT NOT NULL UNIQUE,
    target_kind       TEXT NOT NULL CHECK (target_kind IN (
        'projection', 'receipt', 'candidate', 'population', 'policy')),
    target_ref        TEXT NOT NULL,
    action            TEXT NOT NULL CHECK (action IN ('revoked', 'contaminated', 'superseded')),
    superseded_by     TEXT,
    reason            TEXT NOT NULL CHECK (reason IN (
        'contamination', 'epoch_rotation', 'key_compromise', 'policy_revoked',
        'error_correction', 'newer_evidence')),
    effective_at      INTEGER NOT NULL,
    actor             TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    published_seq     INTEGER,
    CHECK ((action = 'superseded') = (superseded_by IS NOT NULL))
) STRICT;

CREATE INDEX feed_obligations_target ON feed_obligations (target_kind, target_ref);
CREATE INDEX feed_obligations_pending ON feed_obligations (seq) WHERE published_seq IS NULL;

CREATE TRIGGER feed_obligations_stamp_once BEFORE UPDATE ON feed_obligations
WHEN OLD.published_seq IS NOT NULL
  OR NEW.published_seq IS NULL
  OR NEW.seq <> OLD.seq
  OR NEW.obligation_id <> OLD.obligation_id
  OR NEW.target_kind <> OLD.target_kind
  OR NEW.target_ref <> OLD.target_ref
  OR NEW.action <> OLD.action
  OR NEW.superseded_by IS NOT OLD.superseded_by
  OR NEW.reason <> OLD.reason
  OR NEW.effective_at <> OLD.effective_at
  OR NEW.actor <> OLD.actor
  OR NEW.authorization_ref <> OLD.authorization_ref
  OR NEW.created_at <> OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER feed_obligations_no_delete BEFORE DELETE ON feed_obligations
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- The signed envelopes, exactly as published. Contiguous per feed with a
-- matching `previous` link, enforced by trigger as well as by the code, so a
-- fork or a gap cannot be committed whatever the caller does.
CREATE TABLE feed_envelopes (
    feed_id         TEXT NOT NULL,
    sequence        INTEGER NOT NULL CHECK (sequence >= 1),
    previous_digest TEXT,
    digest          TEXT NOT NULL,
    document        TEXT NOT NULL,
    issued_at       INTEGER NOT NULL,
    fresh_until     INTEGER NOT NULL,
    recorded_at     INTEGER NOT NULL,
    PRIMARY KEY (feed_id, sequence),
    CHECK ((sequence = 1) = (previous_digest IS NULL)),
    CHECK (fresh_until > issued_at)
) STRICT;

CREATE TRIGGER feed_envelopes_chain BEFORE INSERT ON feed_envelopes
WHEN NEW.sequence <> COALESCE((SELECT MAX(sequence) FROM feed_envelopes
                               WHERE feed_id = NEW.feed_id), 0) + 1
  OR NEW.previous_digest IS NOT (SELECT digest FROM feed_envelopes
                                 WHERE feed_id = NEW.feed_id AND sequence = NEW.sequence - 1)
BEGIN
    SELECT RAISE(ABORT, 'feed_chain');
END;
CREATE TRIGGER feed_envelopes_immutable BEFORE UPDATE ON feed_envelopes
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER feed_envelopes_no_delete BEFORE DELETE ON feed_envelopes
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- Delivery of an envelope to the public destination, recorded after the
-- destination confirmed the write. Insert-only.
CREATE TABLE feed_deliveries (
    feed_id      TEXT NOT NULL,
    sequence     INTEGER NOT NULL,
    destination  TEXT NOT NULL,
    delivered_at INTEGER NOT NULL,
    PRIMARY KEY (feed_id, sequence),
    FOREIGN KEY (feed_id, sequence) REFERENCES feed_envelopes (feed_id, sequence)
) STRICT;

CREATE TRIGGER feed_deliveries_immutable BEFORE UPDATE ON feed_deliveries
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
CREATE TRIGGER feed_deliveries_no_delete BEFORE DELETE ON feed_deliveries
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
