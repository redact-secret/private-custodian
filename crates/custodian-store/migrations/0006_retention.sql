-- Migration 0006: retention of terminal, fully audited intake rows (HG-4,
-- ADR 0117).
--
-- Forward-only and checksummed like 0001 to 0005. The only change is to three
-- delete guards that 0004 made absolute. Each is replaced by a guard that
-- still refuses every delete except one of a row that is terminal and whose
-- audit events the ledger has acknowledged; the age rule lives in the purge
-- code, which takes a configured minimum with a hard floor. Nothing here
-- adds a delete path for a budget, an attempt, a reservation, a settlement,
-- an approval, a request, the outbox or any history table, and no counter is
-- touched. No statement here may contain input values, secrets or
-- deployment identifiers.

-- A finished queue item backs no audit event of its own (the submission it
-- produced does), and its delivery claim stays as replay protection.
DROP TRIGGER intake_queue_no_delete;
CREATE TRIGGER intake_queue_delete_guard BEFORE DELETE ON intake_queue
WHEN OLD.state <> 'done'
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- An enqueued claim may be forgotten only after the queue row it protects is
-- gone: replay protection never outlives its own evidence while the item is
-- still waiting or leased, and the invariant "a queued request has a
-- permanent claim" keeps holding.
DROP TRIGGER intake_deliveries_delete_guard;
CREATE TRIGGER intake_deliveries_delete_guard BEFORE DELETE ON intake_deliveries
WHEN OLD.enqueued = 1
 AND EXISTS (SELECT 1 FROM intake_queue q WHERE q.delivery_id = OLD.delivery_id)
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;

-- A decided submission may be removed only when both audit events that
-- describe it (submission and decision) are acknowledged. A pending
-- submission is never deleted: it is first cancelled by the audited expiry.
-- Everything that an approved submission produced (request, approval,
-- attempt, reservation, settlement) is a separate append-only row that stays.
DROP TRIGGER submissions_no_delete;
CREATE TRIGGER submissions_delete_guard BEFORE DELETE ON submissions
WHEN OLD.status = 'pending'
  OR NOT EXISTS (SELECT 1 FROM outbox o WHERE o.event_id = 'submitted:' || OLD.request_id
                 AND o.exported_at IS NOT NULL)
  OR NOT EXISTS (SELECT 1 FROM outbox o WHERE o.event_id =
                 (CASE OLD.status WHEN 'approved' THEN 'approved:' ELSE 'cancelled:' END)
                 || OLD.request_id AND o.exported_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'append_only');
END;
