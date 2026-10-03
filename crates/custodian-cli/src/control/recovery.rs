//! The recovery commands of S6: accepting a restore loss (R-1, ADR 0130) and
//! re-issuing a revoked key's ledger history (R-4, ADR 0131).
//!
//! Both are human-operator-only, both refuse unless the operator names the
//! exact object (store id, sequences, chain value, plan digest, key ids), both
//! have a read-only plan that prints the digest to confirm, and neither can
//! raise, lower or reset a budget by any path other than the store's own
//! audited, monotone operations.

use std::collections::{BTreeMap, BTreeSet};

use custodian_contracts::common::BudgetScope;
use custodian_contracts::types::{EpochId, KeyId};
use custodian_core::{ActorId, Contamination};
use custodian_corpus::EpochBlobStore;
use custodian_ledger::recovery::{
    affected_scopes, derive_consumption, epoch_floors, lost_attempts, lost_feed_events, lost_tail,
};
use custodian_ledger::{
    execute_reissue, plan_reissue, revoke_key, walk_ledger, AuditEntry, ReissueRequest,
};
use custodian_lifecycle::OperatorAction;
use custodian_store::{Checkpoint, LossAcceptCommand, LossEpoch, LossEvent, LossOutcome};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{store_id_matches, Control, Res};
use crate::authority::{Permission, Principal};
use crate::command::LOSS_ACKNOWLEDGEMENT;
use crate::output::Output;
use crate::reason::CliReason;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Everything an acceptance would do, computed from the ledger and the store
/// without writing anything.
pub(super) struct LossPlan {
    store_seq: u64,
    tip: Checkpoint,
    events: Vec<LossEvent>,
    consumed: BTreeMap<String, u64>,
    epochs: Vec<LossEpoch>,
    lost_attempts: usize,
    lost_feed: Vec<String>,
    unresolved_scopes: usize,
    unresolved_epochs: usize,
    recovered_scopes: u64,
    recovered_units: u64,
    digest: String,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The store's own payload text for a ledger audit record: the exact text
/// whose digest the chain was built from. A record is adoptable only if this
/// reproduces the recorded digest.
fn store_payload_text(e: &AuditEntry) -> Option<String> {
    // A member the store payload held as null is omitted from the ledger
    // record; `previous_limit` of a first provisioning is the one such member.
    for nulls in [&[][..], &["previous_limit"][..]] {
        let mut m = e.payload.clone();
        for k in nulls {
            m.insert((*k).to_owned(), Value::Null);
        }
        let text = Value::Object(m).to_string();
        if sha256_hex(text.as_bytes()) == e.payload_digest {
            return Some(text);
        }
    }
    None
}

fn contamination_floor(word: &str) -> Option<Contamination> {
    Contamination::parse(word)
}

impl<S: EpochBlobStore> Control<'_, S> {
    /// Read-only. Never sets or clears anything.
    pub(super) fn loss_plan(&self) -> Res<LossPlan> {
        let store = self.p.store;
        let walk =
            walk_ledger(self.p.ledger, self.p.roots).map_err(|_| CliReason::LedgerUnavailable)?;
        if !walk.is_trustworthy() {
            return Err(CliReason::LedgerUntrusted);
        }
        let tip = walk
            .store_checkpoint
            .clone()
            .ok_or(CliReason::StoreNotBehindLedger)?;
        if store.contains_checkpoint(&tip).map_err(CliReason::from)? {
            return Err(CliReason::StoreNotBehindLedger);
        }
        if let Some(point) = &walk.registry_checkpoint {
            let view = self
                .p
                .populations
                .registry()
                .view()
                .map_err(|_| CliReason::StoreUnavailable)?;
            if view.event_count() < point.event_count
                || view.head_after(point.event_count).as_ref() != Some(&point.head)
            {
                return Err(CliReason::RegistryRolledBack);
            }
        }
        let local = store.latest_checkpoint().map_err(CliReason::from)?;
        let (m, mchain) = local.map_or((0, GENESIS.to_owned()), |c| (c.seq, c.chain));
        // The store's history must be a prefix of the ledger's. Anything else
        // is two histories, not one history and a rollback.
        if m >= tip.seq {
            return Err(CliReason::LineageDiverged);
        }
        if m > 0 {
            let at = walk.audit.iter().find(|e| e.seq == m);
            if at.is_none_or(|e| e.chain != mchain) {
                return Err(CliReason::LineageDiverged);
            }
        }
        let tail = lost_tail(&walk.audit, m);
        let contiguous = tail
            .iter()
            .enumerate()
            .all(|(i, e)| e.seq == m + 1 + i as u64);
        let ends_at_tip = tail
            .last()
            .is_some_and(|e| e.seq == tip.seq && e.chain == tip.chain);
        if tail.is_empty() || !contiguous || !ends_at_tip {
            return Err(CliReason::LedgerTailIncomplete);
        }
        let mut events = Vec::with_capacity(tail.len());
        for e in &tail {
            let payload = store_payload_text(e).ok_or(CliReason::LedgerTailIncomplete)?;
            let field = |k: &str| e.payload.get(k).and_then(Value::as_str).map(str::to_owned);
            events.push(LossEvent {
                seq: e.seq,
                event_id: e.event_id.clone(),
                kind: e.kind.clone(),
                request_id: field("request_id"),
                attempt_id: field("attempt_id"),
                payload,
                payload_digest: e.payload_digest.clone(),
                chain: e.chain.clone(),
                created_at: e.issued_at,
                export_ref: format!("ledger/{}", e.record_id),
            });
        }

        let consumed = derive_consumption(&walk.audit).consumed_by_scope;
        let budgets = store.budgets_overview().map_err(CliReason::from)?;
        let mut by_scope: BTreeMap<&str, (String, String, Option<String>)> = BTreeMap::new();
        let mut recovered_scopes = 0u64;
        let mut recovered_units = 0u64;
        for b in &budgets {
            if let Ok(scope) = serde_json::from_str::<BudgetScope>(&b.scope_json) {
                let (c, ep, f) = match &scope {
                    BudgetScope::PopulationEpoch {
                        corpus_id,
                        epoch_id,
                        family_id,
                    }
                    | BudgetScope::CandidateLineageEpoch {
                        corpus_id,
                        epoch_id,
                        family_id,
                        ..
                    } => (
                        corpus_id.as_str().to_owned(),
                        epoch_id.as_str().to_owned(),
                        family_id.as_ref().map(|f| f.as_str().to_owned()),
                    ),
                };
                by_scope.insert(b.scope_key.as_str(), (c, ep, f));
            }
            if let Some(l) = consumed.get(&b.scope_key) {
                let deficit = l.saturating_sub(b.consumed);
                if deficit > 0 {
                    recovered_scopes += 1;
                    recovered_units += deficit.min(b.limit.saturating_sub(b.held + b.consumed));
                }
            }
        }
        // Scopes the ledger shows consumed that the store has no budget for.
        let known: BTreeSet<&str> = budgets.iter().map(|b| b.scope_key.as_str()).collect();
        for (k, l) in &consumed {
            if !known.contains(k.as_str()) && *l > 0 {
                recovered_scopes += 1;
                recovered_units += l;
            }
        }

        // Epochs: retire every epoch with budget-affecting activity in the
        // lost window; raise standing to what the ledger states.
        let view = self
            .p
            .populations
            .registry()
            .view()
            .map_err(|_| CliReason::StoreUnavailable)?;
        let mut epochs: BTreeMap<String, LossEpoch> = BTreeMap::new();
        let mut unresolved_scopes = 0usize;
        for scope in affected_scopes(&tail) {
            match by_scope.get(scope.as_str()) {
                Some((c, ep, f)) => {
                    epochs
                        .entry(ep.clone())
                        .or_insert_with(|| LossEpoch {
                            epoch_id: ep.clone(),
                            corpus_id: c.clone(),
                            family_id: f.clone(),
                            floor: None,
                            retire: false,
                        })
                        .retire = true;
                }
                None => unresolved_scopes += 1,
            }
        }
        let mut unresolved_epochs = 0usize;
        for (id, floor) in epoch_floors(&tail) {
            let row = EpochId::parse(&id)
                .ok()
                .and_then(|e| view.get(&e).map(|(r, _)| r.clone()));
            let Some(row) = row else {
                unresolved_epochs += 1;
                continue;
            };
            let e = epochs.entry(id.clone()).or_insert_with(|| LossEpoch {
                epoch_id: id.clone(),
                corpus_id: row.corpus_id.as_str().to_owned(),
                family_id: row.family_id.as_ref().map(|f| f.as_str().to_owned()),
                floor: None,
                retire: false,
            });
            e.floor = contamination_floor(&floor.contamination);
            e.retire |= floor.retired;
        }
        let epochs: Vec<LossEpoch> = epochs.into_values().collect();
        let lost_attempts = lost_attempts(&tail).len();
        let lost_feed = lost_feed_events(&tail);

        let mut h = Sha256::new();
        h.update(b"private-custodian/cli/loss-plan/v1\0");
        h.update(store.store_id().map_err(CliReason::from)?.as_bytes());
        for part in [
            m.to_string(),
            mchain,
            tip.seq.to_string(),
            tip.chain.clone(),
        ] {
            h.update([0]);
            h.update(part.as_bytes());
        }
        for e in &events {
            h.update([1]);
            h.update(e.seq.to_string().as_bytes());
            h.update(e.chain.as_bytes());
        }
        for (k, v) in &consumed {
            h.update([2]);
            h.update(k.as_bytes());
            h.update(v.to_string().as_bytes());
        }
        for e in &epochs {
            h.update([3]);
            h.update(e.epoch_id.as_bytes());
            h.update([e.floor.map_or(255, |c| c as u8), u8::from(e.retire)]);
        }
        for f in &lost_feed {
            h.update([4]);
            h.update(f.as_bytes());
        }
        for n in [unresolved_scopes, unresolved_epochs] {
            h.update([5]);
            h.update(n.to_string().as_bytes());
        }
        let digest = format!("sha256:{}", sha256_hex(&h.finalize()));

        Ok(LossPlan {
            store_seq: m,
            tip,
            events,
            consumed,
            epochs,
            lost_attempts,
            lost_feed,
            unresolved_scopes,
            unresolved_epochs,
            recovered_scopes,
            recovered_units,
            digest,
        })
    }

    fn plan_fields(o: Output, p: &LossPlan) -> Output {
        o.num("store_seq", p.store_seq)
            .num("ledger_seq", p.tip.seq)
            .id("ledger_chain", &p.tip.chain)
            .num("events_to_adopt", p.events.len() as u64)
            .num("scopes_to_raise", p.recovered_scopes)
            .num("units_to_recover", p.recovered_units)
            .num("epochs_affected", p.epochs.len() as u64)
            .num(
                "epochs_to_retire",
                p.epochs.iter().filter(|e| e.retire).count() as u64,
            )
            .num("lost_attempts", p.lost_attempts as u64)
            .num("lost_feed_events", p.lost_feed.len() as u64)
            .num("unresolved_scopes", p.unresolved_scopes as u64)
            .num("unresolved_epochs", p.unresolved_epochs as u64)
            .id("plan_digest", &p.digest)
    }

    pub(super) fn loss_plan_command(
        &self,
        who: &Principal,
        name: &'static str,
        confirm_store_id: &str,
    ) -> Res<Output> {
        who.check(Permission::Diagnose)?;
        store_id_matches(self.p.store, confirm_store_id)?;
        let plan = self.loss_plan()?;
        Ok(Self::plan_fields(Output::ok(name, "planned"), &plan))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn accept_loss(
        &self,
        who: &Principal,
        name: &'static str,
        confirm_store_id: &str,
        (confirm_store_seq, confirm_ledger_seq): (u64, u64),
        (confirm_chain, confirm_digest, acknowledge): (&str, &str, &str),
        dry: bool,
    ) -> Res<Output> {
        // Human operator only: the same authority as retiring an epoch, since
        // that is part of the effect.
        who.check(Permission::Repair)?;
        who.check(Permission::Lifecycle(OperatorAction::RetireEpoch))?;
        let store = self.p.store;
        store_id_matches(store, confirm_store_id)?;
        if acknowledge != LOSS_ACKNOWLEDGEMENT {
            return Err(CliReason::ConfirmationMismatch);
        }
        // A repeat of an accepted plan changes nothing.
        if store.loss_accepted(confirm_digest).unwrap_or(false) {
            return Ok(Output::ok(name, "accepted").flag("replay", true));
        }
        let plan = self.loss_plan()?;
        if plan.store_seq != confirm_store_seq
            || plan.tip.seq != confirm_ledger_seq
            || plan.tip.chain != confirm_chain
            || plan.digest != confirm_digest
        {
            return Err(CliReason::ConfirmationMismatch);
        }
        if dry {
            return Ok(Self::plan_fields(Output::ok(name, "would_accept"), &plan));
        }
        let outcome = store
            .accept_ledger_loss(&LossAcceptCommand {
                plan_digest: &plan.digest,
                events: &plan.events,
                ledger_consumed: &plan.consumed,
                epochs: &plan.epochs,
                actor: &ActorId::new(who.actor().as_str()),
                now: self.now()?.secs(),
            })
            .map_err(CliReason::from)?;
        Ok(match outcome {
            LossOutcome::Accepted(r) => Output::ok(name, "accepted")
                .id("acceptance_id", &r.acceptance_id)
                .num("adopted_events", r.adopted_events)
                .num("recovered_scopes", r.recovered_scopes)
                .num("recovered_units", r.recovered_units)
                .num("saturated_scopes", r.saturated_scopes)
                .num("epochs_flagged", r.epochs_flagged)
                .num("epochs_retired", r.epochs_retired)
                .num("lost_feed_events", plan.lost_feed.len() as u64)
                .flag("replay", r.replay),
            LossOutcome::Refused(why) => Output::ok(name, "refused")
                .word("refusal", why.code())
                .with_failure(name, CliReason::LossRefused),
        })
    }

    // ---- R-4 --------------------------------------------------------------------

    pub(super) fn revoke_key_command(
        &self,
        who: &Principal,
        name: &'static str,
        key: &KeyId,
        confirm: &KeyId,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Repair)?;
        if key != confirm {
            return Err(CliReason::ConfirmationMismatch);
        }
        if dry {
            return Ok(Output::ok(name, "would_revoke").id("key_id", key.as_str()));
        }
        // No `gate()`: this is the containment step and the ledger may already
        // be untrusted. The signer must be the new, pinned key.
        match revoke_key(
            self.p.ledger,
            self.p.roots,
            self.p.signer,
            key,
            confirm,
            self.now()?.secs(),
        ) {
            Ok(written) => Ok(Output::ok(
                name,
                if written {
                    "revoked"
                } else {
                    "already_revoked"
                },
            )
            .id("key_id", key.as_str())),
            Err(r) => Ok(Output::ok(name, "refused")
                .word("refusal", r.code())
                .with_failure(name, CliReason::ReissueRefused)),
        }
    }

    pub(super) fn reissue_plan_command(&self, who: &Principal, name: &'static str) -> Res<Output> {
        who.check(Permission::Diagnose)?;
        let view = self
            .p
            .populations
            .registry()
            .view()
            .map_err(|_| CliReason::StoreUnavailable)?;
        match plan_reissue(self.p.ledger, self.p.roots, self.p.store, Some(&view)) {
            Ok(plan) => Ok(Output::ok(name, "planned")
                .id("revoked_key_id", plan.revoked_key.as_str())
                .num("records_to_reissue", plan.to_reissue.len() as u64)
                .num("corroborated", plan.corroborated as u64)
                .num("uncorroborated", plan.uncorroborated as u64)
                .num("already_reattested", plan.already_reattested as u64)
                .num("earliest_issued_at", plan.earliest_issued_at.unwrap_or(0))
                .id("plan_digest", &plan.digest)),
            Err(r) => Ok(Output::ok(name, "refused")
                .word("refusal", r.code())
                .with_failure(name, CliReason::ReissueRefused)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn reissue_ledger_command(
        &self,
        who: &Principal,
        name: &'static str,
        revoked: &KeyId,
        new_key: &KeyId,
        digest: &str,
        dry: bool,
    ) -> Res<Output> {
        who.check(Permission::Repair)?;
        if dry {
            return Ok(Output::ok(name, "would_reissue")
                .id("revoked_key_id", revoked.as_str())
                .id("new_key_id", new_key.as_str()));
        }
        let view = self
            .p
            .populations
            .registry()
            .view()
            .map_err(|_| CliReason::StoreUnavailable)?;
        match execute_reissue(
            self.p.ledger,
            self.p.roots,
            self.p.signer,
            self.p.store,
            Some(&view),
            &ReissueRequest {
                confirm_revoked_key: revoked,
                confirm_new_key: new_key,
                confirm_plan_digest: digest,
                now: self.now()?.secs(),
            },
        ) {
            Ok(rep) => Ok(Output::ok(name, "reissued")
                .id("revoked_key_id", rep.revoked_key.as_str())
                .id("new_key_id", rep.new_key.as_str())
                .num("reissued", rep.reissued as u64)
                .num("already_present", rep.already_present as u64)
                .num("ledger_records", rep.ledger_records_after as u64)),
            Err(r) => Ok(Output::ok(name, "refused")
                .word("refusal", r.code())
                .with_failure(name, CliReason::ReissueRefused)),
        }
    }
}
