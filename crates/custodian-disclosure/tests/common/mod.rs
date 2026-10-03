//! Synthetic world for the disclosure tests. Every identity is an obviously
//! synthetic placeholder; keys are generated inside each test and never
//! written anywhere; the "protected" details are canary strings that exist so
//! tests can prove they never reach a public output.
#![allow(dead_code)]

#[path = "../../../custodian-contracts/tests/common/mod.rs"]
pub mod cc;
#[path = "../../../custodian-store/tests/common/mod.rs"]
pub mod sc;

use std::io::Read;

use custodian_contracts::approval::Approval;
use custodian_contracts::common::{ActivationRef, BudgetKind};
use custodian_contracts::execution::{ExecutionRecord, InternalReceipt};
use custodian_contracts::policy::ObservedActivation;
use custodian_contracts::public::{FeedRef, PublicPopulationRef};
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::reservation::Reservation;
use custodian_contracts::types::{DestinationId, IdempotencyKey, Timestamp};
use custodian_core::{ActorId, RunId};
use custodian_disclosure::policy::DisclosurePolicy;
use custodian_disclosure::testing::{RecordingSink, StaticNames, UncheckedEligibility};
use custodian_disclosure::{
    DisclosureService, DisclosureStore, PrepareInput, PreparedRelease, ReleaseEligibility,
    ReleaseRequest,
};
use custodian_ledger::{
    Exporter, KeyEntry, Keyring, MemoryBackend, SignDomain, SoftwareSigner, Verifier,
};
use custodian_store::{ReserveCommand, SqliteStore, StartCommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub use cc::NOW;
use cc::{dg, id, ts};

/// Canary strings standing in for protected details. They are valid label or
/// identifier shapes on purpose, so only the allowlist and the type split
/// (not a parse failure) keep them out of public output.
pub const CANARY_CORPUS: &str = "cor_canarycorpus000000001";
pub const CANARY_EPOCH: &str = "epo_canaryepoch000000001";
pub const CANARY_FAMILY: &str = "fam_canaryfamily00000001";
pub const CANARY_LINEAGE: &str = "lin_canarylineage0000001";
pub const CANARY_ACTOR: &str = "act_canaryrequester0001";
pub const CANARY_TEXT: &str = "canary-protected-text-7f3a";
pub const CANARY_SEED: &str = "canary-seed-9c1d";
pub const CANARY_CASE: &str = "canary-case-0042";

pub fn all_canaries() -> Vec<&'static str> {
    vec![
        CANARY_CORPUS,
        CANARY_EPOCH,
        CANARY_FAMILY,
        CANARY_LINEAGE,
        CANARY_ACTOR,
        CANARY_TEXT,
        CANARY_SEED,
        CANARY_CASE,
    ]
}

pub fn random_seed() -> [u8; 32] {
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    let mut b = [0u8; 32];
    f.read_exact(&mut b).expect("read");
    b
}

pub fn disclosure_ref() -> Value {
    cc::disclosure_policy()
}

/// Strata in suppression-preference order. `c` is small. `all` is the roster.
/// Dimension `len`: all = a + b + c. Dimension `cat`: all = t1 + t2.
pub fn policy_json() -> Value {
    json!({
        "schema": "private-custodian.disclosure-policy/1",
        "policy": disclosure_ref(),
        "strata": [
            {"stratum":"a","dimension":"len"},
            {"stratum":"b","dimension":"len"},
            {"stratum":"c","dimension":"len"},
            {"stratum":"t1","dimension":"cat"},
            {"stratum":"t2","dimension":"cat"},
            {"stratum":"all","dimension":"total"}
        ],
        "metrics": ["detected"],
        "total_stratum": "all",
        "relations": [
            {"total":"all","parts":["a","b","c"]},
            {"total":"all","parts":["t1","t2"]}
        ],
        "min_stratum_size": 10,
        "min_interval_width": 2,
        "perturbation": {"mechanism":"none"},
        "budgets": {"per_population": 5, "per_lineage": 3, "per_requester": 4, "units_per_attempt": 1},
        "withheld_attempts": "charged",
        "failed_attempts": "charged",
        "audit": "acknowledged",
        "destinations": ["benchmarks-feed", "site-preview"],
        "freshness_secs": 86400,
        "state_max_age_secs": 300
    })
}

pub fn policy() -> DisclosurePolicy {
    let p: DisclosurePolicy = serde_json::from_value(policy_json()).unwrap();
    p.validate().unwrap();
    p
}

/// The measured aggregates. a=30/40, b=18/30, c=2/5 (small), all=50/75;
/// t1=35/50, t2=15/25.
pub fn aggregates_json() -> Value {
    let cell = |s: &str, n: u64, d: u64| json!({"stratum": s, "metric": "detected", "numerator": n, "denominator": d});
    json!({
        "schema": "private-custodian.aggregates/1",
        "domain": "credential",
        "protocol": {"name": "synthetic-protocol", "version": "1"},
        "roster": {"expected": 75, "observed": 75, "failed": 0},
        "cells": [
            cell("a", 30, 40), cell("b", 18, 30), cell("c", 2, 5),
            cell("t1", 35, 50), cell("t2", 15, 25), cell("all", 50, 75)
        ]
    })
}

pub fn sha_digest(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    let mut s = String::from("sha256:");
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[derive(Clone)]
pub struct Opts {
    pub conformance: bool,
    pub lineage: bool,
    pub export_before: bool,
    pub aggregates: Value,
    pub roster_failed: u64,
    /// Replace internal identities with canary strings.
    pub canary: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            conformance: false,
            lineage: false,
            export_before: true,
            aggregates: aggregates_json(),
            roster_failed: 0,
            canary: false,
        }
    }
}

pub struct TestKey {
    pub signer: SoftwareSigner,
    pub entry: KeyEntry,
}

pub fn test_key(n: u32) -> TestKey {
    let kid = custodian_contracts::types::KeyId::parse(&id("key_", n)).unwrap();
    let signer = SoftwareSigner::from_seed(kid.clone(), &random_seed(), SignDomain::ALL);
    let entry = KeyEntry::root(
        kid,
        &signer.public_key_hex(),
        SignDomain::ALL,
        ts(NOW - 10_000),
    )
    .unwrap();
    TestKey { signer, entry }
}

pub struct World {
    pub db: sc::TempDb,
    pub store: SqliteStore,
    pub backend: MemoryBackend,
    pub key: TestKey,
    pub verifier: Verifier,
    pub request: EvaluationRequest,
    pub exec_approval: Approval,
    pub reservation: Reservation,
    pub execution: ExecutionRecord,
    pub receipt: InternalReceipt,
    pub aggregates: Vec<u8>,
    pub attempt: RunId,
    pub exec_obs: ObservedActivation,
    pub policy: DisclosurePolicy,
    pub policy_binding: ActivationRef,
    pub policy_obs: ObservedActivation,
    pub opts: Opts,
}

pub const PREPARE_AT: u64 = NOW + 50;
pub const RELEASE_AT: u64 = NOW + 100;

pub fn activation_value(policy: Value, activation_id: &str, sequence: u64, status: &str) -> Value {
    json!({
        "schema": "private-custodian.policy-activation/1",
        "policy": policy,
        "activation_id": activation_id,
        "sequence": sequence,
        "status": status,
        "activates_at": NOW - 1000,
        "expires_at": NOW + 100_000,
        "changed_at": NOW - 1000
    })
}

pub fn disclosure_activation(at: u64, status: &str) -> ObservedActivation {
    let v = activation_value(disclosure_ref(), &id("pac_", 2), 1, status);
    cc::observed(cc::parse(&v), at)
}

pub fn exec_activation(at: u64) -> ObservedActivation {
    cc::observed(cc::activation(), at)
}

impl World {
    pub fn new(opts: Opts) -> Self {
        let db = sc::TempDb::new("disclosure");
        let store = sc::open(&db);
        let backend = MemoryBackend::new();
        let key = test_key(1);
        let verifier = Verifier::new(Keyring::new().with_root(key.entry.clone()));

        // Plan: protected evaluation by default, conformance control on demand.
        let mut plan = cc::plan();
        plan["purpose"] = json!(if opts.conformance {
            "conformance_control"
        } else {
            "protected_evaluation"
        });
        if opts.lineage {
            plan["accounting"]["budget"] = json!({
                "scope": "candidate_lineage_epoch",
                "corpus_id": id("cor_", 1), "epoch_id": id("epo_", 1),
                "lineage_id": id("lin_", 1)
            });
        }
        if opts.canary {
            plan["population"]["corpus_id"] = json!(CANARY_CORPUS);
            plan["population"]["epoch_id"] = json!(CANARY_EPOCH);
            plan["population"]["family_id"] = json!(CANARY_FAMILY);
            plan["population"]["population_digest"] = json!(dg(CANARY_TEXT));
            plan["config_digest"] = json!(dg(CANARY_SEED));
            let b = &mut plan["accounting"]["budget"];
            b["corpus_id"] = json!(CANARY_CORPUS);
            b["epoch_id"] = json!(CANARY_EPOCH);
            b["family_id"] = json!(CANARY_FAMILY);
            if opts.lineage {
                b["lineage_id"] = json!(CANARY_LINEAGE);
            }
        }
        let mut req = cc::request_json();
        req["plan"] = plan;
        if opts.canary {
            req["asserted_actor"] = json!(CANARY_ACTOR);
        }
        let request: EvaluationRequest = cc::parse(&req);
        let plan_digest = request.plan.plan_digest().unwrap();

        let mut apr = cc::approval_json();
        apr["scope"]["plan_digest"] = json!(plan_digest.as_str());
        apr["scope"]["budget"] = req["plan"]["accounting"]["budget"].clone();
        apr["scope"]["population"] = req["plan"]["population"].clone();
        if opts.canary {
            apr["proposer"] = json!(CANARY_ACTOR);
        }
        let exec_approval: Approval = cc::parse(&apr);

        // Drive a real attempt to completed, settled and exported.
        let obs = exec_activation(NOW);
        store
            .provision_budget(
                BudgetKind::Run,
                &request.plan.accounting.budget,
                3,
                &sc::actor(),
                NOW,
            )
            .unwrap();
        let out = store
            .reserve_request(&ReserveCommand {
                request: &request,
                approval: &exec_approval,
                observed: &obs,
                now: ts(NOW),
                max_state_age_secs: sc::MAX_AGE,
                reservation_window_secs: sc::WINDOW,
            })
            .unwrap();
        let lease = store
            .start_attempt(&StartCommand {
                attempt: &out.attempt,
                owner: "worker-a",
                actor: &sc::actor(),
                now: NOW + 1,
                lease_secs: sc::LEASE,
                observed: Some(&obs),
                max_state_age_secs: sc::MAX_AGE,
            })
            .unwrap();
        store
            .record_exposure(&lease, &sc::actor(), NOW + 2)
            .unwrap();
        store
            .begin_validation(&lease, &sc::actor(), NOW + 3)
            .unwrap();
        store
            .finish(
                &lease,
                custodian_contracts::execution::ExecutionOutcome::Success,
                custodian_core::ReasonCode::Completed,
                &sc::actor(),
                NOW + 4,
            )
            .unwrap();
        let reservation_id = out.reservation_id.clone().unwrap();
        let reservation = store.reservation(&reservation_id).unwrap().unwrap();

        let mut exe = cc::execution_json();
        exe["request_id"] = json!(request.request_id.as_str());
        exe["reservation_id"] = json!(reservation_id);
        exe["plan_digest"] = json!(plan_digest.as_str());
        if opts.canary {
            exe["frozen"]["population_digest"] = json!(dg(CANARY_TEXT));
            exe["frozen"]["config_digest"] = json!(dg(CANARY_SEED));
        }
        let execution: ExecutionRecord = cc::parse(&exe);

        let aggregates = serde_json::to_vec(&opts.aggregates).unwrap();
        let mut rcp = cc::receipt_json();
        rcp["plan_digest"] = json!(plan_digest.as_str());
        if opts.canary {
            rcp["frozen"]["population_digest"] = json!(dg(CANARY_TEXT));
            rcp["frozen"]["config_digest"] = json!(dg(CANARY_SEED));
        }
        rcp["result"] = json!({
            "digest": sha_digest(&aggregates),
            "size_bytes": aggregates.len(),
            "protocol": cc::protocol()
        });
        rcp["roster"] = json!({"expected": 75, "observed": 75, "failed": opts.roster_failed});
        rcp["attestation"]["independence"] = json!(if opts.conformance {
            "public-control"
        } else {
            "custodian-declared"
        });
        let receipt: InternalReceipt = cc::parse(&rcp);

        let policy = policy();
        let policy_binding: ActivationRef = serde_json::from_value(json!({
            "policy": disclosure_ref(), "activation_id": id("pac_", 2), "sequence": 1
        }))
        .unwrap();

        let w = Self {
            db,
            store,
            backend,
            key,
            verifier,
            request,
            exec_approval,
            reservation,
            execution,
            receipt,
            aggregates,
            attempt: out.attempt,
            exec_obs: exec_activation(PREPARE_AT),
            policy,
            policy_binding,
            policy_obs: disclosure_activation(PREPARE_AT, "active"),
            opts: opts.clone(),
        };
        if opts.export_before {
            w.export();
        }
        w
    }

    pub fn exporter(&self) -> Exporter<'_> {
        Exporter::new(&self.backend, &self.key.signer, &self.verifier)
    }

    /// Drain the audit outbox to the (in-memory) private ledger.
    pub fn export(&self) {
        let r = self
            .exporter()
            .export_pending(&self.store, NOW + 10)
            .unwrap();
        assert_eq!(r.status, custodian_ledger::ExportStatus::Drained);
    }

    pub fn names(&self) -> StaticNames {
        StaticNames(PublicPopulationRef::Opaque {
            id: custodian_contracts::types::PublicPopulationId::parse(&id("ppr_", 1)).unwrap(),
        })
    }

    pub fn feed(&self) -> FeedRef {
        FeedRef {
            feed_id: custodian_contracts::types::FeedId::parse(&id("fed_", 1)).unwrap(),
            min_sequence: custodian_contracts::types::Count::new(1).unwrap(),
        }
    }

    pub fn provision(&self, svc: &DisclosureService<'_>) {
        svc.provision_budgets(
            &self.policy,
            &self.request.plan,
            &self.request.asserted_actor,
            &sc::actor(),
            NOW,
        )
        .unwrap();
    }

    pub fn release_key(&self, n: u32) -> IdempotencyKey {
        IdempotencyKey::parse(&id("idk_", 100 + n)).unwrap()
    }

    pub fn input<'a>(&'a self, key: &'a IdempotencyKey) -> PrepareInput<'a> {
        PrepareInput {
            policy: &self.policy,
            request: &self.request,
            execution_approval: &self.exec_approval,
            reservation: &self.reservation,
            execution: &self.execution,
            receipt: &self.receipt,
            aggregates: &self.aggregates,
            attempt: &self.attempt,
            execution_activation: &self.exec_obs,
            policy_binding: &self.policy_binding,
            policy_activation: &self.policy_obs,
            release_key: key,
            feed: self.feed(),
        }
    }

    pub fn release_approval(&self, prepared: &PreparedRelease) -> Approval {
        cc::parse(&self.release_approval_json(prepared))
    }

    pub fn release_approval_json(&self, prepared: &PreparedRelease) -> Value {
        let mut v = cc::approval_json();
        v["approval_id"] = json!(id("apr_", 2));
        v["scope"] = json!({
            "operation": "release",
            "execution_id": prepared.execution_id().as_str(),
            "projection_digest": prepared.digest().as_str(),
            "disclosure_policy": disclosure_ref()
        });
        v["activation"] = json!({
            "policy": disclosure_ref(), "activation_id": id("pac_", 2), "sequence": 1
        });
        v["issued_at"] = json!(NOW + 60);
        v["expires_at"] = json!(NOW + 3600);
        v
    }

    pub fn destination(&self, label: &str) -> DestinationId {
        DestinationId::parse(label).unwrap()
    }

    pub fn release_request<'a>(
        &'a self,
        approval: &'a Approval,
        destination: &'a DestinationId,
        obs: &'a ObservedActivation,
    ) -> ReleaseRequest<'a> {
        ReleaseRequest {
            approval,
            destination,
            policy: &self.policy,
            policy_activation: obs,
        }
    }
}

/// Run a closure with a service wired to the world, the real store, the
/// in-memory ledger and the given eligibility.
pub fn with_service<R>(
    w: &World,
    eligibility: &dyn ReleaseEligibility,
    f: impl FnOnce(&DisclosureService<'_>) -> R,
) -> R {
    let exporter = w.exporter();
    let names = w.names();
    let svc = DisclosureService {
        store: &w.store as &dyn DisclosureStore,
        exporter: &exporter,
        signer: &w.key.signer,
        eligibility,
        names: &names,
    };
    f(&svc)
}

pub fn with_default_service<R>(w: &World, f: impl FnOnce(&DisclosureService<'_>) -> R) -> R {
    with_service(w, &UncheckedEligibility, f)
}

pub fn sink() -> RecordingSink {
    RecordingSink::new()
}

pub fn now(secs: u64) -> Timestamp {
    ts(secs)
}

pub fn actor() -> ActorId {
    sc::actor()
}

pub fn digest_of(label: &str) -> String {
    dg(label)
}
