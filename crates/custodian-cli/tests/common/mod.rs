//! Synthetic world for the operator CLI tests. Every identity is an
//! obviously synthetic placeholder, every credential is a readable synthetic
//! string that protects nothing, keys are generated inside each test and never
//! written down, and the protected "population" is a few readable placeholder
//! bytes in a private temporary directory.
#![allow(dead_code)]

#[path = "../../../custodian-lifecycle/tests/common/mod.rs"]
pub mod lc;

use std::sync::Arc;

use custodian_cli::{
    credential_digest, Command, Control, Output, Parts, PolicyAuthority, Principal,
};
use custodian_contracts::canonical::Contract;
use custodian_contracts::common::BudgetKind;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::types::{IdempotencyKey, RequestId, Timestamp};
use custodian_corpus::FsEpochStore;
use custodian_ledger::{Keyring, MemoryBackend, SignDomain};
use custodian_lifecycle::{FeedConfig, MemoryFeed, NoFault};
use custodian_store::ManualClock;
use serde_json::json;

pub use lc::{cc, sc};
pub use lc::{TestKey, NOW};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who {
    Requester,
    Approver,
    Operator,
    Auditor,
    Agent,
    Service,
    /// A human holding both requester and approver.
    Dual,
}

impl Who {
    pub fn actor(self) -> String {
        cc::id(
            "act_",
            match self {
                Who::Requester => 1,
                Who::Approver => 2,
                Who::Operator => 3,
                Who::Auditor => 4,
                Who::Agent => 5,
                Who::Service => 6,
                Who::Dual => 7,
            },
        )
    }

    pub fn token(self) -> Vec<u8> {
        format!("synthetic-credential-{self:?}-00000000000000000000").into_bytes()
    }
}

pub fn policy_json(issued: u64, expires: u64) -> serde_json::Value {
    let ident = |who: Who, kind: &str, roles: &[&str]| {
        json!({
            "actor": who.actor(), "kind": kind, "roles": roles,
            "credential_sha256": credential_digest(&who.token()),
        })
    };
    json!({
        "schema": "private-custodian.operator-policy/1",
        "policy_version": 1,
        "issued_at": issued,
        "expires_at": expires,
        "identities": [
            ident(Who::Requester, "human", &["requester"]),
            ident(Who::Approver, "human", &["approver"]),
            ident(Who::Operator, "human", &["operator", "auditor"]),
            ident(Who::Auditor, "human", &["auditor"]),
            ident(Who::Agent, "agent", &["requester"]),
            ident(Who::Service, "service", &["requester", "auditor"]),
            ident(Who::Dual, "human", &["requester", "approver"]),
        ]
    })
}

pub fn authority() -> PolicyAuthority {
    PolicyAuthority::from_json(
        &serde_json::to_vec(&policy_json(NOW - 1000, NOW + 1_000_000)).unwrap(),
    )
    .unwrap()
}

pub struct World {
    pub rw: lc::RegWorld,
    pub authority: PolicyAuthority,
    pub clock: Arc<ManualClock>,
    pub ledger: MemoryBackend,
    pub key: TestKey,
    pub roots: Keyring,
    pub feed: MemoryFeed,
    pub pubs: lc::StaticPopulations,
    pub fault: NoFault,
}

impl World {
    /// A store with a budget of `limit` run units, the plan's policy
    /// activation recorded, an active sealed population and an empty ledger.
    pub fn new(limit: u64) -> Self {
        let rw = lc::RegWorld::new();
        rw.store
            .provision_budget(
                BudgetKind::Run,
                &lc::run_scope(&rw.binding),
                limit,
                &sc::actor(),
                NOW,
            )
            .unwrap();
        rw.store
            .record_activation(&cc::activation(), &sc::actor(), NOW)
            .unwrap();
        let key = lc::test_key(1, &SignDomain::ALL);
        let roots = Keyring::new().with_root(key.entry.clone());
        let pubs = lc::StaticPopulations::new().with(rw.epoch.as_str(), lc::opaque(1));
        Self {
            rw,
            authority: authority(),
            clock: Arc::new(ManualClock::new(NOW)),
            ledger: MemoryBackend::new(),
            key,
            roots,
            feed: MemoryFeed::new(),
            pubs,
            fault: NoFault,
        }
    }

    pub fn parts(&self) -> Parts<'_, FsEpochStore> {
        Parts {
            store: &self.rw.store,
            clock: self.clock.clone(),
            authority: &self.authority,
            populations: &self.rw.fx.pop,
            ledger: &self.ledger,
            roots: &self.roots,
            signer: &self.key.signer,
            feed_destination: &self.feed,
            feed_populations: &self.pubs,
            feed_config: FeedConfig {
                feed_id: lc::feed_id(),
                destination_label: custodian_contracts::types::DestinationId::parse("public-feed")
                    .unwrap(),
                ttl_secs: 3600,
                renew_margin_secs: 600,
            },
            fault: &self.fault,
        }
    }

    pub fn control(&self) -> Control<'_, FsEpochStore> {
        Control::new(self.parts())
    }

    pub fn principal(&self, who: Who) -> Principal {
        self.authority
            .authenticate(
                &who.actor(),
                &who.token(),
                Timestamp::new(self.clock.as_ref_now()).unwrap(),
            )
            .unwrap()
    }

    /// Run `cmd` as `who`.
    pub fn run(&self, who: Who, cmd: &Command) -> Output {
        self.control().execute(&self.principal(who), cmd, false)
    }

    pub fn dry(&self, who: Who, cmd: &Command) -> Output {
        self.control().execute(&self.principal(who), cmd, true)
    }

    /// The synthetic request number `n`, asserted by the requester identity,
    /// and its canonical document bytes.
    pub fn request(&self, n: u32) -> (EvaluationRequest, Vec<u8>) {
        let (req, _apr) = lc::request_for(&self.rw.binding, n);
        let bytes = req.canonical_bytes().unwrap();
        (req, bytes)
    }

    pub fn submit(&self, who: Who, n: u32) -> Output {
        let (_, doc) = self.request(n);
        self.run(who, &Command::RequestSubmit { document: doc })
    }

    pub fn approve(&self, who: Who, n: u32) -> Output {
        let (req, _) = self.request(n);
        self.run(who, &approve_cmd(&req))
    }

    pub fn budget(&self) -> custodian_store::BudgetStatus {
        self.rw
            .store
            .budget_status(BudgetKind::Run, &lc::run_scope(&self.rw.binding))
            .unwrap()
            .unwrap()
    }

    pub fn kinds(&self) -> Vec<String> {
        self.rw
            .store
            .outbox_pending(1000)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect()
    }
}

pub fn approve_cmd(req: &EvaluationRequest) -> Command {
    Command::RequestApprove {
        request_id: req.request_id.clone(),
        confirm_plan_digest: req.plan.plan_digest().unwrap(),
        ttl_secs: None,
    }
}

pub fn status_cmd(req: &EvaluationRequest) -> Command {
    Command::RequestStatus {
        request_id: req.request_id.clone(),
    }
}

pub fn rid(n: u32) -> RequestId {
    RequestId::parse(&cc::id("req_", n)).unwrap()
}

pub fn idk(n: u32) -> IdempotencyKey {
    lc::idk(n)
}

pub trait ClockExt {
    fn as_ref_now(&self) -> u64;
}
impl ClockExt for Arc<ManualClock> {
    fn as_ref_now(&self) -> u64 {
        use custodian_store::Clock;
        self.now()
    }
}
