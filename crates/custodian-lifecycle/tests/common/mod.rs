//! Shared synthetic fixtures for the lifecycle tests. Keys are generated
//! inside each test and never written anywhere; every identity is an
//! obviously synthetic placeholder; sealed "populations" are readable
//! placeholder bytes in a private temporary directory.
#![allow(dead_code)]

#[path = "../../../custodian-contracts/tests/common/mod.rs"]
pub mod cc;
#[path = "../../../custodian-corpus/tests/common/mod.rs"]
pub mod corpus;
#[path = "../../../custodian-store/tests/common/mod.rs"]
pub mod sc;

use std::io::Read;

use custodian_contracts::common::{ActorKind, EvaluationDomain, PopulationBinding};
use custodian_contracts::public::PublicPopulationRef;
use custodian_contracts::types::{
    ActorRef, ApprovalId, EpochId, FeedId, IdempotencyKey, KeyId, Timestamp,
};
use custodian_corpus::{FsEpochStore, ProtectedPopulations};
use custodian_disclosure::PublicPopulationNames;
use custodian_ledger::{KeyEntry, Keyring, SignDomain, SoftwareSigner, Verifier};
use custodian_lifecycle::testing::StaticAuthority;
use custodian_lifecycle::{
    ChangeRequest, EpochManager, EpochReason, LifecycleFault, NoFault, OperatorAuthorization,
    PublicPopulations,
};
use custodian_store::SqliteStore;

#[allow(unused_imports)]
pub use cc::NOW;
#[allow(unused_imports)]
pub use sc::{actor, TempDb};

pub const HUMAN: &str = "act_synthetichuman000001";
pub const SERVICE: &str = "act_syntheticservice00001";
pub const AGENT: &str = "act_syntheticagent0000001";

pub fn ts(secs: u64) -> Timestamp {
    Timestamp::new(secs).unwrap()
}

pub fn who(kind: ActorKind) -> OperatorAuthorization {
    OperatorAuthorization {
        actor: ActorRef::parse(match kind {
            ActorKind::Human => HUMAN,
            ActorKind::Service => SERVICE,
            ActorKind::Agent => AGENT,
        })
        .unwrap(),
        kind,
        authorization: ApprovalId::parse("apr_synthetic000000000009").unwrap(),
    }
}

pub fn human() -> OperatorAuthorization {
    who(ActorKind::Human)
}
pub fn service() -> OperatorAuthorization {
    who(ActorKind::Service)
}
pub fn agent() -> OperatorAuthorization {
    who(ActorKind::Agent)
}

/// A lenient authority: it permits every actor everything. The kind rules in
/// `authorize` must hold regardless.
pub fn lenient_authority() -> StaticAuthority {
    StaticAuthority::new()
        .allow_all(HUMAN)
        .allow_all(SERVICE)
        .allow_all(AGENT)
}

pub fn idk(n: u32) -> IdempotencyKey {
    IdempotencyKey::parse(&cc::id("idk_", 5000 + n)).unwrap()
}

pub fn feed_id() -> FeedId {
    FeedId::parse(&cc::id("fed_", 1)).unwrap()
}

pub fn random_seed() -> [u8; 32] {
    let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
    let mut b = [0u8; 32];
    f.read_exact(&mut b).expect("read");
    b
}

pub struct TestKey {
    pub signer: SoftwareSigner,
    pub entry: KeyEntry,
}

pub fn test_key(n: u32, purposes: &[SignDomain]) -> TestKey {
    let kid = KeyId::parse(&cc::id("key_", n)).unwrap();
    let signer = SoftwareSigner::from_seed(kid.clone(), &random_seed(), purposes.iter().copied());
    let entry = KeyEntry::root(
        kid,
        &signer.public_key_hex(),
        purposes.iter().copied(),
        ts(NOW - 10_000),
    )
    .unwrap();
    TestKey { signer, entry }
}

pub fn verifier_for(key: &TestKey) -> Verifier {
    Verifier::new(Keyring::new().with_root(key.entry.clone()))
}

/// Maps every epoch to one fixed opaque public reference, or to a per-epoch
/// reference registered with `with`.
pub struct StaticPopulations {
    map: std::sync::Mutex<Vec<(String, PublicPopulationRef)>>,
}

impl StaticPopulations {
    pub fn new() -> Self {
        Self {
            map: std::sync::Mutex::new(Vec::new()),
        }
    }
    pub fn with(self, epoch: &str, public: PublicPopulationRef) -> Self {
        self.map.lock().unwrap().push((epoch.to_owned(), public));
        self
    }
}

impl PublicPopulations for StaticPopulations {
    fn public_ref(&self, epoch: &EpochId) -> Option<PublicPopulationRef> {
        self.map
            .lock()
            .unwrap()
            .iter()
            .find(|(e, _)| e == epoch.as_str())
            .map(|(_, p)| p.clone())
    }
}

pub fn opaque(n: u32) -> PublicPopulationRef {
    PublicPopulationRef::Opaque {
        id: custodian_contracts::types::PublicPopulationId::parse(&cc::id("ppr_", n)).unwrap(),
    }
}

/// Naming object over a real protected-population root: the keyed commitment
/// of the epoch's population, exactly as a deployment's disclosure service
/// would publish it.
pub struct KeyedNames<'a> {
    pub pop: &'a ProtectedPopulations<FsEpochStore>,
    pub key_id: KeyId,
}

impl PublicPopulationNames for KeyedNames<'_> {
    fn public_ref(&self, b: &PopulationBinding) -> Option<PublicPopulationRef> {
        self.pop
            .public_commitment(&b.epoch_id)
            .ok()
            .map(|commitment| PublicPopulationRef::KeyedCommitment {
                key_id: self.key_id.clone(),
                commitment,
            })
    }
}

/// A real protected-population root (registry, sealing) plus a real store.
pub struct RegWorld {
    pub fx: corpus::Fixture,
    pub db: TempDb,
    pub store: SqliteStore,
    pub epoch: EpochId,
    pub binding: PopulationBinding,
    pub authority: StaticAuthority,
}

impl RegWorld {
    pub fn new() -> Self {
        let fx = corpus::Fixture::new();
        let epoch = fx.seal_active(&[("one", b"synthetic-one"), ("two", b"synthetic-two")]);
        let binding = binding_of(&fx, &epoch);
        let db = TempDb::new("lifecycle");
        let store = SqliteStore::open(db.path()).unwrap();
        Self {
            fx,
            db,
            store,
            epoch,
            binding,
            authority: lenient_authority(),
        }
    }

    /// Seal (but do not activate) another reviewed epoch of the same corpus
    /// with different content.
    pub fn seal_next(&self, tag: &str) -> EpochId {
        self.fx.seal(&[
            ("one", format!("synthetic-{tag}-one").as_bytes()),
            ("two", format!("synthetic-{tag}-two").as_bytes()),
        ])
    }

    pub fn manager<'a>(&'a self, fault: &'a dyn LifecycleFault) -> EpochManager<'a, FsEpochStore> {
        EpochManager {
            store: &self.store,
            populations: &self.fx.pop,
            authority: &self.authority,
            fault,
        }
    }

    pub fn names(&self) -> KeyedNames<'_> {
        KeyedNames {
            pop: &self.fx.pop,
            key_id: KeyId::parse(&cc::id("key_", 77)).unwrap(),
        }
    }

    /// Reopen the store on the same file (a restart).
    pub fn restart_store(&mut self) {
        let path = self.db.path();
        self.store = SqliteStore::open(path).unwrap();
    }
}

pub fn binding_of(fx: &corpus::Fixture, epoch: &EpochId) -> PopulationBinding {
    let view = fx.pop.registry().view().unwrap();
    let (row, _) = view.get(epoch).unwrap();
    PopulationBinding {
        domain: EvaluationDomain::Credential,
        corpus_id: row.corpus_id.clone(),
        epoch_id: row.epoch_id.clone(),
        family_id: row.family_id.clone(),
        population_digest: row.population_digest.clone(),
        custody_version: row.custody_version,
    }
}

pub fn change<'a>(
    epoch: &'a EpochId,
    who: &'a OperatorAuthorization,
    key: &'a IdempotencyKey,
    reason: EpochReason,
    now: u64,
) -> ChangeRequest<'a> {
    ChangeRequest {
        epoch,
        who,
        key,
        reason,
        now: ts(now),
    }
}

pub fn no_fault() -> NoFault {
    NoFault
}

/// A request and its approval drawing on the population `binding` (holdout
/// scope: one budget per population epoch).
pub fn request_for(
    binding: &PopulationBinding,
    n: u32,
) -> (
    custodian_contracts::request::EvaluationRequest,
    custodian_contracts::approval::Approval,
) {
    use serde_json::json;
    let pop = serde_json::to_value(binding).unwrap();
    let budget = budget_json(binding);
    let mut plan = cc::plan();
    plan["population"] = pop.clone();
    plan["accounting"]["budget"] = budget.clone();
    let mut req = cc::request_json();
    req["request_id"] = json!(cc::id("req_", n));
    req["idempotency_key"] = json!(cc::id("idk_", n));
    req["plan"] = plan;
    let request: custodian_contracts::request::EvaluationRequest = cc::parse(&req);
    let mut apr = cc::approval_json();
    apr["approval_id"] = json!(cc::id("apr_", n));
    apr["scope"]["request_id"] = json!(cc::id("req_", n));
    apr["scope"]["plan_digest"] = json!(request.plan.plan_digest().unwrap().as_str());
    apr["scope"]["population"] = pop;
    apr["scope"]["budget"] = budget;
    let approval: custodian_contracts::approval::Approval = cc::parse(&apr);
    (request, approval)
}

pub fn budget_json(binding: &PopulationBinding) -> serde_json::Value {
    serde_json::json!({
        "scope": "population_epoch",
        "corpus_id": binding.corpus_id.as_str(),
        "epoch_id": binding.epoch_id.as_str()
    })
}

pub fn run_scope(binding: &PopulationBinding) -> custodian_contracts::common::BudgetScope {
    custodian_contracts::common::BudgetScope::PopulationEpoch {
        corpus_id: binding.corpus_id.clone(),
        epoch_id: binding.epoch_id.clone(),
        family_id: binding.family_id.clone(),
    }
}

pub fn exec_obs(at: u64) -> custodian_contracts::policy::ObservedActivation {
    cc::observed(cc::activation(), at)
}

/// Reserve `request` against its store at `NOW`.
pub fn reserve_req(
    store: &SqliteStore,
    request: &custodian_contracts::request::EvaluationRequest,
    approval: &custodian_contracts::approval::Approval,
) -> Result<custodian_store::ReserveOutcome, custodian_store::StoreError> {
    store.reserve_request(&custodian_store::ReserveCommand {
        request,
        approval,
        observed: &exec_obs(NOW),
        now: ts(NOW),
        max_state_age_secs: sc::MAX_AGE,
        reservation_window_secs: sc::WINDOW,
    })
}

// ---- a store plus a feed publisher world ---------------------------------------

use custodian_contracts::public::PublicProjection;
use custodian_contracts::types::DestinationId;
use custodian_core::{Contamination, EpochChange};
use custodian_ledger::Signer;
use custodian_lifecycle::{
    FeedConfig, FeedConsumer, FeedDestination, FeedPublisher, FeedSource, MemoryFeed,
};
use custodian_store::EpochEventCommand;
use serde_json::json;

pub const EPOCH: &str = "epo_synthetic000000000001";
pub const CORPUS: &str = "cor_synthetic000000000001";

pub struct FeedWorld {
    pub db: TempDb,
    pub store: SqliteStore,
    pub key: TestKey,
    pub verifier: custodian_ledger::Verifier,
    pub dest: MemoryFeed,
    pub pops: StaticPopulations,
    pub authority: custodian_lifecycle::testing::StaticAuthority,
}

impl FeedWorld {
    pub fn new() -> Self {
        let db = TempDb::new("c9-feed");
        let store = SqliteStore::open(db.path()).unwrap();
        let key = test_key(1, &SignDomain::ALL);
        let verifier = verifier_for(&key);
        Self {
            db,
            store,
            key,
            verifier,
            dest: MemoryFeed::new(),
            pops: StaticPopulations::new()
                .with(EPOCH, opaque(1))
                .with("epo_synthetic000000000002", opaque(2)),
            authority: lenient_authority(),
        }
    }

    pub fn config(&self) -> FeedConfig {
        FeedConfig {
            feed_id: feed_id(),
            destination_label: DestinationId::parse("public-feed").unwrap(),
            ttl_secs: 3600,
            renew_margin_secs: 600,
        }
    }

    pub fn publisher<'a>(&'a self, fault: &'a dyn LifecycleFault) -> FeedPublisher<'a> {
        self.publisher_with(&self.store, &self.dest, &self.key.signer, fault)
    }

    pub fn publisher_with<'a>(
        &'a self,
        store: &'a SqliteStore,
        dest: &'a dyn FeedDestination,
        signer: &'a dyn Signer,
        fault: &'a dyn LifecycleFault,
    ) -> FeedPublisher<'a> {
        FeedPublisher {
            store,
            populations: &self.pops,
            signer,
            destination: dest,
            authority: &self.authority,
            config: self.config(),
            fault,
        }
    }

    pub fn consumer(&self) -> FeedConsumer {
        FeedConsumer::new(feed_id(), self.verifier.clone())
    }

    pub fn contaminate(&self, epoch: &str, key: &str) {
        self.store
            .apply_epoch_change(&EpochEventCommand {
                epoch_id: epoch,
                corpus_id: CORPUS,
                family_id: None,
                idempotency_key: key,
                change: EpochChange::Report(Contamination::Exposed),
                reason: "results_exposed",
                actor: HUMAN,
                actor_kind: "human",
                authorization_ref: "apr_synthetic000000000009",
                now: NOW + 50,
            })
            .unwrap();
    }
}

pub fn projection(population: u32, candidate: &str) -> PublicProjection {
    let mut v = cc::projection_json();
    v["population"] = json!({"kind": "opaque", "id": cc::id("ppr_", population)});
    v["candidate"] = json!(cc::dg(candidate));
    v["projection_id"] = json!(cc::id("prj_", 100 + population));
    cc::parse(&v)
}

pub fn bytes_at(w: &FeedWorld, seq: u64) -> Vec<u8> {
    w.dest.get(&feed_id(), seq).unwrap().expect("envelope")
}
