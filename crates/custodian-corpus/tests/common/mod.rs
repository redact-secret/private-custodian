//! Shared synthetic fixtures. Everything is generated in a tempdir inside the
//! test; no corpus-like file is committed. The "bytes" are obviously
//! synthetic placeholders.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use custodian_contracts::common::{
    Attestation, Authorship, BudgetScope, EvaluationDomain, GroundTruthClaim, IndependenceClaim,
    OrganisationalIndependence, ReviewStatus, RoleSeparation,
};
use custodian_contracts::types::{ActorRef, ConfigDigest, CorpusId, Count, EpochId, Timestamp};
use custodian_core::ports::Authorization;
use custodian_core::{ActorId, AuthorizationId, PlanDigest, PopulationId};
use custodian_corpus::seal::{Provenance, ProvenanceOrigin, ReviewRecord};
use custodian_corpus::testing::TempRoot;
use custodian_corpus::{EntryName, FsEpochStore, ProtectedPopulations, SealInputs};

pub const CANARY: &str = "canary-7f3a9c1e5b2d";

pub fn now() -> Timestamp {
    Timestamp::new(1_800_000_000).unwrap()
}

pub fn corpus_id() -> CorpusId {
    CorpusId::parse("cor_aaaaaaaaaaaaaaaa").unwrap()
}

pub fn name(s: &str) -> EntryName {
    EntryName::parse(s).unwrap()
}

pub fn attestation(review: ReviewStatus) -> Attestation {
    Attestation {
        independence: IndependenceClaim::CustodianDeclared,
        role_separation: RoleSeparation::SingleOperatorProcedural,
        organisational_independence: OrganisationalIndependence::NotClaimed,
        authorship: Authorship::ProjectAuthored,
        review,
        ground_truth: GroundTruthClaim::NotEstablished,
    }
}

pub fn inputs_for(epoch: &EpochId, review: ReviewStatus) -> SealInputs {
    SealInputs {
        custody_version: Count::new(1).unwrap(),
        config_digest: ConfigDigest::from_raw([7u8; 32]),
        budget: BudgetScope::PopulationEpoch {
            corpus_id: corpus_id(),
            epoch_id: epoch.clone(),
            family_id: None,
        },
        provenance: Provenance {
            origin: ProvenanceOrigin::SyntheticGenerated,
            generator: None,
            observed_at: now(),
        },
        review: ReviewRecord {
            reviewer: ActorRef::parse("act_bbbbbbbbbbbbbbbb").unwrap(),
            reviewed_at: now(),
            attestation: attestation(review),
        },
        sealed_by: ActorRef::parse("act_cccccccccccccccc").unwrap(),
        sealed_at: now(),
    }
}

pub fn authorization(epoch: &EpochId) -> Authorization {
    Authorization {
        id: AuthorizationId::new("auth-synthetic"),
        actor: ActorId::new("actor-synthetic"),
        plan: PlanDigest::new("plan-synthetic"),
        population: PopulationId::new(epoch.as_str()),
        expires_at: 0,
    }
}

pub struct Fixture {
    pub tmp: TempRoot,
    pub pop: ProtectedPopulations<FsEpochStore>,
}

impl Fixture {
    pub fn new() -> Self {
        let tmp = TempRoot::new();
        let root = tmp.path().join("protected");
        mkdir_private(&root);
        let pop = ProtectedPopulations::open_fs(&root).expect("open_fs");
        Self { tmp, pop }
    }

    pub fn root(&self) -> PathBuf {
        self.tmp.path().join("protected")
    }

    /// Seal (reviewed) a synthetic corpus and return its epoch.
    pub fn seal(&self, entries: &[(&str, &[u8])]) -> EpochId {
        let w = self
            .pop
            .begin_epoch(corpus_id(), EvaluationDomain::Credential, None)
            .unwrap();
        for (n, b) in entries {
            self.pop.add_entry(&w, &name(n), b).unwrap();
        }
        let inputs = inputs_for(w.epoch_id(), ReviewStatus::ProjectReviewed);
        let epoch = w.epoch_id().clone();
        self.pop.seal(w, inputs).unwrap();
        epoch
    }

    pub fn seal_active(&self, entries: &[(&str, &[u8])]) -> EpochId {
        let e = self.seal(entries);
        self.pop.activate(&e, now()).unwrap();
        e
    }

    pub fn sealed_dir(&self, e: &EpochId) -> PathBuf {
        self.root().join("sealed").join(e.as_str())
    }

    pub fn sealed_entry(&self, e: &EpochId, n: &str) -> PathBuf {
        self.sealed_dir(e).join("entries").join(n)
    }

    pub fn staging_entries(&self, e: &EpochId) -> PathBuf {
        self.root().join("staging").join(e.as_str()).join("entries")
    }
}

pub fn mkdir_private(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}

pub fn chmod(p: &Path, mode: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}

/// Mutate a sealed file's bytes the way an attacker with owner rights would.
pub fn tamper_file(p: &Path, bytes: &[u8]) {
    chmod(p, 0o600);
    fs::write(p, bytes).unwrap();
    chmod(p, 0o400);
}

pub fn store_of(root: &Path) -> FsEpochStore {
    FsEpochStore::open(root).unwrap()
}
