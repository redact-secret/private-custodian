//! Benchmarks has no private-ledger credential and no protected corpus access
//! (C11 acceptance). The consumer API takes public inputs only, and that is
//! checked three ways: by type, by the field set of its configuration, and by
//! what its source and manifest may import.

use custodian_bridge::wire::BridgeResponse;
use custodian_bridge::{
    BridgeConsumer, BridgeRequest, ConsumerPins, Rejection, ResponseOutcome, VerifiedProjection,
};
use custodian_contracts::types::Timestamp;

/// Every entry point of the consumer, as a function pointer. If one gained a
/// parameter of a private type (a store, a ledger record, a signer, a corpus
/// handle) this would stop compiling, and the change would need a reviewer.
#[test]
fn consumer_entry_points_take_public_inputs_only() {
    let _new: fn(ConsumerPins) -> BridgeConsumer = BridgeConsumer::new;
    let _request: fn(
        &BridgeConsumer,
        custodian_contracts::types::CandidateDigest,
        custodian_contracts::types::ConfigDigest,
        Vec<custodian_contracts::public::PublicPopulationRef>,
    ) -> Result<BridgeRequest, Rejection> = BridgeConsumer::request;
    let _verify: fn(
        &BridgeConsumer,
        &BridgeRequest,
        &[u8],
        Timestamp,
    ) -> Result<VerifiedProjection, Rejection> = BridgeConsumer::verify_projection;
    let _accept: fn(
        &mut BridgeConsumer,
        &BridgeRequest,
        &BridgeResponse,
        Timestamp,
    ) -> Result<ResponseOutcome, Rejection> = BridgeConsumer::accept_response;
}

/// The configuration holds exactly these public things. Destructuring without
/// `..` fails to compile if a field is added, so a credential or a path cannot
/// slip into the pins unnoticed.
#[test]
fn consumer_pins_hold_public_material_only() {
    fn exhaustive(p: ConsumerPins) {
        let ConsumerPins {
            domain: _,
            feed_id: _,
            destination: _,
            verifier: _, // public keys; `Verifier` has no signing method
            accepted_populations: _,
            accepted_policies: _,
        } = p;
    }
    let _ = exhaustive;
}

#[test]
fn the_consumer_module_imports_nothing_private() {
    let src = include_str!("../src/consumer.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in [
        "custodian_store",
        "custodian_corpus",
        "custodian_worker",
        "custodian_core",
        "custodian_intake",
        "SqliteStore",
        "LedgerBackend",
        "LedgerRecord",
        "GitBackend",
        "ProtectedPopulations",
        "SoftwareSigner",
        "RemoteSigner",
        "Signer",
        "ApprovedPayload",
        "Exporter",
        "std::fs",
        "std::env",
        "std::net",
        "std::process",
    ] {
        assert!(
            !code.contains(forbidden),
            "consumer.rs must not mention {forbidden}"
        );
    }
}

#[test]
fn the_crate_does_not_depend_directly_on_private_runtime_crates() {
    let manifest = include_str!("../Cargo.toml");
    let (deps, _dev) = manifest
        .split_once("[dev-dependencies]")
        .expect("dev-dependencies section");
    for private in [
        "custodian-store",
        "custodian-corpus",
        "custodian-worker",
        "custodian-intake",
    ] {
        assert!(
            !deps.contains(private),
            "{private} is a test-only dependency of the bridge"
        );
    }
}
