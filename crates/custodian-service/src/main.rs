//! Scaffold entry point. It starts no listener, reads no credentials and
//! touches no storage; the deployed service is planned work (ADR 0002).

#![forbid(unsafe_code)]

fn main() {
    println!(
        "custodian-service {}: scaffold only; no listener, storage or credentials (contracts v{} defined, not wired)",
        env!("CARGO_PKG_VERSION"),
        custodian_contracts::CONTRACT_MAJOR_VERSION
    );
}
