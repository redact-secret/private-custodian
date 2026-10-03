//! Scaffold entry point. It starts no listener, reads no credentials and
//! touches no storage; the deployed service is planned work (ADR 0002).

#![forbid(unsafe_code)]

fn main() {
    println!(
        "custodian-service {}: scaffold only; no listener, storage or credentials ({})",
        env!("CARGO_PKG_VERSION"),
        custodian_contracts::CONTRACTS_STATUS
    );
}
