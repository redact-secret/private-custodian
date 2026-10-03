//! The verifier takes public inputs only (S1 acceptance, C11 acceptance). Like
//! the bridge consumer it is checked by type, by the dependency manifest and
//! by what its source may mention.

use custodian_verify::{verify, Bundle, Expectations, Pins, Report};

/// If `verify` gained a parameter of a private type (a store, a ledger record,
/// a signer, a corpus handle) this would stop compiling.
#[test]
fn verify_takes_public_inputs_only() {
    let _verify: fn(&Pins, &Expectations, &Bundle, u64) -> Report = verify;
}

/// Destructuring without `..` fails to compile if a field is added, so a
/// credential or a path cannot slip into the pins unnoticed.
#[test]
fn pins_hold_public_material_only() {
    fn exhaustive(p: Pins) {
        let Pins {
            keyring: _, // public keys; `Keyring` has no signing method
            feed_id: _,
        } = p;
    }
    let _ = exhaustive;
}

fn code_of(src: &str) -> String {
    src.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

const FORBIDDEN_EVERYWHERE: [&str; 17] = [
    "custodian_store",
    "custodian_corpus",
    "custodian_worker",
    "custodian_core",
    "custodian_intake",
    "custodian_disclosure",
    "SqliteStore",
    "LedgerBackend",
    "LedgerRecord",
    "GitBackend",
    "ProtectedPopulations",
    "SoftwareSigner",
    "RemoteSigner",
    "Signer",
    "Exporter",
    "std::net",
    "std::process::Command",
];

#[test]
fn no_source_file_mentions_anything_private() {
    for (name, src) in [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("input.rs", include_str!("../src/input.rs")),
        ("report.rs", include_str!("../src/report.rs")),
        ("run.rs", include_str!("../src/run.rs")),
        ("main.rs", include_str!("../src/main.rs")),
    ] {
        let code = code_of(src);
        for forbidden in FORBIDDEN_EVERYWHERE {
            assert!(
                !code.contains(forbidden),
                "{name} must not mention {forbidden}"
            );
        }
    }
}

/// Only the input loader touches the file system, and nothing here reads the
/// environment (the clock is an argument, the secrets are not a thing).
#[test]
fn only_the_input_loader_touches_files_and_nothing_reads_the_environment() {
    for (name, src) in [
        ("lib.rs", include_str!("../src/lib.rs")),
        ("report.rs", include_str!("../src/report.rs")),
        ("run.rs", include_str!("../src/run.rs")),
    ] {
        let code = code_of(src);
        for forbidden in ["std::fs", "std::env", "File::open"] {
            assert!(!code.contains(forbidden), "{name} must not use {forbidden}");
        }
    }
    for (name, src) in [
        ("input.rs", include_str!("../src/input.rs")),
        ("main.rs", include_str!("../src/main.rs")),
    ] {
        let code = code_of(src);
        assert!(!code.contains("env::var"), "{name} must not read variables");
        assert!(
            !code.contains("SystemTime"),
            "{name} must not read the clock"
        );
    }
}

#[test]
fn the_crate_does_not_depend_on_private_runtime_crates_or_add_third_party_ones() {
    let manifest = include_str!("../Cargo.toml");
    for private in [
        "custodian-store",
        "custodian-corpus",
        "custodian-worker",
        "custodian-intake",
        "custodian-core",
        "custodian-disclosure",
        "custodian-service",
        "custodian-cli",
    ] {
        assert!(
            !manifest.contains(private),
            "{private} must not be a dependency of the verifier"
        );
    }
    // Exactly these dependencies; adding one is a reviewed change.
    let deps = manifest
        .split_once("[dependencies]")
        .expect("dependencies")
        .1;
    let names: Vec<&str> = deps
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && l.contains('='))
        .map(|l| l.split('=').next().unwrap().trim())
        .collect();
    assert_eq!(
        names,
        [
            "custodian-bridge",
            "custodian-contracts",
            "custodian-ledger",
            "serde",
            "serde_json"
        ]
    );
}
