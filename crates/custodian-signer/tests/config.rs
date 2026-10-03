//! The signer configuration format and the committed placeholder example.

use custodian_signer::SignerConfig;
use serde_json::{json, Value};

const EXAMPLE: &str = include_str!("../../../docs/signer-config.example.json");

fn example() -> Value {
    serde_json::from_str(EXAMPLE).unwrap()
}

fn parse(v: &Value) -> bool {
    SignerConfig::parse(&serde_json::to_vec(v).unwrap()).is_ok()
}

#[test]
fn the_placeholder_example_parses_and_contains_no_key_material() {
    let cfg = SignerConfig::parse(EXAMPLE.as_bytes()).unwrap();
    assert_eq!(cfg.setup.purposes.len(), 7, "ledger domains only");
    assert!(EXAMPLE.contains("PLACEHOLDER"));
    // No 64-hex run (a seed or a public key) and no PEM block.
    let mut run = 0;
    for c in EXAMPLE.chars() {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        assert!(run < 32, "hex-looking run in the example");
    }
    assert!(!EXAMPLE.contains("-----BEGIN"));
}

#[test]
fn invalid_configurations_are_refused() {
    let base = example();
    assert!(parse(&base));
    let mut cases: Vec<(&str, Value)> = vec![
        ("schema", json!("other/1")),
        ("purposes", json!([])),
        ("purposes", json!(["not-a-domain"])),
        ("key_path", json!("relative")),
        ("socket_path", json!("relative.sock")),
        ("io_timeout_secs", json!(0)),
        ("io_timeout_secs", json!(61)),
        ("max_concurrent", json!(0)),
        ("max_concurrent", json!(65)),
        ("not_after", json!(1)),
        ("allowed_peer_uid", json!(-1)),
        ("key_id", json!("not a key id")),
    ];
    cases.push(("extra_field", json!(true)));
    for (k, v) in cases {
        let mut c = base.clone();
        c[k] = v;
        assert!(!parse(&c), "{k}");
    }
    let mut c = base.clone();
    c.as_object_mut().unwrap().remove("key_path");
    assert!(!parse(&c));
    assert!(SignerConfig::parse(&vec![b' '; 20_000]).is_err());
    assert!(SignerConfig::parse(b"{}").is_err());
}
