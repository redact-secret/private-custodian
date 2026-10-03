//! Key purposes the pinned keys file may grant (S5 adds `projection_v2`, the
//! destination-bound major the daemon releases; a verifier pinned for major 1
//! only could not accept it). No ledger purpose is ever accepted.

use custodian_verify::{InputError, Pins};
use serde_json::json;

fn pins_with(purposes: serde_json::Value, name: &str) -> Result<Pins, InputError> {
    let dir =
        std::env::temp_dir().join(format!("custodian-verify-purposes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "schema": "private-custodian.verify-keys/1",
            "keys": [{
                "key_id": "key_synthetic000000000001",
                "public_key": "f80cccdce4ae1c07ae208a2adf99a310ae4207e0306fa0236110b06827bbb8d0",
                "purposes": purposes,
                "valid_from": 1
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let r = Pins::load(&path, "fed_synthetic000000000001");
    let _ = std::fs::remove_file(&path);
    r
}

#[test]
fn projection_v2_is_a_purpose_and_a_ledger_purpose_is_not() {
    assert!(pins_with(json!(["projection_v2"]), "a.json").is_ok());
    assert!(pins_with(
        json!(["projection", "projection_v2", "revocation"]),
        "b.json"
    )
    .is_ok());
    for bad in [
        json!(["ledger"]),
        json!(["audit_event"]),
        json!(["projection_v3"]),
        json!([]),
    ] {
        assert_eq!(
            pins_with(bad.clone(), "c.json").err(),
            Some(InputError::KeysInvalid),
            "{bad}"
        );
    }
}
