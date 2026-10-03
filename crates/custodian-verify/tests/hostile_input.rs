//! The bundle and the pins files are untrusted (S1): sizes are bounded before
//! reading, parsing is strict, links and strays are refused, and a failure
//! names a fixed reason, never an input.

mod support;

use std::path::{Path, PathBuf};

use custodian_verify::input::{Bundle, Expectations, InputError, Pins};

fn fresh(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "custodian-verify-test-{label}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write the positive case's bundle into a fresh directory.
fn bundle(label: &str) -> PathBuf {
    let dir = fresh(label);
    let case = support::cases()
        .into_iter()
        .find(|c| c.name == "positive")
        .unwrap();
    for (rel, bytes) in case.files {
        if let Some(rest) = rel.strip_prefix("bundle/") {
            let p = dir.join(rest);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
    }
    dir
}

fn err(b: Result<Bundle, InputError>) -> InputError {
    b.expect_err("must be refused")
}

#[test]
fn the_generated_bundle_loads() {
    let dir = bundle("ok");
    Bundle::load(&dir).unwrap();
}

#[test]
fn a_missing_or_unexpected_entry_is_refused() {
    let dir = bundle("stray");
    std::fs::write(dir.join("notes.txt"), b"x").unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::UnexpectedEntry);

    let dir = bundle("nomanifest");
    std::fs::remove_file(dir.join("manifest.json")).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::BundleMalformed);

    let dir = bundle("badname");
    std::fs::write(dir.join("projections/extra.json"), b"{}").unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::UnexpectedEntry);

    let dir = bundle("nested");
    std::fs::create_dir_all(dir.join("projections/0002.json")).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::Unreadable);
}

#[test]
fn oversized_documents_and_too_many_documents_are_refused_before_parsing() {
    let dir = bundle("bigdoc");
    let big = vec![b' '; custodian_contracts::MAX_DOCUMENT_BYTES + 1];
    std::fs::write(dir.join("projections/0001.json"), big).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::TooLarge);

    let dir = bundle("bigmanifest");
    let big = vec![b' '; 8_193];
    std::fs::write(dir.join("manifest.json"), big).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::TooLarge);

    let dir = bundle("many");
    for n in 2..=40 {
        std::fs::write(dir.join(format!("revocations/{n:04}.json")), b"{}").unwrap();
    }
    assert_eq!(err(Bundle::load(&dir)), InputError::TooLarge);
}

#[test]
fn a_manifest_that_disagrees_with_the_documents_is_malformed() {
    let dir = bundle("mismatch");
    std::fs::remove_file(dir.join("projections/0001.json")).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::BundleMalformed);

    let dir = bundle("junk");
    std::fs::write(dir.join("manifest.json"), b"{\"schema\":1}").unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::BundleMalformed);
}

#[cfg(unix)]
#[test]
fn links_are_never_followed() {
    use std::os::unix::fs::symlink;

    let dir = bundle("linkfile");
    let target = dir.join("projections/0001.json");
    let elsewhere = fresh("linkfile-target").join("elsewhere");
    std::fs::rename(&target, &elsewhere).unwrap();
    symlink(&elsewhere, &target).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::Unreadable);

    let dir = bundle("linkdir");
    let real = dir.join("revocations");
    let moved = fresh("linkdir-moved").join("moved");
    std::fs::rename(&real, &moved).unwrap();
    symlink(&moved, &real).unwrap();
    assert_eq!(err(Bundle::load(&dir)), InputError::Unreadable);

    let real = bundle("linkroot");
    let link = fresh("linkroot-link").join("b");
    symlink(&real, &link).unwrap();
    assert_eq!(err(Bundle::load(&link)), InputError::Unreadable);
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn keys_files_are_strict() {
    let dir = fresh("keys");
    let good = serde_json::to_string(&support::keys_json()).unwrap();
    let feed = support::feed_id();
    Pins::load(&write(&dir, "good.json", &good), &feed).unwrap();

    let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
    let mut v = support::keys_json();
    v["extra"] = serde_json::json!(1);
    cases.push(("unknown top field", v));
    let mut v = support::keys_json();
    v["keys"][0]["secret"] = serde_json::json!("x");
    cases.push(("unknown key field", v));
    let mut v = support::keys_json();
    v["keys"][0]["purposes"] = serde_json::json!(["ledger-key-event"]);
    cases.push(("ledger purpose", v));
    let mut v = support::keys_json();
    v["keys"][0]["purposes"] = serde_json::json!([]);
    cases.push(("no purpose", v));
    let mut v = support::keys_json();
    v["keys"][0]["public_key"] = serde_json::json!("abc");
    cases.push(("short key", v));
    let mut v = support::keys_json();
    v["schema"] = serde_json::json!("private-custodian.verify-keys/2");
    cases.push(("other major", v));
    let mut v = support::keys_json();
    v["keys"] = serde_json::json!([]);
    cases.push(("no keys", v));
    let mut v = support::keys_json();
    let k = v["keys"][0].clone();
    v["keys"] = serde_json::json!([k.clone(), k]);
    cases.push(("duplicate key id", v));
    for (label, v) in cases {
        let p = write(&dir, "bad.json", &serde_json::to_string(&v).unwrap());
        assert_eq!(
            Pins::load(&p, &feed).unwrap_err(),
            InputError::KeysInvalid,
            "{label}"
        );
    }
    assert_eq!(
        Pins::load(&write(&dir, "x.json", &good), "nope").unwrap_err(),
        InputError::FeedIdInvalid
    );
    let big = write(&dir, "big.json", &" ".repeat(70_000));
    assert_eq!(Pins::load(&big, &feed).unwrap_err(), InputError::TooLarge);
    assert_eq!(
        Pins::load(&dir.join("absent.json"), &feed).unwrap_err(),
        InputError::Unreadable
    );
}

#[test]
fn expectations_are_strict_and_non_empty() {
    let ok = support::expectations_json("credential", "synthetic-candidate");
    Expectations::parse(&serde_json::to_vec(&ok).unwrap()).unwrap();
    let mut cases = Vec::new();
    let mut v = ok.clone();
    v["extra"] = serde_json::json!(true);
    cases.push(v);
    let mut v = ok.clone();
    v["populations"] = serde_json::json!([]);
    cases.push(v);
    let mut v = ok.clone();
    v["policies"] = serde_json::json!([]);
    cases.push(v);
    let mut v = ok.clone();
    v["domain"] = serde_json::json!("not-a-domain");
    cases.push(v);
    let mut v = ok.clone();
    v["schema"] = serde_json::json!("other");
    cases.push(v);
    for v in cases {
        assert_eq!(
            Expectations::parse(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
            InputError::ExpectationsInvalid
        );
    }
    assert_eq!(
        Expectations::parse(b"not json").unwrap_err(),
        InputError::ExpectationsInvalid
    );
}

#[test]
fn a_rewritten_bundle_cannot_choose_its_own_judge() {
    // A bundle prepared for another candidate is refused as a response for
    // another request, whatever its contents say about themselves.
    use custodian_verify::verify;
    let dir = bundle("judge");
    let b = Bundle::load(&dir).unwrap();
    let keys = write(
        &fresh("judge-keys"),
        "k.json",
        &serde_json::to_string(&support::keys_json()).unwrap(),
    );
    let pins = Pins::load(&keys, &support::feed_id()).unwrap();
    let other = Expectations::parse(
        &serde_json::to_vec(&support::expectations_json(
            "credential",
            "synthetic-other-candidate",
        ))
        .unwrap(),
    )
    .unwrap();
    let r = verify(&pins, &other, &b, support::cc::NOW + 120);
    assert_eq!(r.exit_code, 12);
    assert_eq!(r.reason, "wrong_request");

    // And an unknown key means nothing verifies: the feed is refused first.
    let mut v = support::keys_json();
    v["keys"][0]["key_id"] = serde_json::json!(support::cc::id("key_", 2));
    let keys = write(
        &fresh("judge-keys2"),
        "k.json",
        &serde_json::to_string(&v).unwrap(),
    );
    let pins = Pins::load(&keys, &support::feed_id()).unwrap();
    let expect = Expectations::parse(
        &serde_json::to_vec(&support::expectations_json(
            "credential",
            "synthetic-candidate",
        ))
        .unwrap(),
    )
    .unwrap();
    let r = verify(&pins, &expect, &b, support::cc::NOW + 120);
    assert_eq!(r.exit_code, 11);
    assert_eq!(r.reason, "feed_bad_signature");
    assert_eq!(r.projections_accepted, 0);
}

#[test]
fn usage_errors_exit_20_and_print_one_json_object() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_custodian-verify"))
        .args(["--bundle", "x", "--bundle", "y"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(20));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(v["reason"], "usage");
    assert_eq!(v["verdict"], "error");
}
