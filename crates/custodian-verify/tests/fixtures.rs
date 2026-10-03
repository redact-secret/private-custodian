//! The checked-in synthetic bundles (S1): they are exactly what the generator
//! produces, and the verifier gives the documented exit code and reason for
//! each, through the library and through the real binary.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/synthetic")
}

fn write_all(base: &Path, files: &std::collections::BTreeMap<String, Vec<u8>>) {
    for (rel, bytes) in files {
        let p = base.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
}

fn list(base: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, base, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_str().unwrap().to_owned());
            }
        }
    }
    let mut out = Vec::new();
    walk(base, base, &mut out);
    out.sort();
    out
}

#[test]
fn checked_in_fixtures_are_exactly_the_generated_ones() {
    let update = std::env::var_os("UPDATE_FIXTURES").is_some();
    let mut expected = support::shared_files();
    for c in support::cases() {
        for (rel, bytes) in c.files {
            expected.insert(format!("{}/{rel}", c.name), bytes);
        }
    }
    if update {
        let _ = std::fs::remove_dir_all(root().join("keys.json"));
        for c in support::cases() {
            let _ = std::fs::remove_dir_all(root().join(c.name));
        }
        write_all(&root(), &expected);
    }
    let on_disk: Vec<String> = list(&root())
        .into_iter()
        .filter(|f| f != "README.md")
        .collect();
    let want: Vec<String> = expected.keys().cloned().collect();
    assert_eq!(
        on_disk, want,
        "fixture file set differs; run with UPDATE_FIXTURES=1 to regenerate"
    );
    for (rel, bytes) in &expected {
        assert_eq!(
            &std::fs::read(root().join(rel)).unwrap(),
            bytes,
            "{rel} differs from the generator; run with UPDATE_FIXTURES=1"
        );
    }
}

fn run_cli(case: &str) -> (i32, Value) {
    let dir = root().join(case);
    let meta: Value =
        serde_json::from_slice(&std::fs::read(dir.join("case.json")).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_custodian-verify"))
        .arg("--bundle")
        .arg(dir.join("bundle"))
        .arg("--keys")
        .arg(root().join("keys.json"))
        .arg("--feed-id")
        .arg(meta["feed_id"].as_str().unwrap())
        .arg("--expect")
        .arg(dir.join("expectations.json"))
        .arg("--now")
        .arg(meta["now"].to_string())
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), 1, "exactly one JSON line");
    (
        out.status.code().unwrap(),
        serde_json::from_str(text.trim()).unwrap(),
    )
}

#[test]
fn every_synthetic_case_gives_its_documented_exit_code_and_reason() {
    let cases = support::cases();
    assert!(cases.len() >= 7);
    for c in cases {
        let (code, out) = run_cli(c.name);
        assert_eq!(code, i32::from(c.expected_exit), "{}", c.name);
        assert_eq!(out["exit_code"], c.expected_exit, "{}", c.name);
        assert_eq!(out["reason"], c.expected_reason, "{}", c.name);
        assert_eq!(out["schema"], "private-custodian.verify-result/1");
        assert!(out["scope"]
            .as_str()
            .unwrap()
            .contains("not an independent"));
        assert_eq!(
            out["verdict"],
            if c.expected_exit == 0 {
                "accepted"
            } else {
                "rejected"
            },
            "{}",
            c.name
        );
    }
}

#[test]
fn the_positive_case_accepts_exactly_one_projection_and_one_feed_entry() {
    let (code, out) = run_cli("positive");
    assert_eq!(code, 0);
    assert_eq!(out["projections_accepted"], 1);
    assert_eq!(out["feed_applied"], 1);
    assert_eq!(out["feed_sequence"], 1);
    assert_eq!(out["feed_error"], Value::Null);
}

#[test]
fn rejected_output_never_echoes_input_text() {
    // A hostile feed id and paths must not appear in any output.
    let out = Command::new(env!("CARGO_BIN_EXE_custodian-verify"))
        .args([
            "--bundle",
            "/nonexistent/secret-looking-path",
            "--keys",
            "/nonexistent/keys",
            "--feed-id",
            "hostile feed text",
            "--expect",
            "/nonexistent/e",
            "--now",
            "1",
        ])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(21));
    assert!(text.contains("feed_id_invalid"));
    assert!(!text.contains("hostile"));
    assert!(!text.contains("nonexistent"));
    assert!(out.stderr.is_empty());
}
