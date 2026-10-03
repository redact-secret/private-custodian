//! The caller workflow states, per synthetic case, the exit code and reason
//! the verifier must give. Those lines must agree with the generator, so the
//! workflow cannot drift into asserting something the fixtures do not mean.

mod support;

const WORKFLOW: &str = include_str!("../../../.github/workflows/synthetic-conformance.yml");
const REUSABLE: &str = include_str!("../../../.github/workflows/verify-signed-results.yml");
const BUILD: &str = include_str!("../../../.github/workflows/build.yml");

/// The workflow without its comment lines.
fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_caller_matrix_matches_every_generated_case() {
    let cases = support::cases();
    for c in &cases {
        let line = format!(
            "- {{case: {}, exit: \"{}\", reason: {}, now: \"{}\"}}",
            c.name, c.expected_exit, c.expected_reason, c.now
        );
        assert!(
            WORKFLOW.contains(&line),
            "synthetic-conformance.yml is missing: {line}"
        );
    }
    let listed = WORKFLOW
        .lines()
        .filter(|l| l.trim_start().starts_with("- {case: "))
        .count();
    assert_eq!(listed, cases.len(), "no stray or missing matrix entries");
}

#[test]
fn the_workflow_feed_id_is_the_fixture_feed_id() {
    assert!(WORKFLOW.contains(&format!("feed-id: {}", support::feed_id())));
}

#[test]
fn no_workflow_declares_or_passes_a_secret() {
    for (name, text) in [
        ("synthetic-conformance.yml", WORKFLOW),
        ("verify-signed-results.yml", REUSABLE),
        ("build.yml", BUILD),
    ] {
        let code = code(text);
        assert!(!code.contains("secrets"), "{name} must not use secrets");
        assert!(
            !code.contains("secrets:"),
            "{name} must not declare secrets"
        );
        assert!(
            !code.contains("pull_request_target"),
            "{name} must not use pull_request_target"
        );
    }
}

#[test]
fn only_the_attest_job_holds_the_attestation_scopes() {
    for (name, text) in [
        ("synthetic-conformance.yml", WORKFLOW),
        ("verify-signed-results.yml", REUSABLE),
    ] {
        let text = code(text);
        assert!(!text.contains("id-token"), "{name}");
        assert!(!text.contains("attestations"), "{name}");
    }
    let build = code(BUILD);
    assert_eq!(build.matches("id-token: write").count(), 1);
    assert_eq!(build.matches("attestations: write").count(), 1);
    // Both sit inside the `attest` job, after its header.
    let attest = build.split("\n  attest:\n").nth(1).expect("attest job");
    assert!(attest.contains("id-token: write") && attest.contains("attestations: write"));
    let before = build.split("\n  attest:\n").next().unwrap();
    assert!(!before.contains("id-token") && !before.contains("attestations"));
    assert!(build.contains("retention-days: 1"));
    assert!(build.contains("startsWith(github.ref, 'refs/tags/v')"));
}

#[test]
fn every_action_is_pinned_to_a_full_commit_sha() {
    for (name, text) in [
        ("synthetic-conformance.yml", WORKFLOW),
        ("verify-signed-results.yml", REUSABLE),
        ("build.yml", BUILD),
    ] {
        for line in code(text).lines().filter(|l| l.contains("uses: ")) {
            let target = line.split("uses: ").nth(1).unwrap().trim();
            if target.starts_with("./") {
                continue;
            }
            let sha = target.split('@').nth(1).unwrap_or("");
            assert!(
                sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                "{name}: unpinned action: {target}"
            );
        }
    }
}
