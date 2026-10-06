//! `deploy/examples/` holds placeholders only (S6, issue 33, ADR 0132).
//!
//! The scanner here fails on a real-looking value: an address outside the
//! documentation ranges, a real domain, key material, a token, an email
//! address, an absolute home path. It has negative controls, so a scanner that
//! stopped finding things would fail too. Each JSON example is also parsed by
//! the real parser of the component it configures, and the systemd units must
//! keep their hardening directives. Synthetic and public: nothing here is a
//! deployment, and a passing run is functional verification, not an
//! independent protected evaluation.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use custodian_cli::deploy::{parse_roots, validate_config_document};
use custodian_cli::OperatorPolicy;
use custodian_daemon::config::DaemonConfig;
use custodian_intake::config::IntakeConfig;
use custodian_signer::SignerConfig;
use serde_json::Value;

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/examples")
}

fn collect(dir: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|_| panic!("deploy/examples is missing"))
        .flatten()
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for e in entries {
        let p = e.path();
        let t = e.file_type().unwrap();
        assert!(!t.is_symlink(), "no links in the examples: {}", p.display());
        if t.is_dir() {
            collect(&p, out);
        } else {
            let rel = p
                .strip_prefix(examples_dir())
                .unwrap()
                .display()
                .to_string();
            let text = std::fs::read_to_string(&p)
                .unwrap_or_else(|_| panic!("{rel} must be UTF-8 text, not a binary"));
            out.push((rel, text));
        }
    }
}

fn all_examples() -> Vec<(String, String)> {
    let mut out = Vec::new();
    collect(&examples_dir(), &mut out);
    out
}

fn example(name: &str) -> String {
    all_examples()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("{name} is missing"))
        .1
}

// ---- the scanner -----------------------------------------------------------------

/// Top-level domains common enough that a hostname ending in one is a real
/// name. `.invalid` and `.example` are reserved and always allowed; so is
/// `example.<tld>` (RFC 2606). The list is deliberately short: it is a net for
/// accidents, not a registry.
const REAL_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "cloud", "xyz", "info", "biz", "co", "ai", "us", "uk",
    "de", "fr", "jp", "kr", "cn", "ru", "eu", "tech", "online", "site", "me", "tv", "gg",
];

fn is_token_char(c: char, extra: &str) -> bool {
    c.is_ascii_alphanumeric() || extra.contains(c)
}

fn tokens<'a>(text: &'a str, extra: &'static str) -> impl Iterator<Item = &'a str> {
    text.split(move |c: char| !is_token_char(c, extra))
        .filter(|t| !t.is_empty())
}

fn ipv4_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    for t in tokens(text, ".") {
        let t = t.trim_matches('.');
        let parts: Vec<&str> = t.split('.').collect();
        if parts.len() != 4 || !parts.iter().all(|p| (1..=3).contains(&p.len())) {
            continue;
        }
        let Ok(n) = parts
            .iter()
            .map(|p| p.parse::<u16>())
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        if n.iter().any(|x| *x > 255) {
            continue;
        }
        let ok = n[0] == 127
            || (n[0] == 192 && n[1] == 0 && n[2] == 2)
            || (n[0] == 198 && n[1] == 51 && n[2] == 100)
            || (n[0] == 203 && n[1] == 0 && n[2] == 113);
        if !ok {
            out.insert("ip_outside_documentation_ranges");
        }
    }
}

fn ipv6_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    for t in tokens(text, ":") {
        if t.matches(':').count() < 2 || t.contains("//") {
            continue;
        }
        let groups: Vec<&str> = t.split(':').collect();
        let hexish = groups
            .iter()
            .all(|g| g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit()));
        let has_letter_or_gap = t.contains("::") || t.bytes().any(|b| b.is_ascii_alphabetic());
        if !hexish || !has_letter_or_gap {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        if lower == "::1" || lower.starts_with("2001:db8:") || lower.starts_with("2001:db8::") {
            continue;
        }
        out.insert("ip_outside_documentation_ranges");
    }
}

fn host_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    for t in tokens(text, ".-") {
        let t = t.trim_matches(|c| c == '.' || c == '-');
        let labels: Vec<&str> = t.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            continue;
        }
        let last = labels[labels.len() - 1].to_ascii_lowercase();
        if !REAL_TLDS.contains(&last.as_str()) {
            continue;
        }
        if labels[labels.len() - 2].eq_ignore_ascii_case("example") {
            continue;
        }
        out.insert("real_domain");
    }
}

fn email_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    for t in tokens(text, "@.-_+") {
        let Some((local, domain)) = t.split_once('@') else {
            continue;
        };
        if local.is_empty() || domain.is_empty() || !domain.contains('.') {
            continue;
        }
        let d = domain.to_ascii_lowercase();
        let reserved = d.ends_with(".invalid")
            || d.ends_with(".example")
            || ["example.com", "example.org", "example.net"]
                .iter()
                .any(|e| d == *e || d.ends_with(&format!(".{e}")));
        if !reserved {
            out.insert("email_address");
        }
    }
}

fn hex_run_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let run = &bytes[start..i];
            // A word like "deadbeef..." that is only letters is not a run of
            // digits worth flagging; real material mixes digits and letters.
            if run.len() >= 32 {
                let zeros = run.iter().filter(|b| **b == b'0').count();
                // An obviously empty digest (all zeros but for a last digit).
                if zeros + 4 < run.len() {
                    out.insert("hex_key_material_or_digest");
                }
            }
        } else {
            i += 1;
        }
    }
}

fn token_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    if text.contains("-----BEGIN") || text.contains("PRIVATE KEY") {
        out.insert("pem_or_private_key");
    }
    for t in tokens(text, "_-+=/.") {
        let prefixes = [
            "ghp_",
            "gho_",
            "ghu_",
            "ghs_",
            "ghr_",
            "github_pat_",
            "xoxb-",
            "xoxp-",
            "AKIA",
        ];
        if prefixes
            .iter()
            .any(|p| t.starts_with(p) && t.len() >= p.len() + 8)
        {
            out.insert("token_prefix");
        }
        if t.starts_with("sk-") && t.len() >= 20 {
            out.insert("token_prefix");
        }
        if t.starts_with("eyJ") && t.matches('.').count() >= 2 {
            out.insert("jwt");
        }
        let plain = !t.contains('/') && !t.contains('.');
        if plain
            && t.len() >= 40
            && t.bytes().any(|b| b.is_ascii_digit())
            && t.bytes().any(|b| b.is_ascii_uppercase())
            && t.bytes().any(|b| b.is_ascii_lowercase())
        {
            out.insert("high_entropy_token");
        }
    }
}

fn path_findings(text: &str, out: &mut BTreeSet<&'static str>) {
    for needle in ["/home/", "/Users/", "/root/", "C:\\Users", "/var/home/"] {
        if text.contains(needle) {
            out.insert("absolute_home_path");
        }
    }
}

/// Every kind of finding in `text`, by fixed name.
fn scan(text: &str) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    ipv4_findings(text, &mut out);
    ipv6_findings(text, &mut out);
    host_findings(text, &mut out);
    email_findings(text, &mut out);
    hex_run_findings(text, &mut out);
    token_findings(text, &mut out);
    path_findings(text, &mut out);
    out
}

#[test]
fn every_example_is_free_of_real_looking_values() {
    let all = all_examples();
    assert!(all.len() >= 14, "the example set shrank: {}", all.len());
    let mut bad = Vec::new();
    for (name, text) in &all {
        let f = scan(text);
        if !f.is_empty() {
            bad.push(format!("{name}: {f:?}"));
        }
    }
    assert!(bad.is_empty(), "real-looking values: {bad:#?}");
}

#[test]
fn the_scanner_has_teeth() {
    // Constructed in pieces so that this file is not itself a finding.
    let dot = ".";
    let cases: Vec<(String, &str)> = vec![
        (
            format!("host 10{dot}1{dot}2{dot}3 listens"),
            "ip_outside_documentation_ranges",
        ),
        (
            format!("bind 8{dot}8{dot}8{dot}8:53"),
            "ip_outside_documentation_ranges",
        ),
        (
            format!("ok 203{dot}0{dot}114{dot}7"),
            "ip_outside_documentation_ranges",
        ),
        (
            "addr fe80::1ff:fe23:4567:890a".to_owned(),
            "ip_outside_documentation_ranges",
        ),
        (format!("https://github{dot}com/org/repo"), "real_domain"),
        (
            format!("server_name ledger{dot}acme{dot}io;"),
            "real_domain",
        ),
        (format!("mail ops@acme{dot}org"), "email_address"),
        (
            format!("contact someone@example{dot}invalid.evil{dot}com"),
            "email_address",
        ),
        (
            format!("key: {}", "ab12".repeat(16)),
            "hex_key_material_or_digest",
        ),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----".to_owned(),
            "pem_or_private_key",
        ),
        (
            format!("token ghp_{}", "A1b2C3d4".repeat(5)),
            "token_prefix",
        ),
        (format!("aws AKIA{}", "ABCDEFGHIJKLMNOP"), "token_prefix"),
        (format!("jwt eyJhbGciOi{dot}eyJzdWIiOiIx{dot}c2ln"), "jwt"),
        (
            format!("blob {}", "Zm9vYmFyQmF6".repeat(5)),
            "high_entropy_token",
        ),
        (
            "path /home/someone/.ssh/id".to_owned(),
            "absolute_home_path",
        ),
        ("path /Users/someone/Work".to_owned(), "absolute_home_path"),
    ];
    for (text, kind) in &cases {
        assert!(
            scan(text).contains(kind),
            "the scanner missed {kind} in a negative control"
        );
    }
    // And what is allowed stays allowed.
    let fine = format!(
        "127{dot}0{dot}0{dot}1:8787 192{dot}0{dot}2{dot}10 198{dot}51{dot}100{dot}1 \
         203{dot}0{dot}113{dot}9 ::1 2001:db8::7 custodian{dot}example{dot}invalid \
         host{dot}example{dot}com git@git{dot}example{dot}invalid {} {}",
        "0".repeat(63) + "1",
        "0".repeat(64)
    );
    assert_eq!(scan(&fine), BTreeSet::new(), "{:?}", scan(&fine));
}

// ---- the real parsers -------------------------------------------------------------

#[test]
fn each_json_example_parses_with_the_real_parser_of_its_component() {
    DaemonConfig::from_json(example("daemon-config.example.json").as_bytes())
        .expect("daemon config");
    SignerConfig::parse(example("signer-config.example.json").as_bytes()).expect("signer config");
    validate_config_document(example("cli-config.example.json").as_bytes()).expect("cli config");
    let policy = OperatorPolicy::from_json(example("operator-policy.example.json").as_bytes())
        .expect("operator policy");
    assert_eq!(policy.identity_count(), 4);
    let roots = parse_roots(example("pinned-roots.example.json").as_bytes()).expect("roots");
    assert_eq!(roots.len(), 1);
    IntakeConfig::from_json(example("intake-config.example.json").as_bytes()).expect("intake");
    for name in [
        "backup-retention.example.json",
        "feed-destination.example.json",
    ] {
        serde_json::from_str::<Value>(&example(name)).unwrap_or_else(|_| panic!("{name}"));
    }
}

#[test]
fn the_daemon_example_is_the_safe_configuration_it_claims_to_be() {
    let v: Value = serde_json::from_str(&example("daemon-config.example.json")).unwrap();
    assert_eq!(v["github"]["mode"], "disabled", "intake stays off");
    assert_eq!(
        v["worker"]["sandbox"], "none",
        "no dispatch without a verified host"
    );
    assert_eq!(v["listener"]["allow_non_loopback"], false);
    assert!(v["listener"]["bind"]
        .as_str()
        .unwrap()
        .starts_with("127.0.0.1:"));
    // The proxy example forwards to exactly that loopback address.
    let proxy = example("proxy/nginx-custodian.conf.example");
    let bind = v["listener"]["bind"].as_str().unwrap();
    assert!(proxy.contains(&format!("proxy_pass http://{bind};")));
    assert!(proxy.contains("custodian.example.invalid"));
    assert!(proxy.contains("access_log off;"));
}

#[test]
fn the_operator_policy_example_uses_obviously_empty_credential_digests() {
    let v: Value = serde_json::from_str(&example("operator-policy.example.json")).unwrap();
    for id in v["identities"].as_array().unwrap() {
        let d = id["credential_sha256"].as_str().unwrap();
        assert!(d.starts_with(&"0".repeat(60)), "{d}");
    }
}

// ---- systemd and layout -----------------------------------------------------------

fn directives(unit: &str) -> BTreeSet<String> {
    unit.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_service_units_keep_their_hardening_directives() {
    let common = [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "CapabilityBoundingSet=",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "UMask=0077",
    ];
    let svc = directives(&example("systemd/custodiand.service.example"));
    let signer = directives(&example("systemd/custodian-signer.service.example"));
    let backup = directives(&example("systemd/custodian-backup.service.example"));
    for d in common {
        assert!(svc.contains(d), "custodiand: {d}");
        assert!(signer.contains(d), "signer: {d}");
        assert!(backup.contains(d), "backup: {d}");
    }
    // The control service starts the worker through bubblewrap, which needs
    // user namespaces: it must not forbid them. The signer must.
    assert!(!svc.contains("RestrictNamespaces=yes"));
    assert!(signer.contains("RestrictNamespaces=yes"));
    // The signer has no network and no core dump (the key never leaves memory).
    assert!(signer.contains("PrivateNetwork=yes"));
    assert!(signer.contains("RestrictAddressFamilies=AF_UNIX"));
    assert!(signer.contains("LimitCORE=0"));
    // Distinct identities; none is root.
    assert!(svc.contains("User=custodian-svc"));
    assert!(signer.contains("User=custodian-signer"));
    assert!(backup.contains("User=custodian-backup"));
    // The backup job cannot write the live state.
    assert!(backup.contains("ReadOnlyPaths=/srv/custodian/state"));
    assert!(svc.contains("InaccessiblePaths=/srv/custodian/backups"));
    // The unit that starts the service validates its configuration first.
    assert!(svc
        .iter()
        .any(|d| d.starts_with("ExecStartPre=") && d.contains("check-config")));
}

#[test]
fn the_layout_matches_the_runbook_and_nothing_is_group_or_other_writable() {
    let text = example("layout/custodian.tmpfiles.example");
    let mut seen = BTreeSet::new();
    for line in text.lines().filter(|l| l.starts_with("d ")) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (path, mode) = (f[1], u32::from_str_radix(f[2], 8).unwrap());
        assert_eq!(mode & 0o022, 0, "{path} is group or other writable");
        seen.insert((path.to_owned(), f[2].to_owned(), f[3].to_owned()));
    }
    let has =
        |p: &str, m: &str, u: &str| seen.contains(&(p.to_owned(), m.to_owned(), u.to_owned()));
    assert!(has("/srv/custodian/state", "0700", "custodian-svc"));
    assert!(has("/srv/custodian/protected", "0700", "custodian-svc"));
    assert!(has("/srv/custodian/artifacts", "0755", "root"));
    assert!(has("/srv/custodian/policy", "0755", "root"));
    assert!(has("/srv/custodian/ledger-clone", "0700", "custodian-svc"));
    assert!(has("/srv/custodian/backups", "0700", "custodian-backup"));
    assert!(has("/var/lib/custodian-signer", "0700", "custodian-signer"));
}

// ---- issue 72: the control/signer/exporter/worker templates -------------------------

fn pending_everywhere(v: &Value, path: &str, bad: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                if k == "status" {
                    let ok = matches!(child.as_str(), Some("PENDING") | Some("NOT_AUTHORIZED"));
                    if !ok {
                        bad.push(format!("{path}/{k}"));
                    }
                }
                pending_everywhere(child, &format!("{path}/{k}"), bad);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                pending_everywhere(child, &format!("{path}/{i}"), bad);
            }
        }
        _ => {}
    }
}

#[test]
fn the_custody_arrangement_templates_are_pending_and_authorize_nothing() {
    for name in [
        "custody-topology.example.json",
        "ec2-worker-host.example.json",
        "protected-delivery.example.json",
        "activation-pins.example.json",
    ] {
        let v: Value = serde_json::from_str(&example(name)).unwrap_or_else(|_| panic!("{name}"));
        assert_eq!(v["status"], "PENDING", "{name} must be PENDING at the top");
        let mut bad = Vec::new();
        pending_everywhere(&v, "", &mut bad);
        assert!(
            bad.is_empty(),
            "{name}: a status other than PENDING: {bad:?}"
        );
    }
}

#[test]
fn the_activation_pins_keep_the_three_approvals_separate_and_every_pin_empty() {
    let v: Value = serde_json::from_str(&example("activation-pins.example.json")).unwrap();
    let a = &v["approvals"];
    assert_eq!(a["first_protected_evaluation"]["status"], "NOT_AUTHORIZED");
    assert_eq!(a["benchmark_authority_cutover"]["status"], "NOT_AUTHORIZED");
    let pins = v["pins"].as_object().unwrap();
    assert!(pins.len() >= 15);
    for (k, p) in pins {
        assert_eq!(p["status"], "PENDING", "{k}");
        assert!(p["owner"].as_str().is_some_and(|o| !o.is_empty()), "{k}");
        if let Some(val) = p["value"].as_str() {
            let empty = val.chars().all(|c| c == '0')
                || val == "UNSET"
                || !val.starts_with(char::is_numeric);
            assert!(empty, "{k} carries a non-placeholder value");
        }
    }
}

#[test]
fn the_topology_keeps_control_functions_off_serverless_and_the_signer_key_off_the_control_host() {
    let v: Value = serde_json::from_str(&example("custody-topology.example.json")).unwrap();
    let zones = v["zones"].as_array().unwrap();
    let control = zones.iter().find(|z| z["zone"] == "control_host").unwrap();
    assert_eq!(control["serverless"], false);
    let never = control["never_holds"].to_string();
    assert!(never.contains("signing key"));
    let worker = zones
        .iter()
        .find(|z| z["zone"] == "ephemeral_worker")
        .unwrap();
    assert!(worker["lifecycle"]
        .as_str()
        .unwrap()
        .contains("never stopped or reused"));
}
