//! TEST FIXTURE ONLY: the synthetic engine used by the daemon's pipeline
//! tests, for both evaluation domains.
//!
//! It is staged and run like any pinned engine (`/stage/engine --job
//! /job/job.json`), reads the job document, and prints one
//! `private-custodian.worker-result/1` document on stdout that embeds a
//! `private-custodian.aggregates/1` artifact. It contains no measurement
//! logic, no real credential, no protected data and no network code: the
//! "measurements" are fixed fractions of the roster, so a test can predict
//! every number a projection will carry.
//!
//! REAL ENGINES DO NOT EMIT THIS YET. credential-eval and pii-eval produce
//! their own result formats; making them print the embedded aggregate artifact
//! is a cross-repository job (docs/daemon.md, ADR 0127; pii-eval issue 37
//! proposes a file under `/scratch` instead, which the production assembly
//! has not adopted). This binary defines the contract the custodian side
//! consumes today, nothing more. It must never be listed in a production
//! artifact directory.
//!
//! Behavior is chosen by the first word of the staged `config` file:
//! `ok` (default), `partial`, `failed-items`, `no-aggregates`,
//! `aggregates-wrong-roster`, `leak`, `crash`, `exit3`, `garbage` and
//! `sleep <secs>`.

use std::fs;

fn root(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_owned())
}

/// The fixed strata of the synthetic disclosure policy, as
/// `(stratum, denominator, numerator)`. For a roster of 75 the cells are
/// a=30/40, b=18/30, c=2/5, t1=35/50, t2=15/25 and all=50/75. For any roster
/// the length strata partition it and the category strata partition it, and
/// both partitions sum to the same total.
fn cells(observed: u64) -> Vec<(&'static str, u64, u64)> {
    let c = observed / 15;
    let b = observed * 2 / 5;
    let a = observed - b - c;
    let (na, nb, nc) = (a * 3 / 4, b * 3 / 5, c * 2 / 5);
    let all_n = na + nb + nc;
    let t1 = observed * 2 / 3;
    let t2 = observed - t1;
    let n1 = (all_n * 7 / 10).min(t1);
    let n2 = all_n - n1;
    vec![
        ("a", a, na),
        ("b", b, nb),
        ("c", c, nc),
        ("t1", t1, n1),
        ("t2", t2, n2),
        ("all", observed, all_n),
    ]
}

fn aggregates(domain: &str, expected: u64, observed: u64, failed: u64) -> String {
    let cells: Vec<String> = cells(observed)
        .into_iter()
        .map(|(s, d, n)| {
            format!(
                "{{\"stratum\":\"{s}\",\"metric\":\"detected\",\"numerator\":{n},\"denominator\":{d}}}"
            )
        })
        .collect();
    format!(
        "{{\"schema\":\"private-custodian.aggregates/1\",\"domain\":\"{domain}\",\
         \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
         \"roster\":{{\"expected\":{expected},\"observed\":{observed},\"failed\":{failed}}},\
         \"cells\":[{}]}}",
        cells.join(",")
    )
}

#[allow(clippy::too_many_arguments)]
fn result(
    domain: &str,
    status: &str,
    expected: u64,
    observed: u64,
    failed: u64,
    agg: Option<String>,
) {
    let tail = agg
        .map(|a| format!(",\"aggregates\":{a}"))
        .unwrap_or_default();
    println!(
        "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
         \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
         \"status\":\"{status}\",\
         \"roster\":{{\"expected\":{expected},\"observed\":{observed},\"failed\":{failed}}}{tail}}}"
    );
}

fn main() {
    let stage = root("CUSTODIAN_STAGE_ROOT", "/stage");
    let job_root = root("CUSTODIAN_JOB_ROOT", "/job");
    let cfg = fs::read_to_string(format!("{stage}/config")).unwrap_or_default();
    let mut words = cfg.split_whitespace();
    let mode = words.next().unwrap_or("ok").to_owned();
    let arg = words.next().unwrap_or("").to_owned();
    let job: serde_json::Value = fs::read(format!("{job_root}/job.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    let n = job["roster"].as_u64().unwrap_or(0);
    let d = job["domain"].as_str().unwrap_or("credential").to_owned();
    match mode.as_str() {
        "ok" => result(&d, "complete", n, n, 0, Some(aggregates(&d, n, n, 0))),
        "partial" => {
            let o = n.saturating_sub(1);
            result(&d, "partial", n, o, 0, Some(aggregates(&d, n, o, 0)));
        }
        "failed-items" => result(&d, "complete", n, n, 1, Some(aggregates(&d, n, n, 1))),
        "no-aggregates" => result(&d, "complete", n, n, 0, None),
        "aggregates-wrong-roster" => {
            result(
                &d,
                "complete",
                n,
                n,
                0,
                Some(aggregates(&d, n + 1, n + 1, 0)),
            );
        }
        "sleep" => {
            let secs: u64 = arg.parse().unwrap_or(1);
            std::thread::sleep(std::time::Duration::from_secs(secs));
            result(&d, "complete", n, n, 0, Some(aggregates(&d, n, n, 0)));
        }
        // A hostile engine: it reads the protected inputs it was given and
        // tries to smuggle them out on stderr and inside the result. The
        // result is rejected (an unknown field) and nothing may reach a log,
        // a Check, the ledger or a projection.
        "leak" => {
            let input = root("CUSTODIAN_INPUT_ROOT", "/input");
            let mut secret = String::new();
            if let Ok(rd) = fs::read_dir(&input) {
                for e in rd.flatten() {
                    secret.push_str(&fs::read_to_string(e.path()).unwrap_or_default());
                }
            }
            eprintln!("{secret}");
            println!(
                "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{d}\",\
                 \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
                 \"status\":\"complete\",\
                 \"roster\":{{\"expected\":{n},\"observed\":{n},\"failed\":0}},\
                 \"note\":\"{}\"}}",
                secret.replace(['"', '\\', '\n'], "")
            );
        }
        "crash" => std::process::abort(),
        "exit3" => std::process::exit(3),
        "garbage" => println!("this is not json"),
        _ => result(&d, "complete", n, n, 0, Some(aggregates(&d, n, n, 0))),
    }
}
