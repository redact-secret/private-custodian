//! TEST FIXTURE ONLY: a deliberately hostile or faulty "engine" used by the
//! worker tests as a synthetic malicious candidate. It is staged and run like
//! any pinned engine; its behavior is selected by the first line of the staged
//! `config` file. It contains no real credential, no measurement logic and no
//! protected data. It must never be listed in a production allowlist.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};
use std::time::Duration;

fn root(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_owned())
}

fn result(roster: u64, expected: u64, observed: u64, failed: u64, status: &str, domain: &str) {
    let _ = roster;
    println!(
        "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
         \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
         \"status\":\"{status}\",\
         \"roster\":{{\"expected\":{expected},\"observed\":{observed},\"failed\":{failed}}}}}"
    );
}

fn sleep_forever() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(600));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--child") {
        sleep_forever();
    }
    let stage = root("CUSTODIAN_STAGE_ROOT", "/stage");
    let job_root = root("CUSTODIAN_JOB_ROOT", "/job");
    let scratch = root("CUSTODIAN_SCRATCH", "/scratch");
    let cfg = fs::read_to_string(format!("{stage}/config")).unwrap_or_default();
    let mut words = cfg.split_whitespace();
    let mode = words.next().unwrap_or("ok").to_owned();
    let arg1 = words.next().unwrap_or("").to_owned();

    let job: serde_json::Value = fs::read(format!("{job_root}/job.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    let n = job["roster"].as_u64().unwrap_or(0);
    let domain = job["domain"].as_str().unwrap_or("credential").to_owned();
    let ok = |d: &str| result(n, n, n, 0, "complete", d);

    match mode.as_str() {
        "ok" => ok(&domain),
        "partial" => result(n, n, n.saturating_sub(1), 0, "partial", &domain),
        "failed-items" => result(n, n, n, 1, "complete", &domain),
        "crash" => std::process::abort(),
        "exit3" => std::process::exit(3),
        "garbage" => println!("this is not json"),
        "oversize" => {
            let chunk = "a".repeat(1000);
            for _ in 0..100 {
                print!("{chunk}");
            }
            println!();
        }
        "flood-stdout" => {
            let chunk = [b'x'; 8192];
            let mut out = std::io::stdout();
            loop {
                if out.write_all(&chunk).is_err() {
                    break;
                }
            }
        }
        "flood-stderr" => {
            let chunk = [b'y'; 8192];
            let mut err = std::io::stderr();
            loop {
                if err.write_all(&chunk).is_err() {
                    break;
                }
            }
        }
        "stderr-secret" => {
            eprintln!("token=SYNTHETIC-SECRET-SHAPED-0000000000000000 password=hunter2-synthetic");
            ok(&domain);
        }
        // S5: a result that also carries the aggregate artifact (an object
        // the worker validates only as an object; the disclosure crate
        // validates its content). "aggregates-scalar" is not an object.
        "with-aggregates" | "aggregates-scalar" => {
            let agg = if mode == "with-aggregates" {
                format!(
                    "{{\"schema\":\"private-custodian.aggregates/1\",\"domain\":\"{domain}\",\
                     \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
                     \"roster\":{{\"expected\":{n},\"observed\":{n},\"failed\":0}},\
                     \"cells\":[]}}"
                )
            } else {
                "7".to_owned()
            };
            println!(
                "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
                 \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
                 \"status\":\"complete\",\
                 \"roster\":{{\"expected\":{n},\"observed\":{n},\"failed\":0}},\
                 \"aggregates\":{agg}}}"
            );
        }
        "wrong-roster" => result(n, n + 1, n + 1, 0, "complete", &domain),
        "wrong-domain" => ok(if domain == "pii" { "credential" } else { "pii" }),
        "unknown-field" => println!(
            "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
             \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
             \"status\":\"complete\",\"roster\":{{\"expected\":{n},\"observed\":{n},\"failed\":0}},\
             \"note\":\"free-form text must never propagate\"}}"
        ),
        "sleep" => sleep_forever(),
        "spin" => {
            let mut x = 0u64;
            loop {
                x = std::hint::black_box(x.wrapping_add(1));
            }
        }
        "fork" => {
            // arg1 = token placed in the child command line for cleanup checks.
            let me = std::env::current_exe().expect("exe");
            let mut spawned = 0u32;
            let mut kids = Vec::new();
            for _ in 0..5000 {
                match Command::new(&me)
                    .args(["--child", &arg1])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                {
                    Ok(c) => {
                        spawned += 1;
                        kids.push(c);
                    }
                    Err(_) => break,
                }
            }
            println!("spawned={spawned}");
        }
        "tree" => {
            // Children that outlive nothing: the parent also sleeps forever,
            // so only a timeout, cancellation or kill ends the tree.
            let me = std::env::current_exe().expect("exe");
            for _ in 0..3 {
                let _ = Command::new(&me)
                    .args(["--child", &arg1])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn();
            }
            sleep_forever();
        }
        "daemon" => {
            let me = std::env::current_exe().expect("exe");
            let _ = Command::new(me)
                .args(["--child", &arg1])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn();
            ok(&domain);
        }
        "memory" => {
            let mut v: Vec<Vec<u8>> = Vec::new();
            for _ in 0..64 {
                let mut b = Vec::new();
                if b.try_reserve_exact(64 * 1024 * 1024).is_err() {
                    println!("alloc-denied");
                    return;
                }
                b.resize(64 * 1024 * 1024, 1u8);
                v.push(b);
            }
            println!("alloc-ok");
        }
        "disk" => {
            let mut written = 0u64;
            if let Ok(mut f) = fs::File::create(format!("{scratch}/flood")) {
                let chunk = vec![7u8; 1024 * 1024];
                while written < 512 * 1024 * 1024 {
                    if f.write_all(&chunk).is_err() {
                        break;
                    }
                    written += chunk.len() as u64;
                }
            }
            println!("written={written}");
        }
        "net" => {
            let port: u16 = arg1.parse().unwrap_or(9);
            let targets = [
                SocketAddr::from(([127, 0, 0, 1], port)),
                SocketAddr::from(([1, 1, 1, 1], 53)),
            ];
            let any = targets
                .iter()
                .any(|t| TcpStream::connect_timeout(t, Duration::from_millis(800)).is_ok());
            println!("{}", if any { "connected" } else { "blocked" });
        }
        "hostfile" => {
            let mut s = String::new();
            let read = fs::File::open(&arg1).and_then(|mut f| f.read_to_string(&mut s));
            println!("{}", if read.is_ok() { "read" } else { "denied" });
        }
        "env" => {
            let mut names: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
            names.sort();
            println!("{}", names.join(","));
        }
        "modify-stage" => {
            let w = fs::OpenOptions::new()
                .write(true)
                .open(format!("{stage}/engine"))
                .is_ok();
            let c = fs::OpenOptions::new()
                .write(true)
                .open(format!("{stage}/config"))
                .is_ok();
            println!("{}", if w || c { "wrote" } else { "denied" });
        }
        // S2 (ADR 0138): DNS over UDP and TCP to well-known resolver ports.
        // --unshare-net denies transport, not name resolution specifically,
        // so a raw socket connect is the same test issue #55 asks for
        // ("a child that cannot resolve names should also be unable to
        // open a raw UDP/TCP socket to a well-known DNS port").
        "dns" => {
            let targets = [
                SocketAddr::from(([1, 1, 1, 1], 53)),
                SocketAddr::from(([8, 8, 8, 8], 53)),
            ];
            let tcp = targets
                .iter()
                .any(|t| TcpStream::connect_timeout(t, Duration::from_millis(800)).is_ok());
            let udp = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s
                    .connect(("1.1.1.1", 53))
                    .and_then(|_| s.send(b"x"))
                    .is_ok(),
                Err(_) => false,
            };
            println!("{}", if tcp || udp { "connected" } else { "blocked" });
        }
        // S2 (ADR 0138): the exact address ADR 0136 found reachable on the
        // unsandboxed diagnostic.
        "linklocal" => {
            let t = SocketAddr::from(([169, 254, 169, 254], 80));
            let ok = TcpStream::connect_timeout(&t, Duration::from_millis(800)).is_ok();
            println!("{}", if ok { "connected" } else { "blocked" });
        }
        // S2 (ADR 0138): IPv6 loopback, a positive-control target that does
        // not depend on any external network -- arg1 is the port the test
        // bound on ::1 outside the sandbox.
        "ipv6loopback" => {
            let port: u16 = arg1.parse().unwrap_or(9);
            let t: SocketAddr = format!("[::1]:{port}").parse().unwrap();
            let ok = TcpStream::connect_timeout(&t, Duration::from_millis(800)).is_ok();
            println!("{}", if ok { "connected" } else { "blocked" });
        }
        // S2 (ADR 0138): a public IPv6 address. Best-effort: CI runners may
        // not route IPv6 at all, which the test records as untested, never
        // as a denial.
        "ipv6public" => {
            let t: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
            let ok = TcpStream::connect_timeout(&t, Duration::from_millis(800)).is_ok();
            println!("{}", if ok { "connected" } else { "blocked" });
        }
        // S3 (ADR 0139): count descriptors actually visible to the payload
        // via readlink on each candidate /proc/self/fd/N, which does not
        // itself open or retain a new descriptor on the target.
        "fdcount" => {
            let n = (0..32)
                .filter(|i| fs::read_link(format!("/proc/self/fd/{i}")).is_ok())
                .count();
            println!("{n}");
        }
        // S3 (ADR 0139): supplementary groups the payload is a member of.
        // ADR 0137's open risk: not yet an automated positive control, only
        // reported here.
        "groups" => {
            let line = fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Groups:"))
                        .map(String::from)
                })
                .unwrap_or_default();
            let n = line
                .trim_start_matches("Groups:")
                .split_whitespace()
                .count();
            println!("{n}");
        }
        // S3 (ADR 0139): symlink inside the one writable directory pointing
        // at a path outside it; reading through the link must fail exactly
        // like reading the target directly (the "hostfile" case), proving
        // the link does not grant a new path out of the sandbox.
        "symlink-escape" => {
            let link = format!("{scratch}/escape-link");
            let _ = fs::remove_file(&link);
            let made = symlink(&arg1, &link).is_ok();
            let read = made
                && fs::File::open(&link)
                    .and_then(|mut f| {
                        let mut s = String::new();
                        f.read_to_string(&mut s).map(|_| s)
                    })
                    .is_ok();
            println!("{}", if read { "read" } else { "denied" });
        }
        // S3 (ADR 0139): a hardlink across the scratch tmpfs and a read-only
        // mount must fail with a cross-device error (EXDEV), not merely be
        // denied by permission -- the mount boundary itself, not a mode bit.
        "hardlink-escape" => {
            let target = format!("{stage}/engine");
            let link = format!("{scratch}/escape-hardlink");
            let _ = fs::remove_file(&link);
            let made = fs::hard_link(&target, &link).is_ok();
            println!("{}", if made { "linked" } else { "denied" });
        }
        // S3 (ADR 0139): a hostile engine printing a verification/attestation
        // -shaped claim on stdout, distinct from the generic "unknown-field"
        // case, naming exactly the forged-attestation scenario the issue
        // describes. The real IsolationVerification is #[non_exhaustive] and
        // constructed only by run_self_check in the trusted process; this
        // proves the *result parser* rejects a payload-side imitation too.
        "forged-attestation" => println!(
            "{{\"schema\":\"private-custodian.worker-result/1\",\"domain\":\"{domain}\",\
             \"protocol\":{{\"name\":\"synthetic-protocol\",\"version\":\"1\"}},\
             \"status\":\"complete\",\"roster\":{{\"expected\":{n},\"observed\":{n},\"failed\":0}},\
             \"verification\":{{\"sandbox\":\"bubblewrap\",\"all_passed\":true}}}}"
        ),
        _ => std::process::exit(64),
    }
}
