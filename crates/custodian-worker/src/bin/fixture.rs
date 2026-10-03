//! TEST FIXTURE ONLY: a deliberately hostile or faulty "engine" used by the
//! worker tests as a synthetic malicious candidate. It is staged and run like
//! any pinned engine; its behavior is selected by the first line of the staged
//! `config` file. It contains no real credential, no measurement logic and no
//! protected data. It must never be listed in a production allowlist.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
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
        _ => std::process::exit(64),
    }
}
