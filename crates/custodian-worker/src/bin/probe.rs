//! Isolation probe. Runs INSIDE the sandbox during the startup self-check and
//! reports, one line per check, `PASS <id>` or `FAIL <id>`. It holds no
//! secret and prints no environment value, path content or host data. The
//! host decides pass or fail; a probe that cannot run is a failed self-check.
//!
//! Arguments (all supplied by the self-check):
//!   --canary-file PATH    host file that must not be reachable
//!   --canary-env A,B,C    environment names that must be absent
//!   --port N              host loopback port that must be unreachable
//!   --nproc N --as BYTES --cpu SECS   rlimits that must be in force

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn report(id: &str, ok: bool) {
    println!("{} {id}", if ok { "PASS" } else { "FAIL" });
}

fn limit_soft(label: &str) -> Option<String> {
    let text = fs::read_to_string("/proc/self/limits").ok()?;
    let line = text.lines().find(|l| l.starts_with(label))?;
    line[label.len()..]
        .split_whitespace()
        .next()
        .map(str::to_owned)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Network: nothing connects, not the host's loopback, not the internet.
    let port: u16 = arg(&args, "--port")
        .and_then(|p| p.parse().ok())
        .unwrap_or(9);
    let mut targets: Vec<SocketAddr> = vec![
        SocketAddr::from(([127, 0, 0, 1], port)),
        SocketAddr::from(([1, 1, 1, 1], 53)),
        SocketAddr::from(([192, 0, 2, 1], 9)),
    ];
    targets.push(SocketAddr::from(([10, 0, 0, 1], 80)));
    let tcp_blocked = targets
        .iter()
        .all(|t| TcpStream::connect_timeout(t, Duration::from_millis(800)).is_err());
    let udp_blocked = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s
            .connect("1.1.1.1:53")
            .and_then(|_| s.send(b"x").map(|_| ()))
            .is_err(),
        Err(_) => true,
    };
    report("egress_denied", tcp_blocked && udp_blocked);

    // Host files and credentials are absent.
    let canary_file_gone = arg(&args, "--canary-file")
        .map(|p| fs::File::open(&p).is_err())
        .unwrap_or(false);
    let sensitive_absent = [
        "/root",
        "/home",
        "/etc/shadow",
        "/var/run/secrets",
        "/run/secrets",
    ]
    .iter()
    .all(|p| fs::metadata(p).is_err());
    report("host_files_absent", canary_file_gone && sensitive_absent);

    // Environment holds only allowlisted names; canary names are gone.
    let canaries = arg(&args, "--canary-env").unwrap_or_default();
    let canary_gone = canaries
        .split(',')
        .filter(|n| !n.is_empty())
        .all(|n| std::env::var_os(n).is_none());
    let only_allowlisted = std::env::vars_os().all(|(k, _)| {
        k.to_str()
            .is_some_and(custodian_worker::sandbox::env_name_allowed)
    });
    report("env_scrubbed", canary_gone && only_allowlisted);

    // Writes outside scratch fail; scratch works.
    let outside_denied = [
        "/probe-write",
        "/usr/probe-write",
        "/input/probe-write",
        "/stage/probe-write",
    ]
    .iter()
    .all(|p| fs::File::create(p).is_err());
    report("write_outside_scratch_denied", outside_denied);
    let scratch_ok = fs::File::create("/scratch/probe-ok")
        .and_then(|mut f| f.write_all(&[0u8; 4096]))
        .is_ok();
    report("scratch_writable", scratch_ok);

    // PID namespace: only a handful of processes are visible.
    let visible = fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .bytes()
                        .all(|b| b.is_ascii_digit())
                })
                .count()
        })
        .unwrap_or(usize::MAX);
    report("pid_namespace", visible <= 8);

    // No capabilities.
    let caps_empty = fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .find(|l| l.starts_with("CapEff:"))
                .is_some_and(|l| {
                    l.trim_start_matches("CapEff:")
                        .trim()
                        .bytes()
                        .all(|b| b == b'0')
                })
        })
        .unwrap_or(false);
    report("no_capabilities", caps_empty);

    // rlimits in force.
    let want = |name: &str| arg(&args, name);
    let limits_ok = limit_soft("Max processes").as_deref() == want("--nproc").as_deref()
        && limit_soft("Max address space").as_deref() == want("--as").as_deref()
        && limit_soft("Max cpu time").as_deref() == want("--cpu").as_deref()
        && limit_soft("Max core file size").as_deref() == Some("0");
    report("rlimits_applied", limits_ok);
}
