//! Trusted runner entrypoint for the AWS MicroVM image (issue #42, issue #54).
//!
//! On startup this binary runs the real isolation self-check -- the exact
//! `BubblewrapSandbox`/`run_self_check` mechanism this repository's CI
//! already proves on both x86_64 and ARM64 hosts (`worker-isolation`,
//! `worker-isolation-arm64`) -- using the pinned `custodian-worker-probe`
//! binary shipped in the same image. It serves a fixed health route
//! reporting the result and refuses to report `verified: true` unless every
//! required check actually passed.
//!
//! There is no fallback mode. If the sandbox cannot be detected or the
//! self-check fails for any reason, this binary reports `verified: false`
//! and never accepts a job -- there is no code path here, or anywhere in
//! `Dispatcher`/`build_worker`, that runs a candidate without a sandbox that
//! passed this exact check.
//!
//! This binary does NOT implement remote job delivery or the control-plane
//! adapter (issue #42's "remote job delivery" and issue #46's distributed
//! store/signer/export migration remain separate, unimplemented work). It is
//! the trusted runner and sandbox packaging step only: proving the real
//! self-check actually runs inside the deployed image, refusing cleanly if
//! it cannot.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use custodian_worker::artifacts::ArtifactAllowlist;
use custodian_worker::bwrap::BubblewrapSandbox;
use custodian_worker::isolation::IsolationVerification;
use custodian_worker::run_self_check;

/// Runs once at startup, not per-request: the self-check launches a real
/// sandboxed child, which this binary does once and caches, exactly like
/// `Dispatcher::new` requires a precomputed `IsolationVerification` rather
/// than re-probing on every dispatch.
fn verify() -> Result<IsolationVerification, String> {
    let sandbox = BubblewrapSandbox::detect().map_err(|e| format!("sandbox_unavailable: {e}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "current_exe has no parent directory".to_owned())?
        .to_path_buf();
    let probe = dir.join("custodian-worker-probe");
    let allowlist =
        ArtifactAllowlist::new(&[dir.clone()]).map_err(|e| format!("allowlist: {e}"))?;
    let work_base: PathBuf = std::env::var("CUSTODIAN_RUNNER_WORK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("custodian-runner-selfcheck"));
    std::fs::create_dir_all(&work_base).map_err(|e| format!("work_base: {e}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    run_self_check(
        &sandbox,
        &sandbox.launcher_version(),
        &probe,
        &allowlist,
        &work_base,
        now,
    )
    .map_err(|e| format!("self_check_failed: {e}"))
}

fn health_body(result: &Result<IsolationVerification, String>) -> String {
    match result {
        Ok(v) if v.all_passed() => format!(
            "{{\"synthetic\":true,\"verified\":true,\"sandbox\":\"{}\",\"platform\":\"{}\",\"launcher\":{:?}}}",
            v.sandbox.code(),
            v.platform,
            v.launcher,
        ),
        Ok(v) => format!(
            "{{\"synthetic\":true,\"verified\":false,\"reason\":\"self_check_incomplete\",\"sandbox\":\"{}\"}}",
            v.sandbox.code()
        ),
        Err(reason) => format!(
            "{{\"synthetic\":true,\"verified\":false,\"reason\":{reason:?}}}"
        ),
    }
}

fn response(line: &[u8], body: &str) -> Vec<u8> {
    match line {
        b"GET /health HTTP/1.1" => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .into_bytes(),
        b"POST /aws/lambda-microvms/runtime/v1/ready HTTP/1.1"
        | b"POST /aws/lambda-microvms/runtime/v1/validate HTTP/1.1" => {
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        }
        _ => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    }
}

fn main() {
    // Run once at startup; a failure here means this process serves
    // `verified: false` for its whole lifetime rather than retrying into an
    // unsandboxed fallback -- there is none.
    let result = verify();
    match &result {
        Ok(v) if v.all_passed() => {
            eprintln!(
                "RUNNER-SELF-CHECK-VERIFIED sandbox={} platform={} launcher={:?}",
                v.sandbox.code(),
                v.platform,
                v.launcher
            );
        }
        Ok(v) => eprintln!(
            "RUNNER-SELF-CHECK-INCOMPLETE sandbox={} checks={}",
            v.sandbox.code(),
            v.checks.len()
        ),
        Err(reason) => eprintln!("RUNNER-SELF-CHECK-FAILED {reason}"),
    }
    let body = health_body(&result);

    let Ok(listener) = TcpListener::bind("0.0.0.0:8080") else {
        std::process::exit(1);
    };
    for mut stream in listener.incoming().flatten() {
        if stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .is_err()
            || stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .is_err()
        {
            continue;
        }
        let mut bytes = [0u8; 8192];
        let mut used = 0;
        let deadline = Instant::now() + Duration::from_secs(3);
        while used < bytes.len() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
                break;
            }
            match stream.read(&mut bytes[used..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    used += n;
                    if bytes[..used].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let line = bytes[..used].split(|b| *b == b'\n').next().unwrap_or(&[]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let complete = bytes[..used].windows(4).any(|w| w == b"\r\n\r\n");
        let _ = stream.write_all(&response(if complete { line } else { b"" }, &body));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_body_never_reports_verified_true_on_error() {
        let body = health_body(&Err("sandbox_unavailable: no bwrap".to_owned()));
        assert!(body.contains("\"verified\":false"));
        assert!(!body.contains("\"verified\":true"));
    }

    #[test]
    fn jobs_and_attacker_controlled_routes_never_echo_or_execute() {
        let body = "{\"synthetic\":true,\"verified\":false,\"reason\":\"test\"}";
        assert!(response(b"GET /health HTTP/1.1", body).starts_with(b"HTTP/1.1 200"));
        for line in [
            b"POST /job HTTP/1.1".as_slice(),
            b"GET /health?SYNTHETIC-CANARY HTTP/1.1",
            b"POST /aws/lambda-microvms/runtime/v1/run HTTP/1.1",
        ] {
            let r = response(line, body);
            assert!(r.starts_with(b"HTTP/1.1 403"));
            assert!(!r.windows(6).any(|w| w == b"CANARY"));
        }
    }
}
