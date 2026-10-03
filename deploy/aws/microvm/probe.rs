//! Public synthetic diagnostic image. No worker jobs or attestations.
#![forbid(unsafe_code)]
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{Duration, Instant};

const STATE: &str = "/tmp/custodian-public-probe-runner-state";
const CANARY: &[u8] = b"PUBLIC-SYNTHETIC-RUNNER-CANARY";

fn child() -> String {
    // These are deliberately NOT isolated from the runner. The denial control
    // must fail if VM separation alone is incorrectly claimed as an inner sandbox.
    let readable = fs::read(STATE).is_ok_and(|bytes| bytes == CANARY);
    let credential_env = [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some());
    let addresses: Vec<_> = ("example.com", 443)
        .to_socket_addrs()
        .map(|iter| iter.collect())
        .unwrap_or_default();
    let ipv4 = addresses
        .iter()
        .filter(|address| address.is_ipv4())
        .take(2)
        .any(|address| TcpStream::connect_timeout(address, Duration::from_secs(1)).is_ok());
    let ipv6 = addresses
        .iter()
        .filter(|address| address.is_ipv6())
        .take(2)
        .any(|address| TcpStream::connect_timeout(address, Duration::from_secs(1)).is_ok());
    let link_local = TcpStream::connect_timeout(
        &"169.254.169.254:80".parse().expect("constant address"),
        Duration::from_secs(1),
    )
    .is_ok();
    let true_tool = Command::new("/usr/bin/true")
        .env_clear()
        .output()
        .is_ok_and(|result| result.status.success());
    let unshare_tool = std::path::Path::new("/usr/bin/unshare").is_file();
    let user_namespace = Command::new("/usr/bin/unshare")
        .args(["-Ur", "/usr/bin/true"])
        .env_clear()
        .output()
        .is_ok_and(|result| result.status.success());
    format!(
        concat!(
            "{{\"controlStateReadable\":{},\"credentialEnvironmentPresent\":{},",
            "\"dnsResolved\":{},\"ipv4Connected\":{},\"ipv6Connected\":{},",
            "\"linkLocalTcpConnected\":{},\"trueToolWorks\":{},",
            "\"unshareToolPresent\":{},\"userNamespaceWorks\":{}}}"
        ),
        readable,
        credential_env,
        !addresses.is_empty(),
        ipv4,
        ipv6,
        link_local,
        true_tool,
        unshare_tool,
        user_namespace
    )
}

fn diagnostic() -> String {
    let runner_control = fs::read(STATE).is_ok_and(|bytes| bytes == CANARY);
    let result = Command::new("/usr/bin/timeout")
        .args(["8", "/app/probe", "--child"])
        .env_clear()
        .output();
    match result {
        Ok(output) if output.status.success() && output.stdout.len() <= 4096 => {
            // Only the immutable, fixed child emits this JSON; request bytes
            // and process stderr are never returned, parsed or logged.
            let bytes = String::from_utf8(output.stdout).unwrap_or_default();
            format!("{{\"synthetic\":true,\"verified\":false,\"runnerControlWorks\":{runner_control},\"childCompleted\":true,\"child\":{bytes}}}")
        }
        _ => format!("{{\"synthetic\":true,\"verified\":false,\"runnerControlWorks\":{runner_control},\"childCompleted\":false}}"),
    }
}

fn route(line: &[u8]) -> u16 {
    match line {
        b"GET /health HTTP/1.1"
        | b"GET /probe HTTP/1.1"
        | b"POST /aws/lambda-microvms/runtime/v1/ready HTTP/1.1"
        | b"POST /aws/lambda-microvms/runtime/v1/validate HTTP/1.1" => 200,
        _ => 403,
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        print!("{}", child());
        return;
    }
    if fs::write(STATE, CANARY).is_err()
        || fs::set_permissions(STATE, fs::Permissions::from_mode(0o600)).is_err()
    {
        std::process::exit(1);
    }
    let Ok(listener) = TcpListener::bind("0.0.0.0:8080") else {
        std::process::exit(1);
    };
    for mut stream in listener.incoming().flatten() {
        if stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .is_err()
        {
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut bytes = [0u8; 8192];
        let mut used = 0;
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
        let complete = bytes[..used].windows(4).any(|w| w == b"\r\n\r\n");
        let line = bytes[..used].split(|b| *b == b'\n').next().unwrap_or(&[]);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = if complete { line } else { b"" };
        let status = route(line);
        let body = if line == b"GET /probe HTTP/1.1" {
            diagnostic()
        } else if line == b"GET /health HTTP/1.1" {
            "{\"synthetic\":true,\"verified\":false}".to_owned()
        } else {
            String::new()
        };
        let header = format!("HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            if status == 200 { "OK" } else { "Forbidden" }, body.len());
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arbitrary_jobs_and_canary_routes_refuse_without_reflection() {
        for path in [
            b"POST /job HTTP/1.1".as_slice(),
            b"GET /probe?PUBLIC-SYNTHETIC-RUNNER-CANARY HTTP/1.1",
            CANARY,
        ] {
            assert_eq!(route(path), 403);
        }
        assert_eq!(route(b"GET /probe HTTP/1.1"), 200);
    }
}
