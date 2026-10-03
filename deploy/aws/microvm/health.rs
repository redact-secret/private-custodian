//! Synthetic-only image/HTTPS lifecycle probe. It refuses every job and cannot
//! access a corpus, invoke an engine or attest that isolation was established.
#![forbid(unsafe_code)]
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

fn response(line: &[u8]) -> &'static [u8] {
    match line {
        b"GET /health HTTP/1.1" => b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 35\r\nConnection: close\r\n\r\n{\"synthetic\":true,\"verified\":false}",
        b"POST /aws/lambda-microvms/runtime/v1/ready HTTP/1.1"
        | b"POST /aws/lambda-microvms/runtime/v1/validate HTTP/1.1" => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        _ => b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    }
}

fn main() {
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
        let _ = stream.write_all(response(if complete { line } else { b"" }));
    }
}

#[cfg(test)]
mod tests {
    use super::response;
    #[test]
    fn jobs_and_attacker_controlled_routes_never_echo_or_execute() {
        assert!(response(b"GET /health HTTP/1.1").starts_with(b"HTTP/1.1 200"));
        for line in [
            b"POST /job HTTP/1.1".as_slice(),
            b"GET /health?SYNTHETIC-CANARY HTTP/1.1",
            b"POST /aws/lambda-microvms/runtime/v1/run HTTP/1.1",
        ] {
            assert!(response(line).starts_with(b"HTTP/1.1 403"));
            assert!(!response(line).windows(6).any(|w| w == b"CANARY"));
        }
    }
}
