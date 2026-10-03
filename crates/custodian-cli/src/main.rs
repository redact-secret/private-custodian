//! `custodian`: the operator command-line interface.
//!
//! Prints exactly one JSON object on standard output and exits with a stable
//! code (see `custodian_cli::reason::ExitClass` and docs/operator-runbook.md).
//! It reads a credential only from a file or a file named by the environment,
//! never from an argument, and it never prints a path, a credential or a
//! free-form message.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::Path;

use custodian_cli::command::{build_command, parse_args, MAX_DOCUMENT_BYTES};
use custodian_cli::deploy::Deployment;
use custodian_cli::output::Output;
use custodian_cli::{credential_digest, CliReason, Control};

fn finish(o: &Output) -> std::process::ExitCode {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", o.render());
    std::process::ExitCode::from(o.exit_code())
}

fn read_file(path: &str, max: usize) -> Result<Vec<u8>, CliReason> {
    let p = Path::new(path);
    let meta = std::fs::metadata(p).map_err(|_| CliReason::InvalidDocument)?;
    if !meta.is_file() {
        return Err(CliReason::InvalidDocument);
    }
    if meta.len() > max as u64 {
        return Err(CliReason::DocumentTooLarge);
    }
    std::fs::read(p).map_err(|_| CliReason::InvalidDocument)
}

/// The credential: file contents without one trailing newline.
fn read_credential(path: &str) -> Result<Vec<u8>, CliReason> {
    // A credential file must be a regular file with no group or other access.
    let mut bytes = custodian_cli::deploy::read_checked(Path::new(path), 4096, 0o077)
        .map_err(|_| CliReason::Unauthenticated)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(bytes)
}

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // `custodian credential-digest --token-file F`: prints the digest to put
    // in the operator policy. Needs no deployment and no authentication.
    if argv.first().map(String::as_str) == Some("credential-digest") {
        let r = (|| {
            if argv.len() != 3 || argv[1] != "--token-file" {
                return Err(CliReason::UsageError);
            }
            let token = read_credential(&argv[2])?;
            if token.len() < custodian_cli::MIN_CREDENTIAL_BYTES {
                return Err(CliReason::UsageError);
            }
            Ok(credential_digest(&token))
        })();
        return finish(&match r {
            Ok(d) => Output::ok("credential-digest", "digest").id("credential_sha256", &d),
            Err(e) => Output::refused("credential-digest", e),
        });
    }

    let parsed = match parse_args(&argv) {
        Ok(p) => p,
        Err(e) => return finish(&Output::refused("usage", e)),
    };
    let read_doc = |p: &str| read_file(p, MAX_DOCUMENT_BYTES);
    let cmd = match build_command(&parsed, &read_doc) {
        Ok(c) => c,
        Err(e) => return finish(&Output::refused("usage", e)),
    };
    let name = cmd.name();
    let fail = |e: CliReason| finish(&Output::refused(name, e).dry(parsed.dry_run));

    let config_path = match parsed.flag("config") {
        Some(p) => p.to_owned(),
        None => match std::env::var("CUSTODIAN_CONFIG") {
            Ok(p) => p,
            Err(_) => return fail(CliReason::NotConfigured),
        },
    };
    let config = match read_file(&config_path, 16 * 1024) {
        Ok(c) => c,
        Err(_) => return fail(CliReason::NotConfigured),
    };
    let deployment = match Deployment::open(&config) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let identity = parsed
        .flag("identity")
        .map(str::to_owned)
        .or_else(|| std::env::var("CUSTODIAN_IDENTITY").ok());
    let token_path = parsed
        .flag("token-file")
        .map(str::to_owned)
        .or_else(|| std::env::var("CUSTODIAN_TOKEN_FILE").ok());
    let (Some(identity), Some(token_path)) = (identity, token_path) else {
        return fail(CliReason::Unauthenticated);
    };
    let token = match read_credential(&token_path) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let names = deployment.names();
    let parts = deployment.parts(&names);
    let now = match custodian_contracts::types::Timestamp::new(parts.clock.now()) {
        Ok(t) => t,
        Err(_) => return fail(CliReason::Internal),
    };
    let principal = match deployment.authority.authenticate(&identity, &token, now) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let control = Control::new(parts);
    finish(&control.execute(&principal, &cmd, parsed.dry_run))
}
