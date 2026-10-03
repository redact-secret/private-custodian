//! `custodian-signer --config <path> [--print-public-key]`
//!
//! Hardens the process, loads the key through the file provider, then either
//! prints the PUBLIC key (for pinning in a verifier's roots) or serves the
//! socket until killed. Output is fixed codes only: no paths, no payloads, no
//! key material. Exit codes: 2 usage or configuration, 3 key, 4 server.

#![forbid(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::process::ExitCode;
use std::sync::Arc;

use custodian_signer::{
    harden_process, start, stderr_sink, FileKeyProvider, SignerConfig, SigningEngine, SystemClock,
};

fn fail(code: &str, exit: u8) -> ExitCode {
    eprintln!("custodian-signer: {code}");
    ExitCode::from(exit)
}

fn read_config(path: &std::path::Path) -> Option<Vec<u8>> {
    let m = std::fs::symlink_metadata(path).ok()?;
    if !m.file_type().is_file()
        || m.len() > custodian_signer::config::MAX_CONFIG_BYTES as u64
        || m.permissions().mode() & 0o022 != 0
    {
        return None;
    }
    std::fs::read(path).ok()
}

fn main() -> ExitCode {
    // Arguments first: hardening clears the environment, not argv.
    let mut args = std::env::args_os().skip(1);
    let mut config_path = None;
    let mut print_public = false;
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--config") => config_path = args.next(),
            Some("--print-public-key") => print_public = true,
            _ => return fail("usage", 2),
        }
    }
    let Some(config_path) = config_path else {
        return fail("usage", 2);
    };
    if harden_process().is_err() {
        return fail("hardening_failed", 2);
    }
    let Some(bytes) = read_config(std::path::Path::new(&config_path)) else {
        return fail("config_unreadable", 2);
    };
    let Ok(cfg) = SignerConfig::parse(&bytes) else {
        return fail("config_invalid", 2);
    };
    let provider = FileKeyProvider::new(cfg.key_path.clone());
    let engine = match SigningEngine::new(
        &provider,
        cfg.setup.clone(),
        Arc::new(SystemClock),
        stderr_sink(),
    ) {
        Ok(e) => Arc::new(e),
        Err(e) => return fail(e.code(), 3),
    };
    if print_public {
        println!("{}", engine.public_key_hex());
        return ExitCode::SUCCESS;
    }
    match start(cfg.server, engine) {
        Ok(server) => {
            server.wait();
            ExitCode::SUCCESS
        }
        Err(e) => fail(e.code(), 4),
    }
}
