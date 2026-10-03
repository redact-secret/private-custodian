//! Dry-run a reviewed legacy metadata extract and print the report.
//!
//! Usage: `cargo run -p custodian-bridge --example legacy_import -- <extract.json>`
//!
//! It reads exactly one file, the extract you name, and nothing else: no
//! corpus, no seed, no private root, no ledger, no store. It writes nothing
//! and executes no cutover. Exit status 0 means a report was produced (read
//! its gate line), 2 means the extract itself was refused.

use std::process::ExitCode;

use custodian_bridge::legacy::dry_run;

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: legacy_import <extract.json>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("extract_unreadable");
        return ExitCode::from(2);
    };
    match dry_run(&bytes) {
        Ok(run) => {
            print!("{}", run.report.render());
            println!("report_digest {}", run.report.digest().as_str());
            ExitCode::SUCCESS
        }
        Err(refusal) => {
            eprintln!("{}", refusal.code());
            ExitCode::from(2)
        }
    }
}
