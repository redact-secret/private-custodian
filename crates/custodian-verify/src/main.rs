//! `custodian-verify --bundle DIR --keys FILE --feed-id ID --expect FILE --now SECS`
//!
//! Prints exactly one JSON object on standard output and exits with the code
//! in `custodian_verify::report`. It reads only the files named, never prints
//! a path or file content, and has no network, ledger, corpus or key access.
//! The result is functional verification of public synthetic or released
//! data, not an independent protected evaluation.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use custodian_verify::{verify, Bundle, Expectations, InputError, Pins, Report};

struct Args {
    bundle: PathBuf,
    keys: PathBuf,
    feed_id: String,
    expect: PathBuf,
    now: u64,
}

const USAGE: &str = "usage: custodian-verify --bundle DIR --keys FILE --feed-id ID --expect FILE --now UNIX_SECONDS\n";

fn parse_args(argv: &[String]) -> Result<Args, InputError> {
    let (mut bundle, mut keys, mut feed_id, mut expect, mut now) = (None, None, None, None, None);
    let mut it = argv.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--bundle" => &mut bundle,
            "--keys" => &mut keys,
            "--feed-id" => &mut feed_id,
            "--expect" => &mut expect,
            "--now" => &mut now,
            _ => return Err(InputError::Usage),
        };
        let value = it.next().ok_or(InputError::Usage)?;
        if slot.replace(value.clone()).is_some() {
            return Err(InputError::Usage);
        }
    }
    let (Some(bundle), Some(keys), Some(feed_id), Some(expect), Some(now)) =
        (bundle, keys, feed_id, expect, now)
    else {
        return Err(InputError::Usage);
    };
    Ok(Args {
        bundle: bundle.into(),
        keys: keys.into(),
        feed_id,
        expect: expect.into(),
        now: now.parse().map_err(|_| InputError::Usage)?,
    })
}

fn run(args: &Args) -> Report {
    let loaded = (|| {
        let pins = Pins::load(&args.keys, &args.feed_id)?;
        let expect = Expectations::load(&args.expect)?;
        let bundle = Bundle::load(&args.bundle)?;
        Ok::<_, InputError>((pins, expect, bundle))
    })();
    match loaded {
        Ok((pins, expect, bundle)) => verify(&pins, &expect, &bundle, args.now),
        Err(e) => Report::input_error(e, Some(args.now)),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.len() == 1 && (argv[0] == "--help" || argv[0] == "-h") {
        let _ = std::io::stdout().write_all(USAGE.as_bytes());
        return ExitCode::SUCCESS;
    }
    let report = match parse_args(&argv) {
        Ok(args) => run(&args),
        Err(e) => Report::input_error(e, None),
    };
    let _ = writeln!(std::io::stdout().lock(), "{}", report.render());
    ExitCode::from(report.class().code())
}
