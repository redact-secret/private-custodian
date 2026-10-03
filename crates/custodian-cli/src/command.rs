//! The command set and its argument grammar.
//!
//! `custodian [global flags] <group> <command> [flags]`. Global flags:
//! `--config FILE`, `--identity ACTOR`, `--token-file FILE`, `--dry-run`.
//! Every flag takes exactly one value except `--dry-run`. Unknown or repeated
//! flags are usage errors. Documents are read by the caller and passed as
//! bytes, so this module does no I/O and the library never echoes a path.
//!
//! Groups, in the order the runbook uses them:
//!
//! * `request`   normal evaluation: `submit`, `status`, `list`, `approve`, `cancel`
//! * `verify`    read-only: `ledger`, `store`, `registry`, `checkpoint`, `all`
//! * `reconcile` read-only diagnosis: `store`, `ledger`, `feed`
//! * `lifecycle` restricted: `report`, `clear`, `retire`, `rotate`
//! * `feed`      restricted: `record-revocation`, `publish`
//! * `policy`    `validate` (read-only), `import-activation` (restricted)
//! * `repair`    operational repair, separate from evaluation, every command
//!   needs exact-object confirmation flags: `recover`, `registry-sweep`,
//!   `export`, `ledger-reconcile`, `feed-deliver`, `clear-reconcile`

use std::collections::BTreeMap;

use custodian_contracts::types::{CandidateDigest, EpochId, IdempotencyKey, PlanDigest, RequestId};

use crate::reason::CliReason;

/// Largest document the CLI reads.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyTarget {
    Ledger,
    Store,
    Registry,
    Checkpoint,
    All,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileTarget {
    Store,
    Ledger,
    Feed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contaminated {
    UnreviewedChange,
    Exposed,
    UsedForTuning,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationKind {
    Candidate(CandidateDigest),
    Projection(String),
    Receipt(String),
    Policy(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationVerb {
    Revoked,
    Contaminated,
    Superseded(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepairCommand {
    Recover {
        confirm_store_id: String,
    },
    RegistrySweep {
        confirm_store_id: String,
    },
    Export {
        confirm_store_id: String,
    },
    LedgerReconcile {
        confirm_store_id: String,
    },
    FeedDeliver {
        confirm_feed_id: String,
    },
    ClearReconcile {
        confirm_store_id: String,
        /// The newest outbox sequence the operator reviewed against the ledger.
        confirm_checkpoint_seq: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    RequestSubmit {
        document: Vec<u8>,
    },
    RequestStatus {
        request_id: RequestId,
    },
    RequestList {
        limit: u32,
    },
    RequestApprove {
        request_id: RequestId,
        confirm_plan_digest: PlanDigest,
        ttl_secs: Option<u64>,
    },
    RequestCancel {
        request_id: RequestId,
    },
    Verify(VerifyTarget),
    Reconcile(ReconcileTarget),
    LifecycleReport {
        epoch: EpochId,
        kind: Contaminated,
        reason: String,
        key: IdempotencyKey,
    },
    LifecycleClear {
        epoch: EpochId,
        confirm_epoch: EpochId,
        key: IdempotencyKey,
    },
    LifecycleRetire {
        epoch: EpochId,
        confirm_epoch: EpochId,
        reason: String,
        key: IdempotencyKey,
    },
    LifecycleRotate {
        predecessor: EpochId,
        successor: EpochId,
        confirm_predecessor: EpochId,
        confirm_successor: EpochId,
        run_budget_limit: u64,
        reason: String,
        key: IdempotencyKey,
    },
    FeedRecordRevocation {
        id: String,
        what: RevocationKind,
        verb: RevocationVerb,
        reason: String,
    },
    FeedPublish,
    PolicyValidate {
        document: Vec<u8>,
    },
    PolicyImportActivation {
        document: Vec<u8>,
        confirm_activation_id: String,
        confirm_sequence: u64,
    },
    Repair(RepairCommand),
}

impl Command {
    /// Stable name used in output and in the runbook.
    pub fn name(&self) -> &'static str {
        match self {
            Self::RequestSubmit { .. } => "request.submit",
            Self::RequestStatus { .. } => "request.status",
            Self::RequestList { .. } => "request.list",
            Self::RequestApprove { .. } => "request.approve",
            Self::RequestCancel { .. } => "request.cancel",
            Self::Verify(_) => "verify",
            Self::Reconcile(_) => "reconcile",
            Self::LifecycleReport { .. } => "lifecycle.report",
            Self::LifecycleClear { .. } => "lifecycle.clear",
            Self::LifecycleRetire { .. } => "lifecycle.retire",
            Self::LifecycleRotate { .. } => "lifecycle.rotate",
            Self::FeedRecordRevocation { .. } => "feed.record-revocation",
            Self::FeedPublish => "feed.publish",
            Self::PolicyValidate { .. } => "policy.validate",
            Self::PolicyImportActivation { .. } => "policy.import-activation",
            Self::Repair(RepairCommand::Recover { .. }) => "repair.recover",
            Self::Repair(RepairCommand::RegistrySweep { .. }) => "repair.registry-sweep",
            Self::Repair(RepairCommand::Export { .. }) => "repair.export",
            Self::Repair(RepairCommand::LedgerReconcile { .. }) => "repair.ledger-reconcile",
            Self::Repair(RepairCommand::FeedDeliver { .. }) => "repair.feed-deliver",
            Self::Repair(RepairCommand::ClearReconcile { .. }) => "repair.clear-reconcile",
        }
    }
}

/// Flags every invocation may carry.
pub const GLOBAL_FLAGS: [&str; 3] = ["config", "identity", "token-file"];

#[derive(Debug, Default)]
pub struct Parsed {
    pub group: String,
    pub command: String,
    pub flags: BTreeMap<String, String>,
    pub dry_run: bool,
}

impl Parsed {
    pub fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }
}

/// Split `argv` (without the program name) into positionals and flags.
pub fn parse_args(argv: &[String]) -> Result<Parsed, CliReason> {
    let mut out = Parsed::default();
    let mut positionals: Vec<&str> = Vec::new();
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if let Some(name) = a.strip_prefix("--") {
            if name == "dry-run" {
                if out.dry_run {
                    return Err(CliReason::UsageError);
                }
                out.dry_run = true;
                continue;
            }
            if name.is_empty() || name.contains('=') {
                return Err(CliReason::UsageError);
            }
            let value = it.next().ok_or(CliReason::UsageError)?;
            if value.starts_with("--") {
                return Err(CliReason::UsageError);
            }
            if out.flags.insert(name.to_owned(), value.clone()).is_some() {
                return Err(CliReason::UsageError);
            }
        } else {
            positionals.push(a);
        }
    }
    match positionals.as_slice() {
        [g, c] => {
            out.group = (*g).to_owned();
            out.command = (*c).to_owned();
            Ok(out)
        }
        _ => Err(CliReason::UsageError),
    }
}

fn require<'a>(p: &'a Parsed, name: &str) -> Result<&'a str, CliReason> {
    p.flag(name).ok_or(CliReason::UsageError)
}

fn confirm<'a>(p: &'a Parsed, name: &str) -> Result<&'a str, CliReason> {
    p.flag(name).ok_or(CliReason::ConfirmationMissing)
}

fn only(p: &Parsed, allowed: &[&str]) -> Result<(), CliReason> {
    for k in p.flags.keys() {
        if !allowed.contains(&k.as_str()) && !GLOBAL_FLAGS.contains(&k.as_str()) {
            return Err(CliReason::UsageError);
        }
    }
    Ok(())
}

fn req_id(p: &Parsed) -> Result<RequestId, CliReason> {
    RequestId::parse(require(p, "request-id")?).map_err(|_| CliReason::UsageError)
}

fn epoch(p: &Parsed, name: &str) -> Result<EpochId, CliReason> {
    EpochId::parse(require(p, name)?).map_err(|_| CliReason::UsageError)
}

fn confirm_epoch(p: &Parsed, name: &str) -> Result<EpochId, CliReason> {
    EpochId::parse(confirm(p, name)?).map_err(|_| CliReason::UsageError)
}

fn key(p: &Parsed) -> Result<IdempotencyKey, CliReason> {
    IdempotencyKey::parse(require(p, "idempotency-key")?).map_err(|_| CliReason::UsageError)
}

fn word(p: &Parsed, name: &str) -> Result<String, CliReason> {
    let v = require(p, name)?;
    if v.is_empty() || v.len() > 64 || !v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        return Err(CliReason::UsageError);
    }
    Ok(v.to_owned())
}

fn number(p: &Parsed, name: &str) -> Result<u64, CliReason> {
    require(p, name)?
        .parse::<u64>()
        .map_err(|_| CliReason::UsageError)
}

/// Build a [`Command`]. `read` loads a document named by a flag (the caller
/// enforces the size cap and maps I/O failure to `InvalidDocument`).
pub fn build_command(
    p: &Parsed,
    read: &dyn Fn(&str) -> Result<Vec<u8>, CliReason>,
) -> Result<Command, CliReason> {
    let doc = |p: &Parsed| -> Result<Vec<u8>, CliReason> {
        let bytes = read(require(p, "document")?)?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(CliReason::DocumentTooLarge);
        }
        Ok(bytes)
    };
    match (p.group.as_str(), p.command.as_str()) {
        ("request", "submit") => {
            only(p, &["document"])?;
            Ok(Command::RequestSubmit { document: doc(p)? })
        }
        ("request", "status") => {
            only(p, &["request-id"])?;
            Ok(Command::RequestStatus {
                request_id: req_id(p)?,
            })
        }
        ("request", "list") => {
            only(p, &["limit"])?;
            let limit = match p.flag("limit") {
                None => 50,
                Some(v) => v.parse::<u32>().map_err(|_| CliReason::UsageError)?,
            };
            Ok(Command::RequestList { limit })
        }
        ("request", "approve") => {
            only(p, &["request-id", "confirm-plan-digest", "ttl-secs"])?;
            let ttl_secs = match p.flag("ttl-secs") {
                None => None,
                Some(v) => Some(v.parse::<u64>().map_err(|_| CliReason::UsageError)?),
            };
            Ok(Command::RequestApprove {
                request_id: req_id(p)?,
                confirm_plan_digest: PlanDigest::parse(confirm(p, "confirm-plan-digest")?)
                    .map_err(|_| CliReason::UsageError)?,
                ttl_secs,
            })
        }
        ("request", "cancel") => {
            only(p, &["request-id"])?;
            Ok(Command::RequestCancel {
                request_id: req_id(p)?,
            })
        }
        ("verify", t) => {
            only(p, &[])?;
            Ok(Command::Verify(match t {
                "ledger" => VerifyTarget::Ledger,
                "store" => VerifyTarget::Store,
                "registry" => VerifyTarget::Registry,
                "checkpoint" => VerifyTarget::Checkpoint,
                "all" => VerifyTarget::All,
                _ => return Err(CliReason::UsageError),
            }))
        }
        ("reconcile", t) => {
            only(p, &[])?;
            Ok(Command::Reconcile(match t {
                "store" => ReconcileTarget::Store,
                "ledger" => ReconcileTarget::Ledger,
                "feed" => ReconcileTarget::Feed,
                _ => return Err(CliReason::UsageError),
            }))
        }
        ("lifecycle", "report") => {
            only(p, &["epoch", "kind", "reason", "idempotency-key"])?;
            let kind = match require(p, "kind")? {
                "unreviewed_change" => Contaminated::UnreviewedChange,
                "exposed" => Contaminated::Exposed,
                "used_for_tuning" => Contaminated::UsedForTuning,
                _ => return Err(CliReason::UsageError),
            };
            Ok(Command::LifecycleReport {
                epoch: epoch(p, "epoch")?,
                kind,
                reason: word(p, "reason")?,
                key: key(p)?,
            })
        }
        ("lifecycle", "clear") => {
            only(p, &["epoch", "confirm-epoch", "idempotency-key"])?;
            Ok(Command::LifecycleClear {
                epoch: epoch(p, "epoch")?,
                confirm_epoch: confirm_epoch(p, "confirm-epoch")?,
                key: key(p)?,
            })
        }
        ("lifecycle", "retire") => {
            only(p, &["epoch", "confirm-epoch", "reason", "idempotency-key"])?;
            Ok(Command::LifecycleRetire {
                epoch: epoch(p, "epoch")?,
                confirm_epoch: confirm_epoch(p, "confirm-epoch")?,
                reason: word(p, "reason")?,
                key: key(p)?,
            })
        }
        ("lifecycle", "rotate") => {
            only(
                p,
                &[
                    "predecessor",
                    "successor",
                    "confirm-predecessor",
                    "confirm-successor",
                    "run-budget-limit",
                    "reason",
                    "idempotency-key",
                ],
            )?;
            Ok(Command::LifecycleRotate {
                predecessor: epoch(p, "predecessor")?,
                successor: epoch(p, "successor")?,
                confirm_predecessor: confirm_epoch(p, "confirm-predecessor")?,
                confirm_successor: confirm_epoch(p, "confirm-successor")?,
                run_budget_limit: number(p, "run-budget-limit")?,
                reason: word(p, "reason")?,
                key: key(p)?,
            })
        }
        ("feed", "record-revocation") => {
            only(
                p,
                &["id", "kind", "target", "action", "superseded-by", "reason"],
            )?;
            let target = require(p, "target")?.to_owned();
            let what = match require(p, "kind")? {
                "candidate" => RevocationKind::Candidate(
                    CandidateDigest::parse(&target).map_err(|_| CliReason::UsageError)?,
                ),
                "projection" => RevocationKind::Projection(target),
                "receipt" => RevocationKind::Receipt(target),
                "policy" => RevocationKind::Policy(target),
                _ => return Err(CliReason::UsageError),
            };
            let verb = match require(p, "action")? {
                "revoked" => RevocationVerb::Revoked,
                "contaminated" => RevocationVerb::Contaminated,
                "superseded" => RevocationVerb::Superseded(require(p, "superseded-by")?.to_owned()),
                _ => return Err(CliReason::UsageError),
            };
            if p.flag("superseded-by").is_some() && !matches!(verb, RevocationVerb::Superseded(_)) {
                return Err(CliReason::UsageError);
            }
            let id = require(p, "id")?.to_owned();
            if id.is_empty()
                || id.len() > 64
                || !id.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_')
                })
            {
                return Err(CliReason::UsageError);
            }
            Ok(Command::FeedRecordRevocation {
                id,
                what,
                verb,
                reason: word(p, "reason")?,
            })
        }
        ("feed", "publish") => {
            only(p, &[])?;
            Ok(Command::FeedPublish)
        }
        ("policy", "validate") => {
            only(p, &["document"])?;
            Ok(Command::PolicyValidate { document: doc(p)? })
        }
        ("policy", "import-activation") => {
            only(
                p,
                &["document", "confirm-activation-id", "confirm-sequence"],
            )?;
            Ok(Command::PolicyImportActivation {
                document: doc(p)?,
                confirm_activation_id: confirm(p, "confirm-activation-id")?.to_owned(),
                confirm_sequence: confirm(p, "confirm-sequence")?
                    .parse::<u64>()
                    .map_err(|_| CliReason::UsageError)?,
            })
        }
        ("repair", c) => {
            let store_id = |p: &Parsed| confirm(p, "confirm-store-id").map(str::to_owned);
            match c {
                "recover" => {
                    only(p, &["confirm-store-id"])?;
                    Ok(Command::Repair(RepairCommand::Recover {
                        confirm_store_id: store_id(p)?,
                    }))
                }
                "registry-sweep" => {
                    only(p, &["confirm-store-id"])?;
                    Ok(Command::Repair(RepairCommand::RegistrySweep {
                        confirm_store_id: store_id(p)?,
                    }))
                }
                "export" => {
                    only(p, &["confirm-store-id"])?;
                    Ok(Command::Repair(RepairCommand::Export {
                        confirm_store_id: store_id(p)?,
                    }))
                }
                "ledger-reconcile" => {
                    only(p, &["confirm-store-id"])?;
                    Ok(Command::Repair(RepairCommand::LedgerReconcile {
                        confirm_store_id: store_id(p)?,
                    }))
                }
                "feed-deliver" => {
                    only(p, &["confirm-feed-id"])?;
                    Ok(Command::Repair(RepairCommand::FeedDeliver {
                        confirm_feed_id: confirm(p, "confirm-feed-id")?.to_owned(),
                    }))
                }
                "clear-reconcile" => {
                    only(p, &["confirm-store-id", "confirm-checkpoint-seq"])?;
                    Ok(Command::Repair(RepairCommand::ClearReconcile {
                        confirm_store_id: store_id(p)?,
                        confirm_checkpoint_seq: confirm(p, "confirm-checkpoint-seq")?
                            .parse::<u64>()
                            .map_err(|_| CliReason::UsageError)?,
                    }))
                }
                _ => Err(CliReason::UsageError),
            }
        }
        _ => Err(CliReason::UsageError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn no_files(_: &str) -> Result<Vec<u8>, CliReason> {
        Ok(b"{}".to_vec())
    }

    #[test]
    fn grammar_rejects_malformed_invocations() {
        for bad in [
            "",
            "request",
            "request submit extra --document f",
            "request submit --document",
            "request submit --document --dry-run",
            "request submit --document=f",
            "request submit --document a --document b",
            "request submit --dry-run --dry-run --document f",
            "request nosuch",
            "nosuch submit",
        ] {
            let r = parse_args(&args(bad)).and_then(|p| build_command(&p, &no_files));
            assert_eq!(r.err(), Some(CliReason::UsageError), "{bad}");
        }
    }

    #[test]
    fn unknown_flags_are_usage_errors() {
        let p = parse_args(&args("request status --request-id req_x --surprise 1")).unwrap();
        assert_eq!(
            build_command(&p, &no_files).err(),
            Some(CliReason::UsageError)
        );
    }

    #[test]
    fn repair_commands_need_their_confirmation_flags() {
        for c in [
            "repair recover",
            "repair registry-sweep",
            "repair export",
            "repair ledger-reconcile",
            "repair feed-deliver",
            "repair clear-reconcile --confirm-store-id abc",
        ] {
            let p = parse_args(&args(c)).unwrap();
            assert_eq!(
                build_command(&p, &no_files).err(),
                Some(CliReason::ConfirmationMissing),
                "{c}"
            );
        }
    }

    #[test]
    fn approve_needs_the_exact_plan_digest() {
        let p = parse_args(&args(
            "request approve --request-id req_synthetic000000000001",
        ))
        .unwrap();
        assert_eq!(
            build_command(&p, &no_files).err(),
            Some(CliReason::ConfirmationMissing)
        );
    }

    #[test]
    fn dry_run_and_globals_parse() {
        let p = parse_args(&args(
            "--config c --identity act_x --dry-run request status --request-id req_synthetic000000000001",
        ))
        .unwrap();
        assert!(p.dry_run);
        assert_eq!(p.flag("config"), Some("c"));
        assert!(build_command(&p, &no_files).is_ok());
    }
}
