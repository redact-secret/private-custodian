//! Offline artifact binding checks. No store, approval, signing or release.
use custodian_contracts::execution::ExecutionOutcome;
use custodian_contracts::execution::InternalReceipt;
use custodian_contracts::request::EvaluationRequest;
use custodian_contracts::Contract;
use custodian_disclosure::aggregate::PrivateAggregates;
use custodian_worker::result::validate_result;

use crate::{CliReason, Output};

/// Validate the embedded object against the exact receipt and frozen plan.
/// Success proves structural binding only, never authorization or freshness.
pub fn validate(request: &[u8], receipt: &[u8], result: &[u8]) -> Output {
    let check = || -> Result<(), CliReason> {
        let request = EvaluationRequest::decode(request).map_err(|_| CliReason::InvalidDocument)?;
        let receipt = InternalReceipt::decode(receipt).map_err(|_| CliReason::InvalidDocument)?;
        let plan = &request.plan;
        if receipt.plan_digest != plan.plan_digest().map_err(|_| CliReason::InvalidDocument)?
            || receipt.activation != plan.policy_activation
            || receipt.frozen != plan.frozen_identities()
        {
            return Err(CliReason::VerificationFailed);
        }
        let result = validate_result(
            result,
            plan.domain,
            &plan.protocol,
            receipt.roster.expected.get(),
        )
        .map_err(|_| CliReason::VerificationFailed)?;
        if receipt.outcome != ExecutionOutcome::Success
            || result.outcome != ExecutionOutcome::Success
            || result.roster != receipt.roster
        {
            return Err(CliReason::Unpublishable);
        }
        let bytes = result.aggregates_bytes().ok_or(CliReason::Unpublishable)?;
        PrivateAggregates::decode(
            bytes,
            &receipt.result,
            plan.domain,
            &plan.protocol,
            &receipt.roster,
        )
        .map_err(|_| CliReason::VerificationFailed)?;
        Ok(())
    };
    match check() {
        Ok(()) => Output::ok("artifact.validate", "artifact_bound"),
        Err(e) => Output::refused("artifact.validate", e),
    }
}

/// Strict offline grammar; paths are consumed, never printed.
pub fn command<F>(argv: &[String], read: &F) -> Output
where
    F: Fn(&str, usize) -> Result<Vec<u8>, CliReason>,
{
    let check = || -> Result<Output, CliReason> {
        if argv.len() != 8 || argv[0] != "artifact" || argv[1] != "validate" {
            return Err(CliReason::UsageError);
        }
        let mut paths = std::collections::BTreeMap::new();
        for index in (2..8).step_by(2) {
            let pair = &argv[index..index + 2];
            if !["--request", "--receipt", "--result"].contains(&pair[0].as_str())
                || paths.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err(CliReason::UsageError);
            }
        }
        let request = read(paths["--request"], crate::command::MAX_READ_BYTES)?;
        let receipt = read(paths["--receipt"], crate::command::MAX_DOCUMENT_BYTES)?;
        let result = read(
            paths["--result"],
            custodian_worker::result::MAX_RESULT_BYTES as usize,
        )?;
        Ok(validate(&request, &receipt, &result))
    };
    check().unwrap_or_else(|e| Output::refused("artifact.validate", e))
}
