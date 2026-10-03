//! Public synthetic integration with a pinned external CLI binary, never engine source imports.
#![cfg(unix)]
mod common;
use common::*;
use custodian_cli::{startup::StoreActivations, Command};
use custodian_contracts::{
    execution::{ExecutionOutcome, InternalReceipt},
    request::EvaluationRequest,
    Contract,
};
use custodian_core::{ActorId, Exposure, RunId, RunState};
use custodian_daemon::{
    clock::{ClockPin, PinnableClock},
    pipeline::Pipeline,
    shutdown::Shutdown,
};
use custodian_disclosure::DisclosurePolicy;
use custodian_store::PipelineStep;
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

const METRICS: [&str; 9] = [
    "type-miss-rate",
    "wrong-family-rate",
    "wrong-jurisdiction-rate",
    "sensitive-miss-rate",
    "non-sensitive-flag-rate",
    "context-discrimination-rate",
    "benign-suppression-rate",
    "jurisdiction-collision-rate",
    "range-collateral-rate",
];
fn assets() -> Option<PathBuf> {
    match std::env::var_os("CUSTODIAN_PII_ASSETS") {
        Some(p) => Some(p.into()),
        None => {
            skip("pii_engine", "external pinned artifacts not built");
            None
        }
    }
}
fn world(root: &Path, scenario: &str, adopted: bool) -> Env {
    let mut env = Env::new(5);
    let dir = root.join(scenario);
    let job: Value = serde_json::from_slice(&fs::read(dir.join("job/job.json")).unwrap()).unwrap();
    let owned: Vec<(String, Vec<u8>)> = job["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            let n = n.as_str().unwrap();
            (n.to_owned(), fs::read(dir.join("input").join(n)).unwrap())
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = owned
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let pop = &env.p.w.rw.fx.pop;
    let corpus_id = custodian_contracts::types::CorpusId::parse("cor_bbbbbbbbbbbbbbbb").unwrap();
    let writer = pop
        .begin_epoch(
            corpus_id.clone(),
            custodian_contracts::common::EvaluationDomain::Pii,
            None,
        )
        .unwrap();
    for (name, bytes) in &refs {
        pop.add_entry(&writer, &lc::corpus::name(name), bytes)
            .unwrap();
    }
    let epoch = writer.epoch_id().clone();
    let mut seal = lc::corpus::inputs_for(
        &epoch,
        custodian_contracts::common::ReviewStatus::ProjectReviewed,
    );
    seal.budget = custodian_contracts::common::BudgetScope::PopulationEpoch {
        corpus_id,
        epoch_id: epoch.clone(),
        family_id: None,
    };
    pop.seal(writer, seal).unwrap();
    pop.activate(&epoch, lc::corpus::now()).unwrap();
    let mut binding = lc::binding_of(&env.p.w.rw.fx, &epoch);
    binding.domain = custodian_contracts::common::EvaluationDomain::Pii;
    env.p.w.rw.epoch = epoch;
    env.p.w.rw.binding = binding;
    env.store()
        .provision_budget(
            custodian_contracts::common::BudgetKind::Run,
            &lc::run_scope(&env.p.w.rw.binding),
            5,
            &ActorId::new("synthetic-operator"),
            NOW,
        )
        .unwrap();
    let sources = &env.p.arts.sources;
    for (name, dst) in [
        ("engine", &sources.engine),
        ("adapter", &sources.adapter),
        ("candidate", &sources.candidate),
        ("config", &sources.config),
        ("scanner-0", &sources.scanners[0]),
    ] {
        let src = if name == "engine" && !adopted {
            root.join("unadopted-pii-eval")
        } else {
            dir.join("stage").join(name)
        };
        fs::copy(src, dst).unwrap();
        set_mode(dst, 0o755);
    }
    // Synthetic activations use distinct identities, leaving existing history untouched.
    for (mut activation, id) in [
        (cc::activation_json(), 3),
        (
            dc::activation_value(dc::disclosure_ref(), &cc::id("pac_", 4), 1, "active"),
            4,
        ),
    ] {
        activation["policy"]["domain"] = json!("pii");
        activation["activation_id"] = json!(cc::id("pac_", id));
        let parsed: custodian_contracts::policy::PolicyActivation =
            serde_json::from_value(activation).unwrap();
        env.store()
            .record_activation(&parsed, &ActorId::new("synthetic-operator"), NOW)
            .unwrap();
    }
    env.lay_out_artifacts();
    env
}
fn request(env: &Env, memory: u64) -> EvaluationRequest {
    let mut v = cc::request_json();
    let sources = &env.p.arts.sources;
    let artifact = |name: &str, version: &str, path: &Path| {
        json!({"name":name, "version":version,
            "digest":custodian_worker::artifacts::hash_file(path).unwrap()})
    };
    v["plan"]["population"] = json!(env.p.w.rw.binding);
    v["plan"]["accounting"]["budget"] = json!(lc::run_scope(&env.p.w.rw.binding));
    v["plan"]["accounting"]["max_retries"] = json!(1);
    v["plan"]["engine"] = artifact("pii-eval", "0.0.0", &sources.engine);
    v["plan"]["adapter"] = artifact("pii-node-shim", "0.0.1", &sources.adapter);
    v["plan"]["scanners"] = json!([artifact("node", "22.23.3", &sources.scanners[0])]);
    v["plan"]["candidate"] =
        json!(custodian_worker::artifacts::hash_file(&sources.candidate).unwrap());
    v["plan"]["config_digest"] =
        json!(custodian_worker::artifacts::hash_file(&sources.config).unwrap());
    v["plan"]["domain"] = json!("pii");
    v["plan"]["purpose"] = json!("conformance_control");
    v["plan"]["engine"]["name"] = json!("pii-eval");
    v["plan"]["engine"]["version"] = json!("0.0.0");
    v["plan"]["adapter"]["name"] = json!("pii-node-shim");
    v["plan"]["scanners"][0]["name"] = json!("node");
    v["plan"]["scanners"][0]["version"] = json!("22.23.3");
    v["plan"]["protocol"] = json!({"domain":"pii", "name":"pii-v1","version":"2"});
    v["plan"]["policy_activation"]["policy"]["domain"] = json!("pii");
    v["plan"]["policy_activation"]["activation_id"] = json!(cc::id("pac_", 3));
    v["plan"]["disclosure_policy"]["domain"] = json!("pii");
    v["plan"]["limits"]["memory_mib"] = json!(memory);
    v["plan"]["limits"]["cpu_seconds"] = json!(30);
    v["plan"]["limits"]["wall_seconds"] = json!(20);
    v["plan"]["limits"]["storage_mib"] = json!(64);
    v["plan"]["limits"]["max_processes"] = json!(32);
    v["plan"]["limits"]["max_output_bytes"] = json!(65536);
    let request: EvaluationRequest = serde_json::from_value(v).unwrap();
    request.validate().unwrap();
    request
}
fn reserve(env: &Env, req: &EvaluationRequest) -> RunId {
    let out = env.p.w.run(
        Who::Requester,
        &Command::RequestSubmit {
            document: req.canonical_bytes().unwrap(),
        },
    );
    assert!(out.is_ok(), "submit {}", out.code());
    let out = env.p.w.run(
        Who::Approver,
        &Command::RequestApprove {
            request_id: req.request_id.clone(),
            confirm_plan_digest: req.plan.plan_digest().unwrap(),
            ttl_secs: None,
        },
    );
    assert!(out.is_ok(), "approve {}", out.code());
    RunId::new(out.field("attempt_id").unwrap().as_str().unwrap())
}
fn settings(env: &Env) -> custodian_daemon::pipeline::PipelineSettings {
    let mut settings = env.settings();
    let mut p = dc::policy_json();
    p["policy"]["domain"] = json!("pii");
    p["strata"] = json!([{"stratum":"overall","dimension":"total"}]);
    p["total_stratum"] = json!("overall");
    p["relations"] = json!([]);
    p["metrics"] = json!(METRICS);
    let policy: DisclosurePolicy = serde_json::from_value(p).unwrap();
    policy.validate().unwrap();
    settings.policy = policy;
    settings.policy_binding.policy = settings.policy.policy.clone();
    settings.policy_binding.activation_id =
        custodian_contracts::types::ActivationId::parse(&cc::id("pac_", 4)).unwrap();
    settings
}
fn pass(env: &Env, d: &custodian_worker::Dispatcher) {
    let pin = ClockPin::new();
    let mut parts = env.p.w.parts();
    parts.clock = Arc::new(PinnableClock::new(env.p.w.clock.clone(), pin.clone()));
    let acts = StoreActivations::new(env.store(), parts.clock.clone());
    let svc = custodian_cli::Service::start(parts.clone(), &startup_config(), &acts).unwrap();
    let pipeline = Pipeline {
        pin: &pin,
        parts,
        svc: &svc,
        dispatcher: Some(d),
        artifacts: &env.artifacts,
        approvals: &env.approvals,
        sink: &env.sink,
        names: &env.names,
        checks: None,
        scope: None,
        settings: settings(env),
        log: env.log.as_ref(),
        fault: &CrashAt::default(),
    };
    pipeline.pass(&Shutdown::new()).unwrap();
}
#[test]
fn pinned_cli_through_the_real_custodian_pipeline() {
    let Some(root) = assets() else { return };
    // The unmodified upstream CLI is not misrepresented as an adopted emitter.
    for (scenario, adopted, memory, success) in [
        ("normal", false, 1024, false),
        ("normal", true, 1024, true),
        ("normal", true, 1536, true),
        ("normal", true, 512, false),
        ("scanner-crash", true, 1024, false),
        ("population-mismatch", true, 1024, false),
        ("run-class-mismatch", true, 1024, false),
        ("wrong-tree-digest", true, 1024, false),
        ("wrong-bundle-digest", true, 1024, false),
        ("wrong-runtime-digest", true, 1024, false),
    ] {
        let mut env = world(&root, scenario, adopted);
        let Some(worker) = real_worker(&env, "pii_engine") else {
            return;
        };
        let req = request(&env, memory);
        let attempt = reserve(&env, &req);
        env.publish_feed();
        pass(&env, &worker);
        let rec = env.store().attempt(&attempt).unwrap().unwrap();
        let run = env.store().pipeline_run(&attempt).unwrap().unwrap();
        let artifacts = env.store().pipeline_artifacts(&attempt).unwrap().unwrap();
        let execution = custodian_contracts::execution::ExecutionRecord::decode(
            artifacts.execution.as_ref().unwrap().as_bytes(),
        )
        .unwrap();
        if success {
            assert_eq!(
                (rec.state, run.step),
                (RunState::Completed, PipelineStep::Prepared),
                "{scenario} {memory} {run:?}"
            );
            assert_eq!(execution.outcome, ExecutionOutcome::Success);
            let receipt =
                InternalReceipt::decode(artifacts.receipt.as_ref().unwrap().as_bytes()).unwrap();
            assert_eq!(
                receipt.attestation.independence,
                custodian_contracts::common::IndependenceClaim::PublicControl
            );
            let aggregates: Value =
                serde_json::from_slice(artifacts.aggregates.as_ref().unwrap()).unwrap();
            assert_eq!(aggregates["cells"].as_array().unwrap().len(), 9);
            assert!(!aggregates.to_string().contains("measurable-share"));
            let result = json!({"schema":"private-custodian.worker-result/1", "domain":"pii",
                "protocol":{"name":"pii-v1", "version":"2"}, "status":"complete", "roster":receipt.roster, "aggregates":aggregates});
            assert!(custodian_cli::artifact::validate(
                &req.canonical_bytes().unwrap(),
                &receipt.canonical_bytes().unwrap(),
                &serde_json::to_vec(&result).unwrap()
            )
            .is_ok());
            let settings = settings(&env);
            let mut approval = cc::approval_json();
            approval["approval_id"] = json!(cc::id("apr_", 2));
            approval["scope"] = json!({"operation":"release",
                "execution_id":run.execution_id.as_ref().unwrap(),
                "projection_digest":run.prepared.as_ref().unwrap().projection_digest,
                "disclosure_policy":settings.policy.policy});
            approval["activation"] = json!(settings.policy_binding);
            approval["issued_at"] = json!(NOW + 60);
            approval["expires_at"] = json!(NOW + 3600);
            let approval_path = env
                .approvals_dir
                .join(format!("{}.json", req.request_id.as_str()));
            fs::write(&approval_path, serde_json::to_vec(&approval).unwrap()).unwrap();
            set_mode(&approval_path, 0o600);
            env.at(RELEASE_AT);
            pass(&env, &worker);
            assert_eq!(
                env.store().pipeline_run(&attempt).unwrap().unwrap().step,
                PipelineStep::Released
            );
            assert_eq!(env.released_files().len(), 1);
            let feed_id = lc::feed_id();
            let public = verify::Public {
                feed: &env.p.w.feed,
                feed_id: &feed_id,
                key_hex: env.p.w.key.signer.public_key_hex(),
                key_id: cc::id("key_", 1),
                roots: &env.p.w.roots,
            };
            let mut consumer = custodian_bridge::consumer::BridgeConsumer::new(
                custodian_bridge::consumer::ConsumerPins {
                    domain: req.plan.domain,
                    feed_id: feed_id.clone(),
                    destination: custodian_contracts::types::DestinationId::parse(DEST).unwrap(),
                    verifier: custodian_ledger::Verifier::new(env.p.w.roots.clone()),
                    accepted_populations: vec![lc::opaque(1)],
                    accepted_policies: vec![settings.policy.policy.clone()],
                },
            );
            let query = consumer
                .request(
                    req.plan.candidate.clone(),
                    req.plan.config_digest.clone(),
                    vec![lc::opaque(1)],
                )
                .unwrap();
            let response = verify::bridge_response(&env, &public, &query);
            let accepted = consumer
                .accept_response(
                    &query,
                    &response,
                    custodian_contracts::types::Timestamp::new(RELEASE_AT + 20).unwrap(),
                )
                .unwrap();
            assert_eq!(accepted.accepted.len(), 1);
            assert!(accepted.rejected.is_empty());
            // Restart/replay uses the durable receipt; it cannot run or publish again.
            env.restart_store();
            pass(&env, &worker);
            assert_eq!(env.released_files().len(), 1);
        } else {
            assert_eq!(rec.state, RunState::Failed, "{scenario} {memory} {run:?}");
            assert_eq!(run.step, PipelineStep::Closed, "{run:?}");
            assert!(artifacts.receipt.is_none());
            assert!(env.released_files().is_empty());
            if adopted && (scenario == "scanner-crash" || memory == 512) {
                assert_eq!(execution.outcome, ExecutionOutcome::Partial);
                let meta = custodian_daemon::pipeline::assemble::ResultMeta::parse(
                    artifacts.result_meta.as_ref().unwrap(),
                )
                .unwrap();
                assert_eq!((meta.observed, meta.failed), (meta.expected, meta.expected));
            } else {
                assert_eq!(execution.outcome, ExecutionOutcome::Failed);
            }
        }
        assert_eq!(rec.exposure, Exposure::Exposed);
        let b = env.p.w.budget();
        assert_eq!((b.held, b.consumed, b.refunded), (0, 1, 0));
        env.store().verify_invariants().unwrap();
        assert_eq!(env.p.arts.staging_entries(), 0);
        println!("PII-PIPELINE-VERIFIED {scenario} adopted={adopted} memory-mib={memory}");
    }
}
