use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_directory(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("pcbex-{label}-{}-{nonce}", std::process::id()))
}

fn record_feedback(
    root: &Path,
    policy: &serde_json::Value,
    id: &str,
    required_minimum_mm: f64,
) -> (PathBuf, PathBuf) {
    let directory = root.join(id);
    let analysis = directory.join("analysis");
    fs::create_dir_all(&analysis).unwrap();
    let board = directory.join("board.kicad_pcb");
    let artifact = directory.join("inspection.csv");
    let declaration = directory.join("declaration.json");
    let feedback = directory.join("feedback.json");
    fs::write(&board, format!("board {id}")).unwrap();
    fs::write(&artifact, "clearance_mm\n0.11\n").unwrap();
    let board_sha256 = format!("{:x}", Sha256::digest(fs::read(&board).unwrap()));
    let manifest = serde_json::json!({
        "schema_version": 1,
        "engine": "pcbex",
        "command": "analyze-kicad",
        "input": {"sha256": board_sha256},
        "configuration": {"dfm_profile": policy["dfm_profile"]}
    });
    let manifest_path = analysis.join("run.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let declaration_document = serde_json::json!({
        "schema_version": 1,
        "id": id,
        "manufacturer": {
            "id": "example-fab",
            "process": "4-layer production",
            "lot": id
        },
        "received_on": "2026-07-28",
        "board_sha256": board_sha256,
        "disposition": "accepted_with_notes",
        "findings": [{
            "id": format!("clearance-{id}"),
            "category": "clearance",
            "severity": "warning",
            "message": "Measured clearance is below the recurring process target.",
            "measurement": {
                "name": "minimum clearance",
                "value": required_minimum_mm - 0.01,
                "unit": "mm",
                "minimum": required_minimum_mm
            },
            "evidence": ["inspection.csv"]
        }]
    });
    fs::write(
        &declaration,
        serde_json::to_string_pretty(&declaration_document).unwrap(),
    )
    .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("record-manufacturing-feedback")
        .arg(&declaration)
        .arg("--analysis-dir")
        .arg(&analysis)
        .arg("--board")
        .arg(&board)
        .arg("--artifact")
        .arg(&artifact)
        .arg("--output")
        .arg(&feedback)
        .status()
        .unwrap();
    assert!(status.success());
    (feedback, manifest_path)
}

#[test]
fn proposes_validates_and_refuses_to_overwrite_governed_policy_evidence() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temporary = temporary_directory("policy-recommendation");
    fs::create_dir_all(&temporary).unwrap();
    let key_a = temporary.join("reviewer-a.key");
    let public_a = temporary.join("reviewer-a.pub");
    let key_b = temporary.join("reviewer-b.key");
    let public_b = temporary.join("reviewer-b.pub");
    let key_c = temporary.join("incident-operator.key");
    let public_c = temporary.join("incident-operator.pub");
    for (private, public) in [
        (&key_a, &public_a),
        (&key_b, &public_b),
        (&key_c, &public_c),
    ] {
        assert!(
            Command::new(env!("CARGO_BIN_EXE_pcbex"))
                .arg("approval-keygen")
                .arg("--private-key")
                .arg(private)
                .arg("--public-key")
                .arg(public)
                .status()
                .unwrap()
                .success()
        );
    }
    let mut policy: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(root.join("examples/acme-policy-pack.json")).unwrap(),
    )
    .unwrap();
    policy["trusted_human_escalation_keys"] = serde_json::json!([
        {
            "signer_id": "reviewer-a",
            "public_key": fs::read_to_string(&public_a).unwrap().trim()
        },
        {
            "signer_id": "reviewer-b",
            "public_key": fs::read_to_string(&public_b).unwrap().trim()
        },
        {
            "signer_id": "incident-operator",
            "public_key": fs::read_to_string(&public_c).unwrap().trim()
        }
    ]);
    let policy_path = temporary.join("policy-pack.json");
    fs::write(&policy_path, serde_json::to_string_pretty(&policy).unwrap()).unwrap();
    let policy_private_key = temporary.join("policy-signing.key");
    let policy_public_key = temporary.join("policy-signing.pub");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("policy-keygen")
            .arg("--private-key")
            .arg(&policy_private_key)
            .arg("--public-key")
            .arg(&policy_public_key)
            .status()
            .unwrap()
            .success()
    );
    let signed_policy = temporary.join("signed-policy-pack.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-policy-pack")
            .arg(&policy_path)
            .arg("--private-key")
            .arg(&policy_private_key)
            .arg("--signer-id")
            .arg("policy-authority")
            .arg("--output")
            .arg(&signed_policy)
            .status()
            .unwrap()
            .success()
    );
    let verified_policy = temporary.join("verified-policy-pack.json");
    let policy_trust_state = temporary.join("policy-trust-state.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("verify-policy-pack")
            .arg(&signed_policy)
            .arg("--public-key")
            .arg(&policy_public_key)
            .arg("--state-output")
            .arg(&policy_trust_state)
            .arg("--output")
            .arg(&verified_policy)
            .status()
            .unwrap()
            .success()
    );
    let (first_feedback, first_manifest) = record_feedback(&temporary, &policy, "lot-one", 0.14);
    let (second_feedback, second_manifest) = record_feedback(&temporary, &policy, "lot-two", 0.15);
    let output = temporary.join("recommendation.json");
    let summary = temporary.join("recommendation.md");

    let recommend = || {
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("recommend-policy")
            .arg(&policy_path)
            .arg("--feedback")
            .arg(&first_feedback)
            .arg("--feedback")
            .arg(&second_feedback)
            .arg("--analysis-manifest")
            .arg(&first_manifest)
            .arg("--analysis-manifest")
            .arg(&second_manifest)
            .arg("--generated-on")
            .arg("2026-07-29")
            .arg("--minimum-occurrences")
            .arg("2")
            .arg("--output")
            .arg(&output)
            .arg("--summary-output")
            .arg(&summary)
            .output()
            .unwrap()
    };
    assert!(recommend().status.success());
    let original = fs::read(&output).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(report["status"], "proposal_only");
    assert_eq!(report["requires_human_approval"], true);
    assert_eq!(report["may_relax_constraints"], false);
    assert_eq!(report["recommendations"][0]["rule"], "minimum_clearance_nm");
    assert_eq!(report["recommendations"][0]["current_value_nm"], 125_000);
    assert_eq!(
        report["recommendations"][0]["recommended_value_nm"],
        150_000
    );
    assert_eq!(
        report["recommendations"][0]["independent_feedback_count"],
        2
    );
    assert!(
        fs::read_to_string(&summary)
            .unwrap()
            .contains("Human approval")
    );

    let overwrite = recommend();
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&output).unwrap(), original);

    let validated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("validate-policy-recommendation")
        .arg(&output)
        .output()
        .unwrap();
    assert!(validated.status.success());
    let normalized: serde_json::Value = serde_json::from_slice(&validated.stdout).unwrap();
    assert_eq!(normalized, report);

    let schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("policy-recommendation-schema")
        .output()
        .unwrap();
    assert!(schema.status.success());
    let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["recommendations"]["items"]["additionalProperties"],
        false
    );

    let candidate_profile = temporary.join("candidate-profile.json");
    let profile = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("policy-rollout-profile")
        .arg(&policy_path)
        .arg(&output)
        .arg("--generated-on")
        .arg("2026-07-29")
        .arg("--output")
        .arg(&candidate_profile)
        .output()
        .unwrap();
    assert!(
        profile.status.success(),
        "{}",
        String::from_utf8_lossy(&profile.stderr)
    );
    let profile: serde_json::Value =
        serde_json::from_slice(&fs::read(&candidate_profile).unwrap()).unwrap();
    assert_eq!(profile["rules"]["minimum_clearance_nm"], 150_000);
    assert!(
        profile["id"]
            .as_str()
            .unwrap()
            .starts_with("pcbex-rollout-")
    );
    let mut candidate_policy = policy.clone();
    candidate_policy["revision"] = serde_json::json!(2);
    candidate_policy["dfm_profile"] = profile.clone();
    let candidate_policy_path = temporary.join("candidate-policy-pack.json");
    fs::write(
        &candidate_policy_path,
        serde_json::to_string_pretty(&candidate_policy).unwrap(),
    )
    .unwrap();
    let signed_candidate_policy = temporary.join("candidate-policy-pack.signed.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-policy-pack")
            .arg(&candidate_policy_path)
            .arg("--private-key")
            .arg(&policy_private_key)
            .arg("--signer-id")
            .arg("policy-authority")
            .arg("--output")
            .arg(&signed_candidate_policy)
            .status()
            .unwrap()
            .success()
    );
    let verified_candidate_policy = temporary.join("candidate-policy-pack.verified.json");
    let candidate_policy_trust_state = temporary.join("candidate-policy-trust-state.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("verify-policy-pack")
            .arg(&signed_candidate_policy)
            .arg("--public-key")
            .arg(&policy_public_key)
            .arg("--baseline-state")
            .arg(&policy_trust_state)
            .arg("--state-output")
            .arg(&candidate_policy_trust_state)
            .arg("--output")
            .arg(&verified_candidate_policy)
            .status()
            .unwrap()
            .success()
    );

    let board = root.join("examples/simple.kicad_pcb");
    let baseline = temporary.join("baseline");
    let candidate = temporary.join("candidate");
    let analyze = |output_dir: &Path, option: &str, configuration: &Path| {
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("analyze-kicad")
            .arg(&board)
            .arg(option)
            .arg(configuration)
            .arg("--output-dir")
            .arg(output_dir)
            .output()
            .unwrap()
    };
    assert!(
        analyze(&baseline, "--policy-pack", &policy_path)
            .status
            .success()
    );
    assert!(
        analyze(&candidate, "--fab-profile", &candidate_profile)
            .status
            .success()
    );
    let rollout = temporary.join("rollout.json");
    let rollout_summary = temporary.join("rollout.md");
    let simulate = || {
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("simulate-policy-rollout")
            .arg(&policy_path)
            .arg(&output)
            .arg("--project-id")
            .arg("controller")
            .arg("--board")
            .arg(&board)
            .arg("--baseline-analysis")
            .arg(&baseline)
            .arg("--candidate-analysis")
            .arg(&candidate)
            .arg("--generated-on")
            .arg("2026-07-29")
            .arg("--output")
            .arg(&rollout)
            .arg("--summary-output")
            .arg(&rollout_summary)
            .output()
            .unwrap()
    };
    let simulated = simulate();
    assert!(
        simulated.status.success(),
        "{}",
        String::from_utf8_lossy(&simulated.stderr)
    );
    let rollout_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&rollout).unwrap()).unwrap();
    assert_eq!(rollout_document["status"], "simulation_only");
    assert_eq!(rollout_document["deployable"], false);
    assert_eq!(rollout_document["requires_human_approval"], true);
    assert_eq!(rollout_document["total_projects"], 1);
    assert_eq!(rollout_document["projects"][0]["project_id"], "controller");
    assert!(!simulate().status.success());

    let validated_rollout = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("validate-policy-rollout")
        .arg(&rollout)
        .output()
        .unwrap();
    assert!(validated_rollout.status.success());
    let mut tampered_report = rollout_document.clone();
    tampered_report["deployable"] = serde_json::json!(true);
    let tampered_report_path = temporary.join("tampered-rollout.json");
    fs::write(
        &tampered_report_path,
        serde_json::to_string_pretty(&tampered_report).unwrap(),
    )
    .unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-policy-rollout")
            .arg(&tampered_report_path)
            .status()
            .unwrap()
            .success()
    );
    let mut nested_tamper = rollout_document.clone();
    nested_tamper["projects"][0]["delta"]["unexpected"] = serde_json::json!(true);
    let nested_tamper_path = temporary.join("nested-tampered-rollout.json");
    fs::write(
        &nested_tamper_path,
        serde_json::to_string_pretty(&nested_tamper).unwrap(),
    )
    .unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-policy-rollout")
            .arg(&nested_tamper_path)
            .status()
            .unwrap()
            .success()
    );
    let rollout_schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("policy-rollout-schema")
        .output()
        .unwrap();
    assert!(rollout_schema.status.success());
    let rollout_schema: serde_json::Value = serde_json::from_slice(&rollout_schema.stdout).unwrap();
    assert_eq!(rollout_schema["additionalProperties"], false);
    assert_eq!(
        rollout_schema["properties"]["projects"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        rollout_schema["properties"]["projects"]["items"]["properties"]["delta"]["additionalProperties"],
        false
    );
    assert_eq!(
        rollout_schema["properties"]["projects"]["items"]["properties"]["delta"]["properties"]["changes"]
            ["additionalProperties"],
        false
    );

    let approval_a = temporary.join("rollout-approval-a.json");
    let approval_b = temporary.join("rollout-approval-b.json");
    for (private_key, signer_id, approval) in [
        (&key_a, "reviewer-a", &approval_a),
        (&key_b, "reviewer-b", &approval_b),
    ] {
        let signed = Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-rollout-approval")
            .arg(&rollout)
            .arg("--canary-project")
            .arg("controller")
            .arg("--valid-from-unix")
            .arg("1000")
            .arg("--expires-at-unix")
            .arg("2000")
            .arg("--private-key")
            .arg(private_key)
            .arg("--signer-id")
            .arg(signer_id)
            .arg("--decision")
            .arg("approve")
            .arg("--reason")
            .arg("Simulation is compatible with the bounded canary.")
            .arg("--ticket")
            .arg("HW-42")
            .arg("--output")
            .arg(approval)
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
    }
    let authorization = temporary.join("canary-authorization.json");
    let authorization_summary = temporary.join("canary-authorization.md");
    let authorized = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-rollout-approvals")
        .arg(&rollout)
        .arg("--policy-pack")
        .arg(&policy_path)
        .arg("--approval")
        .arg(&approval_a)
        .arg("--approval")
        .arg(&approval_b)
        .arg("--evaluated-at-unix")
        .arg("1500")
        .arg("--minimum-approvals")
        .arg("2")
        .arg("--output")
        .arg(&authorization)
        .arg("--summary-output")
        .arg(&authorization_summary)
        .arg("--require-authorized")
        .output()
        .unwrap();
    assert!(
        authorized.status.success(),
        "{}",
        String::from_utf8_lossy(&authorized.stderr)
    );
    let authorization_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&authorization).unwrap()).unwrap();
    assert_eq!(
        authorization_document["status"],
        serde_json::json!("canary_authorized")
    );
    assert_eq!(authorization_document["canary_authorized"], true);
    assert_eq!(
        authorization_document["policy"]["maximum_canary_percent"],
        10
    );
    assert_eq!(
        authorization_document["rollback_policy"]["automatic_rollback"],
        true
    );
    assert_eq!(
        authorization_document["rollback_policy"]["automatic_promotion"],
        false
    );
    assert_eq!(
        authorization_document["rollback_policy"]["requires_post_canary_review"],
        true
    );
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-canary-rollout-authorization")
            .arg(&authorization)
            .status()
            .unwrap()
            .success()
    );
    for schema_command in [
        "signed-rollout-approval-schema",
        "canary-rollout-authorization-schema",
        "canary-monitoring-schema",
    ] {
        let schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg(schema_command)
            .output()
            .unwrap();
        assert!(schema.status.success());
        let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }
    let monitoring = temporary.join("canary-monitoring.json");
    let monitoring_summary = temporary.join("canary-monitoring.md");
    let monitored = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("record-canary-monitoring")
        .arg(&rollout)
        .arg(&authorization)
        .arg("--project-id")
        .arg("controller")
        .arg("--board")
        .arg(&board)
        .arg("--baseline-analysis")
        .arg(&baseline)
        .arg("--observed-analysis")
        .arg(&candidate)
        .arg("--observed-at-unix")
        .arg("1600")
        .arg("--output")
        .arg(&monitoring)
        .arg("--summary-output")
        .arg(&monitoring_summary)
        .arg("--require-passed")
        .output()
        .unwrap();
    assert!(
        monitored.status.success(),
        "{}",
        String::from_utf8_lossy(&monitored.stderr)
    );
    let monitoring_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&monitoring).unwrap()).unwrap();
    assert_eq!(monitoring_document["status"], "monitoring_passed");
    assert_eq!(monitoring_document["promotion_eligible"], true);
    assert_eq!(monitoring_document["rollback_required"], false);
    assert_eq!(monitoring_document["automatic_promotion"], false);
    assert_eq!(monitoring_document["requires_human_decision"], true);
    assert_eq!(
        monitoring_document["projects"][0]["project_id"],
        "controller"
    );
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-canary-monitoring")
            .arg(&monitoring)
            .status()
            .unwrap()
            .success()
    );
    let mut monitoring_tamper = monitoring_document.clone();
    monitoring_tamper["automatic_promotion"] = serde_json::json!(true);
    let monitoring_tamper_path = temporary.join("tampered-canary-monitoring.json");
    fs::write(
        &monitoring_tamper_path,
        serde_json::to_string_pretty(&monitoring_tamper).unwrap(),
    )
    .unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-canary-monitoring")
            .arg(&monitoring_tamper_path)
            .status()
            .unwrap()
            .success()
    );
    let completion_a = temporary.join("completion-a.json");
    let completion_b = temporary.join("completion-b.json");
    for (private_key, signer_id, signed) in [
        (&key_a, "reviewer-a", &completion_a),
        (&key_b, "reviewer-b", &completion_b),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-canary-completion")
            .arg(&rollout)
            .arg(&monitoring)
            .arg(&authorization)
            .arg("--decision")
            .arg("promote")
            .arg("--decided-at-unix")
            .arg("1700")
            .arg("--private-key")
            .arg(private_key)
            .arg("--signer-id")
            .arg(signer_id)
            .arg("--reason")
            .arg("Bound canary monitoring passed without regression.")
            .arg("--ticket")
            .arg("HW-43")
            .arg("--output")
            .arg(signed)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let completion = temporary.join("completion.json");
    let finalized = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-canary-completion")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&policy_path)
        .arg("--decision")
        .arg(&completion_a)
        .arg("--decision")
        .arg(&completion_b)
        .arg("--output")
        .arg(&completion)
        .arg("--require-finalized")
        .output()
        .unwrap();
    assert!(
        finalized.status.success(),
        "{}",
        String::from_utf8_lossy(&finalized.stderr)
    );
    let completion_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&completion).unwrap()).unwrap();
    assert_eq!(completion_document["status"], "promotion_authorized");
    assert_eq!(completion_document["finalized"], true);
    assert_eq!(completion_document["final_decision"], "promote");
    assert_eq!(completion_document["policy"]["automatic_promotion"], false);
    assert_eq!(
        completion_document["policy"]["unanimous_decision_required"],
        true
    );
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-canary-completion")
            .arg(&completion)
            .status()
            .unwrap()
            .success()
    );
    let deployment = temporary.join("policy-deployment.json");
    let deployment_summary = temporary.join("policy-deployment.md");
    let advanced = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("advance-policy-deployment")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&verified_policy)
        .arg("--candidate-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--source-policy-trust-state")
        .arg(&policy_trust_state)
        .arg("--candidate-policy-trust-state")
        .arg(&candidate_policy_trust_state)
        .arg("--decision")
        .arg(&completion_a)
        .arg("--decision")
        .arg(&completion_b)
        .arg("--recorded-at-unix")
        .arg("1800")
        .arg("--output")
        .arg(&deployment)
        .arg("--summary-output")
        .arg(&deployment_summary)
        .arg("--require-promotion")
        .output()
        .unwrap();
    assert!(
        advanced.status.success(),
        "{}",
        String::from_utf8_lossy(&advanced.stderr)
    );
    let deployment_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&deployment).unwrap()).unwrap();
    assert_eq!(deployment_document["status"], "promotion_applied");
    assert_eq!(deployment_document["generation"], 1);
    assert_eq!(deployment_document["active_revision"], 2);
    assert_eq!(deployment_document["deployment_applied"], true);
    assert_eq!(deployment_document["automatic_application"], false);
    assert_eq!(
        deployment_document["post_deployment_verification_required"],
        true
    );
    assert_eq!(deployment_document["verification_status"], "pending");
    assert!(deployment_document["rollback_revision"].is_null());
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-policy-deployment-state")
            .arg(&deployment)
            .status()
            .unwrap()
            .success()
    );
    let deployed = temporary.join("deployed");
    assert!(
        analyze(&deployed, "--policy-pack", &verified_candidate_policy)
            .status
            .success()
    );
    let deployment_verification = temporary.join("policy-deployment-verification.json");
    let deployment_verification_summary = temporary.join("policy-deployment-verification.md");
    let verified_deployment = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-policy-deployment")
        .arg(&deployment)
        .arg(&rollout)
        .arg("--candidate-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--project-id")
        .arg("controller")
        .arg("--board")
        .arg(&board)
        .arg("--expected-analysis")
        .arg(&candidate)
        .arg("--observed-analysis")
        .arg(&deployed)
        .arg("--verified-at-unix")
        .arg("1900")
        .arg("--output")
        .arg(&deployment_verification)
        .arg("--summary-output")
        .arg(&deployment_verification_summary)
        .arg("--require-passed")
        .output()
        .unwrap();
    assert!(
        verified_deployment.status.success(),
        "{}",
        String::from_utf8_lossy(&verified_deployment.stderr)
    );
    let verification_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&deployment_verification).unwrap()).unwrap();
    assert_eq!(verification_document["status"], "verification_passed");
    assert_eq!(verification_document["coverage_complete"], true);
    assert_eq!(verification_document["deployment_verified"], true);
    assert_eq!(verification_document["rollback_required"], false);
    assert_eq!(verification_document["automatic_rollback"], false);
    assert_eq!(
        verification_document["requires_dual_control_rollback"],
        false
    );
    assert_eq!(verification_document["active_revision"], 2);
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-policy-deployment-verification")
            .arg(&deployment_verification)
            .status()
            .unwrap()
            .success()
    );
    let verification_schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("policy-deployment-verification-schema")
        .output()
        .unwrap();
    assert!(verification_schema.status.success());
    let verification_schema: serde_json::Value =
        serde_json::from_slice(&verification_schema.stdout).unwrap();
    assert_eq!(verification_schema["additionalProperties"], false);
    assert_eq!(
        verification_schema["properties"]["automatic_rollback"]["const"],
        false
    );
    let regressed_deployed = temporary.join("deployed-regressed");
    fs::create_dir(&regressed_deployed).unwrap();
    let mut regressed_run: serde_json::Value =
        serde_json::from_slice(&fs::read(deployed.join("run.json")).unwrap()).unwrap();
    regressed_run["result"]["violations"] = serde_json::json!(2);
    fs::write(
        regressed_deployed.join("run.json"),
        serde_json::to_string_pretty(&regressed_run).unwrap(),
    )
    .unwrap();
    let mut regressed_checks: serde_json::Value =
        serde_json::from_slice(&fs::read(deployed.join("checks.json")).unwrap()).unwrap();
    regressed_checks["violations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "rule": "clearance",
            "message": "production-only clearance regression",
            "net_ids": [1]
        }));
    fs::write(
        regressed_deployed.join("checks.json"),
        serde_json::to_string_pretty(&regressed_checks).unwrap(),
    )
    .unwrap();
    fs::copy(
        deployed.join("quality.json"),
        regressed_deployed.join("quality.json"),
    )
    .unwrap();
    let rollback_verification = temporary.join("rollback-verification.json");
    let rollback_evidence = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-policy-deployment")
        .arg(&deployment)
        .arg(&rollout)
        .arg("--candidate-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--project-id")
        .arg("controller")
        .arg("--board")
        .arg(&board)
        .arg("--expected-analysis")
        .arg(&candidate)
        .arg("--observed-analysis")
        .arg(&regressed_deployed)
        .arg("--verified-at-unix")
        .arg("1901")
        .arg("--output")
        .arg(&rollback_verification)
        .output()
        .unwrap();
    assert!(
        rollback_evidence.status.success(),
        "{}",
        String::from_utf8_lossy(&rollback_evidence.stderr)
    );
    let rollback_verification_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&rollback_verification).unwrap()).unwrap();
    assert_eq!(
        rollback_verification_document["status"],
        "rollback_required"
    );
    assert_eq!(rollback_verification_document["deployment_verified"], false);
    assert_eq!(rollback_verification_document["rollback_required"], true);
    assert_eq!(
        rollback_verification_document["requires_dual_control_rollback"],
        true
    );
    assert_eq!(rollback_verification_document["total_new_violations"], 1);
    assert_eq!(rollback_verification_document["automatic_rollback"], false);
    let gated_rollback = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-policy-deployment")
        .arg(&deployment)
        .arg(&rollout)
        .arg("--candidate-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--project-id")
        .arg("controller")
        .arg("--board")
        .arg(&board)
        .arg("--expected-analysis")
        .arg(&candidate)
        .arg("--observed-analysis")
        .arg(&regressed_deployed)
        .arg("--verified-at-unix")
        .arg("1901")
        .arg("--output")
        .arg(temporary.join("gated-rollback-verification.json"))
        .arg("--require-passed")
        .output()
        .unwrap();
    assert!(!gated_rollback.status.success());
    assert!(
        String::from_utf8_lossy(&gated_rollback.stderr).contains("dual-control rollback"),
        "{}",
        String::from_utf8_lossy(&gated_rollback.stderr)
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("advance-policy-deployment")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&verified_policy)
        .arg("--candidate-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--source-policy-trust-state")
        .arg(&policy_trust_state)
        .arg("--candidate-policy-trust-state")
        .arg(&candidate_policy_trust_state)
        .arg("--decision")
        .arg(&completion_a)
        .arg("--decision")
        .arg(&completion_b)
        .arg("--baseline-state")
        .arg(&deployment)
        .arg("--recorded-at-unix")
        .arg("1801")
        .arg("--output")
        .arg(temporary.join("replayed-deployment.json"))
        .output()
        .unwrap();
    assert!(!replay.status.success());
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("does not advance"),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let mut substituted_trust: serde_json::Value =
        serde_json::from_slice(&fs::read(&candidate_policy_trust_state).unwrap()).unwrap();
    substituted_trust["signer_id"] = serde_json::json!("substituted-authority");
    substituted_trust["public_key"] =
        serde_json::json!(fs::read_to_string(&public_a).unwrap().trim());
    let substituted_trust_path = temporary.join("substituted-policy-trust-state.json");
    fs::write(
        &substituted_trust_path,
        serde_json::to_string_pretty(&substituted_trust).unwrap(),
    )
    .unwrap();
    let substitution = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("advance-policy-deployment")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&verified_policy)
        .arg("--candidate-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--source-policy-trust-state")
        .arg(&policy_trust_state)
        .arg("--candidate-policy-trust-state")
        .arg(&substituted_trust_path)
        .arg("--decision")
        .arg(&completion_a)
        .arg("--decision")
        .arg(&completion_b)
        .arg("--recorded-at-unix")
        .arg("1800")
        .arg("--output")
        .arg(temporary.join("substituted-deployment.json"))
        .output()
        .unwrap();
    assert!(!substitution.status.success());
    assert!(
        String::from_utf8_lossy(&substitution.stderr).contains("trusted signing root"),
        "{}",
        String::from_utf8_lossy(&substitution.stderr)
    );
    let deployment_schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("policy-deployment-state-schema")
        .output()
        .unwrap();
    assert!(deployment_schema.status.success());
    let deployment_schema: serde_json::Value =
        serde_json::from_slice(&deployment_schema.stdout).unwrap();
    assert_eq!(deployment_schema["additionalProperties"], false);
    let mut unreviewed_candidate = candidate_policy.clone();
    unreviewed_candidate["require_simulation_evidence"] = serde_json::json!(
        !unreviewed_candidate["require_simulation_evidence"]
            .as_bool()
            .unwrap()
    );
    let unreviewed_candidate_path = temporary.join("unreviewed-candidate-policy.json");
    fs::write(
        &unreviewed_candidate_path,
        serde_json::to_string_pretty(&unreviewed_candidate).unwrap(),
    )
    .unwrap();
    let unreviewed_signed = temporary.join("unreviewed-candidate-policy.signed.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-policy-pack")
            .arg(&unreviewed_candidate_path)
            .arg("--private-key")
            .arg(&policy_private_key)
            .arg("--signer-id")
            .arg("policy-authority")
            .arg("--output")
            .arg(&unreviewed_signed)
            .status()
            .unwrap()
            .success()
    );
    let unreviewed_verified = temporary.join("unreviewed-candidate-policy.verified.json");
    let unreviewed_trust = temporary.join("unreviewed-candidate-policy.trust.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("verify-policy-pack")
            .arg(&unreviewed_signed)
            .arg("--public-key")
            .arg(&policy_public_key)
            .arg("--baseline-state")
            .arg(&policy_trust_state)
            .arg("--state-output")
            .arg(&unreviewed_trust)
            .arg("--output")
            .arg(&unreviewed_verified)
            .status()
            .unwrap()
            .success()
    );
    let unreviewed = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("advance-policy-deployment")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&verified_policy)
        .arg("--candidate-policy-pack")
        .arg(&unreviewed_verified)
        .arg("--source-policy-trust-state")
        .arg(&policy_trust_state)
        .arg("--candidate-policy-trust-state")
        .arg(&unreviewed_trust)
        .arg("--decision")
        .arg(&completion_a)
        .arg("--decision")
        .arg(&completion_b)
        .arg("--recorded-at-unix")
        .arg("1800")
        .arg("--output")
        .arg(temporary.join("unreviewed-deployment.json"))
        .output()
        .unwrap();
    assert!(!unreviewed.status.success());
    assert!(
        String::from_utf8_lossy(&unreviewed.stderr).contains("governance changes"),
        "{}",
        String::from_utf8_lossy(&unreviewed.stderr)
    );
    let mut rollback_candidate = candidate_policy.clone();
    rollback_candidate["revision"] = serde_json::json!(3);
    let rollback_candidate_path = temporary.join("rollback-candidate-policy.json");
    fs::write(
        &rollback_candidate_path,
        serde_json::to_string_pretty(&rollback_candidate).unwrap(),
    )
    .unwrap();
    let rollback_candidate_signed = temporary.join("rollback-candidate-policy.signed.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-policy-pack")
            .arg(&rollback_candidate_path)
            .arg("--private-key")
            .arg(&policy_private_key)
            .arg("--signer-id")
            .arg("policy-authority")
            .arg("--output")
            .arg(&rollback_candidate_signed)
            .status()
            .unwrap()
            .success()
    );
    let rollback_candidate_verified = temporary.join("rollback-candidate-policy.verified.json");
    let rollback_candidate_trust = temporary.join("rollback-candidate-policy.trust.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("verify-policy-pack")
            .arg(&rollback_candidate_signed)
            .arg("--public-key")
            .arg(&policy_public_key)
            .arg("--baseline-state")
            .arg(&candidate_policy_trust_state)
            .arg("--state-output")
            .arg(&rollback_candidate_trust)
            .arg("--output")
            .arg(&rollback_candidate_verified)
            .status()
            .unwrap()
            .success()
    );
    let promoted_revision_three = temporary.join("promoted-revision-three.json");
    let promoted_revision_three_result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("advance-policy-deployment")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&verified_policy)
        .arg("--candidate-policy-pack")
        .arg(&rollback_candidate_verified)
        .arg("--source-policy-trust-state")
        .arg(&policy_trust_state)
        .arg("--candidate-policy-trust-state")
        .arg(&rollback_candidate_trust)
        .arg("--decision")
        .arg(&completion_a)
        .arg("--decision")
        .arg(&completion_b)
        .arg("--baseline-state")
        .arg(&deployment)
        .arg("--recorded-at-unix")
        .arg("1801")
        .arg("--output")
        .arg(&promoted_revision_three)
        .output()
        .unwrap();
    assert!(
        promoted_revision_three_result.status.success(),
        "{}",
        String::from_utf8_lossy(&promoted_revision_three_result.stderr)
    );
    let promoted_revision_three_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&promoted_revision_three).unwrap()).unwrap();
    assert_eq!(promoted_revision_three_document["active_revision"], 3);
    assert_eq!(promoted_revision_three_document["rollback_revision"], 2);
    let deployed_revision_three = temporary.join("deployed-revision-three");
    assert!(
        analyze(
            &deployed_revision_three,
            "--policy-pack",
            &rollback_candidate_verified
        )
        .status
        .success()
    );
    let regressed_revision_three = temporary.join("deployed-revision-three-regressed");
    fs::create_dir(&regressed_revision_three).unwrap();
    let mut revision_three_run: serde_json::Value =
        serde_json::from_slice(&fs::read(deployed_revision_three.join("run.json")).unwrap())
            .unwrap();
    revision_three_run["result"]["violations"] = serde_json::json!(2);
    fs::write(
        regressed_revision_three.join("run.json"),
        serde_json::to_string_pretty(&revision_three_run).unwrap(),
    )
    .unwrap();
    let mut revision_three_checks: serde_json::Value =
        serde_json::from_slice(&fs::read(deployed_revision_three.join("checks.json")).unwrap())
            .unwrap();
    revision_three_checks["violations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "rule": "clearance",
            "message": "revision three production regression",
            "net_ids": [1]
        }));
    fs::write(
        regressed_revision_three.join("checks.json"),
        serde_json::to_string_pretty(&revision_three_checks).unwrap(),
    )
    .unwrap();
    fs::copy(
        deployed_revision_three.join("quality.json"),
        regressed_revision_three.join("quality.json"),
    )
    .unwrap();
    let revision_three_verification = temporary.join("revision-three-verification.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("verify-policy-deployment")
            .arg(&promoted_revision_three)
            .arg(&rollout)
            .arg("--candidate-policy-pack")
            .arg(&rollback_candidate_verified)
            .arg("--project-id")
            .arg("controller")
            .arg("--board")
            .arg(&board)
            .arg("--expected-analysis")
            .arg(&candidate)
            .arg("--observed-analysis")
            .arg(&regressed_revision_three)
            .arg("--verified-at-unix")
            .arg("1900")
            .arg("--output")
            .arg(&revision_three_verification)
            .status()
            .unwrap()
            .success()
    );
    let production_rollback_a = temporary.join("production-rollback-a.json");
    let production_rollback_b = temporary.join("production-rollback-b.json");
    for (private_key, signer_id, signed) in [
        (&key_a, "reviewer-a", &production_rollback_a),
        (&key_b, "reviewer-b", &production_rollback_b),
    ] {
        assert!(
            Command::new(env!("CARGO_BIN_EXE_pcbex"))
                .arg("sign-policy-deployment-rollback")
                .arg(&promoted_revision_three)
                .arg(&revision_three_verification)
                .arg("--approved-at-unix")
                .arg("1901")
                .arg("--private-key")
                .arg(private_key)
                .arg("--signer-id")
                .arg(signer_id)
                .arg("--reason")
                .arg("Production evidence regressed after policy promotion.")
                .arg("--ticket")
                .arg("HW-46")
                .arg("--output")
                .arg(signed)
                .status()
                .unwrap()
                .success()
        );
    }
    let production_rollback_state = temporary.join("production-rollback-state.json");
    let applied_production_rollback = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("apply-policy-deployment-rollback")
        .arg(&promoted_revision_three)
        .arg(&revision_three_verification)
        .arg("--active-policy-pack")
        .arg(&rollback_candidate_verified)
        .arg("--approval")
        .arg(&production_rollback_a)
        .arg("--approval")
        .arg(&production_rollback_b)
        .arg("--recorded-at-unix")
        .arg("1902")
        .arg("--output")
        .arg(&production_rollback_state)
        .arg("--require-applied")
        .output()
        .unwrap();
    assert!(
        applied_production_rollback.status.success(),
        "{}",
        String::from_utf8_lossy(&applied_production_rollback.stderr)
    );
    let production_rollback_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&production_rollback_state).unwrap()).unwrap();
    assert_eq!(production_rollback_document["status"], "rollback_applied");
    assert_eq!(production_rollback_document["generation"], 3);
    assert_eq!(production_rollback_document["active_revision"], 2);
    assert_eq!(production_rollback_document["failed_revision"], 3);
    assert_eq!(production_rollback_document["approvals"], 2);
    assert_eq!(production_rollback_document["rollback_applied"], true);
    assert_eq!(production_rollback_document["automatic_rollback"], false);
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-policy-deployment-rollback-state")
            .arg(&production_rollback_state)
            .status()
            .unwrap()
            .success()
    );
    let insufficient_production_rollback = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("apply-policy-deployment-rollback")
        .arg(&promoted_revision_three)
        .arg(&revision_three_verification)
        .arg("--active-policy-pack")
        .arg(&rollback_candidate_verified)
        .arg("--approval")
        .arg(&production_rollback_a)
        .arg("--recorded-at-unix")
        .arg("1902")
        .arg("--output")
        .arg(temporary.join("insufficient-production-rollback.json"))
        .output()
        .unwrap();
    assert!(!insufficient_production_rollback.status.success());
    assert!(
        String::from_utf8_lossy(&insufficient_production_rollback.stderr)
            .contains("dual-control quorum"),
        "{}",
        String::from_utf8_lossy(&insufficient_production_rollback.stderr)
    );
    let replayed_production_rollback = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("apply-policy-deployment-rollback")
        .arg(&promoted_revision_three)
        .arg(&revision_three_verification)
        .arg("--active-policy-pack")
        .arg(&rollback_candidate_verified)
        .arg("--approval")
        .arg(&production_rollback_a)
        .arg("--approval")
        .arg(&production_rollback_a)
        .arg("--recorded-at-unix")
        .arg("1902")
        .arg("--output")
        .arg(temporary.join("replayed-production-rollback.json"))
        .output()
        .unwrap();
    assert!(!replayed_production_rollback.status.success());
    assert!(
        String::from_utf8_lossy(&replayed_production_rollback.stderr).contains("distinct signer"),
        "{}",
        String::from_utf8_lossy(&replayed_production_rollback.stderr)
    );
    let mut tampered_approval: serde_json::Value =
        serde_json::from_slice(&fs::read(&production_rollback_a).unwrap()).unwrap();
    tampered_approval["ticket"] = serde_json::json!("HW-TAMPERED");
    let tampered_approval_path = temporary.join("tampered-production-rollback.json");
    fs::write(
        &tampered_approval_path,
        serde_json::to_string_pretty(&tampered_approval).unwrap(),
    )
    .unwrap();
    let tampered_production_rollback = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("apply-policy-deployment-rollback")
        .arg(&promoted_revision_three)
        .arg(&revision_three_verification)
        .arg("--active-policy-pack")
        .arg(&rollback_candidate_verified)
        .arg("--approval")
        .arg(&tampered_approval_path)
        .arg("--approval")
        .arg(&production_rollback_b)
        .arg("--recorded-at-unix")
        .arg("1902")
        .arg("--output")
        .arg(temporary.join("tampered-production-rollback-state.json"))
        .output()
        .unwrap();
    assert!(!tampered_production_rollback.status.success());
    assert!(
        String::from_utf8_lossy(&tampered_production_rollback.stderr)
            .contains("invalid deployment rollback signature"),
        "{}",
        String::from_utf8_lossy(&tampered_production_rollback.stderr)
    );
    let signed_rollback_schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("signed-policy-deployment-rollback-schema")
        .output()
        .unwrap();
    assert!(signed_rollback_schema.status.success());
    let signed_rollback_schema: serde_json::Value =
        serde_json::from_slice(&signed_rollback_schema.stdout).unwrap();
    assert_eq!(signed_rollback_schema["additionalProperties"], false);
    let rollback_state_schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("policy-deployment-rollback-state-schema")
        .output()
        .unwrap();
    assert!(rollback_state_schema.status.success());
    let rollback_state_schema: serde_json::Value =
        serde_json::from_slice(&rollback_state_schema.stdout).unwrap();
    assert_eq!(rollback_state_schema["additionalProperties"], false);
    assert_eq!(
        rollback_state_schema["properties"]["automatic_rollback"]["const"],
        false
    );
    let restored_observation = temporary.join("restored-revision-two");
    assert!(
        analyze(
            &restored_observation,
            "--policy-pack",
            &verified_candidate_policy
        )
        .status
        .success()
    );
    let recovery = temporary.join("policy-rollback-recovery.json");
    let recovery_result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-policy-rollback-recovery")
        .arg(&production_rollback_state)
        .arg(&rollout)
        .arg("--deployment")
        .arg(&promoted_revision_three)
        .arg("--failed-verification")
        .arg(&revision_three_verification)
        .arg("--previous-deployment")
        .arg(&deployment)
        .arg("--baseline-verification")
        .arg(&deployment_verification)
        .arg("--restored-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--project-id")
        .arg("controller")
        .arg("--board")
        .arg(&board)
        .arg("--expected-analysis")
        .arg(&deployed)
        .arg("--observed-analysis")
        .arg(&restored_observation)
        .arg("--verified-at-unix")
        .arg("1903")
        .arg("--output")
        .arg(&recovery)
        .arg("--require-passed")
        .output()
        .unwrap();
    assert!(
        recovery_result.status.success(),
        "{}",
        String::from_utf8_lossy(&recovery_result.stderr)
    );
    let recovery_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&recovery).unwrap()).unwrap();
    assert_eq!(recovery_document["status"], "recovery_verified");
    assert_eq!(recovery_document["coverage_complete"], true);
    assert_eq!(recovery_document["recovery_verified"], true);
    assert_eq!(recovery_document["requires_operator_acknowledgment"], true);
    assert_eq!(recovery_document["automatic_incident_closure"], false);

    let wrong_recovery = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-policy-rollback-recovery")
        .arg(&production_rollback_state)
        .arg(&rollout)
        .arg("--deployment")
        .arg(&promoted_revision_three)
        .arg("--failed-verification")
        .arg(&revision_three_verification)
        .arg("--previous-deployment")
        .arg(&deployment)
        .arg("--baseline-verification")
        .arg(&deployment_verification)
        .arg("--restored-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--project-id")
        .arg("controller")
        .arg("--board")
        .arg(&board)
        .arg("--expected-analysis")
        .arg(&candidate)
        .arg("--observed-analysis")
        .arg(&restored_observation)
        .arg("--verified-at-unix")
        .arg("1903")
        .arg("--output")
        .arg(temporary.join("wrong-recovery.json"))
        .output()
        .unwrap();
    assert!(!wrong_recovery.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_recovery.stderr)
            .contains("pre-promotion production baseline")
    );

    let incident_acknowledgment = temporary.join("rollback-incident-acknowledgment.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-rollback-incident-acknowledgment")
            .arg(&production_rollback_state)
            .arg(&recovery)
            .arg("--acknowledged-at-unix")
            .arg("1904")
            .arg("--private-key")
            .arg(&key_c)
            .arg("--operator-id")
            .arg("incident-operator")
            .arg("--reason")
            .arg("The restored production fleet is complete and clean.")
            .arg("--ticket")
            .arg("HW-46")
            .arg("--output")
            .arg(&incident_acknowledgment)
            .status()
            .unwrap()
            .success()
    );
    let incident_closure = temporary.join("rollback-incident-closure.json");
    let closure_result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("close-rollback-incident")
        .arg(&production_rollback_state)
        .arg(&recovery)
        .arg("--restored-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--acknowledgment")
        .arg(&incident_acknowledgment)
        .arg("--closed-at-unix")
        .arg("1905")
        .arg("--output")
        .arg(&incident_closure)
        .arg("--require-closed")
        .output()
        .unwrap();
    assert!(
        closure_result.status.success(),
        "{}",
        String::from_utf8_lossy(&closure_result.stderr)
    );
    let closure_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&incident_closure).unwrap()).unwrap();
    assert_eq!(closure_document["status"], "incident_closed");
    assert_eq!(closure_document["operator_id"], "incident-operator");
    assert_eq!(closure_document["automatic_incident_closure"], false);
    let incident_ledger = temporary.join("policy-incident-ledger.json");
    let ledger_result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("append-policy-incident-ledger")
        .arg(&production_rollback_state)
        .arg("--failed-verification")
        .arg(&revision_three_verification)
        .arg("--recovery")
        .arg(&recovery)
        .arg("--closure")
        .arg(&incident_closure)
        .arg("--output")
        .arg(&incident_ledger)
        .output()
        .unwrap();
    assert!(
        ledger_result.status.success(),
        "{}",
        String::from_utf8_lossy(&ledger_result.stderr)
    );
    let ledger_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&incident_ledger).unwrap()).unwrap();
    assert_eq!(ledger_document["entry_count"], 1);
    assert_eq!(ledger_document["generation"], 1);
    assert_eq!(ledger_document["requires_human_suspension_review"], false);
    assert_eq!(ledger_document["automatic_policy_suspension"], false);
    assert_eq!(ledger_document["entries"][0]["time_to_rollback_seconds"], 2);
    assert_eq!(ledger_document["entries"][0]["time_to_recovery_seconds"], 3);
    assert_eq!(ledger_document["entries"][0]["time_to_close_seconds"], 5);
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("validate-policy-incident-ledger")
            .arg(&incident_ledger)
            .status()
            .unwrap()
            .success()
    );
    let duplicate_incident = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("append-policy-incident-ledger")
        .arg(&production_rollback_state)
        .arg("--failed-verification")
        .arg(&revision_three_verification)
        .arg("--recovery")
        .arg(&recovery)
        .arg("--closure")
        .arg(&incident_closure)
        .arg("--baseline-ledger")
        .arg(&incident_ledger)
        .arg("--output")
        .arg(temporary.join("duplicate-policy-incident-ledger.json"))
        .output()
        .unwrap();
    assert!(!duplicate_incident.status.success());
    assert!(String::from_utf8_lossy(&duplicate_incident.stderr).contains("already retained"));

    let self_acknowledgment = temporary.join("rollback-self-acknowledgment.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-rollback-incident-acknowledgment")
            .arg(&production_rollback_state)
            .arg(&recovery)
            .arg("--acknowledged-at-unix")
            .arg("1904")
            .arg("--private-key")
            .arg(&key_a)
            .arg("--operator-id")
            .arg("reviewer-a")
            .arg("--reason")
            .arg("Self closure must be rejected.")
            .arg("--ticket")
            .arg("HW-46")
            .arg("--output")
            .arg(&self_acknowledgment)
            .status()
            .unwrap()
            .success()
    );
    let self_closure = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("close-rollback-incident")
        .arg(&production_rollback_state)
        .arg(&recovery)
        .arg("--restored-policy-pack")
        .arg(&verified_candidate_policy)
        .arg("--acknowledgment")
        .arg(&self_acknowledgment)
        .arg("--closed-at-unix")
        .arg("1905")
        .arg("--output")
        .arg(temporary.join("rollback-self-closure.json"))
        .output()
        .unwrap();
    assert!(!self_closure.status.success());
    assert!(String::from_utf8_lossy(&self_closure.stderr).contains("independent"));

    for schema_command in [
        "policy-rollback-recovery-schema",
        "signed-rollback-incident-acknowledgment-schema",
        "rollback-incident-closure-schema",
        "policy-incident-ledger-schema",
    ] {
        let schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg(schema_command)
            .output()
            .unwrap();
        assert!(schema.status.success());
        let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }
    let deployment_rollback_a = temporary.join("deployment-rollback-a.json");
    let deployment_rollback_b = temporary.join("deployment-rollback-b.json");
    for (private_key, signer_id, signed) in [
        (&key_a, "reviewer-a", &deployment_rollback_a),
        (&key_b, "reviewer-b", &deployment_rollback_b),
    ] {
        assert!(
            Command::new(env!("CARGO_BIN_EXE_pcbex"))
                .arg("sign-canary-completion")
                .arg(&rollout)
                .arg(&monitoring)
                .arg(&authorization)
                .arg("--decision")
                .arg("rollback")
                .arg("--decided-at-unix")
                .arg("1701")
                .arg("--private-key")
                .arg(private_key)
                .arg("--signer-id")
                .arg(signer_id)
                .arg("--reason")
                .arg("Production promotion is withheld.")
                .arg("--ticket")
                .arg("HW-45")
                .arg("--output")
                .arg(signed)
                .status()
                .unwrap()
                .success()
        );
    }
    let rolled_back_deployment = temporary.join("rolled-back-deployment.json");
    let rollback_result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("advance-policy-deployment")
        .arg(&rollout)
        .arg(&monitoring)
        .arg(&authorization)
        .arg("--policy-pack")
        .arg(&verified_policy)
        .arg("--candidate-policy-pack")
        .arg(&rollback_candidate_verified)
        .arg("--source-policy-trust-state")
        .arg(&policy_trust_state)
        .arg("--candidate-policy-trust-state")
        .arg(&rollback_candidate_trust)
        .arg("--decision")
        .arg(&deployment_rollback_a)
        .arg("--decision")
        .arg(&deployment_rollback_b)
        .arg("--baseline-state")
        .arg(&deployment)
        .arg("--recorded-at-unix")
        .arg("1801")
        .arg("--output")
        .arg(&rolled_back_deployment)
        .output()
        .unwrap();
    assert!(
        rollback_result.status.success(),
        "{}",
        String::from_utf8_lossy(&rollback_result.stderr)
    );
    let rolled_back: serde_json::Value =
        serde_json::from_slice(&fs::read(&rolled_back_deployment).unwrap()).unwrap();
    assert_eq!(rolled_back["status"], "rollback_confirmed");
    assert_eq!(rolled_back["generation"], 2);
    assert_eq!(rolled_back["active_revision"], 2);
    assert_eq!(rolled_back["candidate_revision"], 3);
    assert_eq!(rolled_back["rollback_revision"], 2);
    assert_eq!(rolled_back["deployment_applied"], false);
    assert_eq!(
        rolled_back["previous_state_sha256"].as_str().unwrap().len(),
        64
    );
    let rollback_b = temporary.join("completion-rollback-b.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-canary-completion")
            .arg(&rollout)
            .arg(&monitoring)
            .arg(&authorization)
            .arg("--decision")
            .arg("rollback")
            .arg("--decided-at-unix")
            .arg("1700")
            .arg("--private-key")
            .arg(&key_b)
            .arg("--signer-id")
            .arg("reviewer-b")
            .arg("--reason")
            .arg("Conservative rollback requested.")
            .arg("--ticket")
            .arg("HW-43")
            .arg("--output")
            .arg(&rollback_b)
            .status()
            .unwrap()
            .success()
    );
    let disagreement_path = temporary.join("completion-disagreement.json");
    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("verify-canary-completion")
            .arg(&rollout)
            .arg(&monitoring)
            .arg(&authorization)
            .arg("--policy-pack")
            .arg(&policy_path)
            .arg("--decision")
            .arg(&completion_a)
            .arg("--decision")
            .arg(&rollback_b)
            .arg("--output")
            .arg(&disagreement_path)
            .status()
            .unwrap()
            .success()
    );
    let disagreement: serde_json::Value =
        serde_json::from_slice(&fs::read(&disagreement_path).unwrap()).unwrap();
    assert_eq!(disagreement["finalized"], false);
    assert!(
        disagreement["gate_failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure == "completion_decisions_disagree")
    );
    for schema_command in [
        "signed-canary-completion-schema",
        "canary-completion-schema",
    ] {
        let schema = Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg(schema_command)
            .output()
            .unwrap();
        assert!(schema.status.success());
        let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("sign-canary-completion")
            .arg(&rollout)
            .arg(&monitoring)
            .arg(&authorization)
            .arg("--decision")
            .arg("promote")
            .arg("--decided-at-unix")
            .arg("2001")
            .arg("--private-key")
            .arg(&key_a)
            .arg("--signer-id")
            .arg("reviewer-a")
            .arg("--reason")
            .arg("Too late.")
            .arg("--ticket")
            .arg("HW-44")
            .arg("--output")
            .arg(temporary.join("late-completion.json"))
            .status()
            .unwrap()
            .success()
    );
    let expired_authorization = temporary.join("expired-canary.json");
    let expired = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-rollout-approvals")
        .arg(&rollout)
        .arg("--policy-pack")
        .arg(&policy_path)
        .arg("--approval")
        .arg(&approval_a)
        .arg("--approval")
        .arg(&approval_b)
        .arg("--evaluated-at-unix")
        .arg("2001")
        .arg("--output")
        .arg(&expired_authorization)
        .output()
        .unwrap();
    assert!(expired.status.success());
    let expired: serde_json::Value =
        serde_json::from_slice(&fs::read(&expired_authorization).unwrap()).unwrap();
    assert_eq!(expired["canary_authorized"], false);
    assert!(
        expired["gate_failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure == "approval_window_inactive")
    );
    let mut tampered_approval: serde_json::Value =
        serde_json::from_slice(&fs::read(&approval_a).unwrap()).unwrap();
    let signature = tampered_approval["signature"].as_str().unwrap();
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    tampered_approval["signature"] = serde_json::json!(format!("{replacement}{}", &signature[1..]));
    let tampered_approval_path = temporary.join("tampered-rollout-approval.json");
    fs::write(
        &tampered_approval_path,
        serde_json::to_string_pretty(&tampered_approval).unwrap(),
    )
    .unwrap();
    let tampered_authorization = temporary.join("tampered-canary.json");
    let tampered = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("verify-rollout-approvals")
        .arg(&rollout)
        .arg("--policy-pack")
        .arg(&policy_path)
        .arg("--approval")
        .arg(&tampered_approval_path)
        .arg("--approval")
        .arg(&approval_b)
        .arg("--evaluated-at-unix")
        .arg("1500")
        .arg("--output")
        .arg(&tampered_authorization)
        .arg("--require-authorized")
        .output()
        .unwrap();
    assert!(!tampered.status.success());
    assert!(
        String::from_utf8_lossy(&tampered.stderr).contains("signature"),
        "{}",
        String::from_utf8_lossy(&tampered.stderr)
    );
    assert!(!tampered_authorization.exists());

    let candidate_run_path = candidate.join("run.json");
    let mut candidate_run: serde_json::Value =
        serde_json::from_slice(&fs::read(&candidate_run_path).unwrap()).unwrap();
    candidate_run["input"]["sha256"] = serde_json::json!("f".repeat(64));
    fs::write(
        &candidate_run_path,
        serde_json::to_string_pretty(&candidate_run).unwrap(),
    )
    .unwrap();
    assert!(
        !Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("simulate-policy-rollout")
            .arg(&policy_path)
            .arg(&output)
            .arg("--project-id")
            .arg("controller")
            .arg("--board")
            .arg(&board)
            .arg("--baseline-analysis")
            .arg(&baseline)
            .arg("--candidate-analysis")
            .arg(&candidate)
            .arg("--generated-on")
            .arg("2026-07-29")
            .arg("--output")
            .arg(temporary.join("tampered-simulation.json"))
            .status()
            .unwrap()
            .success()
    );

    fs::remove_dir_all(temporary).unwrap();
}
