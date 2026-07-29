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
    for (private, public) in [(&key_a, &public_a), (&key_b, &public_b)] {
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
        }
    ]);
    let policy_path = temporary.join("policy-pack.json");
    fs::write(&policy_path, serde_json::to_string_pretty(&policy).unwrap()).unwrap();
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
