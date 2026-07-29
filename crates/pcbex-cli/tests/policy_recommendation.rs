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
    let policy_path = root.join("examples/acme-policy-pack.json");
    let policy: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&policy_path).unwrap()).unwrap();
    let temporary = temporary_directory("policy-recommendation");
    fs::create_dir_all(&temporary).unwrap();
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
