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

    fs::remove_dir_all(temporary).unwrap();
}
