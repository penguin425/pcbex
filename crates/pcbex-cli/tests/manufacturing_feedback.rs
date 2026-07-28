use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary()).args(arguments).output().unwrap()
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-manufacturing-feedback-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn declaration(board_sha256: &Value, disposition: &str, severity: &str) -> Value {
    json!({
        "schema_version": 1,
        "id": "fab-lot-42",
        "manufacturer": {
            "id": "example-fab",
            "process": "4-layer production",
            "lot": "lot-42"
        },
        "received_on": "2026-07-29",
        "board_sha256": board_sha256,
        "disposition": disposition,
        "findings": [{
            "id": "mask-sliver",
            "category": "solder_mask",
            "severity": severity,
            "message": "Mask sliver was below the preferred process target.",
            "measurement": {
                "name": "minimum mask sliver",
                "value": 0.08,
                "unit": "mm",
                "minimum": 0.10
            },
            "evidence": ["inspection.csv"]
        }]
    })
}

#[test]
fn binds_fabrication_evidence_and_gates_regressions() {
    let directory = temp_dir();
    let board = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_pcb");
    let analysis = directory.join("analysis");
    assert!(
        run(&[
            "analyze-kicad",
            path(&board),
            "--output-dir",
            path(&analysis),
        ])
        .status
        .success()
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(analysis.join("run.json")).unwrap()).unwrap();
    let board_sha256 = manifest["input"]["sha256"].clone();
    let raw = directory.join("inspection.csv");
    fs::write(&raw, "metric,value\nmask_sliver_mm,0.08\n").unwrap();

    let baseline_declaration = directory.join("baseline-declaration.json");
    fs::write(
        &baseline_declaration,
        serde_json::to_vec_pretty(&declaration(&board_sha256, "accepted", "info")).unwrap(),
    )
    .unwrap();
    let baseline = directory.join("baseline.json");
    let baseline_summary = directory.join("baseline.md");
    let baseline_sarif = directory.join("baseline.sarif");
    let record_arguments = [
        "record-manufacturing-feedback",
        path(&baseline_declaration),
        "--analysis-dir",
        path(&analysis),
        "--board",
        path(&board),
        "--artifact",
        path(&raw),
        "--output",
        path(&baseline),
        "--summary-output",
        path(&baseline_summary),
        "--sarif-output",
        path(&baseline_sarif),
        "--require-passed",
    ];
    assert!(run(&record_arguments).status.success());
    let first_bytes = fs::read(&baseline).unwrap();
    let second = directory.join("baseline-second.json");
    let mut second_arguments = record_arguments;
    second_arguments[9] = path(&second);
    assert!(run(&second_arguments).status.success());
    assert_eq!(first_bytes, fs::read(&second).unwrap());
    let feedback: Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(feedback["passed"], true);
    assert_eq!(feedback["board"]["sha256"], board_sha256);
    assert_eq!(feedback["analysis_manifest"]["name"], "run.json");
    assert_eq!(feedback["artifacts"][0]["name"], "inspection.csv");
    assert!(
        fs::read_to_string(&baseline_summary)
            .unwrap()
            .contains("Manufacturing feedback")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&baseline_sarif).unwrap()).unwrap()["version"],
        "2.1.0"
    );

    let current_declaration = directory.join("current-declaration.json");
    fs::write(
        &current_declaration,
        serde_json::to_vec_pretty(&declaration(&board_sha256, "rejected", "error")).unwrap(),
    )
    .unwrap();
    let current = directory.join("current.json");
    let failed = run(&[
        "record-manufacturing-feedback",
        path(&current_declaration),
        "--analysis-dir",
        path(&analysis),
        "--board",
        path(&board),
        "--artifact",
        path(&raw),
        "--output",
        path(&current),
        "--require-passed",
    ]);
    assert!(!failed.status.success());
    assert!(current.is_file(), "failed gate must retain bound evidence");

    let comparison = directory.join("comparison.json");
    let comparison_summary = directory.join("comparison.md");
    let comparison_sarif = directory.join("comparison.sarif");
    let compared = run(&[
        "compare-manufacturing-feedback",
        path(&baseline),
        path(&current),
        "--output",
        path(&comparison),
        "--summary-output",
        path(&comparison_summary),
        "--sarif-output",
        path(&comparison_sarif),
        "--fail-on-regressions",
    ]);
    assert!(!compared.status.success());
    let delta: Value = serde_json::from_slice(&fs::read(&comparison).unwrap()).unwrap();
    assert_eq!(delta["regression"], true);
    assert_eq!(delta["escalated_findings"][0]["id"], "mask-sliver");
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&comparison_sarif).unwrap()).unwrap()["runs"][0]
            ["results"][0]["ruleId"],
        "manufacturing_finding_escalated"
    );

    for (command, filename) in [
        (
            "manufacturing-feedback-declaration-schema",
            "declaration.schema.json",
        ),
        ("manufacturing-feedback-schema", "feedback.schema.json"),
        (
            "manufacturing-feedback-comparison-schema",
            "comparison.schema.json",
        ),
    ] {
        let output = directory.join(filename);
        assert!(run(&[command, "--output", path(&output)]).status.success());
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }

    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        run(&[
            "record-manufacturing-feedback",
            path(&repository.join("examples/manufacturing-feedback-declaration.json")),
            "--analysis-dir",
            path(&analysis),
            "--board",
            path(&board),
            "--artifact",
            path(&repository.join("examples/manufacturing-inspection.csv")),
            "--output",
            path(&directory.join("example-feedback.json")),
            "--require-passed",
        ])
        .status
        .success(),
        "documented manufacturing feedback example must remain bound to its board"
    );

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_wrong_board_unknown_fields_and_missing_artifacts() {
    let directory = temp_dir();
    let board = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_pcb");
    let other_board =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/nonrect.kicad_pcb");
    let analysis = directory.join("analysis");
    assert!(
        run(&[
            "analyze-kicad",
            path(&board),
            "--output-dir",
            path(&analysis),
        ])
        .status
        .success()
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(analysis.join("run.json")).unwrap()).unwrap();
    let mut value = declaration(&manifest["input"]["sha256"], "accepted", "warning");
    value["unexpected"] = true.into();
    let declaration_path = directory.join("declaration.json");
    fs::write(
        &declaration_path,
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    let raw = directory.join("different.csv");
    fs::write(&raw, "data").unwrap();
    let output = directory.join("feedback.json");
    let result = run(&[
        "record-manufacturing-feedback",
        path(&declaration_path),
        "--analysis-dir",
        path(&analysis),
        "--board",
        path(&board),
        "--artifact",
        path(&raw),
        "--output",
        path(&output),
    ]);
    assert!(!result.status.success());
    assert!(!output.exists());

    value.as_object_mut().unwrap().remove("unexpected");
    fs::write(
        &declaration_path,
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
    let missing = run(&[
        "record-manufacturing-feedback",
        path(&declaration_path),
        "--analysis-dir",
        path(&analysis),
        "--board",
        path(&board),
        "--artifact",
        path(&raw),
        "--output",
        path(&output),
    ]);
    assert!(!missing.status.success());
    assert!(!output.exists());

    fs::write(
        &declaration_path,
        serde_json::to_vec_pretty(&declaration(
            &manifest["input"]["sha256"],
            "accepted",
            "warning",
        ))
        .unwrap(),
    )
    .unwrap();
    fs::write(directory.join("inspection.csv"), "data").unwrap();
    let wrong_board = run(&[
        "record-manufacturing-feedback",
        path(&declaration_path),
        "--analysis-dir",
        path(&analysis),
        "--board",
        path(&other_board),
        "--artifact",
        path(&directory.join("inspection.csv")),
        "--output",
        path(&output),
    ]);
    assert!(!wrong_board.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_board.stderr)
            .contains("run manifest does not describe the supplied board")
    );
    assert!(!output.exists());

    fs::remove_dir_all(directory).unwrap();
}
