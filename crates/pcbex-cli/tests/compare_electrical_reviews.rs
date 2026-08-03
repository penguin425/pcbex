use serde_json::Value;
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
    let path = std::env::temp_dir().join(format!("pcbex-electrical-comparison-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn keeps_the_safety_floor_absolute_while_baselining_advisory_findings() {
    let directory = temp_dir();
    let floor_source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let floor_review = directory.join("floor-review.json");
    assert!(
        run(&[
            "check-schematic",
            path(&floor_source),
            "--output",
            path(&floor_review),
        ])
        .status
        .success()
    );
    let retained_floor = directory.join("retained-floor.json");
    let retained_floor_gate = run(&[
        "compare-electrical-reviews",
        path(&floor_review),
        path(&floor_review),
        "--output",
        path(&retained_floor),
        "--require-no-new-errors",
    ]);
    assert!(!retained_floor_gate.status.success());
    let retained_floor_report: Value =
        serde_json::from_slice(&fs::read(&retained_floor).unwrap()).unwrap();
    assert_eq!(retained_floor_report["passed"], false);
    assert_eq!(retained_floor_report["counts"]["new_errors"], 0);
    assert_eq!(retained_floor_report["counts"]["escalated_errors"], 0);
    assert!(
        retained_floor_report["counts"]["error_regressions"]
            .as_u64()
            .unwrap()
            > 0
    );

    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approved-empty.kicad_sch");
    let baseline = directory.join("baseline.json");
    assert!(
        run(&[
            "check-schematic",
            path(&source),
            "--output",
            path(&baseline),
        ])
        .status
        .success()
    );
    let mut baseline_value: Value = serde_json::from_slice(&fs::read(&baseline).unwrap()).unwrap();
    baseline_value["findings"] = serde_json::json!([{
        "id": "pcbex-er-1111111111111111",
        "rule": "missing_footprint",
        "severity": "warning",
        "message": "advisory footprint metadata finding",
        "net_id": null,
        "symbols": [],
        "pins": []
    }]);
    baseline_value["counts"]["errors"] = Value::from(0);
    baseline_value["counts"]["warnings"] = Value::from(1);
    baseline_value["counts"]["info"] = Value::from(0);
    baseline_value["approved"] = Value::Bool(true);
    fs::write(
        &baseline,
        serde_json::to_vec_pretty(&baseline_value).unwrap(),
    )
    .unwrap();

    let unchanged = directory.join("unchanged.json");
    assert!(
        run(&[
            "compare-electrical-reviews",
            path(&baseline),
            path(&baseline),
            "--output",
            path(&unchanged),
            "--require-no-new-errors",
        ])
        .status
        .success()
    );
    let unchanged_report: Value = serde_json::from_slice(&fs::read(&unchanged).unwrap()).unwrap();
    assert_eq!(unchanged_report["passed"], true);
    assert_eq!(unchanged_report["counts"]["error_regressions"], 0);

    let mut current: Value = serde_json::from_slice(&fs::read(&baseline).unwrap()).unwrap();
    current["findings"][0]["severity"] = Value::String("error".into());
    current["counts"]["errors"] = Value::from(current["counts"]["errors"].as_u64().unwrap() + 1);
    current["counts"]["warnings"] =
        Value::from(current["counts"]["warnings"].as_u64().unwrap() - 1);
    current["approved"] = Value::Bool(false);
    let current_path = directory.join("current.json");
    fs::write(&current_path, serde_json::to_vec_pretty(&current).unwrap()).unwrap();

    let regression = directory.join("regression.json");
    let gated = run(&[
        "compare-electrical-reviews",
        path(&baseline),
        path(&current_path),
        "--output",
        path(&regression),
        "--require-no-new-errors",
    ]);
    assert!(!gated.status.success());
    assert!(regression.is_file());
    let regression_report: Value = serde_json::from_slice(&fs::read(&regression).unwrap()).unwrap();
    assert_eq!(regression_report["passed"], false);
    assert_eq!(regression_report["counts"]["new_errors"], 0);
    assert_eq!(regression_report["counts"]["escalated_errors"], 1);
    assert_eq!(regression_report["counts"]["error_regressions"], 1);

    let schema = directory.join("comparison.schema.json");
    assert!(
        run(&[
            "electrical-review-comparison-schema",
            "--output",
            path(&schema),
        ])
        .status
        .success()
    );
    let schema: Value = serde_json::from_slice(&fs::read(schema).unwrap()).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);

    fs::remove_dir_all(directory).unwrap();
}
