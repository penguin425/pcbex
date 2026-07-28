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
fn gates_only_new_or_escalated_electrical_errors() {
    let directory = temp_dir();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
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
    baseline_value["findings"][0]["severity"] = Value::String("warning".into());
    baseline_value["counts"]["errors"] =
        Value::from(baseline_value["counts"]["errors"].as_u64().unwrap() - 1);
    baseline_value["counts"]["warnings"] =
        Value::from(baseline_value["counts"]["warnings"].as_u64().unwrap() + 1);
    baseline_value["approved"] =
        Value::Bool(baseline_value["counts"]["errors"].as_u64().unwrap() == 0);
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
