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
    let path = std::env::temp_dir().join(format!("pcbex-schematic-diff-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn compares_electrical_intent_and_retains_failed_gate_reports() {
    let directory = temp_dir();
    let baseline =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let unchanged = directory.join("unchanged.json");
    assert!(
        run(&[
            "compare-schematics",
            path(&baseline),
            path(&baseline),
            "--output",
            path(&unchanged),
            "--require-no-review",
        ])
        .status
        .success()
    );
    let unchanged_value: Value = serde_json::from_slice(&fs::read(&unchanged).unwrap()).unwrap();
    assert_eq!(unchanged_value["changed"], false);
    assert_eq!(unchanged_value["review_required"], false);
    assert_eq!(
        unchanged_value["baseline"]["schematic_sha256"],
        unchanged_value["current"]["schematic_sha256"]
    );

    let current = directory.join("current.kicad_sch");
    let source = fs::read_to_string(&baseline)
        .unwrap()
        .replace("\"10k\"", "\"22k\"");
    fs::write(&current, source).unwrap();
    let output = directory.join("diff.json");
    let summary = directory.join("diff.md");
    let sarif = directory.join("diff.sarif");
    let changed = run(&[
        "compare-schematics",
        path(&baseline),
        path(&current),
        "--output",
        path(&output),
        "--summary-output",
        path(&summary),
        "--sarif-output",
        path(&sarif),
        "--require-no-review",
    ]);
    assert!(!changed.status.success());
    assert!(output.is_file());
    assert!(summary.is_file());
    assert!(sarif.is_file());
    let diff: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(diff["changed"], true);
    assert_eq!(diff["review_required"], true);
    assert_eq!(diff["counts"]["modified_symbols"], 1);
    assert_eq!(diff["modified_symbols"][0]["current_reference"], "R1");
    assert!(
        diff["modified_symbols"][0]["changed_fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "value")
    );
    assert!(fs::read_to_string(summary).unwrap().contains("R1"));
    let sarif: Value = serde_json::from_slice(&fs::read(sarif).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "schematic_symbol_modified"
    );

    let schema = directory.join("schema.json");
    assert!(
        run(&["schematic-diff-schema", "--output", path(&schema),])
            .status
            .success()
    );
    let schema: Value = serde_json::from_slice(&fs::read(schema).unwrap()).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["$defs"]["symbol_change"]["additionalProperties"],
        false
    );

    fs::remove_dir_all(directory).unwrap();
}
