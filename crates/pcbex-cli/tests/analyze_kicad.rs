use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_directory(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pcbex-{name}-{}-{unique}", std::process::id()))
}

fn analyze(input: &Path, output: &Path, fail_on_violations: bool) -> std::process::ExitStatus {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pcbex"));
    command
        .arg("analyze-kicad")
        .arg(input)
        .arg("--output-dir")
        .arg(output);
    if fail_on_violations {
        command.arg("--fail-on-violations");
    }
    command.status().expect("analyze-kicad must start")
}

#[test]
fn analyze_kicad_writes_a_complete_bundle_before_gating() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/simple.kicad_pcb");
    let output = temporary_directory("analysis");
    let gated_output = temporary_directory("analysis-gated");

    assert!(analyze(&input, &output, false).success());
    for artifact in [
        "board.json",
        "board.svg",
        "checks.json",
        "quality.json",
        "report.sarif",
        "summary.md",
        "run.json",
    ] {
        assert!(output.join(artifact).is_file(), "missing {artifact}");
    }

    let manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(output.join("run.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["command"], "analyze-kicad");
    assert_eq!(manifest["input"]["bytes"], 1104);
    assert_eq!(
        manifest["input"]["sha256"],
        "6c740dcb4e44c7dc546d3dac46d6b588ae571e58f7e65411cd17faf61d86bd2f"
    );
    assert_eq!(manifest["result"]["violations"], 1);
    assert_eq!(manifest["artifacts"].as_array().unwrap().len(), 7);

    assert!(!analyze(&input, &gated_output, true).success());
    assert!(gated_output.join("run.json").is_file());
    assert!(gated_output.join("report.sarif").is_file());

    fs::remove_dir_all(output).unwrap();
    fs::remove_dir_all(gated_output).unwrap();
}
