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

fn compare(
    baseline: &Path,
    current: &Path,
    output: &Path,
    fail_on_regressions: bool,
) -> std::process::ExitStatus {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pcbex"));
    command
        .arg("compare-analysis")
        .arg(baseline)
        .arg(current)
        .arg("--output-dir")
        .arg(output);
    if fail_on_regressions {
        command.arg("--fail-on-regressions");
    }
    command.status().expect("compare-analysis must start")
}

#[test]
fn analyze_kicad_writes_a_complete_bundle_before_gating() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/simple.kicad_pcb");
    let output = temporary_directory("analysis");
    let gated_output = temporary_directory("analysis-gated");
    let unchanged_comparison = temporary_directory("comparison-unchanged");
    let current = temporary_directory("analysis-current");
    let regressed_comparison = temporary_directory("comparison-regressed");
    let profiled = temporary_directory("analysis-profiled");
    let profiles = temporary_directory("profiles").with_extension("json");

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

    let profile_status = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .arg("analyze-kicad")
        .arg(&input)
        .arg("--output-dir")
        .arg(&profiled)
        .arg("--fab")
        .arg("jlcpcb-2layer")
        .status()
        .unwrap();
    assert!(profile_status.success());
    let profile_manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(profiled.join("run.json")).unwrap()).unwrap();
    assert_eq!(
        profile_manifest["configuration"]["dfm_profile"]["id"],
        "jlcpcb-standard-2layer-1oz-v1"
    );
    assert_eq!(
        profile_manifest["configuration"]["rules"]["via_diameter_nm"],
        660_000
    );
    let profile_board: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(profiled.join("board.json")).unwrap()).unwrap();
    assert_eq!(
        profile_board["manufacturing_rules"]["minimum_copper_to_edge_nm"],
        200_000
    );

    assert!(
        Command::new(env!("CARGO_BIN_EXE_pcbex"))
            .arg("dfm-profiles")
            .arg("--output")
            .arg(&profiles)
            .status()
            .unwrap()
            .success()
    );
    let listed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&profiles).unwrap()).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert_eq!(listed[0]["revision"], 1);

    assert!(compare(&output, &output, &unchanged_comparison, true).success());
    assert!(unchanged_comparison.join("delta.json").is_file());

    assert!(analyze(&input, &current, false).success());
    let mut quality: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(current.join("quality.json")).unwrap()).unwrap();
    quality["total_vias"] = serde_json::json!(1);
    fs::write(
        current.join("quality.json"),
        serde_json::to_string_pretty(&quality).unwrap(),
    )
    .unwrap();
    let mut checks: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(current.join("checks.json")).unwrap()).unwrap();
    checks["violations"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "rule": "clearance",
            "message": "new clearance finding",
            "net_ids": [1]
        }));
    fs::write(
        current.join("checks.json"),
        serde_json::to_string_pretty(&checks).unwrap(),
    )
    .unwrap();

    assert!(!compare(&output, &current, &regressed_comparison, true).success());
    for artifact in ["delta.json", "report.sarif", "run.json", "summary.md"] {
        assert!(
            regressed_comparison.join(artifact).is_file(),
            "missing comparison {artifact}"
        );
    }
    let delta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(regressed_comparison.join("delta.json")).unwrap())
            .unwrap();
    assert_eq!(delta["changes"]["total_vias"], 1);
    assert_eq!(delta["new_violations"].as_array().unwrap().len(), 1);

    fs::remove_dir_all(output).unwrap();
    fs::remove_dir_all(gated_output).unwrap();
    fs::remove_dir_all(unchanged_comparison).unwrap();
    fs::remove_dir_all(current).unwrap();
    fs::remove_dir_all(regressed_comparison).unwrap();
    fs::remove_dir_all(profiled).unwrap();
    fs::remove_file(profiles).unwrap();
}
