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
    let path = std::env::temp_dir().join(format!("pcbex-reviewer-routing-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn routes_power_and_fallback_changes_with_stable_evidence() {
    let directory = temp_dir();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let baseline = root.join("examples/simple.kicad_sch");
    let policy = root.join("examples/reviewer-routing-policy.json");
    let current = directory.join("current.kicad_sch");
    let source = fs::read_to_string(&baseline)
        .unwrap()
        .replace("(global_label \"VCC\"", "(global_label \"VCC_AUX\"")
        .replace("(property \"Value\" \"10k\"", "(property \"Value\" \"22k\"");
    fs::write(&current, source).unwrap();
    let output = directory.join("routing.json");
    let summary = directory.join("routing.md");

    let result = run(&[
        "route-schematic-review",
        path(&baseline),
        path(&current),
        "--routing-policy",
        path(&policy),
        "--output",
        path(&output),
        "--summary-output",
        path(&summary),
        "--require-routed",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plan: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(plan["review_required"], true);
    assert_eq!(plan["all_changes_routed"], true);
    assert_eq!(plan["route_count"], 2);
    assert_eq!(plan["minimum_review_assignments"], 3);
    let routes = plan["routes"].as_array().unwrap();
    let general = routes
        .iter()
        .find(|route| route["profile_id"] == "general")
        .unwrap();
    let power = routes
        .iter()
        .find(|route| route["profile_id"] == "power")
        .unwrap();
    assert!(!general["fallback_changes"].as_array().unwrap().is_empty());
    assert!(!power["matched_changes"].as_array().unwrap().is_empty());
    assert!(
        fs::read_to_string(&summary)
            .unwrap()
            .contains("Power and protection reviewer")
    );

    for command in [
        "schematic-reviewer-routing-policy-schema",
        "schematic-reviewer-routing-plan-schema",
    ] {
        let schema = directory.join(format!("{command}.json"));
        assert!(run(&[command, "--output", path(&schema)]).status.success());
        let schema: Value = serde_json::from_slice(&fs::read(schema).unwrap()).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_unknown_policy_fields_without_writing_a_plan() {
    let directory = temp_dir();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let baseline = root.join("examples/simple.kicad_sch");
    let policy = directory.join("invalid.json");
    let mut value: Value = serde_json::from_slice(
        &fs::read(root.join("examples/reviewer-routing-policy.json")).unwrap(),
    )
    .unwrap();
    value["unexpected"] = Value::Bool(true);
    fs::write(&policy, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    let output = directory.join("routing.json");
    let result = run(&[
        "route-schematic-review",
        path(&baseline),
        path(&baseline),
        "--routing-policy",
        path(&policy),
        "--output",
        path(&output),
    ]);
    assert!(!result.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(directory).unwrap();
}
