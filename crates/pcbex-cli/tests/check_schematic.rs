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
    let path = std::env::temp_dir().join(format!("pcbex-electrical-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn emits_deterministic_policy_gated_electrical_reviews_and_schemas() {
    let directory = temp_dir();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let first = directory.join("first.json");
    let explanations = directory.join("explanations.json");
    let second = directory.join("second.json");
    let rejected = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&first),
        "--explain",
        path(&explanations),
        "--require-approved",
    ]);
    assert!(!rejected.status.success());
    assert!(first.is_file());
    assert!(explanations.is_file());
    assert!(
        run(&["check-schematic", path(&source), "--output", path(&second),])
            .status
            .success()
    );
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let review: Value = serde_json::from_slice(&fs::read(&first).unwrap()).unwrap();
    assert_eq!(review["schema_version"], 1);
    assert_eq!(review["approved"], false);
    assert!(review["counts"]["errors"].as_u64().unwrap() > 0);
    let explanation_report: Value =
        serde_json::from_slice(&fs::read(&explanations).unwrap()).unwrap();
    assert_eq!(explanation_report["schema_version"], 1);
    assert_eq!(
        explanation_report["schematic_sha256"],
        review["schematic_sha256"]
    );
    assert_eq!(explanation_report["policy_sha256"], review["policy_sha256"]);
    assert_eq!(explanation_report["rules"].as_array().unwrap().len(), 12);
    for rule in explanation_report["rules"].as_array().unwrap() {
        for field in ["title", "purpose", "trigger", "remediation"] {
            assert!(!rule[field].as_str().unwrap().is_empty());
        }
    }

    let policy = directory.join("policy.json");
    assert!(
        run(&["electrical-policy", "--output", path(&policy)])
            .status
            .success()
    );
    let mut policy_value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    for setting in policy_value["rules"].as_object_mut().unwrap().values_mut() {
        if setting["severity"] == "error" {
            setting["enabled"] = Value::Bool(false);
        }
    }
    fs::write(&policy, serde_json::to_vec_pretty(&policy_value).unwrap()).unwrap();
    let approved = directory.join("approved.json");
    assert!(
        run(&[
            "check-schematic",
            path(&source),
            "--output",
            path(&approved),
            "--policy",
            path(&policy),
            "--require-approved",
        ])
        .status
        .success()
    );
    let approved_review: Value = serde_json::from_slice(&fs::read(&approved).unwrap()).unwrap();
    assert_eq!(approved_review["approved"], true);

    for (command, filename) in [
        ("electrical-policy-schema", "policy.schema.json"),
        ("electrical-review-schema", "review.schema.json"),
        ("electrical-explanation-schema", "explanation.schema.json"),
    ] {
        let output = directory.join(filename);
        assert!(run(&[command, "--output", path(&output)]).status.success());
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["additionalProperties"], false);
    }

    fs::remove_dir_all(directory).unwrap();
}
