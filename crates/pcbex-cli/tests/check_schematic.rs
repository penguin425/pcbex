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
    let junit = directory.join("electrical-review.xml");
    let sarif = directory.join("electrical-review.sarif");
    let second = directory.join("second.json");
    let rejected = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&first),
        "--explain",
        path(&explanations),
        "--junit-output",
        path(&junit),
        "--sarif-output",
        path(&sarif),
        "--require-approved",
    ]);
    assert!(!rejected.status.success());
    assert!(first.is_file());
    assert!(explanations.is_file());
    assert!(junit.is_file());
    assert!(sarif.is_file());
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
    assert_eq!(explanation_report["rules"].as_array().unwrap().len(), 16);
    for rule in explanation_report["rules"].as_array().unwrap() {
        for field in ["title", "purpose", "trigger", "remediation"] {
            assert!(!rule[field].as_str().unwrap().is_empty());
        }
    }
    let junit_source = fs::read_to_string(&junit).unwrap();
    assert!(junit_source.starts_with(r#"<?xml version="1.0" encoding="UTF-8"?>"#));
    assert!(junit_source.contains(r#"<testsuite name="pcbex electrical rules" tests="16""#));
    assert!(junit_source.contains(r#"<failure type="electrical_error""#));
    assert!(junit_source.contains(review["schematic_sha256"].as_str().unwrap()));
    let sarif_report: Value = serde_json::from_slice(&fs::read(&sarif).unwrap()).unwrap();
    assert_eq!(sarif_report["version"], "2.1.0");
    assert_eq!(
        sarif_report["runs"][0]["properties"]["schematicSha256"],
        review["schematic_sha256"]
    );
    assert_eq!(
        sarif_report["runs"][0]["results"].as_array().unwrap().len(),
        review["findings"].as_array().unwrap().len()
    );
    assert!(
        sarif_report["runs"][0]["results"][0]["partialFingerprints"]["pcbexElectricalFinding/v1"]
            .as_str()
            .unwrap()
            .starts_with("pcbex-er-")
    );

    let policy = directory.join("policy.json");
    assert!(
        run(&["electrical-policy", "--output", path(&policy)])
            .status
            .success()
    );
    let mut policy_value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    policy_value["rules"]["power_input_not_driven"]["enabled"] = Value::Bool(false);
    fs::write(&policy, serde_json::to_vec_pretty(&policy_value).unwrap()).unwrap();
    let unsafe_output = directory.join("unsafe-policy-review.json");
    let unsafe_policy = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&unsafe_output),
        "--policy",
        path(&policy),
        "--require-approved",
    ]);
    assert!(!unsafe_policy.status.success());
    assert!(String::from_utf8_lossy(&unsafe_policy.stderr).contains("immutable safety floor"));
    assert!(!unsafe_output.exists());

    policy_value["rules"]["power_input_not_driven"]["enabled"] = Value::Bool(true);
    policy_value["rules"]["missing_footprint"]["enabled"] = Value::Bool(false);
    fs::write(&policy, serde_json::to_vec_pretty(&policy_value).unwrap()).unwrap();
    let approved_source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approved-empty.kicad_sch");
    let approved = directory.join("approved.json");
    let safe_advisory_override = run(&[
        "check-schematic",
        path(&approved_source),
        "--output",
        path(&approved),
        "--policy",
        path(&policy),
        "--require-approved",
    ]);
    assert!(
        safe_advisory_override.status.success(),
        "{}",
        String::from_utf8_lossy(&safe_advisory_override.stderr)
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

#[test]
fn refuses_existing_or_aliased_outputs_without_partial_publication() {
    let directory = temp_dir();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let output = directory.join("review.json");
    let explanation = directory.join("explanation.json");
    fs::write(&output, b"sentinel").unwrap();

    let collision = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&output),
        "--explain",
        path(&explanation),
    ]);
    assert!(!collision.status.success());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("refusing to overwrite"));
    assert_eq!(fs::read(&output).unwrap(), b"sentinel");
    assert!(!explanation.exists());

    let source_before = fs::read(&source).unwrap();
    let alias = run(&["check-schematic", path(&source), "--output", path(&source)]);
    assert!(!alias.status.success());
    assert_eq!(fs::read(&source).unwrap(), source_before);

    let duplicate = directory.join("duplicate.json");
    let duplicate_result = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&duplicate),
        "--sarif-output",
        path(&duplicate),
    ]);
    assert!(!duplicate_result.status.success());
    assert!(String::from_utf8_lossy(&duplicate_result.stderr).contains("must be distinct"));
    assert!(!duplicate.exists());

    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_oversized_schematic_before_creating_outputs() {
    let directory = temp_dir();
    let source = directory.join("oversized.kicad_sch");
    fs::File::create(&source)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let output = directory.join("review.json");

    let result = run(&["check-schematic", path(&source), "--output", path(&output)]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("exceeds"));
    assert!(!output.exists());

    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn refuses_schematic_outputs_through_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = temp_dir();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let target = directory.join("target.json");
    fs::write(&target, b"sentinel").unwrap();
    let direct_link = directory.join("direct-link.json");
    symlink(&target, &direct_link).unwrap();
    let direct = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&direct_link),
    ]);
    assert!(!direct.status.success());
    assert!(String::from_utf8_lossy(&direct.stderr).contains("symlink"));
    assert_eq!(fs::read(&target).unwrap(), b"sentinel");

    let real_parent = directory.join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = directory.join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    let parent_link = run(&[
        "check-schematic",
        path(&source),
        "--output",
        path(&linked_parent.join("review.json")),
    ]);
    assert!(!parent_link.status.success());
    assert!(String::from_utf8_lossy(&parent_link.stderr).contains("symlink"));
    assert!(!real_parent.join("review.json").exists());

    fs::remove_dir_all(directory).unwrap();
}
