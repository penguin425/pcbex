use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn temporary_directory(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("pcbex-{name}-{}-{unique}", std::process::id()))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_fixture(root: &Path) {
    for (relative, bytes) in [
        ("circuit.json", b"circuit".as_slice()),
        ("design.kicad_sch", b"schematic".as_slice()),
        ("review.json", b"review".as_slice()),
        ("design.kicad_pcb", b"board".as_slice()),
        ("analysis/run.json", b"manifest".as_slice()),
        ("analysis/checks.json", b"checks".as_slice()),
        ("analysis/quality.json", b"quality".as_slice()),
        ("manufacturing.zip", b"package".as_slice()),
        ("firmware/manifest.json", b"firmware manifest".as_slice()),
    ] {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).unwrap();
        fs::write(path, bytes).unwrap();
    }
    for name in [
        "pinout.h",
        "firmware.h",
        "firmware.c",
        "firmware_smoke_test.c",
        "firmware.cpp",
        "firmware_cpp_smoke_test.cpp",
        "host.py",
    ] {
        fs::write(root.join("firmware").join(name), name.as_bytes()).unwrap();
    }
}

fn intent_json() -> Value {
    json!({
        "schema_version": 1,
        "circuit_spec": "circuit.json",
        "schematic": "design.kicad_sch",
        "electrical_policy": null,
        "electrical_review": "review.json",
        "board": "design.kicad_pcb",
        "analysis_manifest": "analysis/run.json",
        "analysis_checks": "analysis/checks.json",
        "quality": "analysis/quality.json",
        "analysis_project": null,
        "analysis_rules": null,
        "analysis_dfm_profile": null,
        "analysis_policy_pack": null,
        "analysis_physical_profile": null,
        "manufacturing_package": "manufacturing.zip",
        "firmware_manifest": "firmware/manifest.json",
        "factory_receipt": null,
        "require_factory": false
    })
}

fn write_intent(root: &Path, value: &Value) -> PathBuf {
    let directory = root.join("intent");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("pipeline-intent.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

fn compile(intent: &Path, output: &Path) -> Output {
    Command::new(binary())
        .args(["compile-deterministic-pipeline-plan"])
        .arg(intent)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

fn assert_failed(output: &Output, context: &str) {
    assert!(!output.status.success(), "{context} unexpectedly succeeded");
}

fn assert_failed_without_output(output: &Output, path: &Path, context: &str) {
    assert_failed(output, context);
    assert!(
        !path.exists(),
        "{context} unexpectedly published {}",
        path.display()
    );
}

#[test]
fn intent_schema_is_closed_and_compiler_output_is_canonical_and_runner_compatible() {
    let root = temporary_directory("deterministic-pipeline-compiler");
    fs::create_dir_all(&root).unwrap();
    write_fixture(&root);
    let intent = write_intent(&root, &intent_json());

    let schema_path = root.join("intent.schema.json");
    let schema = Command::new(binary())
        .args(["deterministic-pipeline-intent-schema", "--output"])
        .arg(&schema_path)
        .output()
        .unwrap();
    assert!(schema.status.success(), "schema: {:?}", schema);
    let schema_value: Value = serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    assert_eq!(schema_value["additionalProperties"], false);
    assert_eq!(schema_value["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema_value["properties"]["electrical_policy"]["oneOf"][0]["type"],
        "null"
    );
    assert!(
        schema_value["required"]
            .as_array()
            .unwrap()
            .contains(&json!("require_factory"))
    );

    let first_path = root.join("pipeline-plan-a.json");
    // The intent deliberately lives in root/intent while the plan and all
    // role paths are resolved from the output parent (root), not intent.parent().
    assert_ne!(intent.parent(), first_path.parent());
    let first = compile(&intent, &first_path);
    assert!(first.status.success(), "first compile: {:?}", first);
    let first_bytes = fs::read(&first_path).unwrap();
    assert_eq!(first_bytes.last(), Some(&b'\n'));
    let first_plan: Value = serde_json::from_slice(&first_bytes).unwrap();
    assert_eq!(first_plan["schema_version"], 1);
    assert_eq!(first_plan["require_factory"], false);
    assert!(first_plan["electrical_policy"].is_null());
    assert_eq!(first_plan["circuit_spec"]["bytes"], 7);
    assert_eq!(first_plan["circuit_spec"]["sha256"], sha256(b"circuit"));
    assert_eq!(
        first_plan["firmware_manifest"]["path"],
        "firmware/manifest.json"
    );
    assert_eq!(first_plan.as_object().unwrap().len(), 18);

    let second_path = root.join("pipeline-plan-b.json");
    let second = compile(&intent, &second_path);
    assert!(second.status.success(), "second compile: {:?}", second);
    assert_eq!(first_bytes, fs::read(&second_path).unwrap());

    let report_path = root.join("pipeline-report.json");
    let runner = Command::new(binary())
        .args(["run-deterministic-pipeline"])
        .arg(&first_path)
        .arg("--output")
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(runner.status.success(), "runner: {:?}", runner);
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["plan_source_bytes"], first_bytes.len());
    assert!(!report["run_sha256"].as_str().unwrap().is_empty());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compiler_handles_optional_null_and_factory_requirement() {
    let root = temporary_directory("deterministic-pipeline-optional");
    fs::create_dir_all(&root).unwrap();
    write_fixture(&root);
    fs::write(root.join("policy.json"), b"policy").unwrap();
    fs::write(root.join("receipt.json"), b"receipt").unwrap();
    let mut intent_value = intent_json();
    intent_value["electrical_policy"] = Value::String("policy.json".into());
    intent_value["factory_receipt"] = Value::String("receipt.json".into());
    intent_value["require_factory"] = Value::Bool(true);
    let intent = write_intent(&root, &intent_value);
    let output = root.join("factory-plan.json");
    let result = compile(&intent, &output);
    assert!(result.status.success(), "compile: {:?}", result);
    let plan: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(plan["require_factory"], true);
    assert_eq!(plan["electrical_policy"]["path"], "policy.json");
    assert_eq!(plan["factory_receipt"]["path"], "receipt.json");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compiler_rejects_malformed_unknown_duplicate_unsafe_missing_empty_nonregular_and_alias_inputs() {
    let root = temporary_directory("deterministic-pipeline-invalid");
    fs::create_dir_all(&root).unwrap();
    write_fixture(&root);
    let intent = write_intent(&root, &intent_json());

    fs::write(&intent, b"not-json").unwrap();
    assert_failed(
        &compile(&intent, &root.join("malformed.json")),
        "malformed intent",
    );

    let mut unknown = intent_json();
    unknown["unknown"] = Value::Bool(true);
    fs::write(&intent, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert_failed(
        &compile(&intent, &root.join("unknown.json")),
        "unknown intent key",
    );

    let duplicate = serde_json::to_string(&intent_json()).unwrap().replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    fs::write(&intent, duplicate).unwrap();
    assert_failed(
        &compile(&intent, &root.join("duplicate.json")),
        "duplicate intent key",
    );

    for (name, value) in [
        ("traversal", "../design.kicad_pcb"),
        ("absolute", "/tmp/design.kicad_pcb"),
    ] {
        let mut unsafe_intent = intent_json();
        unsafe_intent["board"] = Value::String(value.into());
        fs::write(&intent, serde_json::to_vec(&unsafe_intent).unwrap()).unwrap();
        assert_failed(&compile(&intent, &root.join(format!("{name}.json"))), name);
    }

    fs::write(root.join("design.kicad_pcb"), b"").unwrap();
    fs::write(&intent, serde_json::to_vec(&intent_json()).unwrap()).unwrap();
    assert_failed(&compile(&intent, &root.join("empty.json")), "empty input");
    fs::write(root.join("design.kicad_pcb"), b"board").unwrap();

    let mut missing_intent = intent_json();
    missing_intent["board"] = Value::String("missing-board.kicad_pcb".into());
    fs::write(&intent, serde_json::to_vec(&missing_intent).unwrap()).unwrap();
    assert_failed(
        &compile(&intent, &root.join("missing.json")),
        "missing input",
    );

    let mut nonregular_intent = intent_json();
    nonregular_intent["board"] = Value::String("analysis".into());
    fs::write(&intent, serde_json::to_vec(&nonregular_intent).unwrap()).unwrap();
    assert_failed(
        &compile(&intent, &root.join("nonregular.json")),
        "non-regular input",
    );

    for (name, missing_key) in [
        ("missing-optional", "electrical_policy"),
        ("missing-required", "board"),
    ] {
        let mut missing = intent_json();
        missing.as_object_mut().unwrap().remove(missing_key);
        fs::write(&intent, serde_json::to_vec(&missing).unwrap()).unwrap();
        let output = root.join(format!("{name}.json"));
        assert_failed_without_output(&compile(&intent, &output), &output, missing_key);
    }

    let mut casefold_duplicate = intent_json();
    casefold_duplicate["schematic"] = Value::String("CIRCUIT.JSON".into());
    fs::write(&intent, serde_json::to_vec(&casefold_duplicate).unwrap()).unwrap();
    let casefold_output = root.join("casefold-duplicate.json");
    assert_failed_without_output(
        &compile(&intent, &casefold_output),
        &casefold_output,
        "case-fold duplicate role path",
    );

    fs::write(&intent, serde_json::to_vec(&intent_json()).unwrap()).unwrap();
    let existing = root.join("existing.json");
    fs::write(&existing, b"keep").unwrap();
    assert_failed(&compile(&intent, &existing), "existing output");
    assert_eq!(fs::read(&existing).unwrap(), b"keep");
    assert_failed(&compile(&intent, &intent), "output aliases intent");

    let board_output = root.join("design.kicad_pcb");
    fs::write(&board_output, b"board sentinel").unwrap();
    assert_failed(
        &compile(&intent, &board_output),
        "output aliases board source",
    );
    assert_eq!(fs::read(&board_output).unwrap(), b"board sentinel");

    fs::create_dir_all(root.join("plans")).unwrap();
    let mut parent_escape = intent_json();
    parent_escape["board"] = Value::String("../design.kicad_pcb".into());
    fs::write(&intent, serde_json::to_vec(&parent_escape).unwrap()).unwrap();
    let parent_escape_output = root.join("plans/parent-escape.json");
    assert_failed_without_output(
        &compile(&intent, &parent_escape_output),
        &parent_escape_output,
        "parent escape from output subdirectory",
    );

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn compiler_plan_rejects_mutated_source_when_reopened_by_runner() {
    let root = temporary_directory("deterministic-pipeline-mutation");
    fs::create_dir_all(&root).unwrap();
    write_fixture(&root);
    let intent = write_intent(&root, &intent_json());
    let plan = root.join("pipeline-plan.json");
    let compiled = compile(&intent, &plan);
    assert!(compiled.status.success(), "compile: {:?}", compiled);
    fs::write(root.join("design.kicad_pcb"), b"mutated board").unwrap();
    let report = root.join("mutated-report.json");
    let runner = Command::new(binary())
        .args(["run-deterministic-pipeline"])
        .arg(&plan)
        .arg("--output")
        .arg(&report)
        .output()
        .unwrap();
    assert!(
        runner.status.success(),
        "runner should retain rejection: {:?}",
        runner
    );
    let report_value: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(report_value["approved"], false);
    assert!(
        report_value["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| { failure.as_str().unwrap().contains("board") })
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn compiler_rejects_symlinked_source_and_output() {
    use std::os::unix::fs::symlink;

    let root = temporary_directory("deterministic-pipeline-symlink");
    fs::create_dir_all(&root).unwrap();
    write_fixture(&root);
    let target = root.join("real-board.kicad_pcb");
    fs::write(&target, b"board").unwrap();
    fs::remove_file(root.join("design.kicad_pcb")).unwrap();
    symlink(&target, root.join("design.kicad_pcb")).unwrap();
    let intent = write_intent(&root, &intent_json());
    assert_failed(
        &compile(&intent, &root.join("symlink-source.json")),
        "symlink source",
    );

    fs::remove_file(root.join("design.kicad_pcb")).unwrap();
    fs::write(root.join("design.kicad_pcb"), b"board").unwrap();
    let output_target = root.join("output-target.json");
    fs::write(&output_target, b"keep").unwrap();
    let output_link = root.join("output-link.json");
    symlink(&output_target, &output_link).unwrap();
    assert_failed(&compile(&intent, &output_link), "symlink output");
    assert_eq!(fs::read(&output_target).unwrap(), b"keep");
    fs::remove_dir_all(root).unwrap();
}
