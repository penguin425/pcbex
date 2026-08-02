use pcbex_kicad::import_schematic;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const SOURCE_ARTIFACTS: [&str; 7] = [
    "pinout.h",
    "firmware.h",
    "firmware.c",
    "firmware_smoke_test.c",
    "firmware.cpp",
    "firmware_cpp_smoke_test.cpp",
    "host.py",
];

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn schematic() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch")
}

fn run_generate(input: &Path, output: &Path, pin_map: Option<&Path>, options: &[&str]) -> Output {
    run_generate_with_path(input, output, pin_map, options, None)
}

fn run_generate_with_path(
    input: &Path,
    output: &Path,
    pin_map: Option<&Path>,
    options: &[&str],
    prepend_path: Option<&Path>,
) -> Output {
    let mut command = Command::new(binary());
    command
        .arg("generate-firmware")
        .arg(input)
        .arg("--mcu-reference")
        .arg("U1")
        .arg("--output-dir")
        .arg(output);
    if let Some(pin_map) = pin_map {
        command.arg("--pin-map").arg(pin_map);
    }
    if let Some(prepend_path) = prepend_path {
        let mut paths = vec![prepend_path.to_path_buf()];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        command.env(
            "PATH",
            std::env::join_paths(paths).expect("test PATH must be representable"),
        );
    }
    command
        .args(options)
        .output()
        .expect("generate-firmware must start")
}

fn run_schema(output: &Path) -> Output {
    Command::new(binary())
        .args(["firmware-schema", "--output"])
        .arg(output)
        .output()
        .expect("firmware-schema must start")
}

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("expected JSON object")
        .keys()
        .cloned()
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn schematic_hash(input: &Path) -> String {
    let source = fs::read_to_string(input).expect("schematic must be readable");
    let document = import_schematic(&source).expect("fixture schematic must import");
    let canonical = serde_json::to_vec(&document).expect("schematic IR must serialize");
    sha256(&canonical)
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("JSON output must exist")).expect("valid JSON")
}

fn assert_bundle_files(output: &Path) {
    let mut actual = fs::read_dir(output)
        .expect("bundle output must exist")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    actual.sort();
    let mut expected = SOURCE_ARTIFACTS
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    expected.push("manifest.json".to_string());
    expected.sort();
    assert_eq!(
        actual, expected,
        "bundle must contain only its closed artifact set"
    );
    for name in SOURCE_ARTIFACTS {
        let path = output.join(name);
        assert!(path.is_file(), "missing source artifact {name}");
        assert!(
            !fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    assert!(output.join("manifest.json").is_file());
}

fn assert_hash_bound_manifest(manifest: &Value, output: &Path, input: &Path) {
    assert_manifest_shape_and_artifacts(manifest, output, input);

    for label in ["c_build", "cpp_build", "python_check"] {
        assert_build_evidence(&manifest[label], true);
    }
}

fn assert_manifest_shape_and_artifacts(manifest: &Value, output: &Path, input: &Path) {
    assert_eq!(
        keys(manifest),
        BTreeSet::from([
            "schema_version".to_string(),
            "engine".to_string(),
            "engine_version".to_string(),
            "schematic_sha256".to_string(),
            "artifacts".to_string(),
            "c_build".to_string(),
            "cpp_build".to_string(),
            "python_check".to_string(),
        ])
    );
    assert_eq!(manifest["schema_version"], 2);
    assert_eq!(manifest["engine"], "pcbex");
    assert_eq!(manifest["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["schematic_sha256"], schematic_hash(input));

    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts must be an array");
    assert_eq!(artifacts.len(), SOURCE_ARTIFACTS.len());
    for (descriptor, expected_name) in artifacts.iter().zip(SOURCE_ARTIFACTS) {
        assert_eq!(
            keys(descriptor),
            BTreeSet::from([
                "path".to_string(),
                "bytes".to_string(),
                "sha256".to_string()
            ])
        );
        assert_eq!(descriptor["path"], expected_name);
        let bytes = fs::read(output.join(expected_name)).expect("artifact must be readable");
        assert_eq!(descriptor["bytes"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(descriptor["sha256"], sha256(&bytes));
    }
}

fn assert_build_evidence(build: &Value, passed: bool) {
    assert_eq!(
        keys(build),
        BTreeSet::from([
            "attempted".to_string(),
            "passed".to_string(),
            "command".to_string(),
            "exit_code".to_string(),
            "smoke".to_string(),
        ])
    );
    assert_eq!(build["attempted"], passed);
    assert_eq!(build["passed"], passed);
    assert!(
        build["command"]
            .as_array()
            .is_some_and(|command| !command.is_empty())
    );
    if passed {
        assert_eq!(build["exit_code"], 0);
    } else {
        assert!(build["exit_code"].is_null() || build["exit_code"].is_i64());
    }
    let smoke = &build["smoke"];
    assert_eq!(
        keys(smoke),
        BTreeSet::from([
            "attempted".to_string(),
            "passed".to_string(),
            "command".to_string(),
            "exit_code".to_string(),
        ])
    );
    assert_eq!(smoke["attempted"], passed);
    assert_eq!(smoke["passed"], passed);
    assert!(
        smoke["command"]
            .as_array()
            .is_some_and(|command| !command.is_empty())
    );
    if passed {
        assert_eq!(smoke["exit_code"], 0);
    } else {
        assert!(smoke["exit_code"].is_null() || smoke["exit_code"].is_i64());
    }
}

fn assert_failed_compile_evidence(build: &Value) {
    assert_eq!(
        keys(build),
        BTreeSet::from([
            "attempted".to_string(),
            "passed".to_string(),
            "command".to_string(),
            "exit_code".to_string(),
            "smoke".to_string(),
        ])
    );
    assert_eq!(build["attempted"], true);
    assert_eq!(build["passed"], false);
    assert!(
        build["command"]
            .as_array()
            .is_some_and(|command| !command.is_empty())
    );
    assert!(build["exit_code"].is_null() || build["exit_code"].is_i64());

    let smoke = &build["smoke"];
    assert_eq!(smoke["attempted"], false);
    assert_eq!(smoke["passed"], false);
    assert!(
        smoke["command"]
            .as_array()
            .is_some_and(|command| !command.is_empty())
    );
    assert!(smoke["exit_code"].is_null() || smoke["exit_code"].is_i64());
}

fn assert_schema_objects_are_closed(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".into()))
                && object.contains_key("properties")
            {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema is not closed: {value}"
                );
            }
            for nested in object.values() {
                assert_schema_objects_are_closed(nested);
            }
        }
        Value::Array(array) => {
            for nested in array {
                assert_schema_objects_are_closed(nested);
            }
        }
        _ => {}
    }
}

#[test]
fn generate_firmware_is_deterministic_hash_bound_and_runs_c_and_cpp_smokes() {
    let temporary = tempfile::tempdir().unwrap();
    let pin_map = temporary.path().join("pin-map.json");
    fs::write(&pin_map, br#"{"1":"PA0","2":"VCC"}"#).unwrap();
    let first = temporary.path().join("first");
    let second = temporary.path().join("second");

    let first_run = run_generate(&schematic(), &first, Some(&pin_map), &[]);
    assert!(
        first_run.status.success(),
        "{}",
        String::from_utf8_lossy(&first_run.stderr)
    );
    let second_run = run_generate(&schematic(), &second, Some(&pin_map), &[]);
    assert!(
        second_run.status.success(),
        "{}",
        String::from_utf8_lossy(&second_run.stderr)
    );
    assert_bundle_files(&first);
    assert_bundle_files(&second);

    for name in SOURCE_ARTIFACTS.iter().chain(["manifest.json"].iter()) {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(second.join(name)).unwrap(),
            "artifact {name} must be deterministic"
        );
    }
    let manifest = read_json(&first.join("manifest.json"));
    assert_hash_bound_manifest(&manifest, &first, &schematic());

    let pinout = fs::read_to_string(first.join("pinout.h")).unwrap();
    assert!(pinout.contains("#define PCBEX_MCU_REFERENCE \"U1\""));
    assert!(pinout.contains("PA0"));
    assert!(pinout.contains("PCBEX_NET_SIGNAL"));
    assert!(pinout.contains("PCBEX_NET_VCC"));
    let header = fs::read_to_string(first.join("firmware.h")).unwrap();
    let cpp = fs::read_to_string(first.join("firmware.cpp")).unwrap();
    let host = fs::read_to_string(first.join("host.py")).unwrap();
    let c_smoke = fs::read_to_string(first.join("firmware_smoke_test.c")).unwrap();
    let cpp_smoke = fs::read_to_string(first.join("firmware_cpp_smoke_test.cpp")).unwrap();
    assert!(header.contains("pcbex_pin_count"));
    assert!(cpp.contains("pcbex_pin_count"));
    assert!(
        cpp.contains("extern \"C\""),
        "C++ implementation must expose a C ABI"
    );
    assert!(c_smoke.contains("pcbex_pins[1]"));
    assert!(cpp_smoke.contains("pcbex_pin_count"));
    assert!(cpp_smoke.contains("pcbex_pins[1]"));
    assert!(host.contains("MCU_REFERENCE = \"U1\""));
}

#[test]
fn missing_c_compiler_retains_sources_and_failed_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = "pcbex_test_missing_c_compiler_v1398";
    let output = temporary.path().join("missing-c");

    let result = run_generate(&schematic(), &output, None, &["--cc", missing]);
    assert!(!result.status.success());
    assert_bundle_files(&output);

    let manifest = read_json(&output.join("manifest.json"));
    assert_manifest_shape_and_artifacts(&manifest, &output, &schematic());
    assert_failed_compile_evidence(&manifest["c_build"]);
    assert_build_evidence(&manifest["cpp_build"], true);
    assert_build_evidence(&manifest["python_check"], true);
    assert_eq!(manifest["c_build"]["command"][0], missing);
    assert!(!output.join(".pcbex-firmware-c-smoke").exists());
    assert!(!output.join(".pcbex-firmware-cpp-smoke").exists());
    assert!(!output.join("__pycache__").exists());
}

#[cfg(unix)]
#[test]
fn c_compiler_timeout_retains_failed_evidence_without_runtime_outputs() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let compiler = "pcbex_test_sleeping_c_compiler_v1398";
    let compiler_path = temporary.path().join(compiler);
    fs::write(&compiler_path, b"#!/bin/sh\nexec sleep 5\n").unwrap();
    let mut permissions = fs::metadata(&compiler_path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&compiler_path, permissions).unwrap();
    let output = temporary.path().join("timeout-c");

    let result = run_generate_with_path(
        &schematic(),
        &output,
        None,
        &["--cc", compiler, "--timeout-seconds", "1"],
        Some(temporary.path()),
    );
    assert!(!result.status.success());
    assert_bundle_files(&output);

    let manifest = read_json(&output.join("manifest.json"));
    assert_manifest_shape_and_artifacts(&manifest, &output, &schematic());
    assert_failed_compile_evidence(&manifest["c_build"]);
    assert_build_evidence(&manifest["cpp_build"], true);
    assert_build_evidence(&manifest["python_check"], true);
    assert_eq!(manifest["c_build"]["command"][0], compiler);
    assert!(!output.join(".pcbex-firmware-c-smoke").exists());
    assert!(!output.join(".pcbex-firmware-cpp-smoke").exists());
    assert!(!output.join("__pycache__").exists());
}

#[cfg(unix)]
#[test]
fn toolchain_source_mutation_is_never_published() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let compiler = "pcbex_test_mutating_c_compiler_v1398";
    let compiler_path = temporary.path().join(compiler);
    fs::write(
        &compiler_path,
        b"#!/bin/sh\nprintf '\\n/* tool mutation */\\n' >> firmware.c\nexec cc \"$@\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&compiler_path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&compiler_path, permissions).unwrap();
    let output = temporary.path().join("mutated-c");

    let result = run_generate_with_path(
        &schematic(),
        &output,
        None,
        &["--cc", compiler],
        Some(temporary.path()),
    );
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("changed during validation"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.exists());
}

#[test]
fn path_based_c_compiler_is_rejected_before_output_publication() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("path-based-c");
    let path_based_compiler = temporary.path().join("compiler");
    let path_based_compiler = path_based_compiler.to_string_lossy().into_owned();

    let result = run_generate(
        &schematic(),
        &output,
        None,
        &["--cc", path_based_compiler.as_str(), "--skip-build"],
    );
    assert!(!result.status.success());
    assert!(!output.exists());
}

#[test]
fn skip_build_writes_sources_but_records_unpassed_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("skip");
    let result = run_generate(
        &schematic(),
        &output,
        None,
        &["--skip-build", "--timeout-seconds", "120"],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_bundle_files(&output);
    let manifest = read_json(&output.join("manifest.json"));
    for label in ["c_build", "cpp_build", "python_check"] {
        assert_build_evidence(&manifest[label], false);
    }
}

#[test]
fn firmware_schema_is_recursive_closed_and_never_overwrites() {
    let temporary = tempfile::tempdir().unwrap();
    let schema_path = temporary.path().join("firmware.schema.json");
    let result = run_schema(&schema_path);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let schema = read_json(&schema_path);
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["schema_version"]["const"], 2);
    assert_eq!(
        keys(&schema["properties"]),
        BTreeSet::from([
            "schema_version".to_string(),
            "engine".to_string(),
            "engine_version".to_string(),
            "schematic_sha256".to_string(),
            "artifacts".to_string(),
            "c_build".to_string(),
            "cpp_build".to_string(),
            "python_check".to_string(),
        ])
    );
    assert_schema_objects_are_closed(&schema);

    let sentinel = b"preserve existing firmware schema\n";
    fs::write(&schema_path, sentinel).unwrap();
    let overwrite = run_schema(&schema_path);
    assert!(!overwrite.status.success());
    assert_eq!(fs::read(&schema_path).unwrap(), sentinel);
}

#[test]
fn generator_refuses_existing_output_and_bad_pin_maps_without_clobbering() {
    let temporary = tempfile::tempdir().unwrap();
    let existing = temporary.path().join("existing");
    fs::create_dir(&existing).unwrap();
    let sentinel = b"preserve output directory\n";
    fs::write(existing.join("sentinel"), sentinel).unwrap();
    let existing_result = run_generate(&schematic(), &existing, None, &["--skip-build"]);
    assert!(!existing_result.status.success());
    assert_eq!(fs::read(existing.join("sentinel")).unwrap(), sentinel);
    assert_eq!(fs::read_dir(&existing).unwrap().count(), 1);

    let bad_json = temporary.path().join("bad-pin-map.json");
    fs::write(&bad_json, b"{").unwrap();
    let bad_output = temporary.path().join("bad-json");
    let bad_result = run_generate(
        &schematic(),
        &bad_output,
        Some(&bad_json),
        &["--skip-build"],
    );
    assert!(!bad_result.status.success());
    assert!(!bad_output.exists());

    let unknown_pin = temporary.path().join("unknown-pin-map.json");
    fs::write(&unknown_pin, br#"{"99":"PX"}"#).unwrap();
    let unknown_output = temporary.path().join("unknown-pin");
    let unknown_result = run_generate(
        &schematic(),
        &unknown_output,
        Some(&unknown_pin),
        &["--skip-build"],
    );
    assert!(!unknown_result.status.success());
    assert!(!unknown_output.exists());
}

#[cfg(unix)]
#[test]
fn generator_refuses_direct_and_parent_symlink_output_paths() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().unwrap();
    let target = temporary.path().join("target");
    fs::create_dir(&target).unwrap();
    let sentinel = b"preserve symlink target\n";
    fs::write(target.join("sentinel"), sentinel).unwrap();
    let direct = temporary.path().join("direct-link");
    symlink(&target, &direct).unwrap();
    let direct_result = run_generate(&schematic(), &direct, None, &["--skip-build"]);
    assert!(!direct_result.status.success());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), sentinel);
    assert_eq!(fs::read_dir(&target).unwrap().count(), 1);

    let real_parent = temporary.path().join("real-parent");
    let linked_parent = temporary.path().join("linked-parent");
    fs::create_dir(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    let parent_output = linked_parent.join("bundle");
    let parent_result = run_generate(&schematic(), &parent_output, None, &["--skip-build"]);
    assert!(!parent_result.status.success());
    assert!(!real_parent.join("bundle").exists());
}

#[test]
fn generator_rejects_incomplete_coverage_unless_explicitly_allowed() {
    let temporary = tempfile::tempdir().unwrap();
    let incomplete = temporary.path().join("incomplete.kicad_sch");
    let source = fs::read_to_string(schematic()).unwrap();
    let source = source.replace(
        "(sheet_instances",
        "(sheet (at 1 1) (size 10 10) (uuid sheet-1))\n(sheet_instances",
    );
    fs::write(&incomplete, source).unwrap();

    let rejected_output = temporary.path().join("rejected");
    let rejected = run_generate(&incomplete, &rejected_output, None, &["--skip-build"]);
    assert!(!rejected.status.success());
    assert!(!rejected_output.exists());

    let allowed_output = temporary.path().join("allowed");
    let allowed = run_generate(
        &incomplete,
        &allowed_output,
        None,
        &["--allow-incomplete", "--skip-build"],
    );
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert_bundle_files(&allowed_output);
}
