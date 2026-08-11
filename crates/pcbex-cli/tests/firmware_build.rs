use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

#[cfg(target_os = "linux")]
use std::{process::Stdio, thread, time::Duration};

const ARTIFACTS: [(&str, &[u8]); 7] = [
    (
        "pinout.h",
        b"#ifndef PCBEX_PINOUT_H\n#define PCBEX_PINOUT_H\n#define PCBEX_TEST_PIN 7\n#endif\n",
    ),
    (
        "firmware.h",
        b"#ifndef PCBEX_FIRMWARE_H\n#define PCBEX_FIRMWARE_H\nint pcbex_value(void);\n#endif\n",
    ),
    (
        "firmware.c",
        b"#include \"firmware.h\"\nint pcbex_value(void) { return 7; }\n",
    ),
    (
        "firmware_smoke_test.c",
        b"#include \"firmware.h\"\nint main(void) { return pcbex_value() == 7 ? 0 : 1; }\n",
    ),
    (
        "firmware.cpp",
        b"extern \"C\" int pcbex_cpp_value(void) { return 17; }\n",
    ),
    (
        "firmware_cpp_smoke_test.cpp",
        b"extern \"C\" int pcbex_cpp_value(void);\nint main() { return pcbex_cpp_value() == 17 ? 0 : 1; }\n",
    ),
    (
        "host.py",
        b"import sys\n\ndef main():\n    return 0 if sys.argv[1:] == ['--self-test'] else 2\n\nif __name__ == '__main__':\n    raise SystemExit(main())\n",
    ),
];

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(directory.path()).unwrap();
    (directory, canonical)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn skipped_command(command: &[&str]) -> Value {
    json!({
        "attempted": false,
        "passed": false,
        "command": command,
        "exit_code": null
    })
}

fn skipped_build(command: &[&str], smoke: &[&str]) -> Value {
    json!({
        "attempted": false,
        "passed": false,
        "command": command,
        "exit_code": null,
        "smoke": skipped_command(smoke)
    })
}

fn forged_passed_command(command: &[&str]) -> Value {
    json!({
        "attempted": true,
        "passed": true,
        "command": command,
        "exit_code": 0
    })
}

fn forged_passed_build(command: &[&str], smoke: &[&str]) -> Value {
    json!({
        "attempted": true,
        "passed": true,
        "command": command,
        "exit_code": 0,
        "smoke": forged_passed_command(smoke)
    })
}

fn artifact_descriptors(directory: &Path) -> Vec<Value> {
    ARTIFACTS
        .iter()
        .map(|(name, _)| {
            let source = fs::read(directory.join(name)).unwrap();
            json!({
                "path": name,
                "bytes": source.len(),
                "sha256": sha256(&source)
            })
        })
        .collect()
}

fn source_only_manifest(directory: &Path) -> Value {
    json!({
        "schema_version": 2,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "schematic_sha256": "a".repeat(64),
        "artifacts": artifact_descriptors(directory),
        "c_build": skipped_build(
            &["cc", "-std=c11", "firmware.c", "firmware_smoke_test.c"],
            &["./.pcbex-firmware-c-smoke"]
        ),
        "cpp_build": skipped_build(
            &["c++", "-std=c++17", "firmware.cpp", "firmware_cpp_smoke_test.cpp"],
            &["./.pcbex-firmware-cpp-smoke"]
        ),
        "python_check": skipped_build(
            &["python3", "-m", "py_compile", "host.py"],
            &["python3", "host.py", "--self-test"]
        )
    })
}

fn write_bundle(directory: &Path) -> PathBuf {
    fs::create_dir(directory).unwrap();
    for (name, source) in ARTIFACTS {
        fs::write(directory.join(name), source).unwrap();
    }
    let manifest = source_only_manifest(directory);
    let manifest_path = directory.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    manifest_path
}

fn read_manifest(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write_manifest(path: &Path, manifest: &Value) {
    fs::write(path, serde_json::to_vec_pretty(manifest).unwrap()).unwrap();
}

fn refresh_artifact_descriptor(manifest_path: &Path, name: &str) {
    let mut manifest = read_manifest(manifest_path);
    let source = fs::read(manifest_path.parent().unwrap().join(name)).unwrap();
    let descriptor = manifest["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|descriptor| descriptor["path"] == name)
        .unwrap();
    descriptor["bytes"] = json!(source.len());
    descriptor["sha256"] = json!(sha256(&source));
    write_manifest(manifest_path, &manifest);
}

fn forge_historical_success(manifest_path: &Path, command: Option<&str>) {
    let mut manifest = read_manifest(manifest_path);
    manifest["c_build"] = forged_passed_build(
        &[command.unwrap_or("cc"), "attacker-selected-c-argument"],
        &["attacker-selected-c-smoke"],
    );
    manifest["cpp_build"] = forged_passed_build(
        &["c++", "attacker-selected-cpp-argument"],
        &["attacker-selected-cpp-smoke"],
    );
    manifest["python_check"] = forged_passed_build(
        &["python3", "attacker-selected-python-argument"],
        &["python3", "attacker-selected-python-smoke"],
    );
    write_manifest(manifest_path, &manifest);
}

fn verifier(manifest: &Path) -> Command {
    let mut command = Command::new(binary());
    command.arg("verify-firmware-build").arg(manifest);
    #[cfg(windows)]
    command.args(["--cc", "gcc", "--cxx", "g++", "--python", "python"]);
    command
}

fn verifier_with_cc(manifest: &Path, cc: &str) -> Command {
    let mut command = Command::new(binary());
    command
        .arg("verify-firmware-build")
        .arg(manifest)
        .arg("--cc")
        .arg(cc);
    #[cfg(windows)]
    command.args(["--cxx", "g++", "--python", "python"]);
    command
}

fn run_verify(manifest: &Path, arguments: &[&str]) -> Output {
    verifier(manifest).args(arguments).output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn object_keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn assert_all_object_schemas_closed(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".into()))
                && object.contains_key("properties")
            {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "open object schema: {value}"
                );
            }
            for child in object.values() {
                assert_all_object_schemas_closed(child);
            }
        }
        Value::Array(array) => {
            for child in array {
                assert_all_object_schemas_closed(child);
            }
        }
        _ => {}
    }
}

fn assert_ordered_fields(rendered: &str, fields: &[&str]) {
    let mut cursor = 0;
    for field in fields {
        let needle = format!("\"{field}\"");
        let found = rendered[cursor..]
            .find(&needle)
            .unwrap_or_else(|| panic!("missing ordered field {field:?}: {rendered}"));
        cursor += found + needle.len();
    }
}

#[test]
fn help_and_schema_publish_the_exact_closed_fresh_build_contract() {
    let help = Command::new(binary())
        .args(["verify-firmware-build", "--help"])
        .output()
        .unwrap();
    assert_success(&help);
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("verify-firmware-build [OPTIONS] <MANIFEST>"));
    for option in [
        "--cc <CC>",
        "--cxx <CXX>",
        "--python <PYTHON>",
        "--timeout-seconds <TIMEOUT_SECONDS>",
        "--output <OUTPUT>",
        "--require-approved",
    ] {
        assert!(
            help.contains(option),
            "missing help option {option:?}:\n{help}"
        );
    }
    for default in [
        "[default: cc]",
        "[default: c++]",
        "[default: python3]",
        "[default: 120]",
    ] {
        assert!(
            help.contains(default),
            "missing default {default:?}:\n{help}"
        );
    }

    let schema_output = Command::new(binary())
        .arg("firmware-build-report-schema")
        .output()
        .unwrap();
    assert_success(&schema_output);
    assert!(schema_output.stdout.ends_with(b"\n"));
    let schema: Value = serde_json::from_slice(&schema_output.stdout).unwrap();
    assert_eq!(
        schema["$id"],
        "https://github.com/penguin425/pcbex/schemas/fresh-firmware-bundle-build-v1.json"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema["properties"]["scope"]["const"],
        "fresh_firmware_bundle_build_v1"
    );
    assert_eq!(
        schema["required"],
        json!([
            "schema_version",
            "scope",
            "engine_version",
            "bundle",
            "process_limits",
            "checks",
            "toolchain_provenance_verified",
            "approved"
        ])
    );
    assert_eq!(
        schema["properties"]["bundle"]["required"],
        json!([
            "manifest",
            "manifest_schema_version",
            "schematic_sha256",
            "artifacts"
        ])
    );
    assert_eq!(
        schema["properties"]["process_limits"]["required"],
        json!(["timeout_seconds", "stdout_bytes", "stderr_bytes"])
    );
    assert_eq!(
        schema["properties"]["process_limits"]["properties"]["stdout_bytes"]["const"],
        1_048_576
    );
    assert_eq!(
        schema["properties"]["process_limits"]["properties"]["stderr_bytes"]["const"],
        1_048_576
    );
    assert_eq!(
        schema["properties"]["toolchain_provenance_verified"]["const"],
        false
    );
    assert_eq!(schema["properties"]["checks"]["minItems"], 6);
    assert_eq!(schema["properties"]["checks"]["maxItems"], 6);
    assert_eq!(schema["properties"]["checks"]["items"], false);
    let artifact_schema = &schema["properties"]["bundle"]["properties"]["artifacts"];
    assert_eq!(artifact_schema["minItems"], 7);
    assert_eq!(artifact_schema["maxItems"], 7);
    assert_eq!(artifact_schema["items"], false);
    let artifact_prefixes = artifact_schema["prefixItems"].as_array().unwrap();
    assert_eq!(artifact_prefixes.len(), ARTIFACTS.len());
    assert_eq!(
        artifact_prefixes
            .iter()
            .map(|item| item["allOf"][1]["properties"]["path"]["const"]
                .as_str()
                .unwrap())
            .collect::<Vec<_>>(),
        ARTIFACTS.map(|(name, _)| name)
    );
    assert_eq!(
        schema["$defs"]["manifest_identity"]["required"],
        json!(["bytes", "sha256"])
    );
    assert_eq!(
        schema["$defs"]["artifact"]["required"],
        json!(["path", "bytes", "sha256"])
    );
    assert_eq!(
        schema["$defs"]["check"]["required"],
        json!([
            "name",
            "command",
            "attempted",
            "passed",
            "exit_code",
            "failure"
        ])
    );
    assert_eq!(
        schema["$defs"]["check"]["properties"]["failure"]["enum"],
        json!([
            null,
            "dependency_failed",
            "exit_failure",
            "missing_output",
            "spawn_failure",
            "timeout",
            "stdout_limit",
            "stderr_limit",
            "supervision_failure"
        ])
    );
    let check_prefixes = schema["properties"]["checks"]["prefixItems"]
        .as_array()
        .unwrap();
    assert_eq!(
        check_prefixes
            .iter()
            .map(|item| item["allOf"][1]["properties"]["name"]["const"]
                .as_str()
                .unwrap())
            .collect::<Vec<_>>(),
        [
            "c_compile",
            "c_smoke",
            "cpp_compile",
            "cpp_smoke",
            "python_compile",
            "python_self_test"
        ]
    );
    assert_all_object_schemas_closed(&schema);
}

#[test]
fn source_only_historical_manifest_is_freshly_built_with_real_toolchains() {
    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    let output = run_verify(&manifest, &["--require-approved"]);
    assert_success(&output);
    assert!(output.stdout.ends_with(b"\n"));
    let rendered = String::from_utf8(output.stdout).unwrap();
    assert_ordered_fields(
        &rendered,
        &[
            "schema_version",
            "scope",
            "engine_version",
            "bundle",
            "process_limits",
            "checks",
            "toolchain_provenance_verified",
            "approved",
        ],
    );
    let report: Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(
        object_keys(&report),
        BTreeSet::from([
            "schema_version",
            "scope",
            "engine_version",
            "bundle",
            "process_limits",
            "checks",
            "toolchain_provenance_verified",
            "approved",
        ])
    );
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["scope"], "fresh_firmware_bundle_build_v1");
    assert_eq!(report["approved"], true);
    assert_eq!(report["toolchain_provenance_verified"], false);
    assert_eq!(report["bundle"]["manifest_schema_version"], 2);
    assert_eq!(
        object_keys(&report["bundle"]),
        BTreeSet::from([
            "manifest",
            "manifest_schema_version",
            "schematic_sha256",
            "artifacts"
        ])
    );
    assert_eq!(
        object_keys(&report["bundle"]["manifest"]),
        BTreeSet::from(["bytes", "sha256"])
    );
    let artifacts = report["bundle"]["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 7);
    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| artifact["path"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ARTIFACTS.map(|(name, _)| name)
    );
    for artifact in artifacts {
        assert_eq!(
            object_keys(artifact),
            BTreeSet::from(["path", "bytes", "sha256"])
        );
    }
    assert_eq!(report["process_limits"]["timeout_seconds"], 120);
    assert_eq!(report["process_limits"]["stdout_bytes"], 1_048_576);
    assert_eq!(report["process_limits"]["stderr_bytes"], 1_048_576);
    let checks = report["checks"].as_array().unwrap();
    assert_eq!(
        checks
            .iter()
            .map(|check| check["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "c_compile",
            "c_smoke",
            "cpp_compile",
            "cpp_smoke",
            "python_compile",
            "python_self_test"
        ]
    );
    for check in checks {
        assert_eq!(
            object_keys(check),
            BTreeSet::from([
                "name",
                "command",
                "attempted",
                "passed",
                "exit_code",
                "failure"
            ])
        );
        assert_eq!(check["attempted"], true);
        assert_eq!(check["passed"], true);
        assert_eq!(check["exit_code"], 0);
        assert!(check["failure"].is_null());
    }
    assert!(!rendered.contains(directory.to_string_lossy().as_ref()));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(directory.to_string_lossy().as_ref())
    );
}

#[test]
fn hash_correct_uncompilable_source_rejects_forged_historical_success() {
    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    fs::write(
        manifest.parent().unwrap().join("firmware.c"),
        b"this is hash-correct but not C;\n",
    )
    .unwrap();
    refresh_artifact_descriptor(&manifest, "firmware.c");
    forge_historical_success(&manifest, None);

    let output = run_verify(&manifest, &[]);
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["approved"], false);
    assert_eq!(report["checks"][0]["name"], "c_compile");
    assert_eq!(report["checks"][0]["attempted"], true);
    assert_eq!(report["checks"][0]["passed"], false);
    assert_eq!(report["checks"][0]["failure"], "exit_failure");
    assert_eq!(report["checks"][1]["name"], "c_smoke");
    assert_eq!(report["checks"][1]["attempted"], false);
    assert_eq!(report["checks"][1]["failure"], "dependency_failed");
}

#[cfg(unix)]
#[test]
fn historical_manifest_commands_are_never_executed() {
    use std::os::unix::fs::PermissionsExt;

    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    let tools = directory.join("tools");
    fs::create_dir(&tools).unwrap();
    let marker = directory.join("manifest-command-was-executed");
    let malicious_name = "pcbex-test-manifest-command-v1466";
    let malicious = tools.join(malicious_name);
    fs::write(
        &malicious,
        format!(
            "#!/bin/sh\nprintf executed > '{}'\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&malicious, fs::Permissions::from_mode(0o755)).unwrap();
    forge_historical_success(&manifest, Some(malicious_name));

    let mut paths = vec![tools];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let output = verifier(&manifest)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap();
    assert_success(&output);
    assert!(!marker.exists());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["approved"],
        true
    );
}

#[test]
fn missing_tool_is_retained_and_its_dependent_check_is_not_attempted() {
    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    let missing = "pcbex-test-missing-c-compiler-v1466";
    let output = verifier_with_cc(&manifest, missing).output().unwrap();
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["approved"], false);
    assert_eq!(report["checks"][0]["command"][0], missing);
    assert_eq!(report["checks"][0]["attempted"], true);
    assert_eq!(report["checks"][0]["failure"], "spawn_failure");
    assert_eq!(report["checks"][1]["attempted"], false);
    assert_eq!(report["checks"][1]["failure"], "dependency_failed");
    assert_eq!(report["checks"][2]["passed"], true);
    assert_eq!(report["checks"][4]["passed"], true);
}

#[cfg(unix)]
#[test]
fn nonzero_and_missing_compiler_outputs_are_distinct_retained_failures() {
    use std::os::unix::fs::PermissionsExt;

    let (_temporary, directory) = canonical_tempdir();
    let tools = directory.join("tools");
    fs::create_dir(&tools).unwrap();
    for (name, body) in [
        ("pcbex-test-nonzero-cc-v1466", "#!/bin/sh\nexit 23\n"),
        ("pcbex-test-no-output-cc-v1466", "#!/bin/sh\nexit 0\n"),
    ] {
        let path = tools.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut paths = vec![tools];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let path = std::env::join_paths(paths).unwrap();

    for (index, (tool, failure)) in [
        ("pcbex-test-nonzero-cc-v1466", "exit_failure"),
        ("pcbex-test-no-output-cc-v1466", "missing_output"),
    ]
    .into_iter()
    .enumerate()
    {
        let manifest = write_bundle(&directory.join(format!("firmware-{index}")));
        let output = verifier(&manifest)
            .args(["--cc", tool])
            .env("PATH", &path)
            .output()
            .unwrap();
        assert_success(&output);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["approved"], false);
        assert_eq!(report["checks"][0]["attempted"], true);
        assert_eq!(report["checks"][0]["passed"], false);
        assert_eq!(report["checks"][0]["failure"], failure);
        assert_eq!(report["checks"][1]["failure"], "dependency_failed");
    }
}

#[cfg(unix)]
#[test]
fn compiler_timeout_is_retained_and_blocks_the_dependent_smoke() {
    use std::os::unix::fs::PermissionsExt;

    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    let tools = directory.join("tools");
    fs::create_dir(&tools).unwrap();
    let tool_name = "pcbex-test-timeout-cc-v1466";
    let tool = tools.join(tool_name);
    fs::write(&tool, b"#!/bin/sh\nexec sleep 10\n").unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = vec![tools];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let output = verifier(&manifest)
        .args(["--cc", tool_name, "--timeout-seconds", "1"])
        .env("PATH", std::env::join_paths(paths).unwrap())
        .output()
        .unwrap();
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["process_limits"]["timeout_seconds"], 1);
    assert_eq!(report["approved"], false);
    assert_eq!(report["checks"][0]["attempted"], true);
    assert_eq!(report["checks"][0]["failure"], "timeout");
    assert_eq!(report["checks"][1]["attempted"], false);
    assert_eq!(report["checks"][1]["failure"], "dependency_failed");
}

#[test]
fn exact_eight_malformed_hash_and_size_failures_publish_no_report_or_paths() {
    let (_temporary, directory) = canonical_tempdir();
    let root_text = directory.to_string_lossy().into_owned();

    let extra_manifest = write_bundle(&directory.join("extra"));
    fs::write(
        extra_manifest.parent().unwrap().join("extra.txt"),
        b"extra\n",
    )
    .unwrap();
    let extra = run_verify(&extra_manifest, &[]);
    assert!(!extra.status.success());
    assert!(extra.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&extra.stderr).contains(&root_text));

    let missing_manifest = write_bundle(&directory.join("missing"));
    fs::remove_file(missing_manifest.parent().unwrap().join("pinout.h")).unwrap();
    let missing = run_verify(&missing_manifest, &[]);
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&missing.stderr).contains(&root_text));

    let malformed_manifest = write_bundle(&directory.join("malformed"));
    fs::write(&malformed_manifest, b"{").unwrap();
    let malformed = run_verify(&malformed_manifest, &[]);
    assert!(!malformed.status.success());
    assert!(malformed.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&malformed.stderr).contains(&root_text));

    let hash_manifest = write_bundle(&directory.join("hash"));
    fs::write(
        hash_manifest.parent().unwrap().join("firmware.c"),
        b"changed without changing the manifest\n",
    )
    .unwrap();
    let hash = run_verify(&hash_manifest, &[]);
    assert!(!hash.status.success());
    assert!(hash.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&hash.stderr).contains(&root_text));

    let large_manifest = write_bundle(&directory.join("large"));
    let large = fs::OpenOptions::new()
        .write(true)
        .open(large_manifest.parent().unwrap().join("host.py"))
        .unwrap();
    large.set_len(16 * 1024 * 1024 + 1).unwrap();
    drop(large);
    let bounded = run_verify(&large_manifest, &[]);
    assert!(!bounded.status.success());
    assert!(bounded.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&bounded.stderr).contains(&root_text));

    let large_manifest_path = write_bundle(&directory.join("large-manifest"));
    let large_manifest_file = fs::OpenOptions::new()
        .write(true)
        .open(&large_manifest_path)
        .unwrap();
    large_manifest_file.set_len(4 * 1024 * 1024 + 1).unwrap();
    drop(large_manifest_file);
    let bounded_manifest = run_verify(&large_manifest_path, &[]);
    assert!(!bounded_manifest.status.success());
    assert!(bounded_manifest.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&bounded_manifest.stderr).contains(&root_text));

    let wrong_name = directory.join("hash").join("other.json");
    fs::rename(&hash_manifest, &wrong_name).unwrap();
    let named = run_verify(&wrong_name, &[]);
    assert!(!named.status.success());
    assert!(named.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&named.stderr).contains(&root_text));
}

#[cfg(unix)]
#[test]
fn bundle_symlinks_and_special_entries_are_rejected_before_tools() {
    use std::os::unix::{fs::symlink, net::UnixListener};

    let (_temporary, directory) = canonical_tempdir();
    let symlink_manifest = write_bundle(&directory.join("symlink"));
    let host = symlink_manifest.parent().unwrap().join("host.py");
    let target = directory.join("host-target.py");
    fs::rename(&host, &target).unwrap();
    symlink(&target, &host).unwrap();
    let symlinked = run_verify(&symlink_manifest, &[]);
    assert!(!symlinked.status.success());
    assert!(symlinked.stdout.is_empty());

    let special_manifest = write_bundle(&directory.join("special"));
    let special = special_manifest.parent().unwrap().join("host.py");
    fs::remove_file(&special).unwrap();
    let _socket = UnixListener::bind(&special).unwrap();
    let special_output = run_verify(&special_manifest, &[]);
    assert!(!special_output.status.success());
    assert!(special_output.stdout.is_empty());

    let real_bundle = directory.join("real-bundle");
    let nested_manifest = write_bundle(&real_bundle);
    let linked_bundle = directory.join("linked-bundle");
    symlink(&real_bundle, &linked_bundle).unwrap();
    let parent_link = run_verify(&linked_bundle.join("manifest.json"), &[]);
    assert!(!parent_link.status.success());
    assert!(parent_link.stdout.is_empty());
    assert!(nested_manifest.exists());
}

#[test]
fn output_preflight_is_no_clobber_and_rejects_the_bundle_directory() {
    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    let output_path = directory.join("report.json");
    let sentinel = b"preserve existing report\n";
    fs::write(&output_path, sentinel).unwrap();

    let collision = verifier(&directory.join("missing").join("manifest.json"))
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!collision.status.success());
    assert!(collision.stdout.is_empty());
    assert_eq!(fs::read(&output_path).unwrap(), sentinel);
    assert!(String::from_utf8_lossy(&collision.stderr).contains("output already exists"));

    let alias = manifest.parent().unwrap().join("report.json");
    let aliased = verifier(&manifest)
        .arg("--output")
        .arg(&alias)
        .output()
        .unwrap();
    assert!(!aliased.status.success());
    assert!(aliased.stdout.is_empty());
    assert!(!alias.exists());
    assert!(
        String::from_utf8_lossy(&aliased.stderr).contains("outside the exact bundle directory")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let target = directory.join("target-report.json");
        fs::write(&target, sentinel).unwrap();
        let linked = directory.join("linked-report.json");
        symlink(&target, &linked).unwrap();
        let symlinked = verifier(&manifest)
            .arg("--output")
            .arg(&linked)
            .output()
            .unwrap();
        assert!(!symlinked.status.success());
        assert_eq!(fs::read(&target).unwrap(), sentinel);
        assert!(String::from_utf8_lossy(&symlinked.stderr).contains("symlink-free"));
    }
}

#[test]
fn rejected_report_is_retained_before_the_required_approval_gate() {
    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    fs::write(
        manifest.parent().unwrap().join("firmware.c"),
        b"not valid C even though its manifest digest is current\n",
    )
    .unwrap();
    refresh_artifact_descriptor(&manifest, "firmware.c");
    let report_path = directory.join("rejected.json");
    let output = verifier(&manifest)
        .arg("--output")
        .arg(&report_path)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let retained = fs::read(&report_path).unwrap();
    assert!(retained.ends_with(b"\n"));
    let report: Value = serde_json::from_slice(&retained).unwrap();
    assert_eq!(report["approved"], false);
    assert_eq!(report["checks"][0]["failure"], "exit_failure");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fresh firmware bundle build rejected")
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(directory.to_string_lossy().as_ref())
    );
}

#[test]
fn schema_output_is_lf_terminated_atomic_and_no_clobber() {
    let (_temporary, directory) = canonical_tempdir();
    let output_path = directory.join("firmware-build.schema.json");
    let first = Command::new(binary())
        .args(["firmware-build-report-schema", "--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert_success(&first);
    let retained = fs::read(&output_path).unwrap();
    assert!(retained.ends_with(b"\n"));
    serde_json::from_slice::<Value>(&retained).unwrap();

    let second = Command::new(binary())
        .args(["firmware-build-report-schema", "--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), retained);
}

#[cfg(target_os = "linux")]
#[test]
fn final_exact_bundle_reread_rejects_mutation_before_publication() {
    use std::os::unix::fs::PermissionsExt;

    let (_temporary, directory) = canonical_tempdir();
    let manifest = write_bundle(&directory.join("firmware"));
    let tools = directory.join("tools");
    fs::create_dir(&tools).unwrap();
    let started = directory.join("compiler-started");
    let release = directory.join("release-compiler");
    let compiler_name = "pcbex-test-paused-cc-v1466";
    let compiler = tools.join(compiler_name);
    fs::write(
        &compiler,
        b"#!/bin/sh\n: > \"$PCBEX_TEST_STARTED\"\nwhile [ ! -e \"$PCBEX_TEST_RELEASE\" ]; do sleep 0.01; done\nexec cc \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
    let mut paths = vec![tools];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let report = directory.join("report.json");
    let mut child = verifier(&manifest)
        .args(["--cc", compiler_name, "--output"])
        .arg(&report)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("PCBEX_TEST_STARTED", &started)
        .env("PCBEX_TEST_RELEASE", &release)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut observed = false;
    for _ in 0..20_000 {
        if started.exists() {
            observed = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_micros(250));
    }
    assert!(observed, "did not observe fresh compiler start");
    fs::write(
        manifest.parent().unwrap().join("host.py"),
        b"raise SystemExit('mutated caller bundle')\n",
    )
    .unwrap();
    fs::write(&release, b"release\n").unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!report.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("changed during final source revalidation")
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(directory.to_string_lossy().as_ref())
    );
}
