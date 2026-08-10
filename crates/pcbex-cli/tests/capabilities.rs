use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn run_board_producer(
    circuit_spec: &Path,
    schematic: &Path,
    footprint_closure: &Path,
    construction_profile: &Path,
    physical_profile: &Path,
    output_dir: &Path,
) -> Output {
    Command::new(binary())
        .arg("generate-circuit-kicad-board")
        .arg(circuit_spec)
        .arg(schematic)
        .arg("--footprint-closure")
        .arg(footprint_closure)
        .arg("--construction-profile")
        .arg(construction_profile)
        .arg("--physical-profile")
        .arg(physical_profile)
        .arg("--output-dir")
        .arg(output_dir)
        .output()
        .unwrap()
}

#[test]
fn publishes_a_complete_versioned_capability_inventory() {
    let output = Command::new(binary()).arg("capabilities").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["engine"], "pcbex");
    assert_eq!(report["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["board_schema_version"], 2);

    let commands = report["commands"].as_array().unwrap();
    for name in [
        "capabilities",
        "doctor",
        "analyze-kicad",
        "record-manufacturing-feedback",
        "compare-manufacturing-feedback",
        "recommend-policy",
        "policy-rollout-profile",
        "simulate-policy-rollout",
        "validate-policy-rollout",
        "sign-rollout-approval",
        "verify-rollout-approvals",
        "validate-rollout-approval",
        "validate-canary-rollout-authorization",
        "record-canary-monitoring",
        "validate-canary-monitoring",
        "sign-canary-completion",
        "verify-canary-completion",
        "validate-canary-completion",
        "advance-policy-deployment",
        "validate-policy-deployment-state",
        "verify-policy-deployment",
        "validate-policy-deployment-verification",
        "sign-policy-deployment-rollback",
        "apply-policy-deployment-rollback",
        "validate-policy-deployment-rollback-approval",
        "validate-policy-deployment-rollback-state",
        "verify-policy-rollback-recovery",
        "validate-policy-rollback-recovery",
        "sign-rollback-incident-acknowledgment",
        "validate-rollback-incident-acknowledgment",
        "close-rollback-incident",
        "validate-rollback-incident-closure",
        "append-policy-incident-ledger",
        "validate-policy-incident-ledger",
        "sign-policy-suspension-decision",
        "apply-policy-suspension-decision",
        "validate-policy-suspension-decision",
        "validate-policy-suspension-state",
        "sign-policy-remediation-approval",
        "apply-policy-remediation",
        "validate-policy-remediation-approval",
        "validate-policy-remediation-state",
        "append-policy-lifecycle-event",
        "snapshot-policy-lifecycle",
        "validate-policy-lifecycle-ledger",
        "validate-policy-lifecycle-snapshot",
        "sign-policy-lifecycle-checkpoint",
        "verify-policy-lifecycle-checkpoint",
        "validate-policy-lifecycle-checkpoint",
        "validate-policy-lifecycle-trust-state",
        "sign-policy-lifecycle-key-rotation",
        "validate-policy-lifecycle-key-rotation",
        "witness-policy-lifecycle-checkpoint",
        "verify-policy-lifecycle-checkpoint-witnesses",
        "request-policy-lifecycle-checkpoint-witness",
        "validate-policy-lifecycle-checkpoint-witness",
        "init-policy-lifecycle-witness-trust",
        "sign-policy-lifecycle-witness-key-rotation",
        "apply-policy-lifecycle-witness-key-rotation",
        "export-policy-lifecycle-witness-public-key",
        "validate-policy-lifecycle-witness-trust-state",
        "validate-policy-lifecycle-witness-key-rotation",
        "validate-policy-lifecycle-witness-quorum",
        "create-policy-lifecycle-log-anchor",
        "verify-policy-lifecycle-log-anchor",
        "validate-policy-lifecycle-log-anchor-proof",
        "create-policy-lifecycle-log-consistency",
        "verify-policy-lifecycle-log-consistency",
        "validate-policy-lifecycle-log-consistency-proof",
        "sign-policy-lifecycle-log-gossip-receipt",
        "verify-policy-lifecycle-log-gossip-receipt",
        "validate-policy-lifecycle-log-gossip-receipt",
        "verify-policy-lifecycle-log-gossip-quorum",
        "request-policy-lifecycle-log-gossip-observation",
        "validate-policy-lifecycle-log-gossip-observation",
        "validate-policy-lifecycle-log-gossip-quorum",
        "init-policy-lifecycle-log-gossip-observer-trust",
        "sign-policy-lifecycle-log-gossip-observer-key-rotation",
        "apply-policy-lifecycle-log-gossip-observer-key-rotation",
        "export-policy-lifecycle-log-gossip-observer-public-key",
        "validate-policy-lifecycle-log-gossip-observer-trust-state",
        "validate-policy-lifecycle-log-gossip-observer-key-rotation",
        "validate-policy-lifecycle-log-gossip-trust-bound-quorum",
        "init-policy-lifecycle-log-gossip-organization-registry",
        "sign-policy-lifecycle-log-gossip-organization-registry-transition",
        "apply-policy-lifecycle-log-gossip-organization-registry-transition",
        "sign-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
        "apply-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
        "sign-policy-lifecycle-log-gossip-organization-registry-governance",
        "sign-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
        "apply-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
        "sign-policy-lifecycle-log-gossip-organization-registry-governance-rotation",
        "apply-policy-lifecycle-log-gossip-organization-registry-governance-rotation",
        "validate-policy-lifecycle-log-gossip-organization-registry",
        "validate-policy-lifecycle-log-gossip-organization-registry-transition",
        "validate-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
        "validate-policy-lifecycle-log-gossip-organization-registry-governance",
        "validate-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
        "validate-policy-lifecycle-log-gossip-organization-registry-governance-rotation",
        "validate-policy-lifecycle-log-gossip-registry-bound-quorum",
        "compare-schematics",
        "route-schematic-review",
        "check-schematic",
        "check-circuit-spec",
        "write-circuit-spec-kicad-schematic",
        "generate-circuit-kicad-board",
        "footprint-closure-schema",
        "board-construction-profile-schema",
        "circuit-kicad-board-manifest-schema",
        "circuit-kicad-board-binding-schema",
        "verify-circuit-kicad-board-binding",
        "prepare-ai-review",
        "verify-ai-quorum",
        "sign-human-escalation",
        "verify-human-escalation",
        "init-approval-log",
        "append-approval-log",
        "append-verified-remote-approval-registry-history-checkpoint-witness-receipt",
        "append-verified-remote-approval-registry-history-checkpoint-witness-receipt-quorum",
        "signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-schema",
        "remote-approval-registry-history-receipt-quorum-log-checkpoint-verification-schema",
        "validate-signed-remote-approval-registry-history-receipt-quorum-log-checkpoint",
        "sign-remote-approval-registry-history-receipt-quorum-log-checkpoint",
        "verify-remote-approval-registry-history-receipt-quorum-log-checkpoint",
        "signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-schema",
        "validate-signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness",
        "remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report-schema",
        "validate-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report",
        "witness-remote-approval-registry-history-receipt-quorum-log-checkpoint",
        "verify-remote-approval-registry-history-receipt-quorum-log-checkpoint-witnesses",
        "remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-trust-state-schema",
        "validate-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-trust-state",
        "signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation-schema",
        "validate-signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        "init-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-trust",
        "sign-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        "apply-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        "export-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-public-key",
        "sign-approval-log-with-remote-approval-registry-history-checkpoint-witness-receipt-quorum",
        "sign-approval-log",
        "verify-approval-log",
        "witness-approval-log",
        "init-approval-log-witness-trust",
        "sign-approval-log-witness-key-rotation",
        "apply-approval-log-witness-key-rotation",
        "export-approval-log-witness-public-key",
        "create-approval-log-anchor",
        "verify-approval-log-anchor",
        "verify-approval-log-witnesses",
        "request-approval-log-witness",
        "fetch-policy-pack",
        "mcp-server",
        "fabricate",
        "factory-schema",
        "factory-feedback-loop-schema",
        "factory-submit",
        "factory-feedback-loop",
        "deterministic-pipeline-intent-schema",
        "compile-deterministic-pipeline-plan",
        "deterministic-pipeline-plan-schema",
        "deterministic-pipeline-report-schema",
        "signed-fabrication-approval-schema",
        "fabrication-authorization-report-schema",
        "fabrication-authorization-reservation-schema",
        "fabrication-authorization-reservation-ledger-schema",
        "native-kicad-erc-report-schema",
        "run-native-kicad-erc",
        "verify-native-kicad-erc-report",
        "native-kicad-drc-report-schema",
        "run-native-kicad-drc",
        "verify-native-kicad-drc-report",
        "run-deterministic-pipeline",
        "sign-fabrication-approval",
        "verify-fabrication-authorization",
        "reserve-fabrication-authorization",
        "pipeline-schema",
        "pipeline-verify",
        "firmware-schema",
        "generate-firmware",
    ] {
        let command = commands
            .iter()
            .find(|command| command["name"] == name)
            .unwrap_or_else(|| panic!("missing command {name}"));
        assert!(!command["description"].as_str().unwrap().is_empty());
    }
    assert!(report["fabrication_profiles"].as_array().unwrap().len() >= 2);
    assert!(
        report["external_integrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|integration| integration == "MCP stdio")
    );
    assert!(
        report["external_integrations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|integration| integration == "HTTPS factory adapter")
    );
    assert!(
        report["output_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|contract| contract == "SARIF 2.1.0")
    );
    assert!(
        report["output_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|contract| contract == "Factory submission receipt v1")
    );
    assert!(
        report["output_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|contract| contract == "Factory feedback loop report v1")
    );
    assert!(
        report["output_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|contract| contract == "Hardware pipeline gate report v1")
    );
    assert!(
        report["output_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|contract| contract == "Factory-bound hardware pipeline gate report v2")
    );
    for expected in [
        "Deterministic pipeline plan v1",
        "Deterministic pipeline runner report v1",
        "Firmware bundle manifest v2",
        "C11 firmware source bundle",
        "C++17 firmware source bundle",
        "Python host pinout helper",
        "Native KiCad schematic ERC report v1",
        "Signed fabrication approval v1",
        "Fabrication authorization report v1",
        "Fabrication authorization reservation v1",
        "Fabrication authorization reservation ledger manifest v1",
        "Deterministic KiCad board bundle v1",
        "Footprint closure v1",
        "Board construction profile v1",
        "Circuit-to-KiCad board manifest v1",
    ] {
        assert!(
            report["output_contracts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|contract| contract == expected),
            "missing output contract {expected}"
        );
    }
}

#[test]
fn board_producer_help_exposes_only_local_explicit_inputs() {
    let output = Command::new(binary())
        .args(["generate-circuit-kicad-board", "--help"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "<CIRCUIT_SPEC>",
        "<SCHEMATIC>",
        "--footprint-closure <JSON>",
        "--construction-profile <JSON>",
        "--physical-profile <JSON>",
        "--output-dir <NEW_DIR>",
    ] {
        assert!(
            help.contains(expected),
            "missing help fragment {expected:?}\n{help}"
        );
    }
    for forbidden in ["--url", "--token", "--mcp", "--action"] {
        assert!(
            !help.contains(forbidden),
            "unexpected remote integration {forbidden:?}\n{help}"
        );
    }
}

#[test]
fn board_producer_parser_requires_every_closed_input() {
    let output = Command::new(binary())
        .args([
            "generate-circuit-kicad-board",
            "circuit.json",
            "design.kicad_sch",
            "--output-dir",
            "generated-board",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    for required in [
        "--footprint-closure",
        "--construction-profile",
        "--physical-profile",
    ] {
        assert!(
            stderr.contains(required),
            "missing parser diagnostic {required:?}"
        );
    }
}

#[test]
fn board_producer_preflights_output_before_inputs_without_leaking_paths() {
    let directory = tempfile::tempdir().unwrap();
    let output_dir = directory.path().join("existing-output");
    fs::create_dir(&output_dir).unwrap();
    let sentinel = output_dir.join("sentinel");
    fs::write(&sentinel, b"preserve\n").unwrap();
    let missing = directory.path().join("missing");
    let output = Command::new(binary())
        .arg("generate-circuit-kicad-board")
        .arg(&missing)
        .arg(&missing)
        .arg("--footprint-closure")
        .arg(&missing)
        .arg("--construction-profile")
        .arg(&missing)
        .arg("--physical-profile")
        .arg(&missing)
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(sentinel).unwrap(), b"preserve\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("board output directory already exists"));
    assert!(!stderr.contains(&directory.path().display().to_string()));
}

#[test]
fn failed_board_input_capture_removes_the_private_stage() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    let output_dir = directory.path().join("new-output");
    let output = Command::new(binary())
        .arg("generate-circuit-kicad-board")
        .arg(&missing)
        .arg(&missing)
        .arg("--footprint-closure")
        .arg(&missing)
        .arg("--construction-profile")
        .arg(&missing)
        .arg("--physical-profile")
        .arg(&missing)
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!output_dir.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(&directory.path().display().to_string())
    );
}

#[cfg(unix)]
#[test]
fn board_producer_rejects_a_shared_writable_output_parent() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let shared = directory.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let missing = directory.path().join("missing");
    let output_dir = shared.join("new-output");
    let output = Command::new(binary())
        .arg("generate-circuit-kicad-board")
        .arg(&missing)
        .arg(&missing)
        .arg("--footprint-closure")
        .arg(&missing)
        .arg("--construction-profile")
        .arg(&missing)
        .arg("--physical-profile")
        .arg(&missing)
        .arg("--output-dir")
        .arg(&output_dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!output_dir.exists());
    assert_eq!(fs::read_dir(&shared).unwrap().count(), 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("board output parent must not be writable by group or other users"));
    assert!(!stderr.contains(&directory.path().display().to_string()));
}

#[test]
fn board_producer_does_not_treat_distinct_equal_length_inputs_as_aliases() {
    let directory = tempfile::tempdir().unwrap();
    let paths = [
        directory.path().join("circuit.json"),
        directory.path().join("schematic.kicad_sch"),
        directory.path().join("closure.json"),
        directory.path().join("construction.json"),
        directory.path().join("physical.json"),
    ];
    for (index, path) in paths.iter().enumerate() {
        fs::write(path, format!("invalid-{index}\n")).unwrap();
    }
    let output_dir = directory.path().join("output");
    let output = run_board_producer(
        &paths[0],
        &paths[1],
        &paths[2],
        &paths[3],
        &paths[4],
        &output_dir,
    );
    assert!(!output.status.success());
    assert!(!output_dir.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("inputs must not alias"));
    assert!(!stderr.contains(&directory.path().display().to_string()));
}

#[test]
fn board_producer_rejects_hard_linked_input_aliases() {
    let directory = tempfile::tempdir().unwrap();
    let circuit = directory.path().join("circuit.json");
    let schematic = directory.path().join("schematic.kicad_sch");
    let closure = directory.path().join("closure.json");
    let construction = directory.path().join("construction.json");
    let physical = directory.path().join("physical.json");
    fs::write(&circuit, b"invalid\n").unwrap();
    fs::hard_link(&circuit, &schematic).unwrap();
    fs::write(&closure, b"x\n").unwrap();
    fs::write(&construction, b"yy\n").unwrap();
    fs::write(&physical, b"zzz\n").unwrap();
    let output_dir = directory.path().join("output");
    let output = run_board_producer(
        &circuit,
        &schematic,
        &closure,
        &construction,
        &physical,
        &output_dir,
    );
    assert!(!output.status.success());
    assert!(!output_dir.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("circuit specification and KiCad schematic inputs must not alias"));
    assert!(!stderr.contains(&directory.path().display().to_string()));
}

#[test]
fn board_producer_schemas_are_closed() {
    for command in [
        "footprint-closure-schema",
        "board-construction-profile-schema",
        "circuit-kicad-board-manifest-schema",
    ] {
        let output = Command::new(binary()).arg(command).output().unwrap();
        assert!(
            output.status.success(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(schema["additionalProperties"], false, "{command}");
    }
}
