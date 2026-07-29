use serde_json::Value;
use std::{path::PathBuf, process::Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
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
        "compare-schematics",
        "route-schematic-review",
        "check-schematic",
        "prepare-ai-review",
        "verify-ai-quorum",
        "sign-human-escalation",
        "verify-human-escalation",
        "init-approval-log",
        "append-approval-log",
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
        report["output_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|contract| contract == "SARIF 2.1.0")
    );
}
