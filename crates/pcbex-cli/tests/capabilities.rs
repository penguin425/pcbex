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
        "compare-schematics",
        "check-schematic",
        "prepare-ai-review",
        "verify-ai-quorum",
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
