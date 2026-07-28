use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

#[test]
fn diagnoses_required_and_optional_integrations_as_json() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let output_path = std::env::temp_dir().join(format!("pcbex-doctor-{suffix}.json"));
    let output = Command::new(binary())
        .args(["doctor", "--output", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    let report: Value = serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["engine"], "pcbex");
    assert_eq!(report["engine_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(report["ready"], true);
    let checks = report["checks"].as_array().unwrap();
    for id in [
        "pcbex",
        "working_directory",
        "fabrication_profiles",
        "kicad_cli",
        "git",
        "python",
    ] {
        assert!(checks.iter().any(|check| check["id"] == id));
    }
    assert_eq!(
        checks
            .iter()
            .find(|check| check["id"] == "kicad_cli")
            .unwrap()["required"],
        false
    );
    fs::remove_file(output_path).unwrap();
}

#[test]
fn required_kicad_check_fails_after_emitting_the_report() {
    let output = Command::new(binary())
        .args(["doctor", "--require-kicad"])
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ready"], false);
    let kicad = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "kicad_cli")
        .unwrap();
    assert_eq!(kicad["required"], true);
    assert_eq!(kicad["available"], false);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("pcbex installation is not ready: kicad_cli")
    );
}
