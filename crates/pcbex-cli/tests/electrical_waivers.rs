use serde_json::{Value, json};
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

#[test]
fn applies_expiring_auditable_waivers_after_writing_reports() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("pcbex-waivers-{suffix}"));
    fs::create_dir_all(&directory).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let review_path = directory.join("review.json");
    assert!(
        run(&[
            "check-schematic",
            path(&source),
            "--output",
            path(&review_path),
        ])
        .status
        .success()
    );
    let review: Value = serde_json::from_slice(&fs::read(&review_path).unwrap()).unwrap();
    let error_ids = review["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["severity"] == "error")
        .map(|finding| finding["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(!error_ids.is_empty());
    let waiver_path = directory.join("waivers.json");
    let waivers = json!({
        "schema_version": 1,
        "id": "prototype-v1",
        "waivers": error_ids.iter().enumerate().map(|(index, finding_id)| json!({
            "id": format!("prototype-{index}"),
            "finding_id": finding_id,
            "reason": "accepted for isolated prototype validation",
            "approved_by": "hardware-lead",
            "expires_on": "2026-08-31"
        })).collect::<Vec<_>>()
    });
    fs::write(&waiver_path, serde_json::to_vec_pretty(&waivers).unwrap()).unwrap();

    let active_path = directory.join("active.json");
    let active = run(&[
        "apply-electrical-waivers",
        path(&review_path),
        path(&waiver_path),
        "--as-of",
        "2026-08-31",
        "--output",
        path(&active_path),
        "--require-approved",
    ]);
    assert!(
        active.status.success(),
        "{}",
        String::from_utf8_lossy(&active.stderr)
    );
    let active_report: Value = serde_json::from_slice(&fs::read(&active_path).unwrap()).unwrap();
    assert_eq!(active_report["approved"], true);
    assert_eq!(
        active_report["counts"]["waived"].as_u64().unwrap(),
        error_ids.len() as u64
    );

    let expired_path = directory.join("expired.json");
    let expired = run(&[
        "apply-electrical-waivers",
        path(&review_path),
        path(&waiver_path),
        "--as-of",
        "2026-09-01",
        "--output",
        path(&expired_path),
        "--require-approved",
    ]);
    assert!(!expired.status.success());
    let expired_report: Value = serde_json::from_slice(&fs::read(&expired_path).unwrap()).unwrap();
    assert_eq!(expired_report["approved"], false);
    assert!(
        expired_report["counts"]["remaining_errors"]
            .as_u64()
            .unwrap()
            > 0
    );

    for command in [
        "electrical-waiver-set-schema",
        "electrical-waiver-report-schema",
    ] {
        let schema = run(&[command]);
        assert!(schema.status.success());
        let value: Value = serde_json::from_slice(&schema.stdout).unwrap();
        assert_eq!(value["additionalProperties"], false);
    }
    fs::remove_dir_all(directory).unwrap();
}
