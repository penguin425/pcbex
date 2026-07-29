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

fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-approval-log-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn appends_normalized_artifacts_and_verifies_signed_checkpoints() {
    let directory = temp_dir();
    let private_key = directory.join("checkpoint.key");
    let public_key = directory.join("checkpoint.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&private_key),
            "--public-key",
            path(&public_key),
        ])
        .status
        .success()
    );

    let empty = directory.join("empty.json");
    assert!(
        run(&[
            "init-approval-log",
            "--log-id",
            "production-approvals",
            "--output",
            path(&empty),
        ])
        .status
        .success()
    );

    let request_sha256 = "a".repeat(64);
    let approval = directory.join("approval.json");
    fs::write(
        &approval,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "request_sha256": request_sha256,
            "response_sha256": "b".repeat(64),
            "approved": true,
            "gate_failures": [],
            "signer_id": "reviewer-a",
            "algorithm": "ed25519",
            "public_key": "c".repeat(64),
            "signature": "d".repeat(128)
        }))
        .unwrap(),
    )
    .unwrap();
    let first = directory.join("first.json");
    assert!(
        run(&[
            "append-approval-log",
            path(&empty),
            "--artifact",
            path(&approval),
            "--kind",
            "signed-ai-approval",
            "--recorded-at-unix",
            "100",
            "--output",
            path(&first),
        ])
        .status
        .success()
    );

    let human_report = directory.join("human-report.json");
    fs::write(
        &human_report,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "session_sha256": "e".repeat(64),
            "request_sha256": request_sha256,
            "ai_quorum_sha256": "f".repeat(64),
            "evaluated_at_unix": 101,
            "policy": {"minimum_approvals": 2},
            "approvals": 2,
            "rejections": 0,
            "members": [{
                "signer_id": "engineer-a",
                "public_key": "1".repeat(64),
                "decision": "approve",
                "reason": "Reviewed.",
                "ticket": "HW-42"
            }, {
                "signer_id": "engineer-b",
                "public_key": "2".repeat(64),
                "decision": "approve",
                "reason": "Independently reviewed.",
                "ticket": "HW-42"
            }],
            "escalation_eligible": true,
            "escalation_approved": true,
            "gate_failures": []
        }))
        .unwrap(),
    )
    .unwrap();
    let second = directory.join("second.json");
    assert!(
        run(&[
            "append-approval-log",
            path(&first),
            "--artifact",
            path(&human_report),
            "--kind",
            "human-escalation-report",
            "--recorded-at-unix",
            "101",
            "--output",
            path(&second),
        ])
        .status
        .success()
    );

    let checkpoint = directory.join("checkpoint.json");
    assert!(
        run(&[
            "sign-approval-log",
            path(&second),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "security-log",
            "--output",
            path(&checkpoint),
        ])
        .status
        .success()
    );
    let report = directory.join("verification.json");
    assert!(
        run(&[
            "verify-approval-log",
            path(&second),
            "--checkpoint",
            path(&checkpoint),
            "--public-key",
            path(&public_key),
            "--output",
            path(&report),
        ])
        .status
        .success()
    );
    let report: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["entry_count"], 2);

    let log: Value = serde_json::from_slice(&fs::read(&second).unwrap()).unwrap();
    assert_eq!(log["entries"][0]["sequence"], 0);
    assert_eq!(
        log["entries"][1]["previous_entry_sha256"],
        log["entries"][0]["entry_sha256"]
    );
    assert_eq!(
        log["entries"][1]["event"]["artifact_kind"],
        "human_escalation_report"
    );

    let mut tampered = log;
    tampered["entries"][0]["event"]["outcome"] = "rejected".into();
    let tampered_path = directory.join("tampered.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let rejected_output = directory.join("rejected.json");
    assert!(
        !run(&[
            "verify-approval-log",
            path(&tampered_path),
            "--checkpoint",
            path(&checkpoint),
            "--public-key",
            path(&public_key),
            "--output",
            path(&rejected_output),
        ])
        .status
        .success()
    );
    assert!(!rejected_output.exists());

    fs::remove_dir_all(directory).unwrap();
}
