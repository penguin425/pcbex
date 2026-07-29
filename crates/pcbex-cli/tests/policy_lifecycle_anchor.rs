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
    let path = std::env::temp_dir().join(format!("pcbex-lifecycle-anchor-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_checkpoint(path: &Path, marker: u8) {
    let checkpoint = json!({
        "schema_version": 1,
        "policy_pack_id": "organization",
        "generation": 1,
        "entry_count": 1,
        "ledger_sha256": format!("{marker:064x}"),
        "head_sha256": format!("{:064x}", marker + 1),
        "issued_at_unix": 100,
        "signer_id": "lifecycle-root",
        "algorithm": "ed25519",
        "public_key": format!("{:064x}", marker + 2),
        "signature": format!("{:0128x}", marker + 3)
    });
    fs::write(path, serde_json::to_vec_pretty(&checkpoint).unwrap()).unwrap();
}

#[test]
fn creates_and_verifies_policy_lifecycle_public_log_anchor() {
    let directory = temp_dir();
    let private_key = directory.join("public-log.key");
    let public_key = directory.join("public-log.pub");
    let keygen = run(&[
        "approval-keygen",
        "--private-key",
        path(&private_key),
        "--public-key",
        path(&public_key),
    ]);
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    let checkpoints = [
        directory.join("checkpoint-0.json"),
        directory.join("checkpoint-1.json"),
        directory.join("checkpoint-2.json"),
    ];
    for (index, checkpoint) in checkpoints.iter().enumerate() {
        write_checkpoint(checkpoint, index as u8 + 1);
    }

    let proof = directory.join("anchor.json");
    let create = run(&[
        "create-policy-lifecycle-log-anchor",
        path(&checkpoints[1]),
        "--log-checkpoint",
        path(&checkpoints[0]),
        "--log-checkpoint",
        path(&checkpoints[1]),
        "--log-checkpoint",
        path(&checkpoints[2]),
        "--leaf-index",
        "1",
        "--log-id",
        "lifecycle-public-log",
        "--private-key",
        path(&private_key),
        "--observed-at-unix",
        "200",
        "--output",
        path(&proof),
    ]);
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    assert!(
        run(&["validate-policy-lifecycle-log-anchor-proof", path(&proof)])
            .status
            .success()
    );

    let report = directory.join("anchor-verification.json");
    let verify = run(&[
        "verify-policy-lifecycle-log-anchor",
        path(&checkpoints[1]),
        "--proof",
        path(&proof),
        "--log-id",
        "lifecycle-public-log",
        "--public-key",
        path(&public_key),
        "--output",
        path(&report),
    ]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(report["anchored"], true);
    assert_eq!(report["policy_pack_id"], "organization");
    assert_eq!(report["tree_size"], 3);
    assert_eq!(report["leaf_index"], 1);
    assert_eq!(report["tree_head_observed_at_unix"], 200);

    let previous_proof = directory.join("anchor.previous.json");
    let create_previous = run(&[
        "create-policy-lifecycle-log-anchor",
        path(&checkpoints[1]),
        "--log-checkpoint",
        path(&checkpoints[0]),
        "--log-checkpoint",
        path(&checkpoints[1]),
        "--leaf-index",
        "1",
        "--log-id",
        "lifecycle-public-log",
        "--private-key",
        path(&private_key),
        "--observed-at-unix",
        "150",
        "--output",
        path(&previous_proof),
    ]);
    assert!(
        create_previous.status.success(),
        "{}",
        String::from_utf8_lossy(&create_previous.stderr)
    );
    let consistency = directory.join("consistency.json");
    let create_consistency = run(&[
        "create-policy-lifecycle-log-consistency",
        "--previous-anchor",
        path(&previous_proof),
        "--current-anchor",
        path(&proof),
        "--log-checkpoint",
        path(&checkpoints[0]),
        "--log-checkpoint",
        path(&checkpoints[1]),
        "--log-checkpoint",
        path(&checkpoints[2]),
        "--output",
        path(&consistency),
    ]);
    assert!(
        create_consistency.status.success(),
        "{}",
        String::from_utf8_lossy(&create_consistency.stderr)
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-consistency-proof",
            path(&consistency)
        ])
        .status
        .success()
    );
    let consistency_report = directory.join("consistency-verification.json");
    let verify_consistency = run(&[
        "verify-policy-lifecycle-log-consistency",
        "--previous-anchor",
        path(&previous_proof),
        "--current-anchor",
        path(&proof),
        "--proof",
        path(&consistency),
        "--log-id",
        "lifecycle-public-log",
        "--public-key",
        path(&public_key),
        "--output",
        path(&consistency_report),
    ]);
    assert!(
        verify_consistency.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_consistency.stderr)
    );
    let consistency_report: Value =
        serde_json::from_slice(&fs::read(&consistency_report).unwrap()).unwrap();
    assert_eq!(consistency_report["consistent"], true);
    assert_eq!(consistency_report["old_tree_size"], 2);
    assert_eq!(consistency_report["new_tree_size"], 3);

    let mut tampered_consistency: Value =
        serde_json::from_slice(&fs::read(&consistency).unwrap()).unwrap();
    tampered_consistency["consistency_path"][0] = Value::String("0".repeat(64));
    let tampered_consistency_path = directory.join("consistency.tampered.json");
    fs::write(
        &tampered_consistency_path,
        serde_json::to_vec_pretty(&tampered_consistency).unwrap(),
    )
    .unwrap();
    let rejected_consistency_report = directory.join("consistency.rejected.json");
    assert!(
        !run(&[
            "verify-policy-lifecycle-log-consistency",
            "--previous-anchor",
            path(&previous_proof),
            "--current-anchor",
            path(&proof),
            "--proof",
            path(&tampered_consistency_path),
            "--log-id",
            "lifecycle-public-log",
            "--public-key",
            path(&public_key),
            "--output",
            path(&rejected_consistency_report),
        ])
        .status
        .success()
    );
    assert!(!rejected_consistency_report.exists());

    let mut tampered: Value = serde_json::from_slice(&fs::read(&proof).unwrap()).unwrap();
    tampered["tree_head"]["signature"] = Value::String("0".repeat(128));
    let tampered_path = directory.join("anchor.tampered.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    let rejected_report = directory.join("anchor.rejected.json");
    assert!(
        !run(&[
            "verify-policy-lifecycle-log-anchor",
            path(&checkpoints[1]),
            "--proof",
            path(&tampered_path),
            "--log-id",
            "lifecycle-public-log",
            "--public-key",
            path(&public_key),
            "--output",
            path(&rejected_report),
        ])
        .status
        .success()
    );
    assert!(!rejected_report.exists());

    fs::remove_dir_all(directory).unwrap();
}
