#![cfg(unix)]

use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary()).args(arguments).output().unwrap()
}

fn successful(arguments: &[&str]) -> Output {
    let output = run(arguments);
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

fn public(secret: [u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
}

#[derive(Serialize)]
struct Observer<'a> {
    organization_id: &'a str,
    observer_id: &'a str,
    algorithm: &'static str,
    public_key: String,
}

#[derive(Serialize)]
struct Policy<'a> {
    schema_version: u32,
    policy_scope: &'static str,
    policy_id: &'static str,
    minimum_organizations: u32,
    maximum_receipt_age_seconds: u64,
    trusted_observers: Vec<Observer<'a>>,
}

fn write_policy(path: &Path) -> String {
    let policy = Policy {
        schema_version: 1,
        policy_scope: "factory-release-state-transparency-external-gossip-quorum-policy-v1",
        policy_id: "rotation-integration",
        minimum_organizations: 2,
        maximum_receipt_age_seconds: 300,
        trusted_observers: vec![
            Observer {
                organization_id: "lab-a",
                observer_id: "observer-a",
                algorithm: "ed25519",
                public_key: public([11; 32]),
            },
            Observer {
                organization_id: "lab-b",
                observer_id: "observer-b",
                algorithm: "ed25519",
                public_key: public([21; 32]),
            },
        ],
    };
    let compact = serde_json::to_vec(&policy).unwrap();
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&policy).unwrap()),
    )
    .unwrap();
    hex::encode(Sha256::digest(compact))
}

fn write_secret(path: &Path, secret: [u8; 32]) {
    fs::write(path, format!("{}\n", hex::encode(secret))).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn assert_closed_and_bounded(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".into())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false))
                );
            }
            if object.get("type") == Some(&Value::String("array".into())) {
                assert!(object.contains_key("maxItems"));
            }
            for child in object.values() {
                assert_closed_and_bounded(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                assert_closed_and_bounded(child);
            }
        }
        _ => {}
    }
}

#[test]
fn retains_dual_signed_rotations_and_derives_the_current_policy() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let ledger = root.join("ledger");
    fs::create_dir(&ledger).unwrap();
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o700)).unwrap();
    let ledger_id = "e".repeat(64);
    let manifest = ledger.join(".pcbex-signed-factory-receipt-release-reservation-ledger-v1.json");
    fs::write(
        &manifest,
        format!(
            "{{\"schema_version\":1,\"ledger_scope\":\"pinned-local-signed-factory-receipt-release-ledger-at-most-once-v1\",\"ledger_id\":\"{ledger_id}\"}}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();

    let base_policy = root.join("base-policy.json");
    let base_digest = write_policy(&base_policy);
    let old_key = root.join("old.hex");
    let next_key = root.join("next.hex");
    let final_key = root.join("final.hex");
    let fork_key = root.join("fork.hex");
    write_secret(&old_key, [11; 32]);
    write_secret(&next_key, [12; 32]);
    write_secret(&final_key, [13; 32]);
    write_secret(&fork_key, [14; 32]);

    let initial = root.join("initial.json");
    successful(&[
        "export-factory-release-state-transparency-external-gossip-observer-trust-state",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--organization-id",
        "lab-a",
        "--observer-id",
        "observer-a",
        "--output",
        path(&initial),
    ]);
    let initial_value: Value = serde_json::from_slice(&fs::read(&initial).unwrap()).unwrap();
    assert_eq!(initial_value["generation"], 0);
    assert_eq!(initial_value["initial_public_key"], public([11; 32]));
    assert_eq!(
        initial_value["base_observer_quorum_policy_sha256"],
        base_digest
    );

    let rotation = root.join("rotation.json");
    let fork = root.join("fork.json");
    for (successor, output) in [(&next_key, &rotation), (&fork_key, &fork)] {
        successful(&[
            "sign-factory-release-state-transparency-external-gossip-observer-key-rotation",
            "--trust-state",
            path(&initial),
            "--old-private-key",
            path(&old_key),
            "--new-private-key",
            path(successor),
            "--rotated-at-unix",
            "1000",
            "--output",
            path(output),
        ]);
    }

    let applied_a = root.join("applied-a.json");
    let applied_b = root.join("applied-b.json");
    let common = [
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&rotation),
        "--output",
    ];
    let mut first = Command::new(binary())
        .args(common)
        .arg(&applied_a)
        .spawn()
        .unwrap();
    let mut second = Command::new(binary())
        .args(common)
        .arg(&applied_b)
        .spawn()
        .unwrap();
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    assert_eq!(fs::read(&applied_a).unwrap(), fs::read(&applied_b).unwrap());
    let applied_value: Value = serde_json::from_slice(&fs::read(&applied_a).unwrap()).unwrap();
    assert_eq!(applied_value["generation"], 1);
    assert_eq!(applied_value["current_public_key"], public([12; 32]));

    let exact_retry = root.join("exact-retry.json");
    successful(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&rotation),
        "--output",
        path(&exact_retry),
    ]);
    assert_eq!(
        fs::read(&applied_a).unwrap(),
        fs::read(&exact_retry).unwrap()
    );

    let fork_output = root.join("fork-output.json");
    let fork_failure = run(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&fork),
        "--output",
        path(&fork_output),
    ]);
    assert!(!fork_failure.status.success());
    assert!(!fork_output.exists());
    assert!(
        String::from_utf8_lossy(&fork_failure.stderr).contains("conflicts with retained history")
    );

    let tampered = root.join("tampered.json");
    let rotation_source = fs::read_to_string(&rotation).unwrap();
    let rotation_value: Value = serde_json::from_str(&rotation_source).unwrap();
    let signature = rotation_value["new_signature"].as_str().unwrap();
    fs::write(
        &tampered,
        rotation_source.replacen(signature, &"0".repeat(128), 1),
    )
    .unwrap();
    let tampered_output = root.join("tampered-output.json");
    let tampered_failure = run(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&tampered),
        "--output",
        path(&tampered_output),
    ]);
    assert!(!tampered_failure.status.success());
    assert!(!tampered_output.exists());
    assert!(
        String::from_utf8_lossy(&tampered_failure.stderr).contains("signature verification failed")
    );

    let effective = root.join("effective.json");
    let effective_digest_path = root.join("effective.sha256");
    successful(&[
        "derive-factory-release-state-transparency-external-gossip-effective-quorum-policy",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--output",
        path(&effective),
        "--digest-output",
        path(&effective_digest_path),
    ]);
    let effective_value: Value = serde_json::from_slice(&fs::read(&effective).unwrap()).unwrap();
    assert_eq!(
        effective_value["trusted_observers"][0]["public_key"],
        public([12; 32])
    );
    assert_eq!(
        effective_value["trusted_observers"][1]["public_key"],
        public([21; 32])
    );
    assert_ne!(
        fs::read_to_string(&effective_digest_path).unwrap().trim(),
        base_digest
    );

    let second_rotation = root.join("second-rotation.json");
    successful(&[
        "sign-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--trust-state",
        path(&applied_a),
        "--old-private-key",
        path(&next_key),
        "--new-private-key",
        path(&final_key),
        "--rotated-at-unix",
        "2000",
        "--output",
        path(&second_rotation),
    ]);
    let twice = root.join("twice.json");
    successful(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&second_rotation),
        "--output",
        path(&twice),
    ]);
    let twice_value: Value = serde_json::from_slice(&fs::read(&twice).unwrap()).unwrap();
    assert_eq!(twice_value["generation"], 2);
    assert_eq!(twice_value["current_public_key"], public([13; 32]));

    let stale_output = root.join("stale.json");
    let stale = run(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&rotation),
        "--output",
        path(&stale_output),
    ]);
    assert!(!stale.status.success());
    assert!(!stale_output.exists());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("stale replay"));

    let reused_rotation = root.join("reused.json");
    let reused = run(&[
        "sign-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--trust-state",
        path(&twice),
        "--old-private-key",
        path(&final_key),
        "--new-private-key",
        path(&next_key),
        "--rotated-at-unix",
        "3000",
        "--output",
        path(&reused_rotation),
    ]);
    assert!(reused.status.success());
    let reused_output = root.join("reused-output.json");
    let rejected_reuse = run(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&base_policy),
        "--expected-base-observer-quorum-policy-sha256",
        &base_digest,
        "--rotation",
        path(&reused_rotation),
        "--output",
        path(&reused_output),
    ]);
    assert!(!rejected_reuse.status.success());
    assert!(!reused_output.exists());
    assert!(String::from_utf8_lossy(&rejected_reuse.stderr).contains("reuses a historical key"));

    let rotation_records = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with(
                "factory-release-state-transparency-external-gossip-observer-rotation-v1-",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(rotation_records.len(), 2);
    let secrets = [
        hex::encode([11; 32]),
        hex::encode([12; 32]),
        hex::encode([13; 32]),
    ];
    for entry in fs::read_dir(&ledger).unwrap() {
        let source = fs::read(entry.unwrap().path()).unwrap();
        for secret in &secrets {
            assert!(
                !source
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
}

#[test]
fn publishes_closed_bounded_rotation_schemas() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    for (command, filename) in [
        (
            "factory-release-state-transparency-external-gossip-observer-trust-state-schema",
            "state.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-observer-key-rotation-schema",
            "rotation.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-observer-trust-verification-report-schema",
            "report.schema.json",
        ),
    ] {
        let output = root.join(filename);
        successful(&[command, "--output", path(&output)]);
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_closed_and_bounded(&schema);
    }
}
