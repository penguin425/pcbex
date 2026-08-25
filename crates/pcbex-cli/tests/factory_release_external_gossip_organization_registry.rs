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
        policy_id: "registry-integration",
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

fn write_hex(path: &Path, value: impl AsRef<[u8]>, mode: u32) {
    fs::write(path, format!("{}\n", hex::encode(value))).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn create_ledger(root: &Path) -> (PathBuf, String) {
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
    (ledger, ledger_id)
}

#[allow(clippy::too_many_arguments)]
fn export_observer(
    ledger: &Path,
    ledger_id: &str,
    policy: &Path,
    policy_sha256: &str,
    organization_id: &str,
    observer_id: &str,
    output: &Path,
) {
    successful(&[
        "export-factory-release-state-transparency-external-gossip-observer-trust-state",
        "--reservation-ledger",
        path(ledger),
        "--expected-ledger-id",
        ledger_id,
        "--base-observer-quorum-policy",
        path(policy),
        "--expected-base-observer-quorum-policy-sha256",
        policy_sha256,
        "--organization-id",
        organization_id,
        "--observer-id",
        observer_id,
        "--output",
        path(output),
    ]);
}

#[allow(clippy::too_many_arguments)]
fn export_registry(
    ledger: &Path,
    ledger_id: &str,
    policy: &Path,
    policy_sha256: &str,
    genesis: &Path,
    genesis_sha256: &str,
    output: &Path,
) {
    successful(&[
        "export-factory-release-state-transparency-external-gossip-organization-registry",
        "--reservation-ledger",
        path(ledger),
        "--expected-ledger-id",
        ledger_id,
        "--base-observer-quorum-policy",
        path(policy),
        "--expected-base-observer-quorum-policy-sha256",
        policy_sha256,
        "--registry-genesis",
        path(genesis),
        "--expected-registry-genesis-sha256",
        genesis_sha256,
        "--output",
        path(output),
    ]);
}

#[allow(clippy::too_many_arguments)]
fn sign_transition(
    registry: &Path,
    authority_secret: &Path,
    action: &str,
    organization_id: &str,
    observer_trust: Option<&Path>,
    effective_at_unix: &str,
    output: &Path,
) -> Output {
    let mut arguments = vec![
        "sign-factory-release-state-transparency-external-gossip-organization-registry-transition",
        "--registry-state",
        path(registry),
        "--authority-private-key",
        path(authority_secret),
        "--action",
        action,
        "--organization-id",
        organization_id,
    ];
    if let Some(observer_trust) = observer_trust {
        arguments.extend(["--observer-trust-state", path(observer_trust)]);
    }
    let reason = "a".repeat(64);
    arguments.extend([
        "--reason-sha256",
        &reason,
        "--effective-at-unix",
        effective_at_unix,
        "--output",
        path(output),
    ]);
    run(&arguments)
}

#[allow(clippy::too_many_arguments)]
fn apply_transition(
    ledger: &Path,
    ledger_id: &str,
    policy: &Path,
    policy_sha256: &str,
    genesis: &Path,
    genesis_sha256: &str,
    transition: &Path,
    output: &Path,
) -> Output {
    run(&[
        "apply-factory-release-state-transparency-external-gossip-organization-registry-transition",
        "--reservation-ledger",
        path(ledger),
        "--expected-ledger-id",
        ledger_id,
        "--base-observer-quorum-policy",
        path(policy),
        "--expected-base-observer-quorum-policy-sha256",
        policy_sha256,
        "--registry-genesis",
        path(genesis),
        "--expected-registry-genesis-sha256",
        genesis_sha256,
        "--transition",
        path(transition),
        "--output",
        path(output),
    ])
}

fn sign_authority_rotation(
    registry: &Path,
    old_authority_secret: &Path,
    new_authority_secret: &Path,
    rotated_at_unix: &str,
    output: &Path,
) -> Output {
    run(&[
        "sign-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation",
        "--registry-state",
        path(registry),
        "--old-authority-private-key",
        path(old_authority_secret),
        "--new-authority-private-key",
        path(new_authority_secret),
        "--rotated-at-unix",
        rotated_at_unix,
        "--output",
        path(output),
    ])
}

#[allow(clippy::too_many_arguments)]
fn apply_authority_rotation(
    ledger: &Path,
    ledger_id: &str,
    policy: &Path,
    policy_sha256: &str,
    genesis: &Path,
    genesis_sha256: &str,
    rotation: &Path,
    output: &Path,
) -> Output {
    run(&[
        "apply-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation",
        "--reservation-ledger",
        path(ledger),
        "--expected-ledger-id",
        ledger_id,
        "--base-observer-quorum-policy",
        path(policy),
        "--expected-base-observer-quorum-policy-sha256",
        policy_sha256,
        "--registry-genesis",
        path(genesis),
        "--expected-registry-genesis-sha256",
        genesis_sha256,
        "--rotation",
        path(rotation),
        "--output",
        path(output),
    ])
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
fn governs_current_observer_admission_and_organization_status() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (ledger, ledger_id) = create_ledger(&root);
    let policy = root.join("base-policy.json");
    let policy_sha256 = write_policy(&policy);
    let authority_secret = root.join("authority-secret.hex");
    let authority_public = root.join("authority-public.hex");
    let authority = SigningKey::from_bytes(&[31; 32]);
    write_hex(&authority_secret, [31; 32], 0o600);
    write_hex(
        &authority_public,
        authority.verifying_key().to_bytes(),
        0o644,
    );

    let genesis = root.join("registry-genesis.json");
    let genesis_digest = root.join("registry-genesis.sha256");
    successful(&[
        "init-factory-release-state-transparency-external-gossip-organization-registry",
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--registry-id",
        "production-observers",
        "--authority-public-key",
        path(&authority_public),
        "--output",
        path(&genesis),
        "--digest-output",
        path(&genesis_digest),
    ]);
    let genesis_sha256 = fs::read_to_string(&genesis_digest).unwrap();
    let genesis_sha256 = genesis_sha256.trim();
    let genesis_value: Value = serde_json::from_slice(&fs::read(&genesis).unwrap()).unwrap();
    assert_eq!(genesis_value["generation"], 0);
    assert_eq!(genesis_value["authority_public_key"], public([31; 32]));

    let initial_registry = root.join("registry-initial.json");
    export_registry(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &initial_registry,
    );
    assert_eq!(
        fs::read(&genesis).unwrap(),
        fs::read(&initial_registry).unwrap()
    );

    let observer_a = root.join("observer-a.json");
    export_observer(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        "lab-a",
        "observer-a",
        &observer_a,
    );
    let admission_a = root.join("admission-a.json");
    let signed = sign_transition(
        &initial_registry,
        &authority_secret,
        "admit-observer",
        "lab-a",
        Some(&observer_a),
        "1000",
        &admission_a,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );

    let wrong_secret = root.join("wrong-secret.hex");
    write_hex(&wrong_secret, [41; 32], 0o600);
    let wrong_transition = root.join("wrong-transition.json");
    let wrong = sign_transition(
        &initial_registry,
        &wrong_secret,
        "admit-observer",
        "lab-a",
        Some(&observer_a),
        "1000",
        &wrong_transition,
    );
    assert!(!wrong.status.success());
    assert!(!wrong_transition.exists());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("authority key does not match"));

    let applied_a = root.join("applied-a.json");
    let applied_b = root.join("applied-b.json");
    let common = [
        "apply-factory-release-state-transparency-external-gossip-organization-registry-transition",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--registry-genesis",
        path(&genesis),
        "--expected-registry-genesis-sha256",
        genesis_sha256,
        "--transition",
        path(&admission_a),
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
    let current_a: Value = serde_json::from_slice(&fs::read(&applied_a).unwrap()).unwrap();
    assert_eq!(current_a["generation"], 1);
    assert_eq!(current_a["organizations"][0]["status"], "active");

    let exact_retry = root.join("exact-retry.json");
    let retry = apply_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &admission_a,
        &exact_retry,
    );
    assert!(retry.status.success());
    assert_eq!(
        fs::read(&applied_a).unwrap(),
        fs::read(&exact_retry).unwrap()
    );

    let uncommitted = root.join("uncommitted.json");
    assert!(
        sign_transition(
            &applied_a,
            &authority_secret,
            "suspend-organization",
            "lab-a",
            None,
            "1050",
            &uncommitted,
        )
        .status
        .success()
    );
    let tampered = root.join("tampered.json");
    let source = fs::read_to_string(&uncommitted).unwrap();
    let value: Value = serde_json::from_str(&source).unwrap();
    let signature = value["signature"].as_str().unwrap();
    fs::write(&tampered, source.replacen(signature, &"0".repeat(128), 1)).unwrap();
    let tampered_output = root.join("tampered-output.json");
    let tampered_result = apply_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &tampered,
        &tampered_output,
    );
    assert!(!tampered_result.status.success());
    assert!(!tampered_output.exists());
    assert!(
        String::from_utf8_lossy(&tampered_result.stderr).contains("signature verification failed")
    );

    let observer_b_old = root.join("observer-b-old.json");
    export_observer(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        "lab-b",
        "observer-b",
        &observer_b_old,
    );
    let stale_admission = root.join("stale-admission.json");
    assert!(
        sign_transition(
            &applied_a,
            &authority_secret,
            "admit-observer",
            "lab-b",
            Some(&observer_b_old),
            "1100",
            &stale_admission,
        )
        .status
        .success()
    );

    let observer_b_old_secret = root.join("observer-b-old.hex");
    let observer_b_new_secret = root.join("observer-b-new.hex");
    write_hex(&observer_b_old_secret, [21; 32], 0o600);
    write_hex(&observer_b_new_secret, [22; 32], 0o600);
    let observer_b_rotation = root.join("observer-b-rotation.json");
    successful(&[
        "sign-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--trust-state",
        path(&observer_b_old),
        "--old-private-key",
        path(&observer_b_old_secret),
        "--new-private-key",
        path(&observer_b_new_secret),
        "--rotated-at-unix",
        "1050",
        "--output",
        path(&observer_b_rotation),
    ]);
    let observer_b_current = root.join("observer-b-current.json");
    successful(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--rotation",
        path(&observer_b_rotation),
        "--output",
        path(&observer_b_current),
    ]);
    let stale_output = root.join("stale-output.json");
    let stale = apply_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &stale_admission,
        &stale_output,
    );
    assert!(!stale.status.success());
    assert!(!stale_output.exists());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("latest selected-ledger trust state"));

    let registry_one = root.join("registry-one.json");
    export_registry(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &registry_one,
    );
    let admission_b = root.join("admission-b.json");
    assert!(
        sign_transition(
            &registry_one,
            &authority_secret,
            "admit-observer",
            "lab-b",
            Some(&observer_b_current),
            "1200",
            &admission_b,
        )
        .status
        .success()
    );
    let registry_two = root.join("registry-two.json");
    let applied = apply_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &admission_b,
        &registry_two,
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let current: Value = serde_json::from_slice(&fs::read(&registry_two).unwrap()).unwrap();
    assert_eq!(current["generation"], 2);
    assert_eq!(current["organizations"].as_array().unwrap().len(), 2);

    let fork_output = root.join("fork-output.json");
    let fork = apply_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &stale_admission,
        &fork_output,
    );
    assert!(!fork.status.success());
    assert!(!fork_output.exists());
    assert!(String::from_utf8_lossy(&fork.stderr).contains("latest selected-ledger trust state"));

    let suspend = root.join("suspend.json");
    assert!(
        sign_transition(
            &registry_two,
            &authority_secret,
            "suspend-organization",
            "lab-a",
            None,
            "1300",
            &suspend,
        )
        .status
        .success()
    );
    let registry_three = root.join("registry-three.json");
    assert!(
        apply_transition(
            &ledger,
            &ledger_id,
            &policy,
            &policy_sha256,
            &genesis,
            genesis_sha256,
            &suspend,
            &registry_three,
        )
        .status
        .success()
    );
    let suspended: Value = serde_json::from_slice(&fs::read(&registry_three).unwrap()).unwrap();
    assert_eq!(suspended["organizations"][0]["status"], "suspended");

    let revoke = root.join("revoke.json");
    assert!(
        sign_transition(
            &registry_three,
            &authority_secret,
            "revoke-organization",
            "lab-a",
            None,
            "1400",
            &revoke,
        )
        .status
        .success()
    );
    let registry_four = root.join("registry-four.json");
    assert!(
        apply_transition(
            &ledger,
            &ledger_id,
            &policy,
            &policy_sha256,
            &genesis,
            genesis_sha256,
            &revoke,
            &registry_four,
        )
        .status
        .success()
    );
    let revoked: Value = serde_json::from_slice(&fs::read(&registry_four).unwrap()).unwrap();
    assert_eq!(revoked["generation"], 4);
    assert_eq!(revoked["organizations"][0]["status"], "revoked");

    let colliding_rotation = root.join("observer-b-authority-collision.json");
    successful(&[
        "sign-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--trust-state",
        path(&observer_b_current),
        "--old-private-key",
        path(&observer_b_new_secret),
        "--new-private-key",
        path(&authority_secret),
        "--rotated-at-unix",
        "1500",
        "--output",
        path(&colliding_rotation),
    ]);
    let colliding_state = root.join("observer-b-authority-collision-state.json");
    successful(&[
        "apply-factory-release-state-transparency-external-gossip-observer-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--rotation",
        path(&colliding_rotation),
        "--output",
        path(&colliding_state),
    ]);
    let rejected_export = root.join("registry-role-collision.json");
    let collision = run(&[
        "export-factory-release-state-transparency-external-gossip-organization-registry",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--registry-genesis",
        path(&genesis),
        "--expected-registry-genesis-sha256",
        genesis_sha256,
        "--output",
        path(&rejected_export),
    ]);
    assert!(!collision.status.success());
    assert!(!rejected_export.exists());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("not role-disjoint"));

    let records = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with(
                "factory-release-state-transparency-external-gossip-organization-registry-transition-v1-",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 4);
    for entry in fs::read_dir(&ledger).unwrap() {
        let source = fs::read(entry.unwrap().path()).unwrap();
        for secret in [
            hex::encode([31; 32]),
            hex::encode([21; 32]),
            hex::encode([22; 32]),
        ] {
            assert!(
                !source
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
}

#[test]
fn rotates_registry_authority_with_dual_signatures_and_exact_ledger_convergence() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (ledger, ledger_id) = create_ledger(&root);
    let policy = root.join("base-policy.json");
    let policy_sha256 = write_policy(&policy);
    let old_secret = root.join("authority-old.hex");
    let new_secret = root.join("authority-new.hex");
    let third_secret = root.join("authority-third.hex");
    let observer_secret = root.join("observer-a-secret.hex");
    let old_public = root.join("authority-old-public.hex");
    write_hex(&old_secret, [31; 32], 0o600);
    write_hex(&new_secret, [41; 32], 0o600);
    write_hex(&third_secret, [51; 32], 0o600);
    write_hex(&observer_secret, [11; 32], 0o600);
    write_hex(
        &old_public,
        SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        0o644,
    );

    let genesis = root.join("registry-genesis.json");
    let genesis_digest = root.join("registry-genesis.sha256");
    successful(&[
        "init-factory-release-state-transparency-external-gossip-organization-registry",
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--registry-id",
        "production-observers",
        "--authority-public-key",
        path(&old_public),
        "--output",
        path(&genesis),
        "--digest-output",
        path(&genesis_digest),
    ]);
    let genesis_sha256 = fs::read_to_string(&genesis_digest).unwrap();
    let genesis_sha256 = genesis_sha256.trim();
    let initial = root.join("registry-initial.json");
    export_registry(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &initial,
    );

    let wrong_rotation = root.join("wrong-rotation.json");
    let wrong = sign_authority_rotation(
        &initial,
        &third_secret,
        &new_secret,
        "1000",
        &wrong_rotation,
    );
    assert!(!wrong.status.success());
    assert!(!wrong_rotation.exists());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("does not match the current registry"));

    let rotation = root.join("authority-rotation.json");
    let signed = sign_authority_rotation(&initial, &old_secret, &new_secret, "1000", &rotation);
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let rotation_value: Value = serde_json::from_slice(&fs::read(&rotation).unwrap()).unwrap();
    assert_eq!(rotation_value["old_public_key"], public([31; 32]));
    assert_eq!(rotation_value["new_public_key"], public([41; 32]));
    assert_eq!(rotation_value["old_signature"].as_str().unwrap().len(), 128);
    assert_eq!(rotation_value["new_signature"].as_str().unwrap().len(), 128);

    let tampered_rotation = root.join("tampered-rotation.json");
    let source = fs::read_to_string(&rotation).unwrap();
    let signature = rotation_value["new_signature"].as_str().unwrap();
    fs::write(
        &tampered_rotation,
        source.replacen(signature, &"0".repeat(128), 1),
    )
    .unwrap();
    let tampered_output = root.join("tampered-output.json");
    let tampered = apply_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &tampered_rotation,
        &tampered_output,
    );
    assert!(!tampered.status.success());
    assert!(!tampered_output.exists());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("signature verification failed"));

    let applied_a = root.join("rotated-a.json");
    let applied_b = root.join("rotated-b.json");
    let common = [
        "apply-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation",
        "--reservation-ledger",
        path(&ledger),
        "--expected-ledger-id",
        &ledger_id,
        "--base-observer-quorum-policy",
        path(&policy),
        "--expected-base-observer-quorum-policy-sha256",
        &policy_sha256,
        "--registry-genesis",
        path(&genesis),
        "--expected-registry-genesis-sha256",
        genesis_sha256,
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
    let rotated: Value = serde_json::from_slice(&fs::read(&applied_a).unwrap()).unwrap();
    assert_eq!(rotated["generation"], 1);
    assert_eq!(rotated["authority_public_key"], public([41; 32]));
    assert!(rotated["organizations"].as_array().unwrap().is_empty());

    let exact_retry = root.join("rotation-exact-retry.json");
    assert!(
        apply_authority_rotation(
            &ledger,
            &ledger_id,
            &policy,
            &policy_sha256,
            &genesis,
            genesis_sha256,
            &rotation,
            &exact_retry,
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(&applied_a).unwrap(),
        fs::read(&exact_retry).unwrap()
    );

    let observer_a = root.join("observer-a.json");
    export_observer(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        "lab-a",
        "observer-a",
        &observer_a,
    );
    let rejected_old_transition = root.join("rejected-old-transition.json");
    let rejected_old = sign_transition(
        &applied_a,
        &old_secret,
        "admit-observer",
        "lab-a",
        Some(&observer_a),
        "1100",
        &rejected_old_transition,
    );
    assert!(!rejected_old.status.success());
    assert!(!rejected_old_transition.exists());

    let transition = root.join("new-authority-transition.json");
    assert!(
        sign_transition(
            &applied_a,
            &new_secret,
            "admit-observer",
            "lab-a",
            Some(&observer_a),
            "1100",
            &transition,
        )
        .status
        .success()
    );
    let competing_rotation = root.join("competing-rotation.json");
    assert!(
        sign_authority_rotation(
            &applied_a,
            &new_secret,
            &third_secret,
            "1100",
            &competing_rotation,
        )
        .status
        .success()
    );
    let transition_output = root.join("competing-transition-state.json");
    let rotation_output = root.join("competing-rotation-state.json");
    let mut transition_process = Command::new(binary())
        .args([
            "apply-factory-release-state-transparency-external-gossip-organization-registry-transition",
            "--reservation-ledger",
            path(&ledger),
            "--expected-ledger-id",
            &ledger_id,
            "--base-observer-quorum-policy",
            path(&policy),
            "--expected-base-observer-quorum-policy-sha256",
            &policy_sha256,
            "--registry-genesis",
            path(&genesis),
            "--expected-registry-genesis-sha256",
            genesis_sha256,
            "--transition",
            path(&transition),
            "--output",
            path(&transition_output),
        ])
        .spawn()
        .unwrap();
    let mut rotation_process = Command::new(binary())
        .args([
            "apply-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation",
            "--reservation-ledger",
            path(&ledger),
            "--expected-ledger-id",
            &ledger_id,
            "--base-observer-quorum-policy",
            path(&policy),
            "--expected-base-observer-quorum-policy-sha256",
            &policy_sha256,
            "--registry-genesis",
            path(&genesis),
            "--expected-registry-genesis-sha256",
            genesis_sha256,
            "--rotation",
            path(&competing_rotation),
            "--output",
            path(&rotation_output),
        ])
        .spawn()
        .unwrap();
    let transition_status = transition_process.wait().unwrap();
    let rotation_status = rotation_process.wait().unwrap();
    assert_ne!(transition_status.success(), rotation_status.success());

    let generation_two = root.join("registry-generation-two.json");
    export_registry(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &generation_two,
    );
    let generation_two_value: Value =
        serde_json::from_slice(&fs::read(&generation_two).unwrap()).unwrap();
    assert_eq!(generation_two_value["generation"], 2);
    let current_public_key = generation_two_value["authority_public_key"]
        .as_str()
        .unwrap();
    let current_secret = if current_public_key == public([41; 32]) {
        &new_secret
    } else {
        assert_eq!(current_public_key, public([51; 32]));
        &third_secret
    };

    let reused_rotation = root.join("reused-authority-rotation.json");
    assert!(
        sign_authority_rotation(
            &generation_two,
            current_secret,
            &old_secret,
            "1200",
            &reused_rotation,
        )
        .status
        .success()
    );
    let reused_output = root.join("reused-authority-output.json");
    let reused = apply_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &reused_rotation,
        &reused_output,
    );
    assert!(!reused.status.success());
    assert!(!reused_output.exists());
    assert!(String::from_utf8_lossy(&reused.stderr).contains("reuses a historical key"));

    let colliding_rotation = root.join("observer-colliding-authority-rotation.json");
    assert!(
        sign_authority_rotation(
            &generation_two,
            current_secret,
            &observer_secret,
            "1200",
            &colliding_rotation,
        )
        .status
        .success()
    );
    let colliding_output = root.join("observer-colliding-authority-output.json");
    let colliding = apply_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &colliding_rotation,
        &colliding_output,
    );
    assert!(!colliding.status.success());
    assert!(!colliding_output.exists());
    assert!(String::from_utf8_lossy(&colliding.stderr).contains("not role-disjoint"));

    let history_records = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with(
                "factory-release-state-transparency-external-gossip-organization-registry-transition-v1-",
            ) || name.starts_with(
                "factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-v1-",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(history_records.len(), 2);
    for entry in fs::read_dir(&ledger).unwrap() {
        let source = fs::read(entry.unwrap().path()).unwrap();
        for secret in [
            hex::encode([31; 32]),
            hex::encode([41; 32]),
            hex::encode([51; 32]),
            hex::encode([11; 32]),
        ] {
            assert!(
                !source
                    .windows(secret.len())
                    .any(|window| window == secret.as_bytes())
            );
        }
    }
}

#[test]
fn publishes_closed_bounded_registry_schemas() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    for (command, filename) in [
        (
            "factory-release-state-transparency-external-gossip-organization-registry-schema",
            "registry.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-transition-schema",
            "transition.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-authority-key-rotation-schema",
            "authority-rotation.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-verification-report-schema",
            "report.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-verification-report-schema",
            "authority-rotation-report.schema.json",
        ),
    ] {
        let output = root.join(filename);
        successful(&[command, "--output", path(&output)]);
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_closed_and_bounded(&schema);
    }
}
