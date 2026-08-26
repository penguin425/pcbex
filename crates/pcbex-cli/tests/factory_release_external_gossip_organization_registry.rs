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

fn sign_governance(
    registry: &Path,
    root_secret: &Path,
    minimum_approvals: &str,
    authorities: &[(&str, &Path)],
    issued_at_unix: &str,
    output: &Path,
) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "sign-factory-release-state-transparency-external-gossip-organization-registry-governance",
        "--registry-state",
        path(registry),
        "--registry-authority-private-key",
        path(root_secret),
        "--minimum-approvals",
        minimum_approvals,
    ]);
    for (authority_id, public_key) in authorities {
        command.args([
            "--authority-id",
            authority_id,
            "--authority-public-key",
            path(public_key),
        ]);
    }
    command.args(["--issued-at-unix", issued_at_unix, "--output", path(output)]);
    command.output().unwrap()
}

fn sign_successor_governance(
    registry: &Path,
    root_secret: &Path,
    minimum_approvals: &str,
    authorities: &[(&str, &Path)],
    issued_at_unix: &str,
    output: &Path,
) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "sign-factory-release-state-transparency-external-gossip-organization-registry-successor-governance",
        "--registry-state",
        path(registry),
        "--registry-authority-private-key",
        path(root_secret),
        "--minimum-approvals",
        minimum_approvals,
    ]);
    for (authority_id, public_key) in authorities {
        command.args([
            "--authority-id",
            authority_id,
            "--authority-public-key",
            path(public_key),
        ]);
    }
    command.args(["--issued-at-unix", issued_at_unix, "--output", path(output)]);
    command.output().unwrap()
}

fn sign_successor_root_governance(
    registry: &Path,
    successor_root_secret: &Path,
    minimum_approvals: &str,
    authorities: &[(&str, &Path)],
    issued_at_unix: &str,
    output: &Path,
) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "sign-factory-release-state-transparency-external-gossip-organization-registry-successor-root-governance",
        "--registry-state",
        path(registry),
        "--successor-registry-authority-private-key",
        path(successor_root_secret),
        "--minimum-approvals",
        minimum_approvals,
    ]);
    for (authority_id, public_key) in authorities {
        command.args([
            "--authority-id",
            authority_id,
            "--authority-public-key",
            path(public_key),
        ]);
    }
    command.args(["--issued-at-unix", issued_at_unix, "--output", path(output)]);
    command.output().unwrap()
}

fn sign_governance_rotation(
    registry: &Path,
    old_governance: &Path,
    new_governance: &Path,
    old_signers: &[(&str, &Path)],
    new_signers: &[(&str, &Path)],
    rotated_at_unix: &str,
    output: &Path,
) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "sign-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation",
        "--registry-state",
        path(registry),
        "--old-governance",
        path(old_governance),
        "--new-governance",
        path(new_governance),
    ]);
    for (authority_id, private_key) in old_signers {
        command.args([
            "--old-authority-id",
            authority_id,
            "--old-authority-private-key",
            path(private_key),
        ]);
    }
    for (authority_id, private_key) in new_signers {
        command.args([
            "--new-authority-id",
            authority_id,
            "--new-authority-private-key",
            path(private_key),
        ]);
    }
    command.args([
        "--rotated-at-unix",
        rotated_at_unix,
        "--output",
        path(output),
    ]);
    command.output().unwrap()
}

fn sign_governed_authority_rotation(
    registry: &Path,
    old_governance: &Path,
    new_governance: &Path,
    old_signers: &[(&str, &Path)],
    new_signers: &[(&str, &Path)],
    rotated_at_unix: &str,
    output: &Path,
) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "sign-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation",
        "--registry-state",
        path(registry),
        "--old-governance",
        path(old_governance),
        "--new-governance",
        path(new_governance),
    ]);
    for (authority_id, private_key) in old_signers {
        command.args([
            "--old-authority-id",
            authority_id,
            "--old-authority-private-key",
            path(private_key),
        ]);
    }
    for (authority_id, private_key) in new_signers {
        command.args([
            "--new-authority-id",
            authority_id,
            "--new-authority-private-key",
            path(private_key),
        ]);
    }
    command.args([
        "--rotated-at-unix",
        rotated_at_unix,
        "--output",
        path(output),
    ]);
    command.output().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn sign_threshold_transition(
    registry: &Path,
    governance: &Path,
    signers: &[(&str, &Path)],
    action: &str,
    organization_id: &str,
    observer_trust: Option<&Path>,
    effective_at_unix: &str,
    output: &Path,
) -> Output {
    let mut command = Command::new(binary());
    command.args([
        "sign-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition",
        "--registry-state",
        path(registry),
        "--governance",
        path(governance),
    ]);
    for (authority_id, private_key) in signers {
        command.args([
            "--authority-id",
            authority_id,
            "--authority-private-key",
            path(private_key),
        ]);
    }
    command.args(["--action", action, "--organization-id", organization_id]);
    if let Some(observer_trust) = observer_trust {
        command.args(["--observer-trust-state", path(observer_trust)]);
    }
    let reason = "b".repeat(64);
    command.args([
        "--reason-sha256",
        &reason,
        "--effective-at-unix",
        effective_at_unix,
        "--output",
        path(output),
    ]);
    command.output().unwrap()
}

#[allow(clippy::too_many_arguments)]
fn apply_threshold_transition(
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
        "apply-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition",
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

#[allow(clippy::too_many_arguments)]
fn apply_governance_rotation(
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
        "apply-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation",
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

#[allow(clippy::too_many_arguments)]
fn apply_governed_authority_rotation(
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
        "apply-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation",
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
fn activates_threshold_governance_and_rejects_root_only_registry_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (ledger, ledger_id) = create_ledger(&root);
    let policy = root.join("base-policy.json");
    let policy_sha256 = write_policy(&policy);
    let root_secret = root.join("registry-root-secret.hex");
    let root_public = root.join("registry-root-public.hex");
    write_hex(&root_secret, [31; 32], 0o600);
    write_hex(
        &root_public,
        SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        0o644,
    );
    let authority_a_secret = root.join("governance-a-secret.hex");
    let authority_b_secret = root.join("governance-b-secret.hex");
    let authority_c_secret = root.join("governance-c-secret.hex");
    let authority_a_public = root.join("governance-a-public.hex");
    let authority_b_public = root.join("governance-b-public.hex");
    let authority_c_public = root.join("governance-c-public.hex");
    for (secret_path, public_path, secret) in [
        (&authority_a_secret, &authority_a_public, [61; 32]),
        (&authority_b_secret, &authority_b_public, [62; 32]),
        (&authority_c_secret, &authority_c_public, [63; 32]),
    ] {
        write_hex(secret_path, secret, 0o600);
        write_hex(
            public_path,
            SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
            0o644,
        );
    }

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
        path(&root_public),
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

    let duplicate_governance = root.join("duplicate-governance.json");
    let duplicate = sign_governance(
        &initial,
        &root_secret,
        "2",
        &[
            ("authority-a", &authority_a_public),
            ("authority-b", &authority_a_public),
        ],
        "1000",
        &duplicate_governance,
    );
    assert!(!duplicate.status.success());
    assert!(!duplicate_governance.exists());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("distinct"));

    let governance = root.join("governance.json");
    let signed = sign_governance(
        &initial,
        &root_secret,
        "2",
        &[
            ("authority-c", &authority_c_public),
            ("authority-a", &authority_a_public),
            ("authority-b", &authority_b_public),
        ],
        "1000",
        &governance,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let governance_value: Value = serde_json::from_slice(&fs::read(&governance).unwrap()).unwrap();
    assert_eq!(governance_value["minimum_approvals"], 2);
    assert_eq!(
        governance_value["authorities"][0]["authority_id"],
        "authority-a"
    );
    assert_eq!(
        governance_value["authorities"][2]["authority_id"],
        "authority-c"
    );

    let insufficient_transition = root.join("insufficient-threshold-transition.json");
    let insufficient = sign_threshold_transition(
        &initial,
        &governance,
        &[("authority-a", &authority_a_secret)],
        "admit-observer",
        "lab-a",
        Some(&observer_a),
        "1100",
        &insufficient_transition,
    );
    assert!(!insufficient.status.success());
    assert!(!insufficient_transition.exists());
    assert!(String::from_utf8_lossy(&insufficient.stderr).contains("threshold"));

    let substituted_transition = root.join("substituted-threshold-transition.json");
    let substituted = sign_threshold_transition(
        &initial,
        &governance,
        &[
            ("authority-a", &authority_b_secret),
            ("authority-c", &authority_c_secret),
        ],
        "admit-observer",
        "lab-a",
        Some(&observer_a),
        "1100",
        &substituted_transition,
    );
    assert!(!substituted.status.success());
    assert!(!substituted_transition.exists());
    assert!(String::from_utf8_lossy(&substituted.stderr).contains("does not match governance"));

    let observer_collision_secret = root.join("observer-collision-secret.hex");
    let observer_collision_public = root.join("observer-collision-public.hex");
    write_hex(&observer_collision_secret, [11; 32], 0o600);
    write_hex(
        &observer_collision_public,
        SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
        0o644,
    );
    let collision_governance = root.join("collision-governance.json");
    assert!(
        sign_governance(
            &initial,
            &root_secret,
            "2",
            &[
                ("observer-collision", &observer_collision_public),
                ("authority-b", &authority_b_public),
            ],
            "1000",
            &collision_governance,
        )
        .status
        .success()
    );
    let collision_transition = root.join("collision-threshold-transition.json");
    assert!(
        sign_threshold_transition(
            &initial,
            &collision_governance,
            &[
                ("observer-collision", &observer_collision_secret),
                ("authority-b", &authority_b_secret),
            ],
            "admit-observer",
            "lab-a",
            Some(&observer_a),
            "1100",
            &collision_transition,
        )
        .status
        .success()
    );
    let collision_output = root.join("collision-output.json");
    let collision = apply_threshold_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &collision_transition,
        &collision_output,
    );
    assert!(!collision.status.success());
    assert!(!collision_output.exists());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("not role-disjoint"));

    let admission = root.join("threshold-admission.json");
    let signed = sign_threshold_transition(
        &initial,
        &governance,
        &[
            ("authority-b", &authority_b_secret),
            ("authority-a", &authority_a_secret),
        ],
        "admit-observer",
        "lab-a",
        Some(&observer_a),
        "1100",
        &admission,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let admission_value: Value = serde_json::from_slice(&fs::read(&admission).unwrap()).unwrap();
    assert_eq!(
        admission_value["approvals"][0]["authority_id"],
        "authority-a"
    );
    assert_eq!(
        admission_value["approvals"][1]["authority_id"],
        "authority-b"
    );

    let tampered_admission = root.join("tampered-threshold-admission.json");
    let source = fs::read_to_string(&admission).unwrap();
    let approval_signature = admission_value["approvals"][0]["signature"]
        .as_str()
        .unwrap();
    fs::write(
        &tampered_admission,
        source.replacen(approval_signature, &"0".repeat(128), 1),
    )
    .unwrap();
    let tampered_output = root.join("tampered-threshold-output.json");
    let tampered = apply_threshold_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &tampered_admission,
        &tampered_output,
    );
    assert!(!tampered.status.success());
    assert!(!tampered_output.exists());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("approval verification failed"));

    let applied_a = root.join("threshold-applied-a.json");
    let applied_b = root.join("threshold-applied-b.json");
    let common = [
        "apply-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition",
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
        path(&admission),
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
    let governed: Value = serde_json::from_slice(&fs::read(&applied_a).unwrap()).unwrap();
    assert_eq!(governed["generation"], 1);
    assert_eq!(governed["organizations"][0]["status"], "active");
    assert_eq!(
        governed["active_governance_sha256"].as_str().unwrap().len(),
        64
    );

    let retry_output = root.join("threshold-exact-retry.json");
    assert!(
        apply_threshold_transition(
            &ledger,
            &ledger_id,
            &policy,
            &policy_sha256,
            &genesis,
            genesis_sha256,
            &admission,
            &retry_output,
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(&applied_a).unwrap(),
        fs::read(&retry_output).unwrap()
    );

    let root_only_transition = root.join("root-only-transition.json");
    let root_only = sign_transition(
        &applied_a,
        &root_secret,
        "suspend-organization",
        "lab-a",
        None,
        "1200",
        &root_only_transition,
    );
    assert!(!root_only.status.success());
    assert!(!root_only_transition.exists());
    assert!(String::from_utf8_lossy(&root_only.stderr).contains("root-only"));
    let successor_root = root.join("successor-root.hex");
    write_hex(&successor_root, [71; 32], 0o600);
    let root_rotation = root.join("root-only-rotation.json");
    let root_rotation_result = sign_authority_rotation(
        &applied_a,
        &root_secret,
        &successor_root,
        "1200",
        &root_rotation,
    );
    assert!(!root_rotation_result.status.success());
    assert!(!root_rotation.exists());
    assert!(String::from_utf8_lossy(&root_rotation_result.stderr).contains("root-only"));

    let suspension = root.join("threshold-suspension.json");
    assert!(
        sign_threshold_transition(
            &applied_a,
            &governance,
            &[
                ("authority-c", &authority_c_secret),
                ("authority-a", &authority_a_secret),
            ],
            "suspend-organization",
            "lab-a",
            None,
            "1200",
            &suspension,
        )
        .status
        .success()
    );
    let suspended_output = root.join("threshold-suspended.json");
    let suspended = apply_threshold_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &suspension,
        &suspended_output,
    );
    assert!(
        suspended.status.success(),
        "{}",
        String::from_utf8_lossy(&suspended.stderr)
    );
    let suspended_value: Value =
        serde_json::from_slice(&fs::read(&suspended_output).unwrap()).unwrap();
    assert_eq!(suspended_value["generation"], 2);
    assert_eq!(suspended_value["organizations"][0]["status"], "suspended");

    let authority_d_secret = root.join("governance-d-secret.hex");
    let authority_e_secret = root.join("governance-e-secret.hex");
    let authority_f_secret = root.join("governance-f-secret.hex");
    let authority_d_public = root.join("governance-d-public.hex");
    let authority_e_public = root.join("governance-e-public.hex");
    let authority_f_public = root.join("governance-f-public.hex");
    for (secret_path, public_path, secret) in [
        (&authority_d_secret, &authority_d_public, [64; 32]),
        (&authority_e_secret, &authority_e_public, [65; 32]),
        (&authority_f_secret, &authority_f_public, [66; 32]),
    ] {
        write_hex(secret_path, secret, 0o600);
        write_hex(
            public_path,
            SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
            0o644,
        );
    }
    let successor_governance = root.join("successor-governance.json");
    let successor = sign_successor_governance(
        &suspended_output,
        &root_secret,
        "3",
        &[
            ("authority-f", &authority_f_public),
            ("authority-d", &authority_d_public),
            ("authority-e", &authority_e_public),
        ],
        "1250",
        &successor_governance,
    );
    assert!(
        successor.status.success(),
        "{}",
        String::from_utf8_lossy(&successor.stderr)
    );
    let successor_value: Value =
        serde_json::from_slice(&fs::read(&successor_governance).unwrap()).unwrap();
    assert_eq!(successor_value["registry_generation"], 2);
    assert_eq!(successor_value["minimum_approvals"], 3);
    assert_eq!(
        successor_value["authorities"][0]["authority_id"],
        "authority-d"
    );

    let insufficient_rotation = root.join("insufficient-governance-rotation.json");
    let insufficient = sign_governance_rotation(
        &suspended_output,
        &governance,
        &successor_governance,
        &[("authority-a", &authority_a_secret)],
        &[
            ("authority-d", &authority_d_secret),
            ("authority-e", &authority_e_secret),
            ("authority-f", &authority_f_secret),
        ],
        "1300",
        &insufficient_rotation,
    );
    assert!(!insufficient.status.success());
    assert!(!insufficient_rotation.exists());
    assert!(String::from_utf8_lossy(&insufficient.stderr).contains("old governance"));

    let governance_rotation = root.join("governance-rotation.json");
    let signed_rotation = sign_governance_rotation(
        &suspended_output,
        &governance,
        &successor_governance,
        &[
            ("authority-b", &authority_b_secret),
            ("authority-a", &authority_a_secret),
        ],
        &[
            ("authority-f", &authority_f_secret),
            ("authority-d", &authority_d_secret),
            ("authority-e", &authority_e_secret),
        ],
        "1300",
        &governance_rotation,
    );
    assert!(
        signed_rotation.status.success(),
        "{}",
        String::from_utf8_lossy(&signed_rotation.stderr)
    );
    let rotation_value: Value =
        serde_json::from_slice(&fs::read(&governance_rotation).unwrap()).unwrap();
    assert_eq!(rotation_value["from_generation"], 2);
    assert_eq!(rotation_value["to_generation"], 3);
    assert_eq!(
        rotation_value["old_approvals"][0]["authority_id"],
        "authority-a"
    );
    assert_eq!(
        rotation_value["new_approvals"][0]["authority_id"],
        "authority-d"
    );

    let tampered_rotation = root.join("tampered-governance-rotation.json");
    let rotation_source = fs::read_to_string(&governance_rotation).unwrap();
    let old_signature = rotation_value["old_approvals"][0]["signature"]
        .as_str()
        .unwrap();
    fs::write(
        &tampered_rotation,
        rotation_source.replacen(old_signature, &"0".repeat(128), 1),
    )
    .unwrap();
    let tampered_rotation_output = root.join("tampered-governance-rotation-output.json");
    let tampered = apply_governance_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &tampered_rotation,
        &tampered_rotation_output,
    );
    assert!(!tampered.status.success());
    assert!(!tampered_rotation_output.exists());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("approval verification failed"));

    let rotated_output = root.join("governance-rotated.json");
    let rotated = apply_governance_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &governance_rotation,
        &rotated_output,
    );
    assert!(
        rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&rotated.stderr)
    );
    let rotated_value: Value = serde_json::from_slice(&fs::read(&rotated_output).unwrap()).unwrap();
    assert_eq!(rotated_value["generation"], 3);
    assert_eq!(
        rotated_value["active_governance_sha256"],
        rotation_value["new_governance_sha256"]
    );
    let rotation_retry_output = root.join("governance-rotation-retry.json");
    assert!(
        apply_governance_rotation(
            &ledger,
            &ledger_id,
            &policy,
            &policy_sha256,
            &genesis,
            genesis_sha256,
            &governance_rotation,
            &rotation_retry_output,
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(&rotated_output).unwrap(),
        fs::read(&rotation_retry_output).unwrap()
    );

    let same_root_governance = root.join("same-root-successor-governance.json");
    let same_root = sign_successor_root_governance(
        &rotated_output,
        &root_secret,
        "2",
        &[
            ("authority-d", &authority_d_public),
            ("authority-e", &authority_e_public),
            ("authority-f", &authority_f_public),
        ],
        "1350",
        &same_root_governance,
    );
    assert!(!same_root.status.success());
    assert!(!same_root_governance.exists());
    assert!(String::from_utf8_lossy(&same_root.stderr).contains("must differ"));

    let successor_root_governance = root.join("successor-root-governance.json");
    let successor_root_result = sign_successor_root_governance(
        &rotated_output,
        &successor_root,
        "2",
        &[
            ("authority-f", &authority_f_public),
            ("authority-d", &authority_d_public),
            ("authority-e", &authority_e_public),
        ],
        "1350",
        &successor_root_governance,
    );
    assert!(
        successor_root_result.status.success(),
        "{}",
        String::from_utf8_lossy(&successor_root_result.stderr)
    );
    let successor_root_governance_value: Value =
        serde_json::from_slice(&fs::read(&successor_root_governance).unwrap()).unwrap();
    assert_eq!(successor_root_governance_value["registry_generation"], 3);
    assert_eq!(
        successor_root_governance_value["registry_authority_public_key"],
        public([71; 32])
    );

    let insufficient_root_rotation = root.join("insufficient-governed-root-rotation.json");
    let insufficient_root = sign_governed_authority_rotation(
        &rotated_output,
        &successor_governance,
        &successor_root_governance,
        &[
            ("authority-d", &authority_d_secret),
            ("authority-e", &authority_e_secret),
            ("authority-f", &authority_f_secret),
        ],
        &[("authority-d", &authority_d_secret)],
        "1400",
        &insufficient_root_rotation,
    );
    assert!(!insufficient_root.status.success());
    assert!(!insufficient_root_rotation.exists());
    assert!(String::from_utf8_lossy(&insufficient_root.stderr).contains("new governance"));

    let governed_root_rotation = root.join("governed-root-rotation.json");
    let governed_root_signed = sign_governed_authority_rotation(
        &rotated_output,
        &successor_governance,
        &successor_root_governance,
        &[
            ("authority-f", &authority_f_secret),
            ("authority-d", &authority_d_secret),
            ("authority-e", &authority_e_secret),
        ],
        &[
            ("authority-e", &authority_e_secret),
            ("authority-d", &authority_d_secret),
        ],
        "1400",
        &governed_root_rotation,
    );
    assert!(
        governed_root_signed.status.success(),
        "{}",
        String::from_utf8_lossy(&governed_root_signed.stderr)
    );
    let governed_root_value: Value =
        serde_json::from_slice(&fs::read(&governed_root_rotation).unwrap()).unwrap();
    assert_eq!(governed_root_value["from_generation"], 3);
    assert_eq!(governed_root_value["to_generation"], 4);
    assert_eq!(governed_root_value["old_public_key"], public([31; 32]));
    assert_eq!(governed_root_value["new_public_key"], public([71; 32]));

    let tampered_root_rotation = root.join("tampered-governed-root-rotation.json");
    let governed_root_source = fs::read_to_string(&governed_root_rotation).unwrap();
    let new_signature = governed_root_value["new_approvals"][0]["signature"]
        .as_str()
        .unwrap();
    fs::write(
        &tampered_root_rotation,
        governed_root_source.replacen(new_signature, &"0".repeat(128), 1),
    )
    .unwrap();
    let tampered_root_output = root.join("tampered-governed-root-output.json");
    let tampered_root = apply_governed_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &tampered_root_rotation,
        &tampered_root_output,
    );
    assert!(!tampered_root.status.success());
    assert!(!tampered_root_output.exists());
    assert!(
        String::from_utf8_lossy(&tampered_root.stderr).contains("approval verification failed")
    );

    let root_rotated_output = root.join("governed-root-rotated.json");
    let root_rotated = apply_governed_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &governed_root_rotation,
        &root_rotated_output,
    );
    assert!(
        root_rotated.status.success(),
        "{}",
        String::from_utf8_lossy(&root_rotated.stderr)
    );
    let root_rotated_value: Value =
        serde_json::from_slice(&fs::read(&root_rotated_output).unwrap()).unwrap();
    assert_eq!(root_rotated_value["generation"], 4);
    assert_eq!(root_rotated_value["authority_public_key"], public([71; 32]));
    assert_eq!(
        root_rotated_value["active_governance_sha256"],
        governed_root_value["new_governance_sha256"]
    );
    assert_eq!(
        root_rotated_value["organizations"],
        rotated_value["organizations"]
    );
    let governed_root_retry_output = root.join("governed-root-rotation-retry.json");
    assert!(
        apply_governed_authority_rotation(
            &ledger,
            &ledger_id,
            &policy,
            &policy_sha256,
            &genesis,
            genesis_sha256,
            &governed_root_rotation,
            &governed_root_retry_output,
        )
        .status
        .success()
    );
    assert_eq!(
        fs::read(&root_rotated_output).unwrap(),
        fs::read(&governed_root_retry_output).unwrap()
    );

    let reused_root_governance = root.join("reused-root-governance.json");
    assert!(
        sign_successor_root_governance(
            &root_rotated_output,
            &root_secret,
            "2",
            &[
                ("authority-d", &authority_d_public),
                ("authority-e", &authority_e_public),
                ("authority-f", &authority_f_public),
            ],
            "1450",
            &reused_root_governance,
        )
        .status
        .success()
    );
    let reused_root_rotation = root.join("reused-root-rotation.json");
    assert!(
        sign_governed_authority_rotation(
            &root_rotated_output,
            &successor_root_governance,
            &reused_root_governance,
            &[
                ("authority-d", &authority_d_secret),
                ("authority-e", &authority_e_secret),
            ],
            &[
                ("authority-d", &authority_d_secret),
                ("authority-e", &authority_e_secret),
            ],
            "1450",
            &reused_root_rotation,
        )
        .status
        .success()
    );
    let reused_root_output = root.join("reused-root-output.json");
    let reused_root = apply_governed_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &reused_root_rotation,
        &reused_root_output,
    );
    assert!(!reused_root.status.success());
    assert!(!reused_root_output.exists());
    assert!(String::from_utf8_lossy(&reused_root.stderr).contains("historical root key"));

    let old_governance_transition = root.join("old-governance-transition.json");
    let old_governance_result = sign_threshold_transition(
        &root_rotated_output,
        &successor_governance,
        &[
            ("authority-d", &authority_d_secret),
            ("authority-e", &authority_e_secret),
            ("authority-f", &authority_f_secret),
        ],
        "revoke-organization",
        "lab-a",
        None,
        "1500",
        &old_governance_transition,
    );
    assert!(!old_governance_result.status.success());
    assert!(!old_governance_transition.exists());
    assert!(String::from_utf8_lossy(&old_governance_result.stderr).contains("retained root trust"));
    let revocation = root.join("successor-governance-revocation.json");
    assert!(
        sign_threshold_transition(
            &root_rotated_output,
            &successor_root_governance,
            &[
                ("authority-d", &authority_d_secret),
                ("authority-e", &authority_e_secret),
            ],
            "revoke-organization",
            "lab-a",
            None,
            "1500",
            &revocation,
        )
        .status
        .success()
    );
    let revoked_output = root.join("successor-governance-revoked.json");
    let revoked = apply_threshold_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &revocation,
        &revoked_output,
    );
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let revoked_value: Value = serde_json::from_slice(&fs::read(&revoked_output).unwrap()).unwrap();
    assert_eq!(revoked_value["generation"], 5);
    assert_eq!(revoked_value["organizations"][0]["status"], "revoked");

    let exported = root.join("threshold-exported.json");
    export_registry(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &exported,
    );
    assert_eq!(
        fs::read(&revoked_output).unwrap(),
        fs::read(&exported).unwrap()
    );
    let threshold_records = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with(
                "factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-v1-",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(threshold_records.len(), 3);
    let governance_rotation_records = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with(
                "factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-v1-",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(governance_rotation_records.len(), 1);
    let governed_authority_rotation_records = fs::read_dir(&ledger)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry.file_name().to_string_lossy().starts_with(
                "factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-v1-",
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(governed_authority_rotation_records.len(), 1);
    for entry in fs::read_dir(&ledger).unwrap() {
        let source = fs::read(entry.unwrap().path()).unwrap();
        for secret in [
            hex::encode([31; 32]),
            hex::encode([61; 32]),
            hex::encode([62; 32]),
            hex::encode([63; 32]),
            hex::encode([64; 32]),
            hex::encode([65; 32]),
            hex::encode([66; 32]),
            hex::encode([71; 32]),
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
            "signed-factory-release-state-transparency-external-gossip-organization-registry-governance-schema",
            "governance.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-threshold-transition-schema",
            "threshold-transition.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-schema",
            "governance-rotation.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-governed-authority-key-rotation-schema",
            "governed-authority-rotation.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-verification-report-schema",
            "report.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-authority-rotation-verification-report-schema",
            "authority-rotation-report.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-threshold-governance-verification-report-schema",
            "threshold-governance-report.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-governance-rotation-verification-report-schema",
            "governance-rotation-report.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-governed-authority-rotation-verification-report-schema",
            "governed-authority-rotation-report.schema.json",
        ),
    ] {
        let output = root.join(filename);
        successful(&[command, "--output", path(&output)]);
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_closed_and_bounded(&schema);
    }
}
