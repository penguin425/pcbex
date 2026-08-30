#![cfg(unix)]

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread::{self, JoinHandle},
    time::Duration,
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

fn serve_json_once(
    response_body: Vec<u8>,
    expected_bearer: Option<&str>,
) -> (String, JoinHandle<Value>) {
    serve_json_once_at(
        response_body,
        expected_bearer,
        "/v1/factory-registry-history-checkpoint",
    )
}

fn serve_json_once_at(
    response_body: Vec<u8>,
    expected_bearer: Option<&str>,
    request_path: &str,
) -> (String, JoinHandle<Value>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let expected_bearer = expected_bearer.map(str::to_string);
    let request_path = request_path.to_string();
    let endpoint_path = request_path.clone();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let (header_end, content_length) = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0, "remote witness request ended before its body");
            request.extend_from_slice(&buffer[..read]);
            if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let header_end = offset + 4;
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if request.len() >= header_end + content_length {
                    break (header_end, content_length);
                }
            }
        };
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        assert!(headers.starts_with(&format!("POST {request_path} HTTP/1.1\r\n")));
        assert!(
            headers
                .lines()
                .any(|line| { line.eq_ignore_ascii_case("content-type: application/json") })
        );
        if let Some(token) = expected_bearer {
            assert!(headers.lines().any(|line| {
                line.eq_ignore_ascii_case(&format!("authorization: Bearer {token}"))
            }));
        }
        let request_body = &request[header_end..header_end + content_length];
        let request_value: Value = serde_json::from_slice(request_body).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        )
        .unwrap();
        stream.write_all(&response_body).unwrap();
        stream.flush().unwrap();
        request_value
    });
    (format!("http://{address}{endpoint_path}"), handle)
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
fn export_registry_history(
    ledger: &Path,
    ledger_id: &str,
    policy: &Path,
    policy_sha256: &str,
    genesis: &Path,
    genesis_sha256: &str,
    output: &Path,
) -> Output {
    run(&[
        "export-factory-release-state-transparency-external-gossip-organization-registry-history",
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
    ])
}

fn audit_registry_history(history: &Path, output: &Path, final_registry_output: &Path) -> Output {
    run(&[
        "audit-factory-release-state-transparency-external-gossip-organization-registry-history",
        "--history",
        path(history),
        "--output",
        path(output),
        "--final-registry-output",
        path(final_registry_output),
    ])
}

fn write_canonical_json(path: &Path, value: &Value) {
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
    )
    .unwrap();
}

fn compact_json_source(source: &[u8]) -> Vec<u8> {
    let mut compact = Vec::with_capacity(source.len());
    let mut in_string = false;
    let mut escaped = false;
    for &byte in source {
        if in_string {
            compact.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
            compact.push(byte);
        } else if !byte.is_ascii_whitespace() {
            compact.push(byte);
        }
    }
    compact
}

fn exact_identity(value: &Value) -> Value {
    let source = format!("{}\n", serde_json::to_string_pretty(value).unwrap());
    serde_json::json!({
        "bytes": source.len(),
        "sha256": hex::encode(Sha256::digest(source.as_bytes())),
    })
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
fn exports_and_independently_audits_complete_five_kind_registry_history() {
    let temporary = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(temporary.path()).unwrap();
    let (ledger, ledger_id) = create_ledger(&root);
    let policy = root.join("base-policy.json");
    let policy_sha256 = write_policy(&policy);

    let root_a_secret = root.join("root-a-secret.hex");
    let root_a_public = root.join("root-a-public.hex");
    let root_b_secret = root.join("root-b-secret.hex");
    let root_c_secret = root.join("root-c-secret.hex");
    for (secret_path, secret) in [
        (&root_a_secret, [31; 32]),
        (&root_b_secret, [32; 32]),
        (&root_c_secret, [33; 32]),
    ] {
        write_hex(secret_path, secret, 0o600);
    }
    write_hex(
        &root_a_public,
        SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        0o644,
    );

    let mut governance_keys = Vec::new();
    for (name, secret) in [
        ("a", [41; 32]),
        ("b", [42; 32]),
        ("c", [43; 32]),
        ("d", [44; 32]),
        ("e", [45; 32]),
        ("f", [46; 32]),
    ] {
        let secret_path = root.join(format!("governance-{name}-secret.hex"));
        let public_path = root.join(format!("governance-{name}-public.hex"));
        write_hex(&secret_path, secret, 0o600);
        write_hex(
            &public_path,
            SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
            0o644,
        );
        governance_keys.push((secret_path, public_path));
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
        "portable-history",
        "--authority-public-key",
        path(&root_a_public),
        "--output",
        path(&genesis),
        "--digest-output",
        path(&genesis_digest),
    ]);
    let genesis_sha256 = fs::read_to_string(&genesis_digest).unwrap();
    let genesis_sha256 = genesis_sha256.trim();
    let generation_zero = root.join("generation-0.json");
    export_registry(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &generation_zero,
    );
    let observer = root.join("observer-a.json");
    export_observer(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        "lab-a",
        "observer-a",
        &observer,
    );

    let legacy_transition = root.join("legacy-transition.json");
    let signed = sign_transition(
        &generation_zero,
        &root_a_secret,
        "admit-observer",
        "lab-a",
        Some(&observer),
        "1000",
        &legacy_transition,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let generation_one = root.join("generation-1.json");
    let applied = apply_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &legacy_transition,
        &generation_one,
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let authority_rotation = root.join("authority-rotation.json");
    let signed = sign_authority_rotation(
        &generation_one,
        &root_a_secret,
        &root_b_secret,
        "2000",
        &authority_rotation,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let generation_two = root.join("generation-2.json");
    let applied = apply_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &authority_rotation,
        &generation_two,
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let old_governance = root.join("old-governance.json");
    let signed = sign_governance(
        &generation_two,
        &root_b_secret,
        "2",
        &[
            ("authority-a", governance_keys[0].1.as_path()),
            ("authority-b", governance_keys[1].1.as_path()),
        ],
        "2100",
        &old_governance,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let threshold_transition = root.join("threshold-transition.json");
    let signed = sign_threshold_transition(
        &generation_two,
        &old_governance,
        &[
            ("authority-a", governance_keys[0].0.as_path()),
            ("authority-b", governance_keys[1].0.as_path()),
        ],
        "suspend-organization",
        "lab-a",
        None,
        "3000",
        &threshold_transition,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let generation_three = root.join("generation-3.json");
    let applied = apply_threshold_transition(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &threshold_transition,
        &generation_three,
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let middle_governance = root.join("middle-governance.json");
    let signed = sign_successor_governance(
        &generation_three,
        &root_b_secret,
        "2",
        &[
            ("authority-c", governance_keys[2].1.as_path()),
            ("authority-d", governance_keys[3].1.as_path()),
        ],
        "3100",
        &middle_governance,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let governance_rotation = root.join("governance-rotation.json");
    let signed = sign_governance_rotation(
        &generation_three,
        &old_governance,
        &middle_governance,
        &[
            ("authority-a", governance_keys[0].0.as_path()),
            ("authority-b", governance_keys[1].0.as_path()),
        ],
        &[
            ("authority-c", governance_keys[2].0.as_path()),
            ("authority-d", governance_keys[3].0.as_path()),
        ],
        "4000",
        &governance_rotation,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let generation_four = root.join("generation-4.json");
    let applied = apply_governance_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &governance_rotation,
        &generation_four,
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let final_governance = root.join("final-governance.json");
    let signed = sign_successor_root_governance(
        &generation_four,
        &root_c_secret,
        "2",
        &[
            ("authority-e", governance_keys[4].1.as_path()),
            ("authority-f", governance_keys[5].1.as_path()),
        ],
        "4100",
        &final_governance,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let governed_root_rotation = root.join("governed-root-rotation.json");
    let signed = sign_governed_authority_rotation(
        &generation_four,
        &middle_governance,
        &final_governance,
        &[
            ("authority-c", governance_keys[2].0.as_path()),
            ("authority-d", governance_keys[3].0.as_path()),
        ],
        &[
            ("authority-e", governance_keys[4].0.as_path()),
            ("authority-f", governance_keys[5].0.as_path()),
        ],
        "5000",
        &governed_root_rotation,
    );
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let generation_five = root.join("generation-5.json");
    let applied = apply_governed_authority_rotation(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &governed_root_rotation,
        &generation_five,
    );
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );

    let history = root.join("registry-history.json");
    let exported = export_registry_history(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &history,
    );
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let history_value: Value = serde_json::from_slice(&fs::read(&history).unwrap()).unwrap();
    assert_eq!(history_value["schema_version"], 1);
    assert_eq!(history_value["initial_registry"]["generation"], 0);
    assert_eq!(history_value["events"].as_array().unwrap().len(), 5);
    assert_eq!(
        history_value["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "organization_transition",
            "authority_key_rotation",
            "threshold_transition",
            "governance_rotation",
            "governed_authority_key_rotation",
        ]
    );
    for (event, source) in history_value["events"].as_array().unwrap().iter().zip([
        &legacy_transition,
        &authority_rotation,
        &threshold_transition,
        &governance_rotation,
        &governed_root_rotation,
    ]) {
        let bytes = fs::read(source).unwrap();
        assert_eq!(event["artifact"]["bytes"], bytes.len());
        assert_eq!(
            event["artifact"]["sha256"],
            hex::encode(Sha256::digest(&bytes))
        );
    }

    let audit = root.join("registry-history.audit.json");
    let computed_final = root.join("registry-history.final.json");
    let audited = audit_registry_history(&history, &audit, &computed_final);
    assert!(
        audited.status.success(),
        "{}",
        String::from_utf8_lossy(&audited.stderr)
    );
    assert_eq!(
        fs::read(&computed_final).unwrap(),
        fs::read(&generation_five).unwrap()
    );
    let audit_value: Value = serde_json::from_slice(&fs::read(&audit).unwrap()).unwrap();
    assert_eq!(audit_value["event_count"], 5);
    assert_eq!(audit_value["chain_valid"], true);
    assert_eq!(audit_value["entries"].as_array().unwrap().len(), 5);
    assert_eq!(audit_value["entries"][0]["from_generation"], 0);
    assert_eq!(audit_value["entries"][4]["to_generation"], 5);
    assert_eq!(
        audit_value["entries"][4]["resulting_registry_sha256"],
        audit_value["final_registry_sha256"]
    );
    assert_eq!(audit_value["final_registry"]["generation"], 5);
    assert_eq!(
        audit_value["final_registry"]["authority_public_key"],
        public([33; 32])
    );

    let normalized_history = root.join("registry-history.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history",
        path(&history),
        "--output",
        path(&normalized_history),
    ]);
    assert_eq!(
        fs::read(&normalized_history).unwrap(),
        fs::read(&history).unwrap()
    );
    let normalized_audit = root.join("registry-history.audit.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-audit",
        path(&audit),
        "--output",
        path(&normalized_audit),
    ]);
    assert_eq!(
        fs::read(&normalized_audit).unwrap(),
        fs::read(&audit).unwrap()
    );

    let stale_root_checkpoint = root.join("registry-history.stale-root.checkpoint.json");
    let stale_root = run(&[
        "sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint",
        "--history",
        path(&history),
        "--authority-private-key",
        path(&root_b_secret),
        "--issued-at-unix",
        "5100",
        "--output",
        path(&stale_root_checkpoint),
    ]);
    assert!(!stale_root.status.success());
    assert!(!stale_root_checkpoint.exists());

    let checkpoint = root.join("registry-history.checkpoint.json");
    successful(&[
        "sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint",
        "--history",
        path(&history),
        "--authority-private-key",
        path(&root_c_secret),
        "--issued-at-unix",
        "5100",
        "--output",
        path(&checkpoint),
    ]);
    let checkpoint_value: Value = serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    assert_eq!(checkpoint_value["registry_id"], "portable-history");
    assert_eq!(checkpoint_value["generation"], 5);
    assert_eq!(
        checkpoint_value["history_audit_sha256"],
        hex::encode(Sha256::digest(compact_json_source(
            &fs::read(&audit).unwrap()
        )))
    );
    assert_eq!(
        checkpoint_value["final_registry_sha256"],
        audit_value["final_registry_sha256"]
    );
    assert_eq!(checkpoint_value["authority_public_key"], public([33; 32]));
    let normalized_checkpoint = root.join("registry-history.checkpoint.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint",
        path(&checkpoint),
        "--output",
        path(&normalized_checkpoint),
    ]);
    assert_eq!(
        fs::read(&normalized_checkpoint).unwrap(),
        fs::read(&checkpoint).unwrap()
    );

    let checkpoint_trust = root.join("registry-history.checkpoint.trust.json");
    successful(&[
        "accept-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--accepted-at-unix",
        "5200",
        "--output",
        path(&checkpoint_trust),
    ]);
    let checkpoint_trust_value: Value =
        serde_json::from_slice(&fs::read(&checkpoint_trust).unwrap()).unwrap();
    assert_eq!(checkpoint_trust_value["accepted_generation"], 5);
    assert_eq!(
        checkpoint_trust_value["signed_checkpoint"],
        checkpoint_value
    );
    let normalized_trust = root.join("registry-history.checkpoint.trust.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-trust-state",
        path(&checkpoint_trust),
        "--output",
        path(&normalized_trust),
    ]);
    assert_eq!(
        fs::read(&normalized_trust).unwrap(),
        fs::read(&checkpoint_trust).unwrap()
    );
    let retry_trust = root.join("registry-history.checkpoint.trust.retry.json");
    successful(&[
        "accept-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--baseline",
        path(&checkpoint_trust),
        "--accepted-at-unix",
        "5300",
        "--output",
        path(&retry_trust),
    ]);
    assert_eq!(
        fs::read(&retry_trust).unwrap(),
        fs::read(&checkpoint_trust).unwrap()
    );

    let witness_a_secret = root.join("checkpoint-witness-a-secret.hex");
    let witness_a_public = root.join("checkpoint-witness-a-public.hex");
    let witness_b_secret = root.join("checkpoint-witness-b-secret.hex");
    let witness_b_public = root.join("checkpoint-witness-b-public.hex");
    let witness_a_next_secret = root.join("checkpoint-witness-a-next-secret.hex");
    let witness_a_next_public = root.join("checkpoint-witness-a-next-public.hex");
    let receipt_quorum_checkpoint_secret = root.join("receipt-quorum-checkpoint-secret.hex");
    let receipt_quorum_checkpoint_public = root.join("receipt-quorum-checkpoint-public.hex");
    let receipt_quorum_checkpoint_witness_a_secret =
        root.join("receipt-quorum-checkpoint-witness-a-secret.hex");
    let receipt_quorum_checkpoint_witness_a_public =
        root.join("receipt-quorum-checkpoint-witness-a-public.hex");
    let receipt_quorum_checkpoint_witness_a_next_secret =
        root.join("receipt-quorum-checkpoint-witness-a-next-secret.hex");
    let receipt_quorum_checkpoint_witness_a_next_public =
        root.join("receipt-quorum-checkpoint-witness-a-next-public.hex");
    let receipt_quorum_checkpoint_witness_b_secret =
        root.join("receipt-quorum-checkpoint-witness-b-secret.hex");
    let receipt_quorum_checkpoint_witness_b_public =
        root.join("receipt-quorum-checkpoint-witness-b-public.hex");
    for (secret_path, public_path, secret) in [
        (&witness_a_secret, &witness_a_public, [81; 32]),
        (&witness_b_secret, &witness_b_public, [82; 32]),
        (&witness_a_next_secret, &witness_a_next_public, [83; 32]),
        (
            &receipt_quorum_checkpoint_secret,
            &receipt_quorum_checkpoint_public,
            [84; 32],
        ),
        (
            &receipt_quorum_checkpoint_witness_a_secret,
            &receipt_quorum_checkpoint_witness_a_public,
            [85; 32],
        ),
        (
            &receipt_quorum_checkpoint_witness_a_next_secret,
            &receipt_quorum_checkpoint_witness_a_next_public,
            [87; 32],
        ),
        (
            &receipt_quorum_checkpoint_witness_b_secret,
            &receipt_quorum_checkpoint_witness_b_public,
            [86; 32],
        ),
    ] {
        write_hex(secret_path, secret, 0o600);
        write_hex(
            public_path,
            SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
            0o644,
        );
    }
    let witness_a_initial_trust = root.join("checkpoint-witness-a.initial.trust.json");
    let witness_b_trust = root.join("checkpoint-witness-b.trust.json");
    for (witness_id, public_key, output) in [
        ("witness-a", &witness_a_public, &witness_a_initial_trust),
        ("witness-b", &witness_b_public, &witness_b_trust),
    ] {
        successful(&[
            "init-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-trust",
            "--witness-id",
            witness_id,
            "--public-key",
            path(public_key),
            "--output",
            path(output),
        ]);
    }
    let witness_a_rotation = root.join("checkpoint-witness-a.rotation.json");
    successful(&[
        "sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation",
        "--trust-state",
        path(&witness_a_initial_trust),
        "--old-private-key",
        path(&witness_a_secret),
        "--new-private-key",
        path(&witness_a_next_secret),
        "--rotated-at-unix",
        "5250",
        "--output",
        path(&witness_a_rotation),
    ]);
    let normalized_rotation = root.join("checkpoint-witness-a.rotation.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation",
        path(&witness_a_rotation),
        "--output",
        path(&normalized_rotation),
    ]);
    assert_eq!(
        fs::read(&normalized_rotation).unwrap(),
        fs::read(&witness_a_rotation).unwrap()
    );
    let witness_a_rotated_trust = root.join("checkpoint-witness-a.rotated.trust.json");
    let witness_a_exported_public = root.join("checkpoint-witness-a.rotated.public.hex");
    successful(&[
        "apply-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation",
        "--trust-state",
        path(&witness_a_initial_trust),
        "--rotation",
        path(&witness_a_rotation),
        "--output",
        path(&witness_a_rotated_trust),
        "--public-key-output",
        path(&witness_a_exported_public),
    ]);
    assert_eq!(
        fs::read(&witness_a_exported_public).unwrap(),
        fs::read(&witness_a_next_public).unwrap()
    );
    let normalized_witness_trust = root.join("checkpoint-witness-a.trust.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-trust-state",
        path(&witness_a_rotated_trust),
        "--output",
        path(&normalized_witness_trust),
    ]);
    assert_eq!(
        fs::read(&normalized_witness_trust).unwrap(),
        fs::read(&witness_a_rotated_trust).unwrap()
    );
    let separately_exported_public = root.join("checkpoint-witness-a.exported.public.hex");
    successful(&[
        "export-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key",
        "--trust-state",
        path(&witness_a_rotated_trust),
        "--output",
        path(&separately_exported_public),
    ]);
    assert_eq!(
        fs::read(&separately_exported_public).unwrap(),
        fs::read(&witness_a_next_public).unwrap()
    );
    let replayed_trust = root.join("checkpoint-witness-a.replayed.trust.json");
    let replayed_public = root.join("checkpoint-witness-a.replayed.public.hex");
    let replay = run(&[
        "apply-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation",
        "--trust-state",
        path(&witness_a_rotated_trust),
        "--rotation",
        path(&witness_a_rotation),
        "--output",
        path(&replayed_trust),
        "--public-key-output",
        path(&replayed_public),
    ]);
    assert!(!replay.status.success());
    assert!(!replayed_trust.exists());
    assert!(!replayed_public.exists());
    let witness_a = root.join("registry-history.checkpoint.witness-a.json");
    let witness_b = root.join("registry-history.checkpoint.witness-b.json");
    let governance_key_witness =
        root.join("registry-history.checkpoint.governance-key-witness.json");
    let role_collision = run(&[
        "sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness-id",
        "governance-reuse",
        "--witness-private-key",
        path(&governance_keys[4].0),
        "--witnessed-at-unix",
        "5300",
        "--output",
        path(&governance_key_witness),
    ]);
    assert!(!role_collision.status.success());
    assert!(!governance_key_witness.exists());
    for (witness_id, secret, witnessed_at, output) in [
        ("witness-a", &witness_a_secret, "5300", &witness_a),
        ("witness-b", &witness_b_secret, "5301", &witness_b),
    ] {
        successful(&[
            "sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
            "--history",
            path(&history),
            "--checkpoint",
            path(&checkpoint),
            "--witness-id",
            witness_id,
            "--witness-private-key",
            path(secret),
            "--witnessed-at-unix",
            witnessed_at,
            "--output",
            path(output),
        ]);
    }
    let rotated_witness_a = root.join("registry-history.checkpoint.witness-a.rotated.json");
    successful(&[
        "sign-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness-id",
        "witness-a",
        "--witness-private-key",
        path(&witness_a_next_secret),
        "--witnessed-at-unix",
        "5302",
        "--output",
        path(&rotated_witness_a),
    ]);
    let normalized_witness = root.join("registry-history.checkpoint.witness.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        path(&witness_a),
        "--output",
        path(&normalized_witness),
    ]);
    assert_eq!(
        fs::read(&normalized_witness).unwrap(),
        fs::read(&witness_a).unwrap()
    );

    let remote_witness_b = root.join("registry-history.checkpoint.witness-b.remote.json");
    let remote_witness_b_receipt =
        root.join("registry-history.checkpoint.witness-b.remote.receipt.json");
    let (endpoint, server) = serve_json_once(fs::read(&witness_b).unwrap(), Some("bounded-token"));
    let remote = Command::new(binary())
        .args([
            "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
            "--history",
            path(&history),
            "--checkpoint-trust-state",
            path(&checkpoint_trust),
            "--endpoint",
            &endpoint,
            "--public-key",
            path(&witness_b_public),
            "--bearer-token-env",
            "PCBEX_FACTORY_REGISTRY_WITNESS_TOKEN",
            "--timeout-seconds",
            "10",
            "--evaluated-at-unix",
            "5400",
            "--output",
            path(&remote_witness_b),
            "--receipt-output",
            path(&remote_witness_b_receipt),
            "--allow-http-loopback",
        ])
        .env("PCBEX_FACTORY_REGISTRY_WITNESS_TOKEN", "bounded-token")
        .output()
        .unwrap();
    assert!(
        remote.status.success(),
        "{}",
        String::from_utf8_lossy(&remote.stderr)
    );
    let request = server.join().unwrap();
    assert_eq!(request["schema_version"], 1);
    assert_eq!(
        request["protocol"],
        "pcbex-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-v1"
    );
    assert_eq!(request["checkpoint_trust_state"], checkpoint_trust_value);
    assert_eq!(
        fs::read(&remote_witness_b).unwrap(),
        fs::read(&witness_b).unwrap()
    );
    let remote_witness_b_receipt_value: Value =
        serde_json::from_slice(&fs::read(&remote_witness_b_receipt).unwrap()).unwrap();
    assert!(
        !fs::read_to_string(&remote_witness_b_receipt)
            .unwrap()
            .contains("bounded-token")
    );
    assert_eq!(remote_witness_b_receipt_value["verified"], true);
    assert_eq!(remote_witness_b_receipt_value["witness_id"], "witness-b");
    assert_eq!(remote_witness_b_receipt_value["generation"], 5);
    assert_eq!(
        remote_witness_b_receipt_value["history_sha256"],
        hex::encode(Sha256::digest(fs::read(&history).unwrap()))
    );
    assert_eq!(
        remote_witness_b_receipt_value["checkpoint_trust_state_sha256"],
        hex::encode(Sha256::digest(fs::read(&checkpoint_trust).unwrap()))
    );
    assert_eq!(
        remote_witness_b_receipt_value["response_sha256"],
        hex::encode(Sha256::digest(fs::read(&witness_b).unwrap()))
    );
    assert_eq!(
        remote_witness_b_receipt_value["witness_key_trust_state_sha256"],
        Value::Null
    );
    assert_eq!(
        remote_witness_b_receipt_value["witness_key_generation"],
        Value::Null
    );
    let normalized_remote_receipt = root.join("remote-witness.receipt.normalized.json");
    successful(&[
        "validate-remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt",
        path(&remote_witness_b_receipt),
        "--output",
        path(&normalized_remote_receipt),
    ]);
    assert_eq!(
        fs::read(&normalized_remote_receipt).unwrap(),
        fs::read(&remote_witness_b_receipt).unwrap()
    );

    let remote_rotated_witness_a =
        root.join("registry-history.checkpoint.witness-a.rotated.remote.json");
    let remote_rotated_witness_a_receipt =
        root.join("registry-history.checkpoint.witness-a.rotated.remote.receipt.json");
    let (endpoint, server) = serve_json_once(fs::read(&rotated_witness_a).unwrap(), None);
    let remote = run(&[
        "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--endpoint",
        &endpoint,
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--timeout-seconds",
        "10",
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&remote_rotated_witness_a),
        "--receipt-output",
        path(&remote_rotated_witness_a_receipt),
        "--allow-http-loopback",
    ]);
    assert!(
        remote.status.success(),
        "{}",
        String::from_utf8_lossy(&remote.stderr)
    );
    server.join().unwrap();
    assert_eq!(
        fs::read(&remote_rotated_witness_a).unwrap(),
        fs::read(&rotated_witness_a).unwrap()
    );
    let remote_rotated_receipt_value: Value =
        serde_json::from_slice(&fs::read(&remote_rotated_witness_a_receipt).unwrap()).unwrap();
    assert_eq!(remote_rotated_receipt_value["witness_id"], "witness-a");
    assert_eq!(remote_rotated_receipt_value["witness_key_generation"], 1);
    assert_eq!(
        remote_rotated_receipt_value["witness_key_trust_state_sha256"],
        hex::encode(Sha256::digest(fs::read(&witness_a_rotated_trust).unwrap()))
    );

    let remote_direct_witness_a =
        root.join("registry-history.checkpoint.witness-a.rotated.remote-direct.json");
    let remote_direct_witness_a_receipt =
        root.join("registry-history.checkpoint.witness-a.rotated.remote-direct.receipt.json");
    let (endpoint, server) = serve_json_once(fs::read(&rotated_witness_a).unwrap(), None);
    successful(&[
        "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--endpoint",
        &endpoint,
        "--public-key",
        path(&witness_a_next_public),
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&remote_direct_witness_a),
        "--receipt-output",
        path(&remote_direct_witness_a_receipt),
        "--allow-http-loopback",
    ]);
    server.join().unwrap();

    let remote_trusted_witness_b =
        root.join("registry-history.checkpoint.witness-b.remote-trusted.json");
    let remote_trusted_witness_b_receipt =
        root.join("registry-history.checkpoint.witness-b.remote-trusted.receipt.json");
    let (endpoint, server) = serve_json_once(fs::read(&witness_b).unwrap(), None);
    successful(&[
        "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--endpoint",
        &endpoint,
        "--witness-key-trust-state",
        path(&witness_b_trust),
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&remote_trusted_witness_b),
        "--receipt-output",
        path(&remote_trusted_witness_b_receipt),
        "--allow-http-loopback",
    ]);
    server.join().unwrap();

    let receipt_log_empty = root.join("registry-witness-receipts.log.0.json");
    let direct_receipt_log = root.join("registry-witness-receipts.direct.log.1.json");
    let receipt_log = root.join("registry-witness-receipts.log.1.json");
    let receipt_log_checkpoint = root.join("registry-witness-receipts.checkpoint.json");
    let receipt_log_verification = root.join("registry-witness-receipts.verification.json");
    successful(&[
        "init-approval-log",
        "--log-id",
        "factory-release-registry-witness-receipts",
        "--output",
        path(&receipt_log_empty),
    ]);

    let direct_receipt_quorum_log = root.join("registry-witness-receipts.direct-quorum.log.json");
    let direct_receipt_quorum_report =
        root.join("registry-witness-receipts.direct-quorum.report.json");
    successful(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum",
        path(&receipt_log_empty),
        "--receipt",
        path(&remote_witness_b_receipt),
        "--receipt",
        path(&remote_direct_witness_a_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_witness_b),
        "--response",
        path(&remote_direct_witness_a),
        "--trusted-witness-id",
        "witness-b",
        "--trusted-witness-public-key",
        path(&witness_b_public),
        "--trusted-witness-id",
        "witness-a",
        "--trusted-witness-public-key",
        path(&witness_a_next_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--recorded-at-unix",
        "5401",
        "--output",
        path(&direct_receipt_quorum_log),
        "--report-output",
        path(&direct_receipt_quorum_report),
    ]);
    let direct_quorum_value: Value =
        serde_json::from_slice(&fs::read(&direct_receipt_quorum_report).unwrap()).unwrap();
    assert_eq!(direct_quorum_value["quorum_met"], true);
    assert_eq!(direct_quorum_value["valid_witnesses"], 2);
    assert_eq!(direct_quorum_value["minimum_witnesses"], 2);
    assert_eq!(direct_quorum_value["members"][0]["witness_id"], "witness-a");
    assert_eq!(direct_quorum_value["members"][1]["witness_id"], "witness-b");
    assert_eq!(
        direct_quorum_value["history_sha256"],
        hex::encode(Sha256::digest(fs::read(&history).unwrap()))
    );
    assert_eq!(
        direct_quorum_value["checkpoint_trust_state_sha256"],
        hex::encode(Sha256::digest(fs::read(&checkpoint_trust).unwrap()))
    );
    assert_eq!(direct_quorum_value["approval_log_entry_count"], 2);
    let direct_quorum_log_value: Value =
        serde_json::from_slice(&fs::read(&direct_receipt_quorum_log).unwrap()).unwrap();
    assert_eq!(
        direct_quorum_log_value["entries"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        direct_quorum_log_value["entries"][0]["event"]["outcome"],
        "verified-witness:witness-a"
    );
    assert_eq!(
        direct_quorum_log_value["entries"][1]["event"]["outcome"],
        "verified-witness:witness-b"
    );
    let normalized_direct_quorum =
        root.join("registry-witness-receipts.direct-quorum.normalized.json");
    successful(&[
        "validate-remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-quorum-report",
        path(&direct_receipt_quorum_report),
        "--output",
        path(&normalized_direct_quorum),
    ]);
    assert_eq!(
        fs::read(&normalized_direct_quorum).unwrap(),
        fs::read(&direct_receipt_quorum_report).unwrap()
    );

    let quorum_bound_checkpoint =
        root.join("registry-witness-receipts.direct-quorum.bound-checkpoint.json");
    successful(&[
        "sign-approval-log-with-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--private-key",
        path(&witness_a_next_secret),
        "--signer-id",
        "factory-release-registry-receipt-log",
        "--output",
        path(&quorum_bound_checkpoint),
    ]);
    let quorum_bound_checkpoint_value: Value =
        serde_json::from_slice(&fs::read(&quorum_bound_checkpoint).unwrap()).unwrap();
    assert_eq!(quorum_bound_checkpoint_value["entry_count"], 2);
    assert_eq!(
        quorum_bound_checkpoint_value["log_sha256"],
        direct_quorum_value["approval_log_sha256"]
    );
    let quorum_bound_verification =
        root.join("registry-witness-receipts.direct-quorum.bound-verification.json");
    successful(&[
        "verify-approval-log",
        path(&direct_receipt_quorum_log),
        "--checkpoint",
        path(&quorum_bound_checkpoint),
        "--public-key",
        path(&witness_a_next_public),
        "--output",
        path(&quorum_bound_verification),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&quorum_bound_verification).unwrap()).unwrap()["verified"],
        true
    );

    let dedicated_quorum_checkpoint =
        root.join("registry-witness-receipts.direct-quorum.dedicated-checkpoint.json");
    successful(&[
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--private-key",
        path(&receipt_quorum_checkpoint_secret),
        "--signer-id",
        "factory-release-registry-receipt-quorum",
        "--output",
        path(&dedicated_quorum_checkpoint),
    ]);
    let dedicated_checkpoint_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_quorum_checkpoint).unwrap()).unwrap();
    assert_eq!(dedicated_checkpoint_value["approval_log_entry_count"], 2);
    assert_eq!(dedicated_checkpoint_value["minimum_witnesses"], 2);
    assert_eq!(dedicated_checkpoint_value["valid_witnesses"], 2);
    assert_eq!(
        dedicated_checkpoint_value["approval_log_sha256"],
        direct_quorum_value["approval_log_sha256"]
    );

    let dedicated_quorum_verification =
        root.join("registry-witness-receipts.direct-quorum.dedicated-verification.json");
    successful(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--public-key",
        path(&receipt_quorum_checkpoint_public),
        "--output",
        path(&dedicated_quorum_verification),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&dedicated_quorum_verification).unwrap())
            .unwrap()["verified"],
        true
    );

    let dedicated_checkpoint_schema =
        root.join("registry-witness-receipts.dedicated-checkpoint.schema.json");
    successful(&[
        "signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-schema",
        "--output",
        path(&dedicated_checkpoint_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&dedicated_checkpoint_schema).unwrap()).unwrap()
            ["additionalProperties"],
        false
    );
    let dedicated_verification_schema =
        root.join("registry-witness-receipts.dedicated-verification.schema.json");
    successful(&[
        "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-verification-schema",
        "--output",
        path(&dedicated_verification_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&dedicated_verification_schema).unwrap())
            .unwrap()["additionalProperties"],
        false
    );
    let normalized_dedicated_checkpoint =
        root.join("registry-witness-receipts.dedicated-checkpoint.normalized.json");
    successful(&[
        "validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--output",
        path(&normalized_dedicated_checkpoint),
    ]);
    assert_eq!(
        fs::read(&normalized_dedicated_checkpoint).unwrap(),
        fs::read(&dedicated_quorum_checkpoint).unwrap()
    );

    let dedicated_checkpoint_witness_a =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.json");
    let dedicated_checkpoint_witness_b =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-b.json");
    for (private_key, witness_id, witnessed_at_unix, output) in [
        (
            &receipt_quorum_checkpoint_witness_a_secret,
            "independent-factory-witness-a",
            "5500",
            &dedicated_checkpoint_witness_a,
        ),
        (
            &receipt_quorum_checkpoint_witness_b_secret,
            "independent-factory-witness-b",
            "5501",
            &dedicated_checkpoint_witness_b,
        ),
    ] {
        successful(&[
            "witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
            path(&direct_receipt_quorum_log),
            "--quorum-report",
            path(&direct_receipt_quorum_report),
            "--checkpoint",
            path(&dedicated_quorum_checkpoint),
            "--checkpoint-public-key",
            path(&receipt_quorum_checkpoint_public),
            "--private-key",
            path(private_key),
            "--witness-id",
            witness_id,
            "--witnessed-at-unix",
            witnessed_at_unix,
            "--output",
            path(output),
        ]);
    }
    let dedicated_checkpoint_witness_a_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_checkpoint_witness_a).unwrap()).unwrap();
    assert_eq!(
        dedicated_checkpoint_witness_a_value["checkpoint_sha256"],
        hex::encode(Sha256::digest(compact_json_source(
            &fs::read(&dedicated_quorum_checkpoint).unwrap()
        )))
    );
    assert_eq!(
        dedicated_checkpoint_witness_a_value["approval_log_sha256"],
        direct_quorum_value["approval_log_sha256"]
    );

    let dedicated_checkpoint_witness_schema =
        root.join("registry-witness-receipts.dedicated-checkpoint-witness.schema.json");
    successful(&[
        "signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-schema",
        "--output",
        path(&dedicated_checkpoint_witness_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&dedicated_checkpoint_witness_schema).unwrap())
            .unwrap()["additionalProperties"],
        false
    );
    let normalized_dedicated_checkpoint_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.normalized.json");
    successful(&[
        "validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
        path(&dedicated_checkpoint_witness_a),
        "--output",
        path(&normalized_dedicated_checkpoint_witness),
    ]);
    assert_eq!(
        fs::read(&normalized_dedicated_checkpoint_witness).unwrap(),
        fs::read(&dedicated_checkpoint_witness_a).unwrap()
    );

    let dedicated_checkpoint_witness_quorum =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.json");
    successful(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_a_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&dedicated_checkpoint_witness_quorum),
    ]);
    let dedicated_checkpoint_witness_quorum_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_checkpoint_witness_quorum).unwrap()).unwrap();
    assert_eq!(
        dedicated_checkpoint_witness_quorum_value["status"],
        "witness_quorum_met"
    );
    assert_eq!(
        dedicated_checkpoint_witness_quorum_value["valid_witnesses"],
        2
    );
    assert_eq!(
        dedicated_checkpoint_witness_quorum_value["witness_ids"][0],
        "independent-factory-witness-a"
    );
    assert_eq!(
        dedicated_checkpoint_witness_quorum_value["witness_ids"][1],
        "independent-factory-witness-b"
    );

    let dedicated_checkpoint_witness_quorum_reordered =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.reordered.json");
    successful(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_a_public),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&dedicated_checkpoint_witness_quorum_reordered),
    ]);
    assert_eq!(
        fs::read(&dedicated_checkpoint_witness_quorum_reordered).unwrap(),
        fs::read(&dedicated_checkpoint_witness_quorum).unwrap()
    );

    let dedicated_checkpoint_witness_quorum_schema =
        root.join("registry-witness-receipts.dedicated-checkpoint-witness-quorum.schema.json");
    successful(&[
        "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report-schema",
        "--output",
        path(&dedicated_checkpoint_witness_quorum_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(&dedicated_checkpoint_witness_quorum_schema).unwrap()
        )
        .unwrap()["additionalProperties"],
        false
    );
    let normalized_dedicated_checkpoint_witness_quorum =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.normalized.json");
    successful(&[
        "validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report",
        path(&dedicated_checkpoint_witness_quorum),
        "--output",
        path(&normalized_dedicated_checkpoint_witness_quorum),
    ]);
    assert_eq!(
        fs::read(&normalized_dedicated_checkpoint_witness_quorum).unwrap(),
        fs::read(&dedicated_checkpoint_witness_quorum).unwrap()
    );

    let below_threshold_checkpoint_witness_quorum =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.below.json");
    let below_threshold = run(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_a_public),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--minimum-witnesses",
        "3",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&below_threshold_checkpoint_witness_quorum),
    ]);
    assert!(!below_threshold.status.success());
    let below_threshold_value: Value =
        serde_json::from_slice(&fs::read(&below_threshold_checkpoint_witness_quorum).unwrap())
            .unwrap();
    assert_eq!(below_threshold_value["quorum_met"], false);
    assert_eq!(below_threshold_value["valid_witnesses"], 2);

    let stale_checkpoint_witness_quorum =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.stale.json");
    let stale = run(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_a_public),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "92000",
        "--output",
        path(&stale_checkpoint_witness_quorum),
    ]);
    assert!(!stale.status.success());
    assert!(!stale_checkpoint_witness_quorum.exists());

    let reused_checkpoint_key_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.reused-key-witness.json");
    let reused_checkpoint_key = run(&[
        "witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--private-key",
        path(&receipt_quorum_checkpoint_secret),
        "--witness-id",
        "checkpoint-signer",
        "--witnessed-at-unix",
        "5502",
        "--output",
        path(&reused_checkpoint_key_witness),
    ]);
    assert!(!reused_checkpoint_key.status.success());
    assert!(!reused_checkpoint_key_witness.exists());

    let missing_checkpoint_witness_key = root.join("missing-checkpoint-witness-private-key.hex");
    let mismatched_checkpoint_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.mismatched-witness.json");
    let mismatched_checkpoint_witness_result = run(&[
        "witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&receipt_log_empty),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--private-key",
        path(&missing_checkpoint_witness_key),
        "--witness-id",
        "must-not-read-private-key",
        "--witnessed-at-unix",
        "5502",
        "--output",
        path(&mismatched_checkpoint_witness),
    ]);
    assert!(!mismatched_checkpoint_witness_result.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched_checkpoint_witness_result.stderr)
            .contains("does not match the remote factory release receipt quorum log binding")
    );
    assert!(!mismatched_checkpoint_witness.exists());

    let dedicated_checkpoint_witness_a_initial_trust =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.initial.trust.json");
    let dedicated_checkpoint_witness_b_trust =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-b.trust.json");
    for (witness_id, public_key, output) in [
        (
            "independent-factory-witness-a",
            &receipt_quorum_checkpoint_witness_a_public,
            &dedicated_checkpoint_witness_a_initial_trust,
        ),
        (
            "independent-factory-witness-b",
            &receipt_quorum_checkpoint_witness_b_public,
            &dedicated_checkpoint_witness_b_trust,
        ),
    ] {
        successful(&[
            "init-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust",
            "--witness-id",
            witness_id,
            "--public-key",
            path(public_key),
            "--output",
            path(output),
        ]);
    }
    let initial_checkpoint_witness_trust_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_checkpoint_witness_a_initial_trust).unwrap())
            .unwrap();
    assert_eq!(initial_checkpoint_witness_trust_value["generation"], 0);
    assert_eq!(
        initial_checkpoint_witness_trust_value["last_rotation_sha256"],
        Value::Null
    );

    let dedicated_checkpoint_witness_a_rotation =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.rotation.json");
    successful(&[
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        path(&dedicated_checkpoint_witness_a_initial_trust),
        "--old-private-key",
        path(&receipt_quorum_checkpoint_witness_a_secret),
        "--new-private-key",
        path(&receipt_quorum_checkpoint_witness_a_next_secret),
        "--rotated-at-unix",
        "5450",
        "--output",
        path(&dedicated_checkpoint_witness_a_rotation),
    ]);
    let dedicated_checkpoint_witness_a_rotation_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_checkpoint_witness_a_rotation).unwrap())
            .unwrap();
    assert_eq!(
        dedicated_checkpoint_witness_a_rotation_value["from_generation"],
        0
    );
    assert_eq!(
        dedicated_checkpoint_witness_a_rotation_value["to_generation"],
        1
    );
    assert_eq!(
        dedicated_checkpoint_witness_a_rotation_value["new_public_key"],
        fs::read_to_string(&receipt_quorum_checkpoint_witness_a_next_public)
            .unwrap()
            .trim()
    );

    let dedicated_checkpoint_witness_a_rotated_trust =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.rotated.trust.json");
    successful(&[
        "apply-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        path(&dedicated_checkpoint_witness_a_initial_trust),
        "--rotation",
        path(&dedicated_checkpoint_witness_a_rotation),
        "--output",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
    ]);
    let rotated_checkpoint_witness_trust_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_checkpoint_witness_a_rotated_trust).unwrap())
            .unwrap();
    assert_eq!(rotated_checkpoint_witness_trust_value["generation"], 1);
    assert_eq!(
        rotated_checkpoint_witness_trust_value["current_public_key"],
        dedicated_checkpoint_witness_a_rotation_value["new_public_key"]
    );
    assert_eq!(
        rotated_checkpoint_witness_trust_value["last_rotation_sha256"],
        hex::encode(Sha256::digest(compact_json_source(
            &fs::read(&dedicated_checkpoint_witness_a_rotation).unwrap()
        )))
    );

    let exported_dedicated_checkpoint_witness_a_key =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.rotated.public.hex");
    successful(&[
        "export-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-public-key",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--output",
        path(&exported_dedicated_checkpoint_witness_a_key),
    ]);
    assert_eq!(
        fs::read(&exported_dedicated_checkpoint_witness_a_key).unwrap(),
        fs::read(&receipt_quorum_checkpoint_witness_a_next_public).unwrap()
    );

    let dedicated_checkpoint_witness_a_rotated =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.rotated.json");
    successful(&[
        "witness-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--private-key",
        path(&receipt_quorum_checkpoint_witness_a_next_secret),
        "--witness-id",
        "independent-factory-witness-a",
        "--witnessed-at-unix",
        "5552",
        "--output",
        path(&dedicated_checkpoint_witness_a_rotated),
    ]);

    let remote_dedicated_checkpoint_witness_b =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-b.remote.json");
    let remote_dedicated_checkpoint_witness_b_receipt =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-b.remote.receipt.json");
    let (endpoint, server) = serve_json_once_at(
        fs::read(&dedicated_checkpoint_witness_b).unwrap(),
        Some("dedicated-bounded-token"),
        "/v1/factory-receipt-quorum-checkpoint",
    );
    let remote = Command::new(binary())
        .args([
            "request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
            path(&direct_receipt_quorum_log),
            "--quorum-report",
            path(&direct_receipt_quorum_report),
            "--checkpoint",
            path(&dedicated_quorum_checkpoint),
            "--checkpoint-public-key",
            path(&receipt_quorum_checkpoint_public),
            "--endpoint",
            &endpoint,
            "--witness-public-key",
            path(&receipt_quorum_checkpoint_witness_b_public),
            "--bearer-token-env",
            "PCBEX_FACTORY_RECEIPT_QUORUM_WITNESS_TOKEN",
            "--timeout-seconds",
            "10",
            "--evaluated-at-unix",
            "5600",
            "--output",
            path(&remote_dedicated_checkpoint_witness_b),
            "--receipt-output",
            path(&remote_dedicated_checkpoint_witness_b_receipt),
            "--allow-http-loopback",
        ])
        .env(
            "PCBEX_FACTORY_RECEIPT_QUORUM_WITNESS_TOKEN",
            "dedicated-bounded-token",
        )
        .output()
        .unwrap();
    assert!(
        remote.status.success(),
        "{}",
        String::from_utf8_lossy(&remote.stderr)
    );
    let request = server.join().unwrap();
    assert_eq!(request["schema_version"], 1);
    assert_eq!(
        request["protocol"],
        "pcbex-remote-factory-release-registry-receipt-quorum-log-checkpoint-witness-v1"
    );
    assert_eq!(request["quorum_report"], direct_quorum_value);
    assert_eq!(request["approval_log"], direct_quorum_log_value);
    assert_eq!(request["checkpoint"], dedicated_checkpoint_value);
    assert_eq!(
        fs::read(&remote_dedicated_checkpoint_witness_b).unwrap(),
        fs::read(&dedicated_checkpoint_witness_b).unwrap()
    );
    let remote_dedicated_checkpoint_witness_b_receipt_source =
        fs::read(&remote_dedicated_checkpoint_witness_b_receipt).unwrap();
    let remote_dedicated_checkpoint_witness_b_receipt_value: Value =
        serde_json::from_slice(&remote_dedicated_checkpoint_witness_b_receipt_source).unwrap();
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["adapter"],
        "remote-factory-release-registry-receipt-quorum-log-checkpoint-witness-https-v1"
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["endpoint"],
        endpoint
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["quorum_report_sha256"],
        dedicated_checkpoint_value["quorum_report_sha256"]
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["quorum_report_source_sha256"],
        hex::encode(Sha256::digest(
            fs::read(&direct_receipt_quorum_report).unwrap()
        ))
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["approval_log_source_sha256"],
        hex::encode(Sha256::digest(
            fs::read(&direct_receipt_quorum_log).unwrap()
        ))
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["checkpoint_source_sha256"],
        hex::encode(Sha256::digest(
            fs::read(&dedicated_quorum_checkpoint).unwrap()
        ))
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["response_sha256"],
        hex::encode(Sha256::digest(
            fs::read(&dedicated_checkpoint_witness_b).unwrap()
        ))
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["witness_sha256"],
        hex::encode(Sha256::digest(compact_json_source(
            &fs::read(&dedicated_checkpoint_witness_b).unwrap()
        )))
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["witness_key_trust_state_sha256"],
        Value::Null
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["witness_key_generation"],
        Value::Null
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_b_receipt_value["verified"],
        true
    );
    assert!(
        !String::from_utf8_lossy(&remote_dedicated_checkpoint_witness_b_receipt_source)
            .contains("dedicated-bounded-token")
    );

    let remote_dedicated_checkpoint_witness_a =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.remote.json");
    let remote_dedicated_checkpoint_witness_a_receipt =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.remote.receipt.json");
    let (endpoint, server) = serve_json_once_at(
        fs::read(&dedicated_checkpoint_witness_a_rotated).unwrap(),
        None,
        "/v1/factory-receipt-quorum-checkpoint",
    );
    successful(&[
        "request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--endpoint",
        &endpoint,
        "--witness-trust-state",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&remote_dedicated_checkpoint_witness_a),
        "--receipt-output",
        path(&remote_dedicated_checkpoint_witness_a_receipt),
        "--allow-http-loopback",
    ]);
    server.join().unwrap();
    assert_eq!(
        fs::read(&remote_dedicated_checkpoint_witness_a).unwrap(),
        fs::read(&dedicated_checkpoint_witness_a_rotated).unwrap()
    );
    let remote_dedicated_checkpoint_witness_a_receipt_value: Value =
        serde_json::from_slice(&fs::read(&remote_dedicated_checkpoint_witness_a_receipt).unwrap())
            .unwrap();
    assert_eq!(
        remote_dedicated_checkpoint_witness_a_receipt_value["witness_key_generation"],
        1
    );
    assert_eq!(
        remote_dedicated_checkpoint_witness_a_receipt_value["witness_key_trust_state_sha256"],
        hex::encode(Sha256::digest(
            fs::read(&dedicated_checkpoint_witness_a_rotated_trust).unwrap()
        ))
    );

    let dedicated_checkpoint_witness_receipt_schema =
        root.join("registry-witness-receipts.dedicated-checkpoint-witness.receipt.schema.json");
    successful(&[
        "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-schema",
        "--output",
        path(&dedicated_checkpoint_witness_receipt_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(&dedicated_checkpoint_witness_receipt_schema).unwrap()
        )
        .unwrap()["additionalProperties"],
        false
    );
    let normalized_dedicated_checkpoint_witness_receipt =
        root.join("registry-witness-receipts.dedicated-checkpoint-witness.receipt.normalized.json");
    successful(&[
        "validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt",
        path(&remote_dedicated_checkpoint_witness_a_receipt),
        "--output",
        path(&normalized_dedicated_checkpoint_witness_receipt),
    ]);
    assert_eq!(
        fs::read(&normalized_dedicated_checkpoint_witness_receipt).unwrap(),
        fs::read(&remote_dedicated_checkpoint_witness_a_receipt).unwrap()
    );

    let remote_dedicated_checkpoint_witness_quorum =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.remote.json");
    successful(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&remote_dedicated_checkpoint_witness_b),
        "--witnesses",
        path(&remote_dedicated_checkpoint_witness_a),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_b_trust),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&remote_dedicated_checkpoint_witness_quorum),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(&remote_dedicated_checkpoint_witness_quorum).unwrap()
        )
        .unwrap()["quorum_met"],
        true
    );

    let compact_remote_dedicated_checkpoint_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness.compact.remote.json");
    let compact_remote_dedicated_checkpoint_witness_receipt = root
        .join("registry-witness-receipts.dedicated-checkpoint.witness.compact.remote.receipt.json");
    let dedicated_checkpoint_witness_b_value: Value =
        serde_json::from_slice(&fs::read(&dedicated_checkpoint_witness_b).unwrap()).unwrap();
    let (endpoint, server) = serve_json_once_at(
        serde_json::to_vec(&dedicated_checkpoint_witness_b_value).unwrap(),
        None,
        "/v1/factory-receipt-quorum-checkpoint",
    );
    let compact_response = run(&[
        "request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--endpoint",
        &endpoint,
        "--witness-public-key",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&compact_remote_dedicated_checkpoint_witness),
        "--receipt-output",
        path(&compact_remote_dedicated_checkpoint_witness_receipt),
        "--allow-http-loopback",
    ]);
    server.join().unwrap();
    assert!(!compact_response.status.success());
    assert!(
        String::from_utf8_lossy(&compact_response.stderr).contains("not canonical pretty JSON")
    );
    assert!(!compact_remote_dedicated_checkpoint_witness.exists());
    assert!(!compact_remote_dedicated_checkpoint_witness_receipt.exists());

    let stale_trust_remote_dedicated_checkpoint_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness.stale-trust.remote.json");
    let stale_trust_remote_dedicated_checkpoint_witness_receipt = root.join(
        "registry-witness-receipts.dedicated-checkpoint.witness.stale-trust.remote.receipt.json",
    );
    let (endpoint, server) = serve_json_once_at(
        fs::read(&dedicated_checkpoint_witness_a).unwrap(),
        None,
        "/v1/factory-receipt-quorum-checkpoint",
    );
    let stale_trust = run(&[
        "request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--endpoint",
        &endpoint,
        "--witness-trust-state",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&stale_trust_remote_dedicated_checkpoint_witness),
        "--receipt-output",
        path(&stale_trust_remote_dedicated_checkpoint_witness_receipt),
        "--allow-http-loopback",
    ]);
    server.join().unwrap();
    assert!(!stale_trust.status.success());
    assert!(!stale_trust_remote_dedicated_checkpoint_witness.exists());
    assert!(!stale_trust_remote_dedicated_checkpoint_witness_receipt.exists());

    let unsafe_endpoint_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness.unsafe.json");
    let unsafe_endpoint_receipt =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness.unsafe.receipt.json");
    let unsafe_endpoint = run(&[
        "request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--endpoint",
        "https://witness.example/v1/factory-receipt-quorum-checkpoint?token=secret",
        "--witness-public-key",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&unsafe_endpoint_witness),
        "--receipt-output",
        path(&unsafe_endpoint_receipt),
    ]);
    assert!(!unsafe_endpoint.status.success());
    assert!(String::from_utf8_lossy(&unsafe_endpoint.stderr).contains("query"));
    assert!(!unsafe_endpoint_witness.exists());
    assert!(!unsafe_endpoint_receipt.exists());

    let existing_remote_dedicated_checkpoint_witness =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness.existing.json");
    let existing_remote_dedicated_checkpoint_witness_receipt =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness.existing.receipt.json");
    fs::write(&existing_remote_dedicated_checkpoint_witness, b"preserve\n").unwrap();
    let no_clobber = run(&[
        "request-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--endpoint",
        "https://witness.example/v1/factory-receipt-quorum-checkpoint",
        "--witness-public-key",
        path(&receipt_quorum_checkpoint_witness_b_public),
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&existing_remote_dedicated_checkpoint_witness),
        "--receipt-output",
        path(&existing_remote_dedicated_checkpoint_witness_receipt),
    ]);
    assert!(!no_clobber.status.success());
    assert_eq!(
        fs::read(&existing_remote_dedicated_checkpoint_witness).unwrap(),
        b"preserve\n"
    );
    assert!(!existing_remote_dedicated_checkpoint_witness_receipt.exists());

    let trusted_dedicated_checkpoint_witness_quorum =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.trusted.json");
    successful(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a_rotated),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_b_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&trusted_dedicated_checkpoint_witness_quorum),
    ]);
    let trusted_checkpoint_witness_quorum_value: Value =
        serde_json::from_slice(&fs::read(&trusted_dedicated_checkpoint_witness_quorum).unwrap())
            .unwrap();
    assert_eq!(trusted_checkpoint_witness_quorum_value["quorum_met"], true);
    assert_eq!(
        trusted_checkpoint_witness_quorum_value["valid_witnesses"],
        2
    );
    assert_eq!(
        trusted_checkpoint_witness_quorum_value["witness_public_keys"][0],
        [
            fs::read_to_string(&receipt_quorum_checkpoint_witness_a_next_public)
                .unwrap()
                .trim()
                .to_string(),
            fs::read_to_string(&receipt_quorum_checkpoint_witness_b_public)
                .unwrap()
                .trim()
                .to_string(),
        ]
        .into_iter()
        .min()
        .unwrap()
    );

    let trusted_dedicated_checkpoint_witness_quorum_reordered = root.join(
        "registry-witness-receipts.dedicated-checkpoint.witness-quorum.trusted.reordered.json",
    );
    successful(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a_rotated),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_b_trust),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&trusted_dedicated_checkpoint_witness_quorum_reordered),
    ]);
    assert_eq!(
        fs::read(&trusted_dedicated_checkpoint_witness_quorum_reordered).unwrap(),
        fs::read(&trusted_dedicated_checkpoint_witness_quorum).unwrap()
    );

    let below_trusted_checkpoint_witness_quorum = root
        .join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.trusted.below.json");
    let below_trusted = run(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a_rotated),
        "--witnesses",
        path(&dedicated_checkpoint_witness_b),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_b_trust),
        "--minimum-witnesses",
        "3",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&below_trusted_checkpoint_witness_quorum),
    ]);
    assert!(!below_trusted.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(&below_trusted_checkpoint_witness_quorum).unwrap()
        )
        .unwrap()["quorum_met"],
        false
    );

    for (label, witness, trust_state) in [
        (
            "old-witness-new-trust",
            &dedicated_checkpoint_witness_a,
            &dedicated_checkpoint_witness_a_rotated_trust,
        ),
        (
            "new-witness-old-trust",
            &dedicated_checkpoint_witness_a_rotated,
            &dedicated_checkpoint_witness_a_initial_trust,
        ),
    ] {
        let rejected_output = root.join(format!(
            "registry-witness-receipts.dedicated-checkpoint.witness-quorum.{label}.json"
        ));
        let rejected = run(&[
            "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
            path(&direct_receipt_quorum_log),
            "--quorum-report",
            path(&direct_receipt_quorum_report),
            "--checkpoint",
            path(&dedicated_quorum_checkpoint),
            "--checkpoint-public-key",
            path(&receipt_quorum_checkpoint_public),
            "--witnesses",
            path(witness),
            "--witnesses",
            path(&dedicated_checkpoint_witness_b),
            "--witness-trust-states",
            path(trust_state),
            "--witness-trust-states",
            path(&dedicated_checkpoint_witness_b_trust),
            "--minimum-witnesses",
            "2",
            "--evaluated-at-unix",
            "5600",
            "--output",
            path(&rejected_output),
        ]);
        assert!(!rejected.status.success());
        assert!(!rejected_output.exists());
    }

    let mixed_trust_output =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-quorum.mixed-trust.json");
    let mixed_trust = run(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witnesses",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&dedicated_quorum_checkpoint),
        "--checkpoint-public-key",
        path(&receipt_quorum_checkpoint_public),
        "--witnesses",
        path(&dedicated_checkpoint_witness_a_rotated),
        "--witness-public-keys",
        path(&receipt_quorum_checkpoint_witness_a_next_public),
        "--witness-trust-states",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5600",
        "--output",
        path(&mixed_trust_output),
    ]);
    assert!(!mixed_trust.status.success());
    assert!(!mixed_trust_output.exists());

    let invalid_checkpoint_witness_trust =
        root.join("registry-witness-receipts.dedicated-checkpoint.witness-a.invalid.trust.json");
    let initial_checkpoint_witness_key =
        initial_checkpoint_witness_trust_value["current_public_key"]
            .as_str()
            .unwrap();
    let weak_checkpoint_witness_key = format!("01{}", "00".repeat(31));
    let invalid_checkpoint_witness_trust_source =
        String::from_utf8(fs::read(&dedicated_checkpoint_witness_a_initial_trust).unwrap())
            .unwrap()
            .replace(initial_checkpoint_witness_key, &weak_checkpoint_witness_key);
    fs::write(
        &invalid_checkpoint_witness_trust,
        invalid_checkpoint_witness_trust_source,
    )
    .unwrap();
    let forbidden_rotation_output = root
        .join("registry-witness-receipts.dedicated-checkpoint.witness-a.forbidden.rotation.json");
    let missing_old_rotation_key = root.join("missing-receipt-quorum-witness-old-rotation.key");
    let missing_new_rotation_key = root.join("missing-receipt-quorum-witness-new-rotation.key");
    let invalid_rotation = run(&[
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        path(&invalid_checkpoint_witness_trust),
        "--old-private-key",
        path(&missing_old_rotation_key),
        "--new-private-key",
        path(&missing_new_rotation_key),
        "--rotated-at-unix",
        "5450",
        "--output",
        path(&forbidden_rotation_output),
    ]);
    assert!(!invalid_rotation.status.success());
    let invalid_rotation_stderr = String::from_utf8_lossy(&invalid_rotation.stderr);
    assert!(
        invalid_rotation_stderr.contains("weak"),
        "{invalid_rotation_stderr}"
    );
    assert!(!forbidden_rotation_output.exists());

    let initial_trust_before_alias =
        fs::read(&dedicated_checkpoint_witness_a_initial_trust).unwrap();
    let aliased_apply = run(&[
        "apply-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        path(&dedicated_checkpoint_witness_a_initial_trust),
        "--rotation",
        path(&dedicated_checkpoint_witness_a_rotation),
        "--output",
        path(&dedicated_checkpoint_witness_a_initial_trust),
    ]);
    assert!(!aliased_apply.status.success());
    assert_eq!(
        fs::read(&dedicated_checkpoint_witness_a_initial_trust).unwrap(),
        initial_trust_before_alias
    );

    let dedicated_checkpoint_witness_trust_schema =
        root.join("registry-witness-receipts.dedicated-checkpoint-witness-trust.schema.json");
    successful(&[
        "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust-state-schema",
        "--output",
        path(&dedicated_checkpoint_witness_trust_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(&dedicated_checkpoint_witness_trust_schema).unwrap()
        )
        .unwrap()["additionalProperties"],
        false
    );
    let dedicated_checkpoint_witness_rotation_schema =
        root.join("registry-witness-receipts.dedicated-checkpoint-witness-rotation.schema.json");
    successful(&[
        "signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation-schema",
        "--output",
        path(&dedicated_checkpoint_witness_rotation_schema),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(&dedicated_checkpoint_witness_rotation_schema).unwrap()
        )
        .unwrap()["additionalProperties"],
        false
    );
    let normalized_dedicated_checkpoint_witness_trust = root.join(
        "registry-witness-receipts.dedicated-checkpoint.witness-a.rotated.trust.normalized.json",
    );
    successful(&[
        "validate-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust-state",
        path(&dedicated_checkpoint_witness_a_rotated_trust),
        "--output",
        path(&normalized_dedicated_checkpoint_witness_trust),
    ]);
    assert_eq!(
        fs::read(&normalized_dedicated_checkpoint_witness_trust).unwrap(),
        fs::read(&dedicated_checkpoint_witness_a_rotated_trust).unwrap()
    );
    let normalized_dedicated_checkpoint_witness_rotation = root
        .join("registry-witness-receipts.dedicated-checkpoint.witness-a.rotation.normalized.json");
    successful(&[
        "validate-signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation",
        path(&dedicated_checkpoint_witness_a_rotation),
        "--output",
        path(&normalized_dedicated_checkpoint_witness_rotation),
    ]);
    assert_eq!(
        fs::read(&normalized_dedicated_checkpoint_witness_rotation).unwrap(),
        fs::read(&dedicated_checkpoint_witness_a_rotation).unwrap()
    );

    let tampered_dedicated_checkpoint =
        root.join("registry-witness-receipts.dedicated-checkpoint.tampered.json");
    let mut tampered_checkpoint_value = dedicated_checkpoint_value;
    tampered_checkpoint_value["valid_witnesses"] = Value::from(3);
    let mut tampered_checkpoint_source =
        serde_json::to_vec_pretty(&tampered_checkpoint_value).unwrap();
    tampered_checkpoint_source.push(b'\n');
    fs::write(&tampered_dedicated_checkpoint, tampered_checkpoint_source).unwrap();
    let tampered_dedicated_verification =
        root.join("registry-witness-receipts.dedicated-checkpoint.tampered-verification.json");
    let tampered = run(&[
        "verify-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&direct_receipt_quorum_log),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--checkpoint",
        path(&tampered_dedicated_checkpoint),
        "--public-key",
        path(&receipt_quorum_checkpoint_public),
        "--output",
        path(&tampered_dedicated_verification),
    ]);
    assert!(!tampered.status.success());
    assert!(!tampered_dedicated_verification.exists());

    let mismatched_quorum_checkpoint =
        root.join("registry-witness-receipts.direct-quorum.mismatched-checkpoint.json");
    let private_key_must_not_be_read = root.join("factory-quorum-forbidden-missing.key");
    let mismatched_dedicated_checkpoint =
        root.join("registry-witness-receipts.direct-quorum.mismatched-dedicated-checkpoint.json");
    let mismatched_dedicated = run(&[
        "sign-remote-factory-release-registry-history-receipt-quorum-log-checkpoint",
        path(&receipt_log_empty),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--private-key",
        path(&private_key_must_not_be_read),
        "--signer-id",
        "factory-release-registry-receipt-quorum",
        "--output",
        path(&mismatched_dedicated_checkpoint),
    ]);
    assert!(!mismatched_dedicated.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched_dedicated.stderr)
            .contains("does not match the remote factory release receipt quorum log binding")
    );
    assert!(!mismatched_dedicated_checkpoint.exists());
    let mismatched = run(&[
        "sign-approval-log-with-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum",
        path(&receipt_log_empty),
        "--quorum-report",
        path(&direct_receipt_quorum_report),
        "--private-key",
        path(&private_key_must_not_be_read),
        "--signer-id",
        "factory-release-registry-receipt-log",
        "--output",
        path(&mismatched_quorum_checkpoint),
    ]);
    assert!(!mismatched.status.success());
    assert!(
        String::from_utf8_lossy(&mismatched.stderr)
            .contains("does not match the remote factory release receipt quorum log binding")
    );
    assert!(!mismatched_quorum_checkpoint.exists());

    let trusted_receipt_quorum_log = root.join("registry-witness-receipts.trusted-quorum.log.json");
    let trusted_receipt_quorum_report =
        root.join("registry-witness-receipts.trusted-quorum.report.json");
    successful(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum",
        path(&receipt_log_empty),
        "--receipt",
        path(&remote_rotated_witness_a_receipt),
        "--receipt",
        path(&remote_trusted_witness_b_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_rotated_witness_a),
        "--response",
        path(&remote_trusted_witness_b),
        "--witness-key-trust-state",
        path(&witness_b_trust),
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--recorded-at-unix",
        "5401",
        "--output",
        path(&trusted_receipt_quorum_log),
        "--report-output",
        path(&trusted_receipt_quorum_report),
    ]);
    let trusted_quorum_value: Value =
        serde_json::from_slice(&fs::read(&trusted_receipt_quorum_report).unwrap()).unwrap();
    assert_eq!(trusted_quorum_value["quorum_met"], true);
    assert_eq!(
        trusted_quorum_value["members"][0]["witness_key_generation"],
        1
    );
    assert_eq!(
        trusted_quorum_value["members"][1]["witness_key_generation"],
        0
    );

    let below_quorum_log = root.join("registry-witness-receipts.below-quorum.log.json");
    let below_quorum_report = root.join("registry-witness-receipts.below-quorum.report.json");
    let rejected = run(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt-quorum",
        path(&receipt_log_empty),
        "--receipt",
        path(&remote_witness_b_receipt),
        "--receipt",
        path(&remote_direct_witness_a_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_witness_b),
        "--response",
        path(&remote_direct_witness_a),
        "--trusted-witness-id",
        "witness-b",
        "--trusted-witness-public-key",
        path(&witness_b_public),
        "--trusted-witness-id",
        "witness-a",
        "--trusted-witness-public-key",
        path(&witness_a_next_public),
        "--minimum-witnesses",
        "3",
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&below_quorum_log),
        "--report-output",
        path(&below_quorum_report),
    ]);
    assert!(!rejected.status.success());
    assert!(!below_quorum_log.exists());
    assert!(!below_quorum_report.exists());

    successful(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log_empty),
        "--receipt",
        path(&remote_witness_b_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_witness_b),
        "--public-key",
        path(&witness_b_public),
        "--evaluated-at-unix",
        "5400",
        "--recorded-at-unix",
        "5401",
        "--output",
        path(&direct_receipt_log),
    ]);
    successful(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log_empty),
        "--receipt",
        path(&remote_rotated_witness_a_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_rotated_witness_a),
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5400",
        "--recorded-at-unix",
        "5401",
        "--output",
        path(&receipt_log),
    ]);
    let receipt_log_value: Value =
        serde_json::from_slice(&fs::read(&receipt_log).unwrap()).unwrap();
    let receipt_event = &receipt_log_value["entries"][0]["event"];
    assert_eq!(
        receipt_event["artifact_kind"],
        "remote_factory_release_registry_history_checkpoint_witness_receipt"
    );
    assert_eq!(
        receipt_event["artifact_sha256"],
        hex::encode(Sha256::digest(compact_json_source(
            &fs::read(&remote_rotated_witness_a_receipt).unwrap()
        )))
    );
    assert_eq!(
        receipt_event["subject_id"],
        remote_rotated_receipt_value["checkpoint_sha256"]
    );
    assert_eq!(
        receipt_event["request_sha256"],
        remote_rotated_receipt_value["request_sha256"]
    );
    assert_eq!(
        receipt_event["session_sha256"],
        remote_rotated_receipt_value["response_sha256"]
    );
    assert_eq!(receipt_event["outcome"], "verified-witness:witness-a");
    successful(&[
        "sign-approval-log",
        path(&receipt_log),
        "--private-key",
        path(&witness_a_next_secret),
        "--signer-id",
        "factory-release-registry-receipt-log",
        "--output",
        path(&receipt_log_checkpoint),
    ]);
    successful(&[
        "verify-approval-log",
        path(&receipt_log),
        "--checkpoint",
        path(&receipt_log_checkpoint),
        "--public-key",
        path(&witness_a_next_public),
        "--output",
        path(&receipt_log_verification),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&receipt_log_verification).unwrap()).unwrap()["verified"],
        true
    );

    let mut rejected_receipt_value = remote_rotated_receipt_value.clone();
    rejected_receipt_value["verified"] = false.into();
    let rejected_receipt = root.join("registry-witness-receipt.rejected.json");
    let rejected_receipt_log = root.join("registry-witness-receipts.rejected-log.json");
    write_canonical_json(&rejected_receipt, &rejected_receipt_value);
    let rejected = run(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log),
        "--receipt",
        path(&rejected_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_rotated_witness_a),
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5401",
        "--recorded-at-unix",
        "5402",
        "--output",
        path(&rejected_receipt_log),
    ]);
    assert!(!rejected.status.success());
    assert!(!rejected_receipt_log.exists());

    let mut truncated_history_value = history_value.clone();
    truncated_history_value["events"]
        .as_array_mut()
        .unwrap()
        .pop();
    let truncated_history = root.join("registry-history.truncated-at-admission.json");
    write_canonical_json(&truncated_history, &truncated_history_value);
    let truncated_history_log = root.join("registry-witness-receipts.truncated-history.json");
    let rejected = run(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log),
        "--receipt",
        path(&remote_rotated_witness_a_receipt),
        "--history",
        path(&truncated_history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_rotated_witness_a),
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5401",
        "--recorded-at-unix",
        "5402",
        "--output",
        path(&truncated_history_log),
    ]);
    assert!(!rejected.status.success());
    assert!(!truncated_history_log.exists());

    let substituted_response_log = root.join("registry-witness-receipts.substituted-response.json");
    let rejected = run(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log),
        "--receipt",
        path(&remote_rotated_witness_a_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_witness_b),
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5401",
        "--recorded-at-unix",
        "5402",
        "--output",
        path(&substituted_response_log),
    ]);
    assert!(!rejected.status.success());
    assert!(!substituted_response_log.exists());

    let stale_trust_log = root.join("registry-witness-receipts.stale-trust.json");
    let rejected = run(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log),
        "--receipt",
        path(&remote_rotated_witness_a_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_rotated_witness_a),
        "--witness-key-trust-state",
        path(&witness_a_initial_trust),
        "--evaluated-at-unix",
        "5401",
        "--recorded-at-unix",
        "5402",
        "--output",
        path(&stale_trust_log),
    ]);
    assert!(!rejected.status.success());
    assert!(!stale_trust_log.exists());

    let stale_admission_log = root.join("registry-witness-receipts.stale-admission.json");
    let rejected = run(&[
        "append-verified-remote-factory-release-registry-history-checkpoint-witness-receipt",
        path(&receipt_log),
        "--receipt",
        path(&remote_rotated_witness_a_receipt),
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--response",
        path(&remote_rotated_witness_a),
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--evaluated-at-unix",
        "91703",
        "--recorded-at-unix",
        "91703",
        "--output",
        path(&stale_admission_log),
    ]);
    assert!(!rejected.status.success());
    assert!(!stale_admission_log.exists());

    let mixed_direct_quorum = root.join("registry-history.checkpoint.mixed-remote-quorum.json");
    successful(&[
        "verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness",
        path(&witness_a),
        "--witness",
        path(&remote_witness_b),
        "--trusted-witness-id",
        "witness-a",
        "--trusted-witness-id",
        "witness-b",
        "--trusted-witness-public-key",
        path(&witness_a_public),
        "--trusted-witness-public-key",
        path(&witness_b_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--require-quorum",
        "--output",
        path(&mixed_direct_quorum),
    ]);
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&mixed_direct_quorum).unwrap()).unwrap()["quorum_met"],
        true
    );
    let mixed_trust_quorum =
        root.join("registry-history.checkpoint.mixed-remote-trust-quorum.json");
    successful(&[
        "verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness",
        path(&witness_b),
        "--witness",
        path(&remote_rotated_witness_a),
        "--witness-trust-state",
        path(&witness_b_trust),
        "--witness-trust-state",
        path(&witness_a_rotated_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--require-quorum",
        "--output",
        path(&mixed_trust_quorum),
    ]);

    let compact_response = compact_json_source(&fs::read(&witness_b).unwrap());
    let (endpoint, server) = serve_json_once(compact_response, None);
    let noncanonical_witness = root.join("registry-history.checkpoint.noncanonical.remote.json");
    let noncanonical_receipt =
        root.join("registry-history.checkpoint.noncanonical.remote.receipt.json");
    let noncanonical = run(&[
        "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--endpoint",
        &endpoint,
        "--public-key",
        path(&witness_b_public),
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&noncanonical_witness),
        "--receipt-output",
        path(&noncanonical_receipt),
        "--allow-http-loopback",
    ]);
    assert!(!noncanonical.status.success());
    assert!(String::from_utf8_lossy(&noncanonical.stderr).contains("not canonical pretty JSON"));
    server.join().unwrap();
    assert!(!noncanonical_witness.exists());
    assert!(!noncanonical_receipt.exists());

    let (endpoint, server) = serve_json_once(fs::read(&witness_b).unwrap(), None);
    let substituted_witness = root.join("registry-history.checkpoint.substituted.remote.json");
    let substituted_receipt =
        root.join("registry-history.checkpoint.substituted.remote.receipt.json");
    let substituted = run(&[
        "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--endpoint",
        &endpoint,
        "--witness-key-trust-state",
        path(&witness_a_rotated_trust),
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&substituted_witness),
        "--receipt-output",
        path(&substituted_receipt),
        "--allow-http-loopback",
    ]);
    assert!(!substituted.status.success());
    assert!(String::from_utf8_lossy(&substituted.stderr).contains("identity does not match"));
    server.join().unwrap();
    assert!(!substituted_witness.exists());
    assert!(!substituted_receipt.exists());

    #[derive(Serialize)]
    struct MaliciousWitnessPayload<'a> {
        domain: &'static str,
        registry_id: &'a str,
        generation: u64,
        checkpoint_sha256: &'a str,
        witness_id: &'a str,
        witnessed_at_unix: u64,
    }
    #[derive(Serialize)]
    struct MaliciousWitness<'a> {
        schema_version: u32,
        registry_id: &'a str,
        generation: u64,
        checkpoint_sha256: &'a str,
        witness_id: &'a str,
        witnessed_at_unix: u64,
        algorithm: &'static str,
        public_key: String,
        signature: String,
    }
    let checkpoint_sha256 = hex::encode(Sha256::digest(compact_json_source(
        &fs::read(&checkpoint).unwrap(),
    )));
    let malicious_payload = MaliciousWitnessPayload {
        domain: "pcbex-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-v1",
        registry_id: "portable-history",
        generation: 5,
        checkpoint_sha256: &checkpoint_sha256,
        witness_id: "governance-reuse",
        witnessed_at_unix: 5_303,
    };
    let governance_signing_key = SigningKey::from_bytes(&[45; 32]);
    let malicious_witness = MaliciousWitness {
        schema_version: 1,
        registry_id: "portable-history",
        generation: 5,
        checkpoint_sha256: &checkpoint_sha256,
        witness_id: "governance-reuse",
        witnessed_at_unix: 5_303,
        algorithm: "ed25519",
        public_key: hex::encode(governance_signing_key.verifying_key().to_bytes()),
        signature: hex::encode(
            governance_signing_key
                .sign(&serde_json::to_vec(&malicious_payload).unwrap())
                .to_bytes(),
        ),
    };
    let malicious_witness_path = root.join("registry-history.checkpoint.malicious-witness.json");
    fs::write(
        &malicious_witness_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&malicious_witness).unwrap()
        ),
    )
    .unwrap();
    let (endpoint, server) = serve_json_once(fs::read(&malicious_witness_path).unwrap(), None);
    let reused_role_witness = root.join("registry-history.checkpoint.reused-role.remote.json");
    let reused_role_receipt =
        root.join("registry-history.checkpoint.reused-role.remote.receipt.json");
    let reused_role = run(&[
        "request-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness",
        "--history",
        path(&history),
        "--checkpoint-trust-state",
        path(&checkpoint_trust),
        "--endpoint",
        &endpoint,
        "--public-key",
        path(&governance_keys[4].1),
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&reused_role_witness),
        "--receipt-output",
        path(&reused_role_receipt),
        "--allow-http-loopback",
    ]);
    assert!(!reused_role.status.success());
    assert!(
        String::from_utf8_lossy(&reused_role.stderr)
            .contains("reuses a registry root or governance key")
    );
    server.join().unwrap();
    assert!(!reused_role_witness.exists());
    assert!(!reused_role_receipt.exists());

    let witness_quorum = root.join("registry-history.checkpoint.witness-quorum.json");
    successful(&[
        "verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness",
        path(&witness_b),
        "--witness",
        path(&witness_a),
        "--trusted-witness-id",
        "witness-b",
        "--trusted-witness-id",
        "witness-a",
        "--trusted-witness-public-key",
        path(&witness_b_public),
        "--trusted-witness-public-key",
        path(&witness_a_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--require-quorum",
        "--output",
        path(&witness_quorum),
    ]);
    let witness_quorum_value: Value =
        serde_json::from_slice(&fs::read(&witness_quorum).unwrap()).unwrap();
    assert_eq!(witness_quorum_value["valid_witnesses"], 2);
    assert_eq!(witness_quorum_value["quorum_met"], true);
    assert_eq!(
        witness_quorum_value["members"][0]["witness_id"],
        "witness-a"
    );
    let normalized_quorum = root.join("registry-history.checkpoint.witness-quorum.normalized.json");
    successful(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-quorum",
        path(&witness_quorum),
        "--output",
        path(&normalized_quorum),
    ]);
    assert_eq!(
        fs::read(&normalized_quorum).unwrap(),
        fs::read(&witness_quorum).unwrap()
    );

    let rotated_witness_quorum =
        root.join("registry-history.checkpoint.witness-quorum.rotated.json");
    successful(&[
        "verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness",
        path(&witness_b),
        "--witness",
        path(&rotated_witness_a),
        "--witness-trust-state",
        path(&witness_b_trust),
        "--witness-trust-state",
        path(&witness_a_rotated_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--require-quorum",
        "--output",
        path(&rotated_witness_quorum),
    ]);
    let rotated_witness_quorum_value: Value =
        serde_json::from_slice(&fs::read(&rotated_witness_quorum).unwrap()).unwrap();
    assert_eq!(rotated_witness_quorum_value["valid_witnesses"], 2);
    assert_eq!(rotated_witness_quorum_value["quorum_met"], true);
    assert_eq!(
        rotated_witness_quorum_value["members"][0]["public_key"],
        public([83; 32])
    );

    let stale_trust_quorum =
        root.join("registry-history.checkpoint.witness-quorum.stale-trust.json");
    let stale_trust = run(&[
        "verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness",
        path(&witness_b),
        "--witness",
        path(&rotated_witness_a),
        "--witness-trust-state",
        path(&witness_b_trust),
        "--witness-trust-state",
        path(&witness_a_initial_trust),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--output",
        path(&stale_trust_quorum),
    ]);
    assert!(!stale_trust.status.success());
    assert!(!stale_trust_quorum.exists());

    let below_quorum = root.join("registry-history.checkpoint.below-quorum.json");
    let below = run(&[
        "verify-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witnesses",
        "--history",
        path(&history),
        "--checkpoint",
        path(&checkpoint),
        "--witness",
        path(&witness_a),
        "--trusted-witness-id",
        "witness-a",
        "--trusted-witness-public-key",
        path(&witness_a_public),
        "--minimum-witnesses",
        "2",
        "--evaluated-at-unix",
        "5400",
        "--require-quorum",
        "--output",
        path(&below_quorum),
    ]);
    assert!(!below.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&below_quorum).unwrap()).unwrap()["quorum_met"],
        false
    );

    for (name, mutate) in [
        (
            "reordered",
            (|value: &mut Value| value["events"].as_array_mut().unwrap().swap(0, 1))
                as fn(&mut Value),
        ),
        (
            "omitted",
            (|value: &mut Value| {
                value["events"].as_array_mut().unwrap().remove(1);
            }) as fn(&mut Value),
        ),
        (
            "replayed",
            (|value: &mut Value| {
                let first = value["events"][0].clone();
                value["events"].as_array_mut().unwrap().insert(1, first);
            }) as fn(&mut Value),
        ),
    ] {
        let mut invalid = history_value.clone();
        mutate(&mut invalid);
        let invalid_history = root.join(format!("{name}-history.json"));
        write_canonical_json(&invalid_history, &invalid);
        let invalid_audit = root.join(format!("{name}-audit.json"));
        let invalid_final = root.join(format!("{name}-final.json"));
        let result = audit_registry_history(&invalid_history, &invalid_audit, &invalid_final);
        assert!(
            !result.status.success(),
            "{name} history unexpectedly passed"
        );
        assert!(!invalid_audit.exists());
        assert!(!invalid_final.exists());
    }

    let mut non_genesis = history_value.clone();
    let final_registry = audit_value["final_registry"].clone();
    non_genesis["initial_registry_artifact"] = exact_identity(&final_registry);
    non_genesis["initial_registry"] = final_registry;
    let non_genesis_history = root.join("non-genesis-history.json");
    write_canonical_json(&non_genesis_history, &non_genesis);
    let non_genesis_audit = root.join("non-genesis-audit.json");
    let non_genesis_final = root.join("non-genesis-final.json");
    let result =
        audit_registry_history(&non_genesis_history, &non_genesis_audit, &non_genesis_final);
    assert!(!result.status.success());
    assert!(!non_genesis_audit.exists());
    assert!(!non_genesis_final.exists());

    let signature = history_value["events"][4]["rotation"]["new_approvals"][0]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut replacement = signature.clone();
    replacement.replace_range(
        ..2,
        if signature.starts_with("00") {
            "ff"
        } else {
            "00"
        },
    );
    let rotation_source = fs::read_to_string(&governed_root_rotation).unwrap();
    let tampered_rotation_source = rotation_source.replacen(&signature, &replacement, 1);
    assert_ne!(tampered_rotation_source, rotation_source);
    let original_rotation_sha256 = hex::encode(Sha256::digest(rotation_source.as_bytes()));
    let tampered_rotation_sha256 = hex::encode(Sha256::digest(tampered_rotation_source.as_bytes()));
    let history_source = fs::read_to_string(&history).unwrap();
    let tampered_history_source = history_source
        .replacen(&signature, &replacement, 1)
        .replacen(&original_rotation_sha256, &tampered_rotation_sha256, 1);
    assert_ne!(tampered_history_source, history_source);
    let tampered_history = root.join("tampered-history.json");
    fs::write(&tampered_history, tampered_history_source).unwrap();
    let tampered_audit = root.join("tampered-audit.json");
    let tampered_final = root.join("tampered-final.json");
    let result = audit_registry_history(&tampered_history, &tampered_audit, &tampered_final);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("approval verification failed"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!tampered_audit.exists());
    assert!(!tampered_final.exists());

    let mut inconsistent_audit = audit_value;
    inconsistent_audit["entries"][4]["resulting_registry_sha256"] = Value::String("0".repeat(64));
    let inconsistent_audit_path = root.join("inconsistent-audit.json");
    write_canonical_json(&inconsistent_audit_path, &inconsistent_audit);
    let invalid_normalized = root.join("invalid-audit.normalized.json");
    let result = run(&[
        "validate-factory-release-state-transparency-external-gossip-organization-registry-history-audit",
        path(&inconsistent_audit_path),
        "--output",
        path(&invalid_normalized),
    ]);
    assert!(!result.status.success());
    assert!(!invalid_normalized.exists());

    let second_export = export_registry_history(
        &ledger,
        &ledger_id,
        &policy,
        &policy_sha256,
        &genesis,
        genesis_sha256,
        &history,
    );
    assert!(!second_export.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&history).unwrap()).unwrap()["events"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
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
        (
            "factory-release-state-transparency-external-gossip-organization-registry-history-schema",
            "history.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-history-audit-schema",
            "history-audit.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-schema",
            "history-checkpoint.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-trust-state-schema",
            "history-checkpoint-trust-state.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-schema",
            "history-checkpoint-witness.schema.json",
        ),
        (
            "remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-schema",
            "remote-history-checkpoint-witness-receipt.schema.json",
        ),
        (
            "remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-quorum-report-schema",
            "remote-history-checkpoint-witness-receipt-quorum-report.schema.json",
        ),
        (
            "signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-schema",
            "remote-history-receipt-quorum-log-checkpoint.schema.json",
        ),
        (
            "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-verification-schema",
            "remote-history-receipt-quorum-log-checkpoint-verification.schema.json",
        ),
        (
            "signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-schema",
            "remote-history-receipt-quorum-log-checkpoint-witness.schema.json",
        ),
        (
            "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-schema",
            "remote-history-receipt-quorum-log-checkpoint-witness-receipt.schema.json",
        ),
        (
            "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report-schema",
            "remote-history-receipt-quorum-log-checkpoint-witness-quorum-report.schema.json",
        ),
        (
            "remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust-state-schema",
            "remote-history-receipt-quorum-log-checkpoint-witness-trust-state.schema.json",
        ),
        (
            "signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation-schema",
            "remote-history-receipt-quorum-log-checkpoint-witness-key-rotation.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-trust-state-schema",
            "history-checkpoint-witness-trust-state.schema.json",
        ),
        (
            "signed-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-key-rotation-schema",
            "history-checkpoint-witness-key-rotation.schema.json",
        ),
        (
            "factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-quorum-schema",
            "history-checkpoint-witness-quorum.schema.json",
        ),
    ] {
        let output = root.join(filename);
        successful(&[command, "--output", path(&output)]);
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_closed_and_bounded(&schema);
    }
}
