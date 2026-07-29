use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary()).args(arguments).output().unwrap()
}

fn run_with_env(arguments: &[&str], name: &str, value: &str) -> Output {
    Command::new(binary())
        .args(arguments)
        .env(name, value)
        .output()
        .unwrap()
}

fn serve_policy(
    body: Vec<u8>,
    expected_authorization: Option<&str>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/current", listener.local_addr().unwrap());
    let authorization = expected_authorization.map(str::to_string);
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
        }
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /v1/current HTTP/1.1\r\n"));
        assert!(request.contains("\r\naccept: application/json\r\n"));
        if let Some(authorization) = authorization {
            assert!(request.contains(&format!("\r\nauthorization: {authorization}\r\n")));
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
    });
    (endpoint, handle)
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-signed-policy-pack-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn signs_verifies_extracts_and_rejects_policy_pack_tampering() {
    let directory = temp_dir();
    let pack =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/acme-policy-pack.json");
    let private_key = directory.join("policy.key");
    let public_key = directory.join("policy.pub");
    assert!(
        run(&[
            "policy-keygen",
            "--private-key",
            path(&private_key),
            "--public-key",
            path(&public_key),
        ])
        .status
        .success()
    );

    let signed = directory.join("signed-policy-pack.json");
    assert!(
        run(&[
            "sign-policy-pack",
            path(&pack),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "hardware-security",
            "--output",
            path(&signed),
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "sign-policy-pack",
            path(&pack),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "hardware-security",
            "--output",
            path(&signed),
        ])
        .status
        .success()
    );

    let extracted = directory.join("verified-policy-pack.json");
    let trust_state = directory.join("policy-trust-state.json");
    assert!(
        run(&[
            "verify-policy-pack",
            path(&signed),
            "--public-key",
            path(&public_key),
            "--output",
            path(&extracted),
            "--state-output",
            path(&trust_state),
        ])
        .status
        .success()
    );
    let original: Value = serde_json::from_slice(&fs::read(&pack).unwrap()).unwrap();
    let verified: Value = serde_json::from_slice(&fs::read(&extracted).unwrap()).unwrap();
    assert_eq!(verified, original);
    let state: Value = serde_json::from_slice(&fs::read(&trust_state).unwrap()).unwrap();
    assert_eq!(state["accepted_revision"], 1);

    let mut newer_pack = original.clone();
    newer_pack["revision"] = 2.into();
    newer_pack["description"] = "Second accepted policy revision".into();
    let newer_pack_path = directory.join("policy-pack-v2.json");
    fs::write(
        &newer_pack_path,
        serde_json::to_vec_pretty(&newer_pack).unwrap(),
    )
    .unwrap();
    let newer_signed = directory.join("signed-policy-pack-v2.json");
    assert!(
        run(&[
            "sign-policy-pack",
            path(&newer_pack_path),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "hardware-security",
            "--output",
            path(&newer_signed),
        ])
        .status
        .success()
    );
    let newer_extracted = directory.join("verified-policy-pack-v2.json");
    let newer_state = directory.join("policy-trust-state-v2.json");
    assert!(
        run(&[
            "verify-policy-pack",
            path(&newer_signed),
            "--public-key",
            path(&public_key),
            "--baseline-state",
            path(&trust_state),
            "--output",
            path(&newer_extracted),
            "--state-output",
            path(&newer_state),
        ])
        .status
        .success()
    );
    let state: Value = serde_json::from_slice(&fs::read(&newer_state).unwrap()).unwrap();
    assert_eq!(state["accepted_revision"], 2);

    let (endpoint, server) = serve_policy(
        fs::read(&newer_signed).unwrap(),
        Some("Bearer registry-secret"),
    );
    let fetched_signed = directory.join("fetched-signed-policy-pack.json");
    let fetched_pack = directory.join("fetched-policy-pack.json");
    let fetched_state = directory.join("fetched-policy-trust-state.json");
    let fetched_receipt = directory.join("fetched-policy-receipt.json");
    let fetched = run_with_env(
        &[
            "fetch-policy-pack",
            "--endpoint",
            &endpoint,
            "--public-key",
            path(&public_key),
            "--baseline-state",
            path(&trust_state),
            "--bearer-token-env",
            "PCBEX_TEST_POLICY_TOKEN",
            "--signed-output",
            path(&fetched_signed),
            "--output",
            path(&fetched_pack),
            "--state-output",
            path(&fetched_state),
            "--receipt-output",
            path(&fetched_receipt),
            "--allow-http-loopback",
        ],
        "PCBEX_TEST_POLICY_TOKEN",
        "registry-secret",
    );
    server.join().unwrap();
    assert!(fetched.status.success(), "{fetched:?}");
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&fetched_pack).unwrap()).unwrap(),
        serde_json::from_slice::<Value>(&fs::read(&newer_pack_path).unwrap()).unwrap()
    );
    let receipt: Value = serde_json::from_slice(&fs::read(&fetched_receipt).unwrap()).unwrap();
    assert_eq!(receipt["verified"], true);
    assert_eq!(receipt["policy_pack_revision"], 2);
    assert_eq!(receipt["baseline_revision"], 1);

    let (rollback_endpoint, rollback_server) = serve_policy(fs::read(&signed).unwrap(), None);
    let rollback_signed = directory.join("rollback-signed.json");
    let rollback_pack = directory.join("rollback-pack.json");
    let rollback_state = directory.join("rollback-state.json");
    let rollback_receipt = directory.join("rollback-receipt.json");
    let rollback = run(&[
        "fetch-policy-pack",
        "--endpoint",
        &rollback_endpoint,
        "--public-key",
        path(&public_key),
        "--baseline-state",
        path(&newer_state),
        "--signed-output",
        path(&rollback_signed),
        "--output",
        path(&rollback_pack),
        "--state-output",
        path(&rollback_state),
        "--receipt-output",
        path(&rollback_receipt),
        "--allow-http-loopback",
    ]);
    rollback_server.join().unwrap();
    assert!(!rollback.status.success());
    for output in [
        rollback_signed,
        rollback_pack,
        rollback_state,
        rollback_receipt,
    ] {
        assert!(!output.exists());
    }

    assert!(
        !run(&[
            "verify-policy-pack",
            path(&signed),
            "--public-key",
            path(&public_key),
            "--baseline-state",
            path(&newer_state),
        ])
        .status
        .success()
    );

    let mut equivocated_pack = newer_pack;
    equivocated_pack["description"] = "Conflicting content at revision two".into();
    let equivocated_pack_path = directory.join("equivocated-policy-pack-v2.json");
    fs::write(
        &equivocated_pack_path,
        serde_json::to_vec_pretty(&equivocated_pack).unwrap(),
    )
    .unwrap();
    let equivocated_signed = directory.join("equivocated-signed-policy-pack-v2.json");
    assert!(
        run(&[
            "sign-policy-pack",
            path(&equivocated_pack_path),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "hardware-security",
            "--output",
            path(&equivocated_signed),
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "verify-policy-pack",
            path(&equivocated_signed),
            "--public-key",
            path(&public_key),
            "--baseline-state",
            path(&newer_state),
        ])
        .status
        .success()
    );

    let wrong_public_key = directory.join("wrong.pub");
    let wrong_private_key = directory.join("wrong.key");
    assert!(
        run(&[
            "policy-keygen",
            "--private-key",
            path(&wrong_private_key),
            "--public-key",
            path(&wrong_public_key),
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "verify-policy-pack",
            path(&signed),
            "--public-key",
            path(&wrong_public_key),
        ])
        .status
        .success()
    );

    let mut tampered: Value = serde_json::from_slice(&fs::read(&signed).unwrap()).unwrap();
    tampered["policy_pack"]["revision"] = 2.into();
    let tampered_path = directory.join("tampered-policy-pack.json");
    fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&tampered).unwrap(),
    )
    .unwrap();
    assert!(
        !run(&[
            "verify-policy-pack",
            path(&tampered_path),
            "--public-key",
            path(&public_key),
        ])
        .status
        .success()
    );

    let schema = run(&["signed-policy-pack-schema"]);
    assert!(schema.status.success());
    let schema: Value = serde_json::from_slice(&schema.stdout).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    let state_schema = run(&["policy-trust-state-schema"]);
    assert!(state_schema.status.success());
    let state_schema: Value = serde_json::from_slice(&state_schema.stdout).unwrap();
    assert_eq!(state_schema["additionalProperties"], false);
    let receipt_schema = run(&["remote-policy-pack-receipt-schema"]);
    assert!(receipt_schema.status.success());
    let receipt_schema: Value = serde_json::from_slice(&receipt_schema.stdout).unwrap();
    assert_eq!(receipt_schema["additionalProperties"], false);
}
