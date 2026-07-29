use pcbex_kicad::{SignedApprovalLogCheckpoint, approval_public_key, sign_approval_log_witness};
use serde_json::{Value, json};
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

fn remote_witness_server(
    checkpoint: SignedApprovalLogCheckpoint,
    secret: [u8; 32],
    expected_bearer: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/witness", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
            if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        assert!(headers.starts_with("POST /v1/witness HTTP/1.1\r\n"));
        if let Some(token) = expected_bearer {
            assert!(headers.to_ascii_lowercase().contains(&format!(
                "authorization: bearer {}\r\n",
                token.to_ascii_lowercase()
            )));
        }
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|value| value.parse::<usize>().unwrap())
            })
            .unwrap();
        while request.len() - header_end < content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
        }
        let body: Value =
            serde_json::from_slice(&request[header_end..header_end + content_length]).unwrap();
        assert_eq!(body["protocol"], "pcbex-approval-log-witness-v1");
        assert_eq!(body["checkpoint"]["log_id"], checkpoint.log_id);
        let witness =
            sign_approval_log_witness(&checkpoint, "remote-witness-a", 104, &secret).unwrap();
        let response = serde_json::to_vec(&witness).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .unwrap();
        stream.write_all(&response).unwrap();
    });
    (endpoint, handle)
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

    let witness_a_key = directory.join("witness-a.key");
    let witness_a_public = directory.join("witness-a.pub");
    let witness_b_key = directory.join("witness-b.key");
    let witness_b_public = directory.join("witness-b.pub");
    for (private, public) in [
        (&witness_a_key, &witness_a_public),
        (&witness_b_key, &witness_b_public),
    ] {
        assert!(
            run(&[
                "approval-keygen",
                "--private-key",
                path(private),
                "--public-key",
                path(public),
            ])
            .status
            .success()
        );
    }
    let witness_a = directory.join("witness-a.json");
    let witness_b = directory.join("witness-b.json");
    for (id, private, output, observed_at) in [
        ("witness-a", &witness_a_key, &witness_a, "102"),
        ("witness-b", &witness_b_key, &witness_b, "103"),
    ] {
        assert!(
            run(&[
                "witness-approval-log",
                path(&checkpoint),
                "--private-key",
                path(private),
                "--witness-id",
                id,
                "--observed-at-unix",
                observed_at,
                "--output",
                path(output),
            ])
            .status
            .success()
        );
    }
    let witness_report = directory.join("witness-quorum.json");
    assert!(
        run(&[
            "verify-approval-log-witnesses",
            path(&checkpoint),
            "--witness",
            path(&witness_a),
            "--witness",
            path(&witness_b),
            "--public-key",
            path(&witness_a_public),
            "--public-key",
            path(&witness_b_public),
            "--minimum-witnesses",
            "2",
            "--output",
            path(&witness_report),
            "--require-quorum",
        ])
        .status
        .success()
    );
    let witness_report: Value =
        serde_json::from_slice(&fs::read(&witness_report).unwrap()).unwrap();
    assert_eq!(witness_report["quorum_met"], true);
    assert_eq!(witness_report["valid_witnesses"], 2);

    let witness_a_next_key = directory.join("witness-a-next.key");
    let witness_a_next_public = directory.join("witness-a-next.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&witness_a_next_key),
            "--public-key",
            path(&witness_a_next_public),
        ])
        .status
        .success()
    );
    let witness_trust = directory.join("witness-a.trust.json");
    assert!(
        run(&[
            "init-approval-log-witness-trust",
            "--witness-id",
            "witness-a",
            "--public-key",
            path(&witness_a_public),
            "--output",
            path(&witness_trust),
        ])
        .status
        .success()
    );
    let rotation = directory.join("witness-a.rotation.json");
    assert!(
        run(&[
            "sign-approval-log-witness-key-rotation",
            path(&witness_trust),
            "--old-private-key",
            path(&witness_a_key),
            "--new-private-key",
            path(&witness_a_next_key),
            "--rotated-at-unix",
            "104",
            "--output",
            path(&rotation),
        ])
        .status
        .success()
    );
    let rotated_trust = directory.join("witness-a.rotated-trust.json");
    let exported_public = directory.join("witness-a.rotated.pub");
    assert!(
        run(&[
            "apply-approval-log-witness-key-rotation",
            path(&witness_trust),
            path(&rotation),
            "--output",
            path(&rotated_trust),
            "--public-key-output",
            path(&exported_public),
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(&exported_public).unwrap(),
        fs::read_to_string(&witness_a_next_public).unwrap()
    );
    let validated_public = directory.join("witness-a.validated.pub");
    assert!(
        run(&[
            "export-approval-log-witness-public-key",
            path(&rotated_trust),
            "--output",
            path(&validated_public),
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(&validated_public).unwrap(),
        fs::read_to_string(&witness_a_next_public).unwrap()
    );
    let rotated_trust_value: Value =
        serde_json::from_slice(&fs::read(&rotated_trust).unwrap()).unwrap();
    assert_eq!(rotated_trust_value["generation"], 1);
    assert!(
        rotated_trust_value["last_rotation_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64)
    );
    let rotated_witness_a = directory.join("witness-a.rotated.json");
    assert!(
        run(&[
            "witness-approval-log",
            path(&checkpoint),
            "--private-key",
            path(&witness_a_next_key),
            "--witness-id",
            "witness-a",
            "--observed-at-unix",
            "105",
            "--output",
            path(&rotated_witness_a),
        ])
        .status
        .success()
    );
    let rotated_quorum = directory.join("witness-rotated-quorum.json");
    assert!(
        run(&[
            "verify-approval-log-witnesses",
            path(&checkpoint),
            "--witness",
            path(&rotated_witness_a),
            "--witness",
            path(&witness_b),
            "--public-key",
            path(&validated_public),
            "--public-key",
            path(&witness_b_public),
            "--minimum-witnesses",
            "2",
            "--output",
            path(&rotated_quorum),
            "--require-quorum",
        ])
        .status
        .success()
    );
    let replayed_trust = directory.join("witness-a.replayed-trust.json");
    let replayed_public = directory.join("witness-a.replayed.pub");
    assert!(
        !run(&[
            "apply-approval-log-witness-key-rotation",
            path(&rotated_trust),
            path(&rotation),
            "--output",
            path(&replayed_trust),
            "--public-key-output",
            path(&replayed_public),
        ])
        .status
        .success()
    );
    assert!(!replayed_trust.exists());
    assert!(!replayed_public.exists());

    let checkpoint_value: SignedApprovalLogCheckpoint =
        serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    let remote_secret = [42_u8; 32];
    let remote_public = directory.join("remote-witness.pub");
    fs::write(&remote_public, approval_public_key(&remote_secret)).unwrap();
    let (endpoint, server) =
        remote_witness_server(checkpoint_value, remote_secret, Some("integration-secret"));
    let remote_witness = directory.join("remote-witness.json");
    let remote_receipt = directory.join("remote-witness-receipt.json");
    let remote = Command::new(binary())
        .args([
            "request-approval-log-witness",
            path(&checkpoint),
            "--endpoint",
            &endpoint,
            "--public-key",
            path(&remote_public),
            "--bearer-token-env",
            "PCBEX_TEST_REMOTE_WITNESS_TOKEN",
            "--timeout-seconds",
            "5",
            "--output",
            path(&remote_witness),
            "--receipt-output",
            path(&remote_receipt),
            "--allow-http-loopback",
        ])
        .env("PCBEX_TEST_REMOTE_WITNESS_TOKEN", "integration-secret")
        .output()
        .unwrap();
    assert!(
        remote.status.success(),
        "{}",
        String::from_utf8_lossy(&remote.stderr)
    );
    server.join().unwrap();
    let remote_receipt: Value =
        serde_json::from_slice(&fs::read(&remote_receipt).unwrap()).unwrap();
    assert_eq!(remote_receipt["verified"], true);
    assert_eq!(remote_receipt["witness_id"], "remote-witness-a");
    assert!(remote_receipt["response_bytes"].as_u64().unwrap() > 0);

    let mismatched_checkpoint: SignedApprovalLogCheckpoint =
        serde_json::from_slice(&fs::read(&checkpoint).unwrap()).unwrap();
    let (mismatched_endpoint, mismatched_server) =
        remote_witness_server(mismatched_checkpoint, remote_secret, None);
    let mismatched_witness = directory.join("mismatched-remote.json");
    let mismatched_receipt = directory.join("mismatched-remote-receipt.json");
    assert!(
        !run(&[
            "request-approval-log-witness",
            path(&checkpoint),
            "--endpoint",
            &mismatched_endpoint,
            "--public-key",
            path(&witness_a_public),
            "--output",
            path(&mismatched_witness),
            "--receipt-output",
            path(&mismatched_receipt),
            "--allow-http-loopback",
        ])
        .status
        .success()
    );
    mismatched_server.join().unwrap();
    assert!(!mismatched_witness.exists());
    assert!(!mismatched_receipt.exists());

    let rejected_remote = directory.join("rejected-remote.json");
    let rejected_receipt = directory.join("rejected-remote-receipt.json");
    assert!(
        !run(&[
            "request-approval-log-witness",
            path(&checkpoint),
            "--endpoint",
            "http://example.com/v1/witness",
            "--public-key",
            path(&remote_public),
            "--output",
            path(&rejected_remote),
            "--receipt-output",
            path(&rejected_receipt),
        ])
        .status
        .success()
    );
    assert!(!rejected_remote.exists());
    assert!(!rejected_receipt.exists());

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
