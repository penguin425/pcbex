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

fn remote_gossip_server(observation: Value) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/gossip", listener.local_addr().unwrap());
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
        assert!(headers.starts_with("POST /v1/gossip HTTP/1.1\r\n"));
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
        assert_eq!(body["protocol"], "pcbex-approval-public-log-gossip-v1");
        assert_eq!(body["log_id"], "public-approvals");
        let response = serde_json::to_vec(&observation).unwrap();
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

    let anchor_private = directory.join("public-log.key");
    let anchor_public = directory.join("public-log.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&anchor_private),
            "--public-key",
            path(&anchor_public),
        ])
        .status
        .success()
    );
    let old_anchor = directory.join("checkpoint.old-anchor.json");
    assert!(
        run(&[
            "create-approval-log-anchor",
            path(&checkpoint),
            "--log-checkpoint",
            path(&checkpoint),
            "--leaf-index",
            "0",
            "--log-id",
            "public-approvals",
            "--private-key",
            path(&anchor_private),
            "--observed-at-unix",
            "105",
            "--output",
            path(&old_anchor),
        ])
        .status
        .success()
    );
    let anchor = directory.join("checkpoint.anchor.json");
    assert!(
        run(&[
            "create-approval-log-anchor",
            path(&checkpoint),
            "--log-checkpoint",
            path(&checkpoint),
            "--log-checkpoint",
            path(&checkpoint),
            "--log-checkpoint",
            path(&checkpoint),
            "--leaf-index",
            "1",
            "--log-id",
            "public-approvals",
            "--private-key",
            path(&anchor_private),
            "--observed-at-unix",
            "106",
            "--output",
            path(&anchor),
        ])
        .status
        .success()
    );
    let anchor_report = directory.join("checkpoint.anchor-verification.json");
    assert!(
        run(&[
            "verify-approval-log-anchor",
            path(&checkpoint),
            "--proof",
            path(&anchor),
            "--public-key",
            path(&anchor_public),
            "--output",
            path(&anchor_report),
        ])
        .status
        .success()
    );
    let anchor_report: Value = serde_json::from_slice(&fs::read(&anchor_report).unwrap()).unwrap();
    assert_eq!(anchor_report["anchored"], true);
    assert_eq!(anchor_report["tree_size"], 3);

    let consistency = directory.join("checkpoint.consistency.json");
    assert!(
        run(&[
            "create-approval-log-consistency",
            "--old-anchor",
            path(&old_anchor),
            "--new-anchor",
            path(&anchor),
            "--log-checkpoint",
            path(&checkpoint),
            "--log-checkpoint",
            path(&checkpoint),
            "--log-checkpoint",
            path(&checkpoint),
            "--output",
            path(&consistency),
        ])
        .status
        .success()
    );
    let consistency_report = directory.join("checkpoint.consistency-verification.json");
    assert!(
        run(&[
            "verify-approval-log-consistency",
            "--old-anchor",
            path(&old_anchor),
            "--new-anchor",
            path(&anchor),
            "--proof",
            path(&consistency),
            "--public-key",
            path(&anchor_public),
            "--output",
            path(&consistency_report),
        ])
        .status
        .success()
    );
    let consistency_report: Value =
        serde_json::from_slice(&fs::read(&consistency_report).unwrap()).unwrap();
    assert_eq!(consistency_report["consistent"], true);
    assert_eq!(consistency_report["old_tree_size"], 1);
    assert_eq!(consistency_report["new_tree_size"], 3);

    let mut tampered_consistency: Value =
        serde_json::from_slice(&fs::read(&consistency).unwrap()).unwrap();
    tampered_consistency["consistency_path"][0] = "0".repeat(64).into();
    let tampered_consistency_path = directory.join("checkpoint.tampered-consistency.json");
    fs::write(
        &tampered_consistency_path,
        serde_json::to_vec_pretty(&tampered_consistency).unwrap(),
    )
    .unwrap();
    let rejected_consistency = directory.join("checkpoint.rejected-consistency.json");
    assert!(
        !run(&[
            "verify-approval-log-consistency",
            "--old-anchor",
            path(&old_anchor),
            "--new-anchor",
            path(&anchor),
            "--proof",
            path(&tampered_consistency_path),
            "--public-key",
            path(&anchor_public),
            "--output",
            path(&rejected_consistency),
        ])
        .status
        .success()
    );
    assert!(!rejected_consistency.exists());

    let gossip_private = directory.join("gossip-observer.key");
    let gossip_public = directory.join("gossip-observer.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&gossip_private),
            "--public-key",
            path(&gossip_public),
        ])
        .status
        .success()
    );
    let gossip_receipt = directory.join("checkpoint.gossip.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-receipt",
            "--anchor",
            path(&anchor),
            "--log-public-key",
            path(&anchor_public),
            "--observer-id",
            "independent-observer",
            "--observer-private-key",
            path(&gossip_private),
            "--received-at-unix",
            "107",
            "--expires-at-unix",
            "200",
            "--output",
            path(&gossip_receipt),
        ])
        .status
        .success()
    );
    let gossip_report = directory.join("checkpoint.gossip-verification.json");
    assert!(
        run(&[
            "verify-approval-log-gossip-receipt",
            "--local-anchor",
            path(&old_anchor),
            "--receipt",
            path(&gossip_receipt),
            "--consistency-proof",
            path(&consistency),
            "--log-public-key",
            path(&anchor_public),
            "--observer-id",
            "independent-observer",
            "--observer-public-key",
            path(&gossip_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&gossip_report),
        ])
        .status
        .success()
    );
    let gossip_report: Value = serde_json::from_slice(&fs::read(&gossip_report).unwrap()).unwrap();
    assert_eq!(gossip_report["verified"], true);
    assert_eq!(gossip_report["split_view_detected"], false);
    assert_eq!(gossip_report["relationship"], "local_precedes_observed");

    let rejected_gossip = directory.join("checkpoint.rejected-gossip.json");
    assert!(
        !run(&[
            "verify-approval-log-gossip-receipt",
            "--local-anchor",
            path(&old_anchor),
            "--receipt",
            path(&gossip_receipt),
            "--log-public-key",
            path(&anchor_public),
            "--observer-id",
            "independent-observer",
            "--observer-public-key",
            path(&gossip_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&rejected_gossip),
        ])
        .status
        .success()
    );
    assert!(!rejected_gossip.exists());

    let gossip_private_b = directory.join("gossip-observer-b.key");
    let gossip_public_b = directory.join("gossip-observer-b.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&gossip_private_b),
            "--public-key",
            path(&gossip_public_b),
        ])
        .status
        .success()
    );
    let gossip_receipt_b = directory.join("checkpoint.gossip-b.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-receipt",
            "--anchor",
            path(&anchor),
            "--log-public-key",
            path(&anchor_public),
            "--observer-id",
            "independent-observer-b",
            "--observer-private-key",
            path(&gossip_private_b),
            "--received-at-unix",
            "108",
            "--expires-at-unix",
            "200",
            "--output",
            path(&gossip_receipt_b),
        ])
        .status
        .success()
    );
    let observation_a = directory.join("checkpoint.observation-a.json");
    let observation_b = directory.join("checkpoint.observation-b.json");
    let consistency_value: Value =
        serde_json::from_slice(&fs::read(&consistency).unwrap()).unwrap();
    for (receipt, output) in [
        (&gossip_receipt, &observation_a),
        (&gossip_receipt_b, &observation_b),
    ] {
        let receipt_value: Value = serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        fs::write(
            output,
            serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "receipt": receipt_value,
                "consistency_proof": consistency_value
            }))
            .unwrap(),
        )
        .unwrap();
    }
    let gossip_quorum = directory.join("checkpoint.gossip-quorum.json");
    assert!(
        run(&[
            "verify-approval-log-gossip-quorum",
            "--local-anchor",
            path(&old_anchor),
            "--observation",
            path(&observation_a),
            "--observation",
            path(&observation_b),
            "--organization-id",
            "independent-lab",
            "--organization-id",
            "security-partner",
            "--observer-id",
            "independent-observer",
            "--observer-id",
            "independent-observer-b",
            "--observer-public-key",
            path(&gossip_public),
            "--observer-public-key",
            path(&gossip_public_b),
            "--minimum-organizations",
            "2",
            "--log-public-key",
            path(&anchor_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&gossip_quorum),
            "--require-quorum",
        ])
        .status
        .success()
    );
    let gossip_quorum: Value = serde_json::from_slice(&fs::read(&gossip_quorum).unwrap()).unwrap();
    assert_eq!(gossip_quorum["quorum_met"], true);
    assert_eq!(gossip_quorum["distinct_organizations"], 2);
    assert_eq!(
        gossip_quorum["members"][0]["organization_id"],
        "independent-lab"
    );

    let gossip_next_private = directory.join("gossip-observer-next.key");
    let gossip_next_public = directory.join("gossip-observer-next.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&gossip_next_private),
            "--public-key",
            path(&gossip_next_public),
        ])
        .status
        .success()
    );
    let observer_trust_a = directory.join("gossip-observer-a.trust.json");
    let observer_trust_b = directory.join("gossip-observer-b.trust.json");
    for (organization, observer, public, output) in [
        (
            "independent-lab",
            "independent-observer",
            &gossip_public,
            &observer_trust_a,
        ),
        (
            "security-partner",
            "independent-observer-b",
            &gossip_public_b,
            &observer_trust_b,
        ),
    ] {
        assert!(
            run(&[
                "init-approval-log-gossip-observer-trust",
                "--organization-id",
                organization,
                "--observer-id",
                observer,
                "--public-key",
                path(public),
                "--output",
                path(output),
            ])
            .status
            .success()
        );
    }
    let observer_rotation = directory.join("gossip-observer-a.rotation.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-observer-key-rotation",
            path(&observer_trust_a),
            "--old-private-key",
            path(&gossip_private),
            "--new-private-key",
            path(&gossip_next_private),
            "--rotated-at-unix",
            "109",
            "--output",
            path(&observer_rotation),
        ])
        .status
        .success()
    );
    let observer_trust_a_rotated = directory.join("gossip-observer-a.rotated-trust.json");
    let exported_observer_key = directory.join("gossip-observer-a.rotated.pub");
    assert!(
        run(&[
            "apply-approval-log-gossip-observer-key-rotation",
            path(&observer_trust_a),
            path(&observer_rotation),
            "--output",
            path(&observer_trust_a_rotated),
            "--public-key-output",
            path(&exported_observer_key),
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(&exported_observer_key).unwrap().trim(),
        fs::read_to_string(&gossip_next_public).unwrap().trim()
    );
    let rotated_gossip_receipt = directory.join("checkpoint.rotated-gossip.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-receipt",
            "--anchor",
            path(&anchor),
            "--log-public-key",
            path(&anchor_public),
            "--observer-id",
            "independent-observer",
            "--observer-private-key",
            path(&gossip_next_private),
            "--received-at-unix",
            "110",
            "--expires-at-unix",
            "200",
            "--output",
            path(&rotated_gossip_receipt),
        ])
        .status
        .success()
    );
    let rotated_observation = directory.join("checkpoint.rotated-observation.json");
    let rotated_receipt_value: Value =
        serde_json::from_slice(&fs::read(&rotated_gossip_receipt).unwrap()).unwrap();
    fs::write(
        &rotated_observation,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "receipt": rotated_receipt_value,
            "consistency_proof": consistency_value
        }))
        .unwrap(),
    )
    .unwrap();
    let trust_bound_quorum = directory.join("checkpoint.trust-bound-gossip-quorum.json");
    assert!(
        run(&[
            "verify-approval-log-gossip-quorum",
            "--local-anchor",
            path(&old_anchor),
            "--observation",
            path(&rotated_observation),
            "--observation",
            path(&observation_b),
            "--observer-trust-state",
            path(&observer_trust_a_rotated),
            "--observer-trust-state",
            path(&observer_trust_b),
            "--minimum-organizations",
            "2",
            "--log-public-key",
            path(&anchor_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&trust_bound_quorum),
            "--require-quorum",
        ])
        .status
        .success()
    );
    let trust_bound_quorum: Value =
        serde_json::from_slice(&fs::read(&trust_bound_quorum).unwrap()).unwrap();
    assert_eq!(trust_bound_quorum["trust_bound"], true);
    assert_eq!(trust_bound_quorum["quorum"]["quorum_met"], true);
    assert_eq!(trust_bound_quorum["observer_trust"][0]["generation"], 1);

    let registry_private = directory.join("gossip-registry.key");
    let registry_public = directory.join("gossip-registry.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&registry_private),
            "--public-key",
            path(&registry_public),
        ])
        .status
        .success()
    );
    let registry_initial = directory.join("gossip-registry.initial.json");
    assert!(
        run(&[
            "init-approval-log-gossip-organization-registry",
            "--registry-id",
            "production-approvals",
            "--authority-public-key",
            path(&registry_public),
            "--output",
            path(&registry_initial),
        ])
        .status
        .success()
    );
    let registry_reason_a = "11".repeat(32);
    let registry_admission_a = directory.join("gossip-registry.admit-a.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-organization-registry-transition",
            path(&registry_initial),
            "--authority-private-key",
            path(&registry_private),
            "--action",
            "admit-observer",
            "--organization-id",
            "independent-lab",
            "--observer-trust-state",
            path(&observer_trust_a_rotated),
            "--reason-sha256",
            &registry_reason_a,
            "--effective-at-unix",
            "111",
            "--output",
            path(&registry_admission_a),
        ])
        .status
        .success()
    );
    let registry_a = directory.join("gossip-registry.a.json");
    assert!(
        run(&[
            "apply-approval-log-gossip-organization-registry-transition",
            path(&registry_initial),
            path(&registry_admission_a),
            "--output",
            path(&registry_a),
        ])
        .status
        .success()
    );
    let registry_reason_b = "22".repeat(32);
    let registry_admission_b = directory.join("gossip-registry.admit-b.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-organization-registry-transition",
            path(&registry_a),
            "--authority-private-key",
            path(&registry_private),
            "--action",
            "admit-observer",
            "--organization-id",
            "security-partner",
            "--observer-trust-state",
            path(&observer_trust_b),
            "--reason-sha256",
            &registry_reason_b,
            "--effective-at-unix",
            "112",
            "--output",
            path(&registry_admission_b),
        ])
        .status
        .success()
    );
    let registry = directory.join("gossip-registry.json");
    assert!(
        run(&[
            "apply-approval-log-gossip-organization-registry-transition",
            path(&registry_a),
            path(&registry_admission_b),
            "--output",
            path(&registry),
        ])
        .status
        .success()
    );
    let registry_bound_quorum = directory.join("checkpoint.registry-bound-gossip-quorum.json");
    assert!(
        run(&[
            "verify-approval-log-gossip-quorum",
            "--local-anchor",
            path(&old_anchor),
            "--observation",
            path(&rotated_observation),
            "--observation",
            path(&observation_b),
            "--observer-trust-state",
            path(&observer_trust_a_rotated),
            "--observer-trust-state",
            path(&observer_trust_b),
            "--organization-registry",
            path(&registry),
            "--minimum-organizations",
            "2",
            "--log-public-key",
            path(&anchor_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&registry_bound_quorum),
            "--require-quorum",
        ])
        .status
        .success()
    );
    let registry_bound_quorum: Value =
        serde_json::from_slice(&fs::read(&registry_bound_quorum).unwrap()).unwrap();
    assert_eq!(registry_bound_quorum["registry_bound"], true);
    assert_eq!(registry_bound_quorum["registry_generation"], 2);
    assert_eq!(
        registry_bound_quorum["trust_quorum"]["quorum"]["quorum_met"],
        true
    );
    assert_eq!(
        registry_bound_quorum["registry_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    let next_registry_private = directory.join("gossip-registry.next.key");
    let next_registry_public = directory.join("gossip-registry.next.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&next_registry_private),
            "--public-key",
            path(&next_registry_public),
        ])
        .status
        .success()
    );
    let registry_rotation = directory.join("gossip-registry-authority.rotation.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-organization-registry-authority-key-rotation",
            path(&registry),
            "--old-private-key",
            path(&registry_private),
            "--new-private-key",
            path(&next_registry_private),
            "--rotated-at-unix",
            "113",
            "--output",
            path(&registry_rotation),
        ])
        .status
        .success()
    );
    let rotated_registry = directory.join("gossip-registry.rotated.json");
    let exported_registry_key = directory.join("gossip-registry.rotated.pub");
    assert!(
        run(&[
            "apply-approval-log-gossip-organization-registry-authority-key-rotation",
            path(&registry),
            path(&registry_rotation),
            "--output",
            path(&rotated_registry),
            "--public-key-output",
            path(&exported_registry_key),
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(&exported_registry_key).unwrap().trim(),
        fs::read_to_string(&next_registry_public).unwrap().trim()
    );
    let rotated_registry_value: Value =
        serde_json::from_slice(&fs::read(&rotated_registry).unwrap()).unwrap();
    assert_eq!(rotated_registry_value["generation"], 3);
    assert_eq!(
        rotated_registry_value["organizations"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let governance_a_private = directory.join("gossip-governance-a.key");
    let governance_a_public = directory.join("gossip-governance-a.pub");
    let governance_b_private = directory.join("gossip-governance-b.key");
    let governance_b_public = directory.join("gossip-governance-b.pub");
    for (private, public) in [
        (&governance_a_private, &governance_a_public),
        (&governance_b_private, &governance_b_public),
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
    let registry_governance = directory.join("gossip-registry.governance.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-organization-registry-governance",
            path(&rotated_registry),
            "--registry-authority-private-key",
            path(&next_registry_private),
            "--minimum-approvals",
            "2",
            "--authority-id",
            "reviewer-a",
            "--authority-public-key",
            path(&governance_a_public),
            "--authority-id",
            "reviewer-b",
            "--authority-public-key",
            path(&governance_b_public),
            "--issued-at-unix",
            "114",
            "--output",
            path(&registry_governance),
        ])
        .status
        .success()
    );

    let suspension_reason = "33".repeat(32);
    let registry_suspension = directory.join("gossip-registry.suspend-a.json");
    assert!(
        run(&[
            "sign-approval-log-gossip-organization-registry-threshold-transition",
            path(&rotated_registry),
            path(&registry_governance),
            "--authority-id",
            "reviewer-b",
            "--authority-private-key",
            path(&governance_b_private),
            "--authority-id",
            "reviewer-a",
            "--authority-private-key",
            path(&governance_a_private),
            "--action",
            "suspend-organization",
            "--organization-id",
            "independent-lab",
            "--reason-sha256",
            &suspension_reason,
            "--effective-at-unix",
            "115",
            "--output",
            path(&registry_suspension),
        ])
        .status
        .success()
    );
    let suspended_registry = directory.join("gossip-registry.suspended.json");
    assert!(
        run(&[
            "apply-approval-log-gossip-organization-registry-threshold-transition",
            path(&rotated_registry),
            path(&registry_governance),
            path(&registry_suspension),
            "--output",
            path(&suspended_registry),
        ])
        .status
        .success()
    );
    let rejected_suspended = directory.join("checkpoint.rejected-suspended-registry-quorum.json");
    assert!(
        !run(&[
            "verify-approval-log-gossip-quorum",
            "--local-anchor",
            path(&old_anchor),
            "--observation",
            path(&rotated_observation),
            "--observation",
            path(&observation_b),
            "--observer-trust-state",
            path(&observer_trust_a_rotated),
            "--observer-trust-state",
            path(&observer_trust_b),
            "--organization-registry",
            path(&suspended_registry),
            "--minimum-organizations",
            "2",
            "--log-public-key",
            path(&anchor_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&rejected_suspended),
        ])
        .status
        .success()
    );
    assert!(!rejected_suspended.exists());

    let rejected_duplicate = directory.join("checkpoint.rejected-gossip-quorum.json");
    assert!(
        !run(&[
            "verify-approval-log-gossip-quorum",
            "--local-anchor",
            path(&old_anchor),
            "--observation",
            path(&observation_a),
            "--observation",
            path(&observation_b),
            "--organization-id",
            "independent-lab",
            "--organization-id",
            "independent-lab",
            "--observer-id",
            "independent-observer",
            "--observer-id",
            "independent-observer-b",
            "--observer-public-key",
            path(&gossip_public),
            "--observer-public-key",
            path(&gossip_public_b),
            "--log-public-key",
            path(&anchor_public),
            "--evaluated-at-unix",
            "150",
            "--output",
            path(&rejected_duplicate),
            "--require-quorum",
        ])
        .status
        .success()
    );
    assert!(!rejected_duplicate.exists());

    let observation_value: Value =
        serde_json::from_slice(&fs::read(&rotated_observation).unwrap()).unwrap();
    let (gossip_endpoint, gossip_server) = remote_gossip_server(observation_value);
    let remote_gossip = directory.join("remote-gossip-observation.json");
    let remote_gossip_receipt = directory.join("remote-gossip-receipt.json");
    let remote_gossip_result = run(&[
        "request-approval-log-gossip-observation",
        "--local-anchor",
        path(&old_anchor),
        "--endpoint",
        &gossip_endpoint,
        "--log-public-key",
        path(&anchor_public),
        "--observer-trust-state",
        path(&observer_trust_a_rotated),
        "--timeout-seconds",
        "5",
        "--evaluated-at-unix",
        "150",
        "--output",
        path(&remote_gossip),
        "--receipt-output",
        path(&remote_gossip_receipt),
        "--allow-http-loopback",
    ]);
    assert!(
        remote_gossip_result.status.success(),
        "{}",
        String::from_utf8_lossy(&remote_gossip_result.stderr)
    );
    gossip_server.join().unwrap();
    let remote_gossip_receipt: Value =
        serde_json::from_slice(&fs::read(&remote_gossip_receipt).unwrap()).unwrap();
    assert_eq!(remote_gossip_receipt["verified"], true);
    assert_eq!(remote_gossip_receipt["organization_id"], "independent-lab");
    assert_eq!(remote_gossip_receipt["observer_key_generation"], 1);
    assert_eq!(
        remote_gossip_receipt["observer_trust_state_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(remote_gossip_receipt["response_bytes"].as_u64().unwrap() > 0);
    let remote_gossip_value: Value =
        serde_json::from_slice(&fs::read(&remote_gossip).unwrap()).unwrap();
    let local_gossip_value: Value =
        serde_json::from_slice(&fs::read(&rotated_observation).unwrap()).unwrap();
    assert_eq!(remote_gossip_value, local_gossip_value);

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
