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
    let path = std::env::temp_dir().join(format!("pcbex-lifecycle-anchor-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn json_server_once(response: Vec<u8>) -> (String, thread::JoinHandle<()>) {
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
        let request_json: Value =
            serde_json::from_slice(&request[header_end..header_end + content_length]).unwrap();
        assert_eq!(
            request_json["protocol"],
            "pcbex-policy-lifecycle-public-log-gossip-v1"
        );
        assert_eq!(request_json["log_id"], "lifecycle-public-log");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        );
        stream.write_all(header.as_bytes()).unwrap();
        stream.write_all(&response).unwrap();
    });
    (endpoint, handle)
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

    let observer_private = directory.join("gossip-observer.key");
    let observer_public = directory.join("gossip-observer.pub");
    let observer_keygen = run(&[
        "approval-keygen",
        "--private-key",
        path(&observer_private),
        "--public-key",
        path(&observer_public),
    ]);
    assert!(
        observer_keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&observer_keygen.stderr)
    );
    let gossip_receipt = directory.join("gossip-receipt.json");
    let sign_gossip = run(&[
        "sign-policy-lifecycle-log-gossip-receipt",
        "--anchor",
        path(&previous_proof),
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--observer-id",
        "independent-ci",
        "--private-key",
        path(&observer_private),
        "--received-at-unix",
        "160",
        "--expires-at-unix",
        "300",
        "--output",
        path(&gossip_receipt),
    ]);
    assert!(
        sign_gossip.status.success(),
        "{}",
        String::from_utf8_lossy(&sign_gossip.stderr)
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-receipt",
            path(&gossip_receipt)
        ])
        .status
        .success()
    );
    let gossip_report = directory.join("gossip-verification.json");
    let verify_gossip = run(&[
        "verify-policy-lifecycle-log-gossip-receipt",
        "--local-anchor",
        path(&proof),
        "--receipt",
        path(&gossip_receipt),
        "--consistency-proof",
        path(&consistency),
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--observer-id",
        "independent-ci",
        "--observer-public-key",
        path(&observer_public),
        "--evaluated-at-unix",
        "200",
        "--output",
        path(&gossip_report),
    ]);
    assert!(
        verify_gossip.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_gossip.stderr)
    );
    let gossip_report: Value = serde_json::from_slice(&fs::read(&gossip_report).unwrap()).unwrap();
    assert_eq!(gossip_report["verified"], true);
    assert_eq!(gossip_report["split_view_detected"], false);
    assert_eq!(gossip_report["relationship"], "observed_precedes_local");
    assert_eq!(gossip_report["observer_id"], "independent-ci");

    let observer_b_private = directory.join("gossip-observer-b.key");
    let observer_b_public = directory.join("gossip-observer-b.pub");
    assert!(
        run(&[
            "approval-keygen",
            "--private-key",
            path(&observer_b_private),
            "--public-key",
            path(&observer_b_public),
        ])
        .status
        .success()
    );
    let gossip_receipt_b = directory.join("gossip-receipt-b.json");
    let sign_gossip_b = run(&[
        "sign-policy-lifecycle-log-gossip-receipt",
        "--anchor",
        path(&proof),
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--observer-id",
        "independent-security",
        "--private-key",
        path(&observer_b_private),
        "--received-at-unix",
        "210",
        "--expires-at-unix",
        "350",
        "--output",
        path(&gossip_receipt_b),
    ]);
    assert!(
        sign_gossip_b.status.success(),
        "{}",
        String::from_utf8_lossy(&sign_gossip_b.stderr)
    );
    let observation_a = directory.join("gossip-observation-a.json");
    let observation_b = directory.join("gossip-observation-b.json");
    fs::write(
        &observation_a,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "receipt": serde_json::from_slice::<Value>(&fs::read(&gossip_receipt).unwrap()).unwrap(),
            "consistency_proof": serde_json::from_slice::<Value>(&fs::read(&consistency).unwrap()).unwrap()
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        &observation_b,
        serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "receipt": serde_json::from_slice::<Value>(&fs::read(&gossip_receipt_b).unwrap()).unwrap(),
            "consistency_proof": null
        }))
        .unwrap(),
    )
    .unwrap();
    for observation in [&observation_a, &observation_b] {
        assert!(
            run(&[
                "validate-policy-lifecycle-log-gossip-observation",
                path(observation)
            ])
            .status
            .success()
        );
    }
    let (endpoint, server) = json_server_once(fs::read(&observation_b).unwrap());
    let remote_observation = directory.join("gossip-observation-remote.json");
    let remote_receipt = directory.join("gossip-transport-receipt.json");
    let remote = run(&[
        "request-policy-lifecycle-log-gossip-observation",
        "--local-anchor",
        path(&proof),
        "--endpoint",
        &endpoint,
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--organization-id",
        "security-partner",
        "--observer-id",
        "independent-security",
        "--observer-public-key",
        path(&observer_b_public),
        "--timeout-seconds",
        "5",
        "--evaluated-at-unix",
        "220",
        "--output",
        path(&remote_observation),
        "--receipt-output",
        path(&remote_receipt),
        "--allow-http-loopback",
    ]);
    server.join().unwrap();
    assert!(
        remote.status.success(),
        "{}",
        String::from_utf8_lossy(&remote.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&remote_observation).unwrap()).unwrap(),
        serde_json::from_slice::<Value>(&fs::read(&observation_b).unwrap()).unwrap()
    );
    let transport: Value = serde_json::from_slice(&fs::read(&remote_receipt).unwrap()).unwrap();
    assert_eq!(transport["verified"], true);
    assert_eq!(transport["organization_id"], "security-partner");
    assert_eq!(transport["observer_id"], "independent-security");
    assert_eq!(
        transport["adapter"],
        "remote-policy-lifecycle-public-log-gossip-https-v1"
    );

    let gossip_quorum = directory.join("gossip-quorum.json");
    let verify_quorum = run(&[
        "verify-policy-lifecycle-log-gossip-quorum",
        "--local-anchor",
        path(&proof),
        "--observation",
        path(&observation_a),
        "--observation",
        path(&observation_b),
        "--organization-id",
        "independent-lab",
        "--organization-id",
        "security-partner",
        "--observer-id",
        "independent-ci",
        "--observer-id",
        "independent-security",
        "--observer-public-key",
        path(&observer_public),
        "--observer-public-key",
        path(&observer_b_public),
        "--minimum-organizations",
        "2",
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--evaluated-at-unix",
        "220",
        "--output",
        path(&gossip_quorum),
        "--require-quorum",
    ]);
    assert!(
        verify_quorum.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_quorum.stderr)
    );
    let quorum: Value = serde_json::from_slice(&fs::read(&gossip_quorum).unwrap()).unwrap();
    assert_eq!(quorum["quorum_met"], true);
    assert_eq!(quorum["distinct_organizations"], 2);
    assert_eq!(quorum["all_consistent"], true);
    assert_eq!(quorum["members"][0]["organization_id"], "independent-lab");
    assert_eq!(
        quorum["members"][0]["relationship"],
        "observed_precedes_local"
    );
    assert_eq!(quorum["members"][1]["organization_id"], "security-partner");
    assert_eq!(quorum["members"][1]["relationship"], "same_tree");
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-quorum",
            path(&gossip_quorum)
        ])
        .status
        .success()
    );
    let observer_a_trust = directory.join("observer-a.trust.json");
    let observer_b_trust = directory.join("observer-b.trust.json");
    for (organization, observer, public_key, trust_state) in [
        (
            "independent-lab",
            "independent-ci",
            &observer_public,
            &observer_a_trust,
        ),
        (
            "security-partner",
            "independent-security",
            &observer_b_public,
            &observer_b_trust,
        ),
    ] {
        assert!(
            run(&[
                "init-policy-lifecycle-log-gossip-observer-trust",
                "--organization-id",
                organization,
                "--observer-id",
                observer,
                "--public-key",
                path(public_key),
                "--output",
                path(trust_state),
            ])
            .status
            .success()
        );
    }
    let (trust_endpoint, trust_server) = json_server_once(fs::read(&observation_b).unwrap());
    let trust_remote_observation = directory.join("gossip-observation-trust-remote.json");
    let trust_remote_receipt = directory.join("gossip-transport-trust-receipt.json");
    let trust_remote = run(&[
        "request-policy-lifecycle-log-gossip-observation",
        "--local-anchor",
        path(&proof),
        "--endpoint",
        &trust_endpoint,
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--observer-trust-state",
        path(&observer_b_trust),
        "--timeout-seconds",
        "5",
        "--evaluated-at-unix",
        "220",
        "--output",
        path(&trust_remote_observation),
        "--receipt-output",
        path(&trust_remote_receipt),
        "--allow-http-loopback",
    ]);
    trust_server.join().unwrap();
    assert!(
        trust_remote.status.success(),
        "{}",
        String::from_utf8_lossy(&trust_remote.stderr)
    );
    let trust_transport: Value =
        serde_json::from_slice(&fs::read(&trust_remote_receipt).unwrap()).unwrap();
    assert_eq!(trust_transport["observer_key_generation"], 0);
    assert_eq!(
        trust_transport["observer_trust_state_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );

    let trust_bound_quorum = directory.join("gossip-quorum.trust-bound.json");
    let verify_trust_bound = run(&[
        "verify-policy-lifecycle-log-gossip-quorum",
        "--local-anchor",
        path(&proof),
        "--observation",
        path(&observation_a),
        "--observation",
        path(&observation_b),
        "--observer-trust-state",
        path(&observer_a_trust),
        "--observer-trust-state",
        path(&observer_b_trust),
        "--minimum-organizations",
        "2",
        "--log-id",
        "lifecycle-public-log",
        "--log-public-key",
        path(&public_key),
        "--evaluated-at-unix",
        "220",
        "--output",
        path(&trust_bound_quorum),
        "--require-quorum",
    ]);
    assert!(
        verify_trust_bound.status.success(),
        "{}",
        String::from_utf8_lossy(&verify_trust_bound.stderr)
    );
    let trust_bound: Value =
        serde_json::from_slice(&fs::read(&trust_bound_quorum).unwrap()).unwrap();
    assert_eq!(trust_bound["trust_bound"], true);
    assert_eq!(trust_bound["quorum"]["quorum_met"], true);
    assert_eq!(
        trust_bound["observer_trust"][0]["organization_id"],
        "independent-lab"
    );
    assert_eq!(trust_bound["observer_trust"][0]["generation"], 0);
    assert_eq!(
        trust_bound["observer_trust"][0]["trust_state_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-trust-bound-quorum",
            path(&trust_bound_quorum)
        ])
        .status
        .success()
    );
    let duplicate_quorum = directory.join("gossip-quorum-duplicate.json");
    assert!(
        !run(&[
            "verify-policy-lifecycle-log-gossip-quorum",
            "--local-anchor",
            path(&proof),
            "--observation",
            path(&observation_a),
            "--observation",
            path(&observation_b),
            "--organization-id",
            "same-organization",
            "--organization-id",
            "same-organization",
            "--observer-id",
            "independent-ci",
            "--observer-id",
            "independent-security",
            "--observer-public-key",
            path(&observer_public),
            "--observer-public-key",
            path(&observer_b_public),
            "--log-id",
            "lifecycle-public-log",
            "--log-public-key",
            path(&public_key),
            "--evaluated-at-unix",
            "220",
            "--output",
            path(&duplicate_quorum),
        ])
        .status
        .success()
    );
    assert!(!duplicate_quorum.exists());

    let expired_report = directory.join("gossip-expired.json");
    assert!(
        !run(&[
            "verify-policy-lifecycle-log-gossip-receipt",
            "--local-anchor",
            path(&proof),
            "--receipt",
            path(&gossip_receipt),
            "--consistency-proof",
            path(&consistency),
            "--log-id",
            "lifecycle-public-log",
            "--log-public-key",
            path(&public_key),
            "--observer-id",
            "independent-ci",
            "--observer-public-key",
            path(&observer_public),
            "--evaluated-at-unix",
            "301",
            "--output",
            path(&expired_report),
        ])
        .status
        .success()
    );
    assert!(!expired_report.exists());

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
