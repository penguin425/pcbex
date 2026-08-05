use pcbex_kicad::{
    AiReviewArtifactBinding, AiReviewRequest, DeterministicPipelineIdentity, ExactArtifactIdentity,
    bind_ai_review_request,
};
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
    let path = std::env::temp_dir().join(format!("pcbex-ai-approval-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn prepares_signs_verifies_and_gates_ai_schematic_approval() {
    let directory = temp_dir();
    let schematic =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approved-empty.kicad_sch");
    let policy = directory.join("policy.json");
    assert!(
        run(&["electrical-policy", "--output", path(&policy)])
            .status
            .success()
    );
    let policy_value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    let review = directory.join("electrical-review.json");
    assert!(
        run(&[
            "check-schematic",
            path(&schematic),
            "--policy",
            path(&policy),
            "--output",
            path(&review),
            "--require-approved",
        ])
        .status
        .success()
    );

    let request = directory.join("request.json");
    assert!(
        run(&[
            "prepare-ai-review",
            path(&schematic),
            "--electrical-review",
            path(&review),
            "--policy",
            path(&policy),
            "--requirement",
            "power=Power input treatment is intentional",
            "--allow-no-simulation",
            "--output",
            path(&request),
            "--session-output",
            path(&directory.join("review-session.json")),
        ])
        .status
        .success()
    );
    let request_value: Value = serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
    assert_eq!(request_value["request_sha256"].as_str().unwrap().len(), 64);

    let response = directory.join("response.json");
    let response_value = json!({
        "schema_version": 1,
        "request_sha256": request_value["request_sha256"],
        "model": {
            "provider": "test-provider",
            "model": "schematic-reviewer",
            "version": "1"
        },
        "decision": "approve",
        "summary": "The supplied requirement is supported by the bound review.",
        "requirements": [{
            "id": "power",
            "status": "pass",
            "rationale": "The deterministic review is approved.",
            "evidence_refs": ["electrical-review"]
        }],
        "risks": []
    });
    fs::write(
        &response,
        serde_json::to_vec_pretty(&response_value).unwrap(),
    )
    .unwrap();

    let private_key = directory.join("approval.key");
    let public_key = directory.join("approval.pub");
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
    assert_eq!(fs::read_to_string(&private_key).unwrap().trim().len(), 64);
    assert_eq!(fs::read_to_string(&public_key).unwrap().trim().len(), 64);
    assert!(
        !run(&[
            "approval-keygen",
            "--private-key",
            path(&private_key),
            "--public-key",
            path(&public_key),
        ])
        .status
        .success()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&private_key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let approval = directory.join("approval.json");
    assert!(
        run(&[
            "sign-ai-review",
            path(&request),
            path(&response),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "ci-production",
            "--output",
            path(&approval),
            "--require-approved",
        ])
        .status
        .success()
    );
    let approval_value: Value = serde_json::from_slice(&fs::read(&approval).unwrap()).unwrap();
    assert_eq!(approval_value["approved"], true);
    assert_eq!(approval_value["algorithm"], "ed25519");
    assert_eq!(approval_value["signature"].as_str().unwrap().len(), 128);
    assert!(
        run(&[
            "verify-ai-approval",
            path(&approval),
            path(&request),
            path(&response),
            "--public-key",
            path(&public_key),
            "--require-approved",
        ])
        .status
        .success()
    );
    let equivalent_schematic = directory.join("equivalent-live.kicad_sch");
    fs::write(
        &equivalent_schematic,
        format!("{}\n\n", fs::read_to_string(&schematic).unwrap()),
    )
    .unwrap();
    let live_approval = directory.join("live-approval.json");
    assert!(
        run(&[
            "sign-ai-review",
            path(&request),
            path(&response),
            "--schematic",
            path(&equivalent_schematic),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "ci-production",
            "--output",
            path(&live_approval),
            "--require-approved",
        ])
        .status
        .success()
    );
    let live_approval_value: Value =
        serde_json::from_slice(&fs::read(&live_approval).unwrap()).unwrap();
    assert_eq!(live_approval_value["approved"], true);
    assert!(
        run(&[
            "verify-ai-approval",
            path(&approval),
            path(&request),
            path(&response),
            "--schematic",
            path(&equivalent_schematic),
            "--public-key",
            path(&public_key),
            "--require-approved",
        ])
        .status
        .success()
    );

    let mutated_schematic = directory.join("mutated-live.kicad_sch");
    let schematic_source = fs::read_to_string(&schematic).unwrap();
    let mutated_source = schematic_source.replace(
        "00000000-0000-0000-0000-000000000100",
        "00000000-0000-0000-0000-000000000101",
    );
    assert_ne!(mutated_source, schematic_source);
    fs::write(&mutated_schematic, mutated_source).unwrap();
    let mutated_verification = run(&[
        "verify-ai-approval",
        path(&approval),
        path(&request),
        path(&response),
        "--schematic",
        path(&mutated_schematic),
        "--public-key",
        path(&public_key),
    ]);
    assert!(!mutated_verification.status.success());
    assert!(
        String::from_utf8_lossy(&mutated_verification.stderr)
            .contains("live schematic semantic document does not match")
    );

    let missing_private_key = directory.join("missing-live-private.key");
    let rejected_live_approval = directory.join("rejected-live-approval.json");
    let rejected_live_sign = run(&[
        "sign-ai-review",
        path(&request),
        path(&response),
        "--schematic",
        path(&mutated_schematic),
        "--private-key",
        path(&missing_private_key),
        "--signer-id",
        "ci-production",
        "--output",
        path(&rejected_live_approval),
    ]);
    assert!(!rejected_live_sign.status.success());
    assert!(
        String::from_utf8_lossy(&rejected_live_sign.stderr)
            .contains("live schematic semantic document does not match")
    );
    assert!(!rejected_live_approval.exists());

    let request_model: AiReviewRequest =
        serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();
    let schema_v2_request = bind_ai_review_request(
        &request_model,
        &AiReviewArtifactBinding {
            schema_version: 1,
            generated_schematic: ExactArtifactIdentity {
                bytes: 1,
                sha256: "a".repeat(64),
            },
            pipeline: DeterministicPipelineIdentity {
                plan_source: ExactArtifactIdentity {
                    bytes: 1,
                    sha256: "b".repeat(64),
                },
                plan_sha256: "c".repeat(64),
                report: ExactArtifactIdentity {
                    bytes: 1,
                    sha256: "d".repeat(64),
                },
                run_sha256: "e".repeat(64),
            },
            native_kicad_erc: None,
        },
    )
    .unwrap();
    let schema_v2_request_path = directory.join("schema-v2-request.json");
    fs::write(
        &schema_v2_request_path,
        serde_json::to_vec_pretty(&schema_v2_request).unwrap(),
    )
    .unwrap();
    let schema_v2_verification = run(&[
        "verify-ai-approval",
        path(&approval),
        path(&schema_v2_request_path),
        path(&response),
        "--schematic",
        path(&schematic),
        "--public-key",
        path(&public_key),
    ]);
    assert!(!schema_v2_verification.status.success());
    assert!(String::from_utf8_lossy(&schema_v2_verification.stderr).contains("schema version 1"));
    let schema_v2_live_approval = directory.join("schema-v2-live-approval.json");
    let schema_v2_live_sign = run(&[
        "sign-ai-review",
        path(&schema_v2_request_path),
        path(&response),
        "--schematic",
        path(&schematic),
        "--private-key",
        path(&private_key),
        "--signer-id",
        "ci-production",
        "--output",
        path(&schema_v2_live_approval),
    ]);
    assert!(!schema_v2_live_sign.status.success());
    assert!(String::from_utf8_lossy(&schema_v2_live_sign.stderr).contains("schema version 1"));
    assert!(!schema_v2_live_approval.exists());

    let conflicting_live_artifacts = run(&[
        "verify-ai-approval",
        path(&approval),
        path(&request),
        path(&response),
        "--schematic",
        path(&schematic),
        "--generated-schematic",
        path(&schematic),
        "--deterministic-pipeline-plan",
        "missing-plan.json",
        "--deterministic-pipeline-report",
        "missing-report.json",
        "--public-key",
        path(&public_key),
    ]);
    assert!(!conflicting_live_artifacts.status.success());
    assert!(
        String::from_utf8_lossy(&conflicting_live_artifacts.stderr).contains("cannot be used with")
    );
    let conflicting_live_sign = run(&[
        "sign-ai-review",
        path(&request),
        path(&response),
        "--schematic",
        path(&schematic),
        "--generated-schematic",
        path(&schematic),
        "--deterministic-pipeline-plan",
        "missing-plan.json",
        "--deterministic-pipeline-report",
        "missing-report.json",
        "--private-key",
        path(&private_key),
        "--signer-id",
        "ci-production",
        "--output",
        path(&directory.join("conflicting-live-sign.json")),
    ]);
    assert!(!conflicting_live_sign.status.success());
    assert!(String::from_utf8_lossy(&conflicting_live_sign.stderr).contains("cannot be used with"));

    let session = directory.join("review-session.json");
    let session_value: Value = serde_json::from_slice(&fs::read(&session).unwrap()).unwrap();
    assert_eq!(session_value["schema_version"], 1);
    assert!(
        session_value["expires_at_unix"].as_u64().unwrap()
            > session_value["issued_at_unix"].as_u64().unwrap()
    );
    assert_eq!(session_value["challenge"].as_str().unwrap().len(), 64);

    let session_approval = directory.join("session-approval.json");
    assert!(
        run(&[
            "sign-ai-review",
            path(&request),
            path(&response),
            "--private-key",
            path(&private_key),
            "--signer-id",
            "ci-production",
            "--session",
            path(&session),
            "--schematic",
            path(&equivalent_schematic),
            "--output",
            path(&session_approval),
            "--require-approved",
        ])
        .status
        .success()
    );
    let session_approval_value: Value =
        serde_json::from_slice(&fs::read(&session_approval).unwrap()).unwrap();
    assert_eq!(session_approval_value["schema_version"], 2);
    assert_eq!(
        session_approval_value["session_sha256"],
        session_value["session_sha256"]
    );
    assert!(
        run(&[
            "verify-ai-approval",
            path(&session_approval),
            path(&request),
            path(&response),
            "--public-key",
            path(&public_key),
            "--session",
            path(&session),
            "--require-approved",
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "verify-ai-approval",
            path(&session_approval),
            path(&request),
            path(&response),
            "--public-key",
            path(&public_key),
        ])
        .status
        .success()
    );

    let sample_pack =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/acme-policy-pack.json");
    let mut pack_value: Value = serde_json::from_slice(&fs::read(sample_pack).unwrap()).unwrap();
    pack_value["electrical_policy"] = policy_value;
    pack_value["ai_requirements"] = json!([{
        "id": "power",
        "text": "Power input treatment is intentional"
    }]);
    pack_value["require_simulation_evidence"] = false.into();
    pack_value["trusted_approval_keys"] = json!([{
        "signer_id": "ci-production",
        "public_key": fs::read_to_string(&public_key).unwrap().trim()
    }]);
    let policy_pack = directory.join("organization-policy-pack.json");
    fs::write(
        &policy_pack,
        serde_json::to_vec_pretty(&pack_value).unwrap(),
    )
    .unwrap();
    assert!(
        run(&["validate-policy-pack", path(&policy_pack)])
            .status
            .success()
    );
    assert!(
        run(&[
            "verify-ai-approval",
            path(&approval),
            path(&request),
            path(&response),
            "--policy-pack",
            path(&policy_pack),
            "--require-approved",
        ])
        .status
        .success()
    );
    let mismatched_policy_pack = directory.join("mismatched-organization-policy-pack.json");
    let mut mismatched_pack_value = pack_value.clone();
    mismatched_pack_value["require_simulation_evidence"] = true.into();
    fs::write(
        &mismatched_policy_pack,
        serde_json::to_vec_pretty(&mismatched_pack_value).unwrap(),
    )
    .unwrap();
    assert!(
        !run(&[
            "verify-ai-approval",
            path(&approval),
            path(&request),
            path(&response),
            "--policy-pack",
            path(&mismatched_policy_pack),
        ])
        .status
        .success()
    );
    let packed_review = directory.join("packed-electrical-review.json");
    assert!(
        run(&[
            "check-schematic",
            path(&schematic),
            "--policy-pack",
            path(&policy_pack),
            "--output",
            path(&packed_review),
            "--require-approved",
        ])
        .status
        .success()
    );
    let packed_request = directory.join("packed-request.json");
    assert!(
        run(&[
            "prepare-ai-review",
            path(&schematic),
            "--electrical-review",
            path(&packed_review),
            "--policy-pack",
            path(&policy_pack),
            "--output",
            path(&packed_request),
        ])
        .status
        .success()
    );
    let packed_request_value: Value =
        serde_json::from_slice(&fs::read(packed_request).unwrap()).unwrap();
    assert_eq!(packed_request_value["requirements"][0]["id"], "power");
    assert_eq!(
        packed_request_value["approval_policy"]["require_simulation_evidence"],
        false
    );

    let mut tampered = response_value;
    tampered["summary"] = json!("tampered");
    fs::write(&response, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    assert!(
        !run(&[
            "verify-ai-approval",
            path(&approval),
            path(&request),
            path(&response),
            "--public-key",
            path(&public_key),
        ])
        .status
        .success()
    );

    for (command, filename) in [
        ("ai-review-request-schema", "request.schema.json"),
        ("ai-review-response-schema", "response.schema.json"),
        ("signed-ai-approval-schema", "approval.schema.json"),
    ] {
        let output = directory.join(filename);
        assert!(run(&[command, "--output", path(&output)]).status.success());
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }

    fs::remove_dir_all(directory).unwrap();
}
