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
    let path = std::env::temp_dir().join(format!("pcbex-ai-quorum-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn verifies_gates_and_retains_multi_reviewer_quorum_evidence() {
    let directory = temp_dir();
    let schematic =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let sample_pack =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/acme-policy-pack.json");

    let private_a = directory.join("reviewer-a.key");
    let public_a = directory.join("reviewer-a.pub");
    let private_b = directory.join("reviewer-b.key");
    let public_b = directory.join("reviewer-b.pub");
    for (private, public) in [(&private_a, &public_a), (&private_b, &public_b)] {
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

    let electrical_policy = directory.join("electrical-policy.json");
    assert!(
        run(&["electrical-policy", "--output", path(&electrical_policy)])
            .status
            .success()
    );
    let mut electrical_policy_value: Value =
        serde_json::from_slice(&fs::read(&electrical_policy).unwrap()).unwrap();
    for setting in electrical_policy_value["rules"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        if setting["severity"] == "error" {
            setting["enabled"] = false.into();
        }
    }

    let mut pack: Value = serde_json::from_slice(&fs::read(sample_pack).unwrap()).unwrap();
    pack["electrical_policy"] = electrical_policy_value;
    pack["require_simulation_evidence"] = false.into();
    pack["ai_requirements"] = json!([{
        "id": "power",
        "text": "Power input treatment is intentional"
    }]);
    pack["trusted_approval_keys"] = json!([
        {
            "signer_id": "reviewer-a",
            "public_key": fs::read_to_string(&public_a).unwrap().trim()
        },
        {
            "signer_id": "reviewer-b",
            "public_key": fs::read_to_string(&public_b).unwrap().trim()
        }
    ]);
    let policy_pack = directory.join("policy-pack.json");
    fs::write(&policy_pack, serde_json::to_vec_pretty(&pack).unwrap()).unwrap();
    assert!(
        run(&["validate-policy-pack", path(&policy_pack)])
            .status
            .success()
    );

    let electrical_review = directory.join("electrical-review.json");
    assert!(
        run(&[
            "check-schematic",
            path(&schematic),
            "--policy-pack",
            path(&policy_pack),
            "--output",
            path(&electrical_review),
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
            path(&electrical_review),
            "--policy-pack",
            path(&policy_pack),
            "--output",
            path(&request),
        ])
        .status
        .success()
    );
    let request_value: Value = serde_json::from_slice(&fs::read(&request).unwrap()).unwrap();

    let response = |provider: &str, model: &str| {
        json!({
            "schema_version": 1,
            "request_sha256": request_value["request_sha256"],
            "model": {"provider": provider, "model": model, "version": "1"},
            "decision": "approve",
            "summary": "The bound deterministic evidence supports approval.",
            "requirements": [{
                "id": "power",
                "status": "pass",
                "rationale": "The deterministic electrical review is approved.",
                "evidence_refs": ["electrical-review"]
            }],
            "risks": []
        })
    };
    let response_a = directory.join("response-a.json");
    let response_b = directory.join("response-b.json");
    fs::write(
        &response_a,
        serde_json::to_vec_pretty(&response("provider-a", "model-a")).unwrap(),
    )
    .unwrap();
    fs::write(
        &response_b,
        serde_json::to_vec_pretty(&response("provider-b", "model-b")).unwrap(),
    )
    .unwrap();

    let approval_a = directory.join("approval-a.json");
    let approval_b = directory.join("approval-b.json");
    for (response, private, signer, approval) in [
        (&response_a, &private_a, "reviewer-a", &approval_a),
        (&response_b, &private_b, "reviewer-b", &approval_b),
    ] {
        assert!(
            run(&[
                "sign-ai-review",
                path(&request),
                path(response),
                "--private-key",
                path(private),
                "--signer-id",
                signer,
                "--output",
                path(approval),
                "--require-approved",
            ])
            .status
            .success()
        );
    }

    let report = directory.join("quorum.json");
    let summary = directory.join("quorum.md");
    assert!(
        run(&[
            "verify-ai-quorum",
            path(&request),
            "--approval",
            path(&approval_b),
            "--approval",
            path(&approval_a),
            "--response",
            path(&response_b),
            "--response",
            path(&response_a),
            "--policy-pack",
            path(&policy_pack),
            "--minimum-approvals",
            "2",
            "--minimum-distinct-providers",
            "2",
            "--minimum-distinct-models",
            "2",
            "--output",
            path(&report),
            "--summary-output",
            path(&summary),
            "--require-quorum",
        ])
        .status
        .success()
    );
    let report_value: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(report_value["quorum_met"], true);
    assert_eq!(report_value["counts"]["approvals"], 2);
    assert_eq!(report_value["counts"]["distinct_providers"], 2);
    assert_eq!(report_value["members"][0]["signer_id"], "reviewer-a");
    assert!(
        fs::read_to_string(&summary)
            .unwrap()
            .contains("**Result:** approved")
    );

    let failed_report = directory.join("failed-quorum.json");
    let failed_summary = directory.join("failed-quorum.md");
    let failed = run(&[
        "verify-ai-quorum",
        path(&request),
        "--approval",
        path(&approval_a),
        "--approval",
        path(&approval_b),
        "--response",
        path(&response_a),
        "--response",
        path(&response_b),
        "--policy-pack",
        path(&policy_pack),
        "--minimum-approvals",
        "3",
        "--minimum-distinct-providers",
        "2",
        "--minimum-distinct-models",
        "2",
        "--output",
        path(&failed_report),
        "--summary-output",
        path(&failed_summary),
        "--require-quorum",
    ]);
    assert!(!failed.status.success());
    assert!(failed_report.is_file());
    assert!(failed_summary.is_file());
    let failed_value: Value = serde_json::from_slice(&fs::read(&failed_report).unwrap()).unwrap();
    assert_eq!(failed_value["quorum_met"], false);
    assert_eq!(
        failed_value["quorum_failures"][0],
        "insufficient_approvals:required=3:actual=2"
    );

    let duplicate_approval = directory.join("duplicate-response-approval.json");
    assert!(
        run(&[
            "sign-ai-review",
            path(&request),
            path(&response_a),
            "--private-key",
            path(&private_b),
            "--signer-id",
            "reviewer-b",
            "--output",
            path(&duplicate_approval),
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "verify-ai-quorum",
            path(&request),
            "--approval",
            path(&approval_a),
            "--approval",
            path(&duplicate_approval),
            "--response",
            path(&response_a),
            "--response",
            path(&response_a),
            "--policy-pack",
            path(&policy_pack),
            "--output",
            path(&directory.join("duplicate.json")),
        ])
        .status
        .success()
    );

    let schema = directory.join("quorum.schema.json");
    assert!(
        run(&["ai-approval-quorum-schema", "--output", path(&schema)])
            .status
            .success()
    );
    let schema_value: Value = serde_json::from_slice(&fs::read(schema).unwrap()).unwrap();
    assert_eq!(schema_value["additionalProperties"], false);

    fs::remove_dir_all(directory).unwrap();
}
