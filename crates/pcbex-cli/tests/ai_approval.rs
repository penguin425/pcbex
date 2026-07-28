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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let policy = directory.join("policy.json");
    assert!(
        run(&["electrical-policy", "--output", path(&policy)])
            .status
            .success()
    );
    let mut policy_value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    for setting in policy_value["rules"].as_object_mut().unwrap().values_mut() {
        if setting["severity"] == "error" {
            setting["enabled"] = Value::Bool(false);
        }
    }
    fs::write(&policy, serde_json::to_vec_pretty(&policy_value).unwrap()).unwrap();
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
