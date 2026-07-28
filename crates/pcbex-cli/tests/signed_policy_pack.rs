use serde_json::Value;
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
}
