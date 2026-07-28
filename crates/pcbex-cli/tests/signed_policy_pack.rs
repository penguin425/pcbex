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
    assert!(
        run(&[
            "verify-policy-pack",
            path(&signed),
            "--public-key",
            path(&public_key),
            "--output",
            path(&extracted),
        ])
        .status
        .success()
    );
    let original: Value = serde_json::from_slice(&fs::read(&pack).unwrap()).unwrap();
    let verified: Value = serde_json::from_slice(&fs::read(&extracted).unwrap()).unwrap();
    assert_eq!(verified, original);

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
}
