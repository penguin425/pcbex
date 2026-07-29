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
    let path = std::env::temp_dir().join(format!("pcbex-lifecycle-witness-rotation-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn rotates_identity_bound_lifecycle_witness_trust_without_overwrite() {
    let directory = temp_dir();
    let old_private = directory.join("witness.old.key");
    let old_public = directory.join("witness.old.pub");
    let new_private = directory.join("witness.new.key");
    let new_public = directory.join("witness.new.pub");
    for (private, public) in [(&old_private, &old_public), (&new_private, &new_public)] {
        let output = run(&[
            "approval-keygen",
            "--private-key",
            path(private),
            "--public-key",
            path(public),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let initial = directory.join("witness.trust.0.json");
    assert!(
        run(&[
            "init-policy-lifecycle-witness-trust",
            "--witness-id",
            "witness-a",
            "--public-key",
            path(&old_public),
            "--output",
            path(&initial),
        ])
        .status
        .success()
    );
    let initial_value: Value = serde_json::from_slice(&fs::read(&initial).unwrap()).unwrap();
    assert_eq!(initial_value["witness_id"], "witness-a");
    assert_eq!(initial_value["generation"], 0);

    let rotation = directory.join("witness.rotation.1.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-witness-key-rotation",
            path(&initial),
            "--old-private-key",
            path(&old_private),
            "--new-private-key",
            path(&new_private),
            "--rotated-at-unix",
            "1000",
            "--output",
            path(&rotation),
        ])
        .status
        .success()
    );

    let rotated = directory.join("witness.trust.1.json");
    let exported = directory.join("witness.trust.1.pub");
    assert!(
        run(&[
            "apply-policy-lifecycle-witness-key-rotation",
            path(&initial),
            path(&rotation),
            "--output",
            path(&rotated),
            "--public-key-output",
            path(&exported),
        ])
        .status
        .success()
    );
    let rotated_value: Value = serde_json::from_slice(&fs::read(&rotated).unwrap()).unwrap();
    assert_eq!(rotated_value["witness_id"], "witness-a");
    assert_eq!(rotated_value["generation"], 1);
    assert_eq!(
        fs::read_to_string(&exported).unwrap(),
        fs::read_to_string(&new_public).unwrap()
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-witness-trust-state",
            path(&rotated),
        ])
        .status
        .success()
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-witness-key-rotation",
            path(&rotation),
        ])
        .status
        .success()
    );

    let replayed = directory.join("witness.trust.replayed.json");
    let replayed_public = directory.join("witness.trust.replayed.pub");
    assert!(
        !run(&[
            "apply-policy-lifecycle-witness-key-rotation",
            path(&rotated),
            path(&rotation),
            "--output",
            path(&replayed),
            "--public-key-output",
            path(&replayed_public),
        ])
        .status
        .success()
    );
    assert!(!replayed.exists());
    assert!(!replayed_public.exists());

    fs::remove_dir_all(directory).unwrap();
}
