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
    let path = std::env::temp_dir().join(format!("pcbex-gossip-observer-rotation-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn rotates_organization_bound_gossip_observer_trust_without_overwrite() {
    let directory = temp_dir();
    let old_private = directory.join("observer.old.key");
    let old_public = directory.join("observer.old.pub");
    let new_private = directory.join("observer.new.key");
    let new_public = directory.join("observer.new.pub");
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

    let initial = directory.join("observer.trust.0.json");
    assert!(
        run(&[
            "init-policy-lifecycle-log-gossip-observer-trust",
            "--organization-id",
            "independent-lab",
            "--observer-id",
            "observer-a",
            "--public-key",
            path(&old_public),
            "--output",
            path(&initial),
        ])
        .status
        .success()
    );
    let initial_value: Value = serde_json::from_slice(&fs::read(&initial).unwrap()).unwrap();
    assert_eq!(initial_value["organization_id"], "independent-lab");
    assert_eq!(initial_value["observer_id"], "observer-a");
    assert_eq!(initial_value["generation"], 0);

    let rotation = directory.join("observer.rotation.1.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-observer-key-rotation",
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
    let rotated = directory.join("observer.trust.1.json");
    let exported = directory.join("observer.trust.1.pub");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-observer-key-rotation",
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
    assert_eq!(rotated_value["organization_id"], "independent-lab");
    assert_eq!(rotated_value["observer_id"], "observer-a");
    assert_eq!(rotated_value["generation"], 1);
    assert_eq!(
        fs::read_to_string(&exported).unwrap(),
        fs::read_to_string(&new_public).unwrap()
    );
    for (command, input) in [
        (
            "validate-policy-lifecycle-log-gossip-observer-trust-state",
            &rotated,
        ),
        (
            "validate-policy-lifecycle-log-gossip-observer-key-rotation",
            &rotation,
        ),
    ] {
        assert!(run(&[command, path(input)]).status.success());
    }

    let replayed = directory.join("observer.trust.replayed.json");
    let replayed_public = directory.join("observer.trust.replayed.pub");
    assert!(
        !run(&[
            "apply-policy-lifecycle-log-gossip-observer-key-rotation",
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
