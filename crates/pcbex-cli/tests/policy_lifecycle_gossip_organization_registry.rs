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
    let path = std::env::temp_dir().join(format!("pcbex-gossip-org-registry-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn governs_observer_admission_suspension_and_permanent_revocation() {
    let directory = temp_dir();
    let authority_private = directory.join("authority.key");
    let authority_public = directory.join("authority.pub");
    let authority_next_private = directory.join("authority.next.key");
    let authority_next_public = directory.join("authority.next.pub");
    let observer_private = directory.join("observer.key");
    let observer_public = directory.join("observer.pub");
    for (private, public) in [
        (&authority_private, &authority_public),
        (&authority_next_private, &authority_next_public),
        (&observer_private, &observer_public),
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

    let trust = directory.join("observer.trust.json");
    assert!(
        run(&[
            "init-policy-lifecycle-log-gossip-observer-trust",
            "--organization-id",
            "independent-lab",
            "--observer-id",
            "observer-a",
            "--public-key",
            path(&observer_public),
            "--output",
            path(&trust),
        ])
        .status
        .success()
    );
    let initial = directory.join("registry.0.json");
    assert!(
        run(&[
            "init-policy-lifecycle-log-gossip-organization-registry",
            "--registry-id",
            "production-gossip",
            "--authority-public-key",
            path(&authority_public),
            "--output",
            path(&initial),
        ])
        .status
        .success()
    );

    let admission = directory.join("registry.admit.1.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&initial),
            "--authority-private-key",
            path(&authority_private),
            "--action",
            "admit-observer",
            "--organization-id",
            "independent-lab",
            "--observer-trust-state",
            path(&trust),
            "--reason-sha256",
            &"1".repeat(64),
            "--effective-at-unix",
            "1000",
            "--output",
            path(&admission),
        ])
        .status
        .success()
    );
    let admitted = directory.join("registry.1.json");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&initial),
            path(&admission),
            "--output",
            path(&admitted),
        ])
        .status
        .success()
    );
    let admitted_value: Value = serde_json::from_slice(&fs::read(&admitted).unwrap()).unwrap();
    assert_eq!(admitted_value["generation"], 1);
    assert_eq!(admitted_value["organizations"][0]["status"], "active");
    assert_eq!(
        admitted_value["organizations"][0]["observers"][0]["observer_id"],
        "observer-a"
    );

    let authority_rotation = directory.join("registry.authority-rotation.2.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
            path(&admitted),
            "--old-private-key",
            path(&authority_private),
            "--new-private-key",
            path(&authority_next_private),
            "--rotated-at-unix",
            "1500",
            "--output",
            path(&authority_rotation),
        ])
        .status
        .success()
    );
    let rotated = directory.join("registry.2.json");
    let exported_authority = directory.join("registry.authority.next.pub");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
            path(&admitted),
            path(&authority_rotation),
            "--output",
            path(&rotated),
            "--public-key-output",
            path(&exported_authority),
        ])
        .status
        .success()
    );
    let rotated_value: Value = serde_json::from_slice(&fs::read(&rotated).unwrap()).unwrap();
    assert_eq!(rotated_value["generation"], 2);
    assert_eq!(
        fs::read_to_string(&exported_authority).unwrap(),
        fs::read_to_string(&authority_next_public).unwrap()
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
            path(&authority_rotation),
        ])
        .status
        .success()
    );
    let replayed_rotation = directory.join("registry.rotation-replayed.json");
    let replayed_rotation_public = directory.join("registry.rotation-replayed.pub");
    assert!(
        !run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation",
            path(&rotated),
            path(&authority_rotation),
            "--output",
            path(&replayed_rotation),
            "--public-key-output",
            path(&replayed_rotation_public),
        ])
        .status
        .success()
    );
    assert!(!replayed_rotation.exists());
    assert!(!replayed_rotation_public.exists());

    let suspension = directory.join("registry.suspend.3.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&rotated),
            "--authority-private-key",
            path(&authority_next_private),
            "--action",
            "suspend-organization",
            "--organization-id",
            "independent-lab",
            "--reason-sha256",
            &"2".repeat(64),
            "--effective-at-unix",
            "2000",
            "--output",
            path(&suspension),
        ])
        .status
        .success()
    );
    let suspended = directory.join("registry.3.json");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&rotated),
            path(&suspension),
            "--output",
            path(&suspended),
        ])
        .status
        .success()
    );
    let suspended_value: Value = serde_json::from_slice(&fs::read(&suspended).unwrap()).unwrap();
    assert_eq!(suspended_value["organizations"][0]["status"], "suspended");

    let revocation = directory.join("registry.revoke.4.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&suspended),
            "--authority-private-key",
            path(&authority_next_private),
            "--action",
            "revoke-organization",
            "--organization-id",
            "independent-lab",
            "--reason-sha256",
            &"3".repeat(64),
            "--effective-at-unix",
            "3000",
            "--output",
            path(&revocation),
        ])
        .status
        .success()
    );
    let revoked = directory.join("registry.4.json");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&suspended),
            path(&revocation),
            "--output",
            path(&revoked),
        ])
        .status
        .success()
    );
    let revoked_value: Value = serde_json::from_slice(&fs::read(&revoked).unwrap()).unwrap();
    assert_eq!(revoked_value["organizations"][0]["status"], "revoked");

    for (command, input) in [
        (
            "validate-policy-lifecycle-log-gossip-organization-registry",
            &revoked,
        ),
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-transition",
            &revocation,
        ),
    ] {
        assert!(run(&[command, path(input)]).status.success());
    }
    let replayed = directory.join("registry.replayed.json");
    assert!(
        !run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-transition",
            path(&revoked),
            path(&revocation),
            "--output",
            path(&replayed),
        ])
        .status
        .success()
    );
    assert!(!replayed.exists());
    fs::remove_dir_all(directory).unwrap();
}
