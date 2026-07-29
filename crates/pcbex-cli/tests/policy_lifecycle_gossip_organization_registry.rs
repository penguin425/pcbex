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
    let authority_final_private = directory.join("authority.final.key");
    let authority_final_public = directory.join("authority.final.pub");
    let observer_private = directory.join("observer.key");
    let observer_public = directory.join("observer.pub");
    let governance_a_private = directory.join("governance-a.key");
    let governance_a_public = directory.join("governance-a.pub");
    let governance_b_private = directory.join("governance-b.key");
    let governance_b_public = directory.join("governance-b.pub");
    let governance_c_private = directory.join("governance-c.key");
    let governance_c_public = directory.join("governance-c.pub");
    let successor_a_private = directory.join("successor-a.key");
    let successor_a_public = directory.join("successor-a.pub");
    let successor_b_private = directory.join("successor-b.key");
    let successor_b_public = directory.join("successor-b.pub");
    for (private, public) in [
        (&authority_private, &authority_public),
        (&authority_next_private, &authority_next_public),
        (&authority_final_private, &authority_final_public),
        (&observer_private, &observer_public),
        (&governance_a_private, &governance_a_public),
        (&governance_b_private, &governance_b_public),
        (&governance_c_private, &governance_c_public),
        (&successor_a_private, &successor_a_public),
        (&successor_b_private, &successor_b_public),
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

    let governance = directory.join("registry.governance.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-governance",
            path(&rotated),
            "--registry-authority-private-key",
            path(&authority_next_private),
            "--minimum-approvals",
            "2",
            "--authority-id",
            "governance-a",
            "--authority-id",
            "governance-b",
            "--authority-id",
            "governance-c",
            "--authority-public-key",
            path(&governance_a_public),
            "--authority-public-key",
            path(&governance_b_public),
            "--authority-public-key",
            path(&governance_c_public),
            "--issued-at-unix",
            "1600",
            "--output",
            path(&governance),
        ])
        .status
        .success()
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-organization-registry-governance",
            path(&governance),
        ])
        .status
        .success()
    );

    let suspension = directory.join("registry.suspend.3.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            path(&rotated),
            path(&governance),
            "--authority-id",
            "governance-a",
            "--authority-id",
            "governance-b",
            "--authority-private-key",
            path(&governance_a_private),
            "--authority-private-key",
            path(&governance_b_private),
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
            "apply-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            path(&rotated),
            path(&governance),
            path(&suspension),
            "--output",
            path(&suspended),
        ])
        .status
        .success()
    );
    let suspended_value: Value = serde_json::from_slice(&fs::read(&suspended).unwrap()).unwrap();
    let suspension_value: Value = serde_json::from_slice(&fs::read(&suspension).unwrap()).unwrap();
    assert_eq!(suspended_value["organizations"][0]["status"], "suspended");
    assert_eq!(
        suspended_value["active_governance_sha256"],
        suspension_value["governance_sha256"]
    );
    let root_only_bypass = directory.join("registry.root-only-bypass.json");
    assert!(
        !run(&[
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
            "2100",
            "--output",
            path(&root_only_bypass),
        ])
        .status
        .success()
    );
    assert!(!root_only_bypass.exists());

    let successor_governance = directory.join("registry.governance.next.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-governance",
            path(&suspended),
            "--registry-authority-private-key",
            path(&authority_next_private),
            "--minimum-approvals",
            "2",
            "--authority-id",
            "successor-a",
            "--authority-id",
            "successor-b",
            "--authority-public-key",
            path(&successor_a_public),
            "--authority-public-key",
            path(&successor_b_public),
            "--issued-at-unix",
            "2200",
            "--output",
            path(&successor_governance),
        ])
        .status
        .success()
    );
    let governance_rotation = directory.join("registry.governance.rotation.4.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-governance-rotation",
            path(&suspended),
            path(&governance),
            path(&successor_governance),
            "--old-authority-id",
            "governance-a",
            "--old-authority-id",
            "governance-b",
            "--old-authority-private-key",
            path(&governance_a_private),
            "--old-authority-private-key",
            path(&governance_b_private),
            "--new-authority-id",
            "successor-a",
            "--new-authority-id",
            "successor-b",
            "--new-authority-private-key",
            path(&successor_a_private),
            "--new-authority-private-key",
            path(&successor_b_private),
            "--rotated-at-unix",
            "2500",
            "--output",
            path(&governance_rotation),
        ])
        .status
        .success()
    );
    let governance_rotated = directory.join("registry.4.json");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-governance-rotation",
            path(&suspended),
            path(&governance),
            path(&successor_governance),
            path(&governance_rotation),
            "--output",
            path(&governance_rotated),
        ])
        .status
        .success()
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-organization-registry-governance-rotation",
            path(&governance_rotation),
        ])
        .status
        .success()
    );
    let governance_rotated_value: Value =
        serde_json::from_slice(&fs::read(&governance_rotated).unwrap()).unwrap();
    let governance_rotation_value: Value =
        serde_json::from_slice(&fs::read(&governance_rotation).unwrap()).unwrap();
    assert_eq!(
        governance_rotated_value["active_governance_sha256"],
        governance_rotation_value["new_governance_sha256"]
    );
    let stale_governance_transition = directory.join("registry.stale-governance.json");
    assert!(
        !run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            path(&governance_rotated),
            path(&governance),
            "--authority-id",
            "governance-a",
            "--authority-id",
            "governance-b",
            "--authority-private-key",
            path(&governance_a_private),
            "--authority-private-key",
            path(&governance_b_private),
            "--action",
            "revoke-organization",
            "--organization-id",
            "independent-lab",
            "--reason-sha256",
            &"3".repeat(64),
            "--effective-at-unix",
            "2700",
            "--output",
            path(&stale_governance_transition),
        ])
        .status
        .success()
    );
    assert!(!stale_governance_transition.exists());

    let final_governance = directory.join("registry.governance.final.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-successor-governance",
            path(&governance_rotated),
            "--successor-registry-authority-private-key",
            path(&authority_final_private),
            "--minimum-approvals",
            "2",
            "--authority-id",
            "governance-a",
            "--authority-id",
            "governance-b",
            "--authority-public-key",
            path(&governance_a_public),
            "--authority-public-key",
            path(&governance_b_public),
            "--issued-at-unix",
            "2800",
            "--output",
            path(&final_governance),
        ])
        .status
        .success()
    );
    let governed_authority_rotation = directory.join("registry.governed-authority-rotation.5.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation",
            path(&governance_rotated),
            path(&successor_governance),
            path(&final_governance),
            "--old-authority-id",
            "successor-a",
            "--old-authority-id",
            "successor-b",
            "--old-authority-private-key",
            path(&successor_a_private),
            "--old-authority-private-key",
            path(&successor_b_private),
            "--new-authority-id",
            "governance-a",
            "--new-authority-id",
            "governance-b",
            "--new-authority-private-key",
            path(&governance_a_private),
            "--new-authority-private-key",
            path(&governance_b_private),
            "--rotated-at-unix",
            "2900",
            "--output",
            path(&governed_authority_rotation),
        ])
        .status
        .success()
    );
    let authority_governed = directory.join("registry.5.json");
    let authority_final_exported = directory.join("registry.authority.final.pub");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation",
            path(&governance_rotated),
            path(&successor_governance),
            path(&final_governance),
            path(&governed_authority_rotation),
            "--output",
            path(&authority_governed),
            "--public-key-output",
            path(&authority_final_exported),
        ])
        .status
        .success()
    );
    assert_eq!(
        fs::read_to_string(&authority_final_exported).unwrap(),
        fs::read_to_string(&authority_final_public).unwrap()
    );
    let authority_governed_value: Value =
        serde_json::from_slice(&fs::read(&authority_governed).unwrap()).unwrap();
    let governed_authority_rotation_value: Value =
        serde_json::from_slice(&fs::read(&governed_authority_rotation).unwrap()).unwrap();
    assert_eq!(
        authority_governed_value["active_governance_sha256"],
        governed_authority_rotation_value["new_governance_sha256"]
    );
    assert!(
        run(&[
            "validate-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation",
            path(&governed_authority_rotation),
        ])
        .status
        .success()
    );

    let revocation = directory.join("registry.revoke.6.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            path(&authority_governed),
            path(&final_governance),
            "--authority-id",
            "governance-a",
            "--authority-id",
            "governance-b",
            "--authority-private-key",
            path(&governance_a_private),
            "--authority-private-key",
            path(&governance_b_private),
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
    let revoked = directory.join("registry.6.json");
    assert!(
        run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            path(&authority_governed),
            path(&final_governance),
            path(&revocation),
            "--output",
            path(&revoked),
        ])
        .status
        .success()
    );
    let revoked_value: Value = serde_json::from_slice(&fs::read(&revoked).unwrap()).unwrap();
    assert_eq!(revoked_value["organizations"][0]["status"], "revoked");

    let read_json =
        |path: &Path| -> Value { serde_json::from_slice(&fs::read(path).unwrap()).unwrap() };
    let history = directory.join("registry.history.json");
    let history_value = json!({
        "schema_version": 1,
        "initial_registry": read_json(&initial),
        "events": [
            {"kind": "root_transition", "transition": read_json(&admission)},
            {"kind": "root_authority_key_rotation", "rotation": read_json(&authority_rotation)},
            {
                "kind": "threshold_transition",
                "governance": read_json(&governance),
                "transition": read_json(&suspension)
            },
            {
                "kind": "governance_rotation",
                "old_governance": read_json(&governance),
                "new_governance": read_json(&successor_governance),
                "rotation": read_json(&governance_rotation)
            },
            {
                "kind": "governed_authority_key_rotation",
                "old_governance": read_json(&successor_governance),
                "new_governance": read_json(&final_governance),
                "rotation": read_json(&governed_authority_rotation)
            },
            {
                "kind": "threshold_transition",
                "governance": read_json(&final_governance),
                "transition": read_json(&revocation)
            }
        ]
    });
    fs::write(&history, serde_json::to_vec_pretty(&history_value).unwrap()).unwrap();
    let history_audit = directory.join("registry.history.audit.json");
    let history_final = directory.join("registry.history.final.json");
    assert!(
        run(&[
            "audit-policy-lifecycle-log-gossip-organization-registry-history",
            path(&history),
            "--output",
            path(&history_audit),
            "--final-registry-output",
            path(&history_final),
        ])
        .status
        .success()
    );
    let history_audit_value = read_json(&history_audit);
    assert_eq!(history_audit_value["event_count"], 6);
    assert_eq!(history_audit_value["chain_valid"], true);
    assert_eq!(read_json(&history_final), revoked_value);
    for (command, input) in [
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-history",
            &history,
        ),
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-history-audit",
            &history_audit,
        ),
    ] {
        assert!(run(&[command, path(input)]).status.success());
    }

    let history_checkpoint = directory.join("registry.history.checkpoint.json");
    assert!(
        run(&[
            "sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint",
            path(&history),
            "--authority-private-key",
            path(&authority_final_private),
            "--issued-at-unix",
            "3100",
            "--output",
            path(&history_checkpoint),
        ])
        .status
        .success()
    );
    let checkpoint_trust = directory.join("registry.history.checkpoint.trust.json");
    assert!(
        run(&[
            "accept-policy-lifecycle-log-gossip-organization-registry-history-checkpoint",
            path(&history),
            path(&history_checkpoint),
            "--accepted-at-unix",
            "3200",
            "--output",
            path(&checkpoint_trust),
        ])
        .status
        .success()
    );
    let checkpoint_trust_value = read_json(&checkpoint_trust);
    assert_eq!(checkpoint_trust_value["accepted_generation"], 6);

    let witness_a = directory.join("registry.history.checkpoint.witness-a.json");
    let witness_b = directory.join("registry.history.checkpoint.witness-b.json");
    for (witness_id, private_key, output) in [
        ("independent-a", &governance_a_private, &witness_a),
        ("independent-b", &governance_b_private, &witness_b),
    ] {
        assert!(
            run(&[
                "sign-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness",
                path(&history),
                path(&history_checkpoint),
                "--witness-id",
                witness_id,
                "--witness-private-key",
                path(private_key),
                "--witnessed-at-unix",
                "3300",
                "--output",
                path(output),
            ])
            .status
            .success()
        );
    }
    let witness_quorum = directory.join("registry.history.checkpoint.quorum.json");
    assert!(
        run(&[
            "verify-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witnesses",
            path(&history),
            path(&history_checkpoint),
            "--witness",
            path(&witness_b),
            "--witness",
            path(&witness_a),
            "--trusted-witness-id",
            "independent-a",
            "--trusted-witness-id",
            "independent-b",
            "--trusted-witness-public-key",
            path(&governance_a_public),
            "--trusted-witness-public-key",
            path(&governance_b_public),
            "--minimum-witnesses",
            "2",
            "--evaluated-at-unix",
            "3400",
            "--require-quorum",
            "--output",
            path(&witness_quorum),
        ])
        .status
        .success()
    );
    let quorum_value = read_json(&witness_quorum);
    assert_eq!(quorum_value["valid_witnesses"], 2);
    assert_eq!(quorum_value["quorum_met"], true);
    assert_eq!(quorum_value["members"][0]["witness_id"], "independent-a");

    for (command, input) in [
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-history-checkpoint",
            &history_checkpoint,
        ),
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-trust-state",
            &checkpoint_trust,
        ),
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness",
            &witness_a,
        ),
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-quorum",
            &witness_quorum,
        ),
    ] {
        assert!(run(&[command, path(input)]).status.success());
    }

    let rejected_quorum = directory.join("registry.history.checkpoint.rejected-quorum.json");
    assert!(
        !run(&[
            "verify-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witnesses",
            path(&history),
            path(&history_checkpoint),
            "--witness",
            path(&witness_a),
            "--witness",
            path(&witness_b),
            "--trusted-witness-id",
            "independent-a",
            "--trusted-witness-id",
            "independent-b",
            "--trusted-witness-public-key",
            path(&governance_a_public),
            "--trusted-witness-public-key",
            path(&governance_b_public),
            "--minimum-witnesses",
            "3",
            "--evaluated-at-unix",
            "3400",
            "--require-quorum",
            "--output",
            path(&rejected_quorum),
        ])
        .status
        .success()
    );
    assert!(!rejected_quorum.exists());

    let mut reordered_history = history_value;
    reordered_history["events"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    let reordered_history_path = directory.join("registry.history.reordered.json");
    fs::write(
        &reordered_history_path,
        serde_json::to_vec_pretty(&reordered_history).unwrap(),
    )
    .unwrap();
    let rejected_audit = directory.join("registry.history.rejected-audit.json");
    let rejected_final = directory.join("registry.history.rejected-final.json");
    assert!(
        !run(&[
            "audit-policy-lifecycle-log-gossip-organization-registry-history",
            path(&reordered_history_path),
            "--output",
            path(&rejected_audit),
            "--final-registry-output",
            path(&rejected_final),
        ])
        .status
        .success()
    );
    assert!(!rejected_audit.exists());
    assert!(!rejected_final.exists());

    for (command, input) in [
        (
            "validate-policy-lifecycle-log-gossip-organization-registry",
            &revoked,
        ),
        (
            "validate-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            &revocation,
        ),
    ] {
        assert!(run(&[command, path(input)]).status.success());
    }
    let replayed = directory.join("registry.replayed.json");
    assert!(
        !run(&[
            "apply-policy-lifecycle-log-gossip-organization-registry-threshold-transition",
            path(&revoked),
            path(&final_governance),
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
