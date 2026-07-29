use crate::policy_lifecycle_anchor::{
    PolicyLifecycleLogAnchorProof, PolicyLifecycleLogConsistencyProof,
    policy_lifecycle_public_log_tree_head_sha256, validate_policy_lifecycle_log_anchor_proof,
    validate_policy_lifecycle_log_consistency_proof,
};
use crate::policy_lifecycle_gossip::{
    SignedPolicyLifecycleLogGossipReceipt, validate_policy_lifecycle_log_gossip_receipt,
    verify_policy_lifecycle_log_gossip_receipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MAX_GOSSIP_OBSERVATIONS: usize = 100;
const MAX_GOSSIP_QUORUM_RECEIPT_AGE_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipObservation {
    pub schema_version: u32,
    pub receipt: SignedPolicyLifecycleLogGossipReceipt,
    pub consistency_proof: Option<PolicyLifecycleLogConsistencyProof>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipQuorumMember {
    pub organization_id: String,
    pub observer_id: String,
    pub observer_public_key: String,
    pub gossip_receipt_sha256: String,
    pub observed_tree_head_sha256: String,
    pub observed_tree_size: u64,
    pub observed_root_sha256: String,
    pub relationship: String,
    pub consistency_proof_sha256: Option<String>,
    pub received_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipQuorumReport {
    pub schema_version: u32,
    pub status: String,
    pub log_id: String,
    pub local_tree_head_sha256: String,
    pub local_tree_size: u64,
    pub local_root_sha256: String,
    pub evaluated_at_unix: u64,
    pub minimum_organizations: u32,
    pub valid_observations: u32,
    pub distinct_organizations: u32,
    pub freshest_received_at_unix: u64,
    pub earliest_expires_at_unix: u64,
    pub members: Vec<PolicyLifecycleLogGossipQuorumMember>,
    pub all_consistent: bool,
    pub quorum_met: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_policy_lifecycle_log_gossip_quorum(
    local_anchor: &PolicyLifecycleLogAnchorProof,
    observations: &[PolicyLifecycleLogGossipObservation],
    organization_ids: &[String],
    trusted_observer_ids: &[String],
    trusted_observer_public_keys: &[[u8; 32]],
    minimum_organizations: u32,
    trusted_log_id: &str,
    trusted_log_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipQuorumReport, String> {
    validate_policy_lifecycle_log_anchor_proof(local_anchor)?;
    if !(2..=MAX_GOSSIP_OBSERVATIONS as u32).contains(&minimum_organizations) {
        return Err("policy lifecycle gossip quorum must require 2 to 100 organizations".into());
    }
    if observations.is_empty()
        || observations.len() > MAX_GOSSIP_OBSERVATIONS
        || observations.len() != organization_ids.len()
        || observations.len() != trusted_observer_ids.len()
        || observations.len() != trusted_observer_public_keys.len()
    {
        return Err(
            "policy lifecycle gossip observations and trusted observer evidence must be non-empty, paired, and bounded"
                .into(),
        );
    }

    let mut organizations = BTreeSet::new();
    let mut observers = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut members = Vec::with_capacity(observations.len());
    for (((observation, organization_id), observer_id), observer_key) in observations
        .iter()
        .zip(organization_ids)
        .zip(trusted_observer_ids)
        .zip(trusted_observer_public_keys)
    {
        validate_policy_lifecycle_log_gossip_observation(observation)?;
        validate_slug(organization_id, "policy lifecycle gossip organization id")?;
        validate_slug(observer_id, "trusted policy lifecycle gossip observer id")?;
        let report = verify_policy_lifecycle_log_gossip_receipt(
            local_anchor,
            &observation.receipt,
            observation.consistency_proof.as_ref(),
            trusted_log_id,
            trusted_log_public_key,
            observer_id,
            observer_key,
            evaluated_at_unix,
        )?;
        if evaluated_at_unix - report.received_at_unix > MAX_GOSSIP_QUORUM_RECEIPT_AGE_SECONDS {
            return Err(
                "policy lifecycle gossip quorum receipt is older than the 24-hour quorum window"
                    .into(),
            );
        }
        let key = hex_encode(observer_key);
        if !organizations.insert(organization_id.clone()) {
            return Err("policy lifecycle gossip quorum requires distinct organizations".into());
        }
        if !observers.insert(observer_id.clone()) {
            return Err(
                "policy lifecycle gossip quorum requires distinct observer identities".into(),
            );
        }
        if !keys.insert(key.clone()) {
            return Err("policy lifecycle gossip quorum requires distinct observer keys".into());
        }
        if !receipts.insert(report.gossip_receipt_sha256.clone()) {
            return Err("policy lifecycle gossip quorum rejects duplicate receipts".into());
        }
        members.push(PolicyLifecycleLogGossipQuorumMember {
            organization_id: organization_id.clone(),
            observer_id: observer_id.clone(),
            observer_public_key: key,
            gossip_receipt_sha256: report.gossip_receipt_sha256,
            observed_tree_head_sha256: report.observed_tree_head_sha256,
            observed_tree_size: report.observed_tree_size,
            observed_root_sha256: report.observed_root_sha256,
            relationship: report.relationship,
            consistency_proof_sha256: report.consistency_proof_sha256,
            received_at_unix: report.received_at_unix,
            expires_at_unix: report.expires_at_unix,
        });
    }
    members.sort_by(|left, right| {
        (&left.organization_id, &left.observer_id)
            .cmp(&(&right.organization_id, &right.observer_id))
    });
    let valid_observations = u32::try_from(members.len())
        .map_err(|_| "policy lifecycle gossip observation count overflow".to_string())?;
    let distinct_organizations = u32::try_from(organizations.len())
        .map_err(|_| "policy lifecycle gossip organization count overflow".to_string())?;
    let quorum_met = distinct_organizations >= minimum_organizations;
    let local_head = &local_anchor.tree_head;
    let report = PolicyLifecycleLogGossipQuorumReport {
        schema_version: 1,
        status: if quorum_met {
            "gossip_quorum_met"
        } else {
            "insufficient_organizations"
        }
        .into(),
        log_id: trusted_log_id.into(),
        local_tree_head_sha256: policy_lifecycle_public_log_tree_head_sha256(local_head)?,
        local_tree_size: local_head.tree_size,
        local_root_sha256: local_head.root_sha256.clone(),
        evaluated_at_unix,
        minimum_organizations,
        valid_observations,
        distinct_organizations,
        freshest_received_at_unix: members
            .iter()
            .map(|member| member.received_at_unix)
            .max()
            .unwrap_or(0),
        earliest_expires_at_unix: members
            .iter()
            .map(|member| member.expires_at_unix)
            .min()
            .unwrap_or(0),
        members,
        all_consistent: true,
        quorum_met,
    };
    validate_policy_lifecycle_log_gossip_quorum_report(&report)?;
    Ok(report)
}

pub fn parse_policy_lifecycle_log_gossip_observation(
    source: &str,
) -> Result<PolicyLifecycleLogGossipObservation, String> {
    let observation = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle gossip observation JSON: {error}"))?;
    validate_policy_lifecycle_log_gossip_observation(&observation)?;
    Ok(observation)
}

pub fn validate_policy_lifecycle_log_gossip_observation(
    observation: &PolicyLifecycleLogGossipObservation,
) -> Result<(), String> {
    if observation.schema_version != 1 {
        return Err("unsupported policy lifecycle gossip observation".into());
    }
    validate_policy_lifecycle_log_gossip_receipt(&observation.receipt)?;
    if let Some(proof) = &observation.consistency_proof {
        validate_policy_lifecycle_log_consistency_proof(proof)?;
    }
    Ok(())
}

pub fn parse_policy_lifecycle_log_gossip_quorum_report(
    source: &str,
) -> Result<PolicyLifecycleLogGossipQuorumReport, String> {
    let report = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle gossip quorum JSON: {error}"))?;
    validate_policy_lifecycle_log_gossip_quorum_report(&report)?;
    Ok(report)
}

pub fn validate_policy_lifecycle_log_gossip_quorum_report(
    report: &PolicyLifecycleLogGossipQuorumReport,
) -> Result<(), String> {
    let count = usize::try_from(report.valid_observations)
        .map_err(|_| "policy lifecycle gossip observation count overflow".to_string())?;
    if report.schema_version != 1
        || !(2..=MAX_GOSSIP_OBSERVATIONS as u32).contains(&report.minimum_organizations)
        || count == 0
        || count > MAX_GOSSIP_OBSERVATIONS
        || count != report.members.len()
        || report.distinct_organizations != report.valid_observations
        || report.quorum_met != (report.distinct_organizations >= report.minimum_organizations)
        || report.status
            != if report.quorum_met {
                "gossip_quorum_met"
            } else {
                "insufficient_organizations"
            }
        || !report.all_consistent
        || report.freshest_received_at_unix
            != report
                .members
                .iter()
                .map(|member| member.received_at_unix)
                .max()
                .unwrap_or(0)
        || report.earliest_expires_at_unix
            != report
                .members
                .iter()
                .map(|member| member.expires_at_unix)
                .min()
                .unwrap_or(0)
    {
        return Err("invalid policy lifecycle gossip quorum invariants".into());
    }
    validate_log_id(&report.log_id)?;
    validate_sha256(
        &report.local_tree_head_sha256,
        "policy lifecycle local tree-head SHA-256",
    )?;
    validate_sha256(
        &report.local_root_sha256,
        "policy lifecycle local Merkle root",
    )?;
    let mut organizations = BTreeSet::new();
    let mut observers = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut previous = None;
    if report.local_tree_size == 0 {
        return Err("invalid policy lifecycle local tree size".into());
    }
    for member in &report.members {
        validate_slug(
            &member.organization_id,
            "policy lifecycle gossip organization id",
        )?;
        validate_slug(&member.observer_id, "policy lifecycle gossip observer id")?;
        validate_sha256(
            &member.observer_public_key,
            "policy lifecycle gossip observer public key",
        )?;
        validate_sha256(
            &member.gossip_receipt_sha256,
            "policy lifecycle gossip receipt SHA-256",
        )?;
        validate_sha256(
            &member.observed_tree_head_sha256,
            "policy lifecycle observed tree-head SHA-256",
        )?;
        validate_sha256(
            &member.observed_root_sha256,
            "policy lifecycle observed Merkle root",
        )?;
        if member.observed_tree_size == 0
            || !matches!(
                member.relationship.as_str(),
                "same_tree" | "observed_precedes_local" | "local_precedes_observed"
            )
            || (member.relationship == "same_tree") != member.consistency_proof_sha256.is_none()
            || member.received_at_unix > report.evaluated_at_unix
            || member.expires_at_unix < report.evaluated_at_unix
            || report.evaluated_at_unix - member.received_at_unix
                > MAX_GOSSIP_QUORUM_RECEIPT_AGE_SECONDS
        {
            return Err("invalid policy lifecycle gossip quorum member".into());
        }
        if let Some(proof) = &member.consistency_proof_sha256 {
            validate_sha256(proof, "policy lifecycle consistency proof SHA-256")?;
        }
        let order = (&member.organization_id, &member.observer_id);
        if previous.is_some_and(|value| value >= order) {
            return Err(
                "policy lifecycle gossip quorum members are not canonically ordered".into(),
            );
        }
        previous = Some(order);
        if !organizations.insert(&member.organization_id)
            || !observers.insert(&member.observer_id)
            || !keys.insert(&member.observer_public_key)
            || !receipts.insert(&member.gossip_receipt_sha256)
        {
            return Err("policy lifecycle gossip quorum members are not distinct".into());
        }
    }
    Ok(())
}

pub fn policy_lifecycle_log_gossip_observation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-observation-v1.json",
        "title": "pcbex policy lifecycle public-log gossip observation",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "receipt", "consistency_proof"],
        "properties": {
            "schema_version": {"const": 1},
            "receipt": crate::policy_lifecycle_gossip::signed_policy_lifecycle_log_gossip_receipt_json_schema(),
            "consistency_proof": {
                "oneOf": [
                    {"type": "null"},
                    crate::policy_lifecycle_anchor::policy_lifecycle_log_consistency_proof_json_schema()
                ]
            }
        }
    })
}

pub fn policy_lifecycle_log_gossip_quorum_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let slug = json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
    });
    let log_id = json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-quorum-v1.json",
        "title": "pcbex policy lifecycle public-log gossip organization quorum",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "log_id", "local_tree_head_sha256",
            "local_tree_size", "local_root_sha256", "evaluated_at_unix",
            "minimum_organizations", "valid_observations", "distinct_organizations",
            "freshest_received_at_unix", "earliest_expires_at_unix", "members",
            "all_consistent", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"enum": ["gossip_quorum_met", "insufficient_organizations"]},
            "log_id": log_id,
            "local_tree_head_sha256": digest.clone(),
            "local_tree_size": {"type": "integer", "minimum": 1},
            "local_root_sha256": digest.clone(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "minimum_organizations": {"type": "integer", "minimum": 2, "maximum": 100},
            "valid_observations": {"type": "integer", "minimum": 1, "maximum": 100},
            "distinct_organizations": {"type": "integer", "minimum": 1, "maximum": 100},
            "freshest_received_at_unix": {"type": "integer", "minimum": 0},
            "earliest_expires_at_unix": {"type": "integer", "minimum": 0},
            "members": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "organization_id", "observer_id", "observer_public_key",
                        "gossip_receipt_sha256", "observed_tree_head_sha256",
                        "observed_tree_size", "observed_root_sha256", "relationship",
                        "consistency_proof_sha256", "received_at_unix", "expires_at_unix"
                    ],
                    "properties": {
                        "organization_id": slug.clone(),
                        "observer_id": slug.clone(),
                        "observer_public_key": digest.clone(),
                        "gossip_receipt_sha256": digest.clone(),
                        "observed_tree_head_sha256": digest.clone(),
                        "observed_tree_size": {"type": "integer", "minimum": 1},
                        "observed_root_sha256": digest.clone(),
                        "relationship": {
                            "enum": ["same_tree", "observed_precedes_local", "local_precedes_observed"]
                        },
                        "consistency_proof_sha256": {
                            "oneOf": [{"type": "null"}, digest.clone()]
                        },
                        "received_at_unix": {"type": "integer", "minimum": 0},
                        "expires_at_unix": {"type": "integer", "minimum": 0}
                    }
                }
            },
            "all_consistent": {"const": true},
            "quorum_met": {"type": "boolean"}
        }
    })
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_log_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-'))
        })
    {
        return Err("invalid policy lifecycle public-log id".into());
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_lifecycle_anchor::{
        create_policy_lifecycle_log_anchor_proof, create_policy_lifecycle_log_consistency_proof,
        policy_lifecycle_signed_checkpoint_sha256,
    };
    use crate::policy_lifecycle_checkpoint::SignedPolicyLifecycleCheckpoint;
    use crate::policy_lifecycle_gossip::sign_policy_lifecycle_log_gossip_receipt;
    use ed25519_dalek::SigningKey;

    fn checkpoint(marker: u8) -> SignedPolicyLifecycleCheckpoint {
        SignedPolicyLifecycleCheckpoint {
            schema_version: 1,
            policy_pack_id: "organization".into(),
            generation: 1,
            entry_count: 1,
            ledger_sha256: format!("{marker:064x}"),
            head_sha256: format!("{:064x}", marker + 1),
            issued_at_unix: 10,
            signer_id: "lifecycle-root".into(),
            algorithm: "ed25519".into(),
            public_key: format!("{:064x}", marker + 2),
            signature: format!("{:0128x}", marker + 3),
        }
    }

    fn fixtures() -> (
        PolicyLifecycleLogAnchorProof,
        Vec<PolicyLifecycleLogGossipObservation>,
        Vec<[u8; 32]>,
    ) {
        let checkpoints = [checkpoint(1), checkpoint(2), checkpoint(3)];
        let digests = checkpoints
            .iter()
            .map(policy_lifecycle_signed_checkpoint_sha256)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let old = create_policy_lifecycle_log_anchor_proof(
            &checkpoints[0],
            &digests[..2],
            0,
            "lifecycle-log",
            20,
            &[9; 32],
        )
        .unwrap();
        let current = create_policy_lifecycle_log_anchor_proof(
            &checkpoints[0],
            &digests,
            0,
            "lifecycle-log",
            30,
            &[9; 32],
        )
        .unwrap();
        let consistency =
            create_policy_lifecycle_log_consistency_proof(&old, &current, &digests).unwrap();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let keys = [[7; 32], [8; 32]];
        let public_keys = keys
            .iter()
            .map(|key| SigningKey::from_bytes(key).verifying_key().to_bytes())
            .collect::<Vec<_>>();
        let receipts = [
            sign_policy_lifecycle_log_gossip_receipt(
                &old,
                "lifecycle-log",
                &log_key,
                "observer-a",
                31,
                100,
                &keys[0],
            )
            .unwrap(),
            sign_policy_lifecycle_log_gossip_receipt(
                &current,
                "lifecycle-log",
                &log_key,
                "observer-b",
                32,
                110,
                &keys[1],
            )
            .unwrap(),
        ];
        (
            current,
            vec![
                PolicyLifecycleLogGossipObservation {
                    schema_version: 1,
                    receipt: receipts[0].clone(),
                    consistency_proof: Some(consistency),
                },
                PolicyLifecycleLogGossipObservation {
                    schema_version: 1,
                    receipt: receipts[1].clone(),
                    consistency_proof: None,
                },
            ],
            public_keys,
        )
    }

    #[test]
    fn schemas_are_closed_and_bounded() {
        let observation = policy_lifecycle_log_gossip_observation_json_schema();
        assert_eq!(observation["additionalProperties"], false);
        assert_eq!(
            observation["properties"]["receipt"]["additionalProperties"],
            false
        );
        let quorum = policy_lifecycle_log_gossip_quorum_report_json_schema();
        assert_eq!(quorum["additionalProperties"], false);
        assert_eq!(
            quorum["properties"]["members"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(quorum["properties"]["members"]["maxItems"], 100);
    }

    #[test]
    fn verifies_fresh_distinct_organization_quorum_deterministically() {
        let (anchor, observations, keys) = fixtures();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let report = verify_policy_lifecycle_log_gossip_quorum(
            &anchor,
            &observations,
            &["org-b".into(), "org-a".into()],
            &["observer-a".into(), "observer-b".into()],
            &keys,
            2,
            "lifecycle-log",
            &log_key,
            50,
        )
        .unwrap();
        assert!(report.quorum_met);
        assert_eq!(report.status, "gossip_quorum_met");
        assert_eq!(report.distinct_organizations, 2);
        assert_eq!(report.members[0].organization_id, "org-a");
        assert_eq!(report.members[0].relationship, "same_tree");
        assert_eq!(report.members[1].relationship, "observed_precedes_local");
        assert_eq!(report.freshest_received_at_unix, 32);
        assert_eq!(report.earliest_expires_at_unix, 100);
        validate_policy_lifecycle_log_gossip_quorum_report(&report).unwrap();
    }

    #[test]
    fn rejects_duplicate_trust_and_retains_below_threshold_evidence() {
        let (anchor, observations, keys) = fixtures();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let one = verify_policy_lifecycle_log_gossip_quorum(
            &anchor,
            &observations[..1],
            &["org-a".into()],
            &["observer-a".into()],
            &keys[..1],
            2,
            "lifecycle-log",
            &log_key,
            50,
        )
        .unwrap();
        assert!(!one.quorum_met);
        assert_eq!(one.status, "insufficient_organizations");

        assert!(
            verify_policy_lifecycle_log_gossip_quorum(
                &anchor,
                &observations,
                &["org-a".into(), "org-a".into()],
                &["observer-a".into(), "observer-b".into()],
                &keys,
                2,
                "lifecycle-log",
                &log_key,
                50,
            )
            .is_err()
        );
        assert!(
            verify_policy_lifecycle_log_gossip_quorum(
                &anchor,
                &observations,
                &["org-a".into(), "org-b".into()],
                &["observer-a".into(), "observer-a".into()],
                &keys,
                2,
                "lifecycle-log",
                &log_key,
                50,
            )
            .is_err()
        );
        let stale_receipt = sign_policy_lifecycle_log_gossip_receipt(
            &anchor,
            "lifecycle-log",
            &log_key,
            "observer-a",
            31,
            200_000,
            &[7; 32],
        )
        .unwrap();
        assert!(
            verify_policy_lifecycle_log_gossip_quorum(
                &anchor,
                &[PolicyLifecycleLogGossipObservation {
                    schema_version: 1,
                    receipt: stale_receipt,
                    consistency_proof: None,
                }],
                &["org-a".into()],
                &["observer-a".into()],
                &keys[..1],
                2,
                "lifecycle-log",
                &log_key,
                31 + MAX_GOSSIP_QUORUM_RECEIPT_AGE_SECONDS + 1,
            )
            .is_err()
        );
    }
}
