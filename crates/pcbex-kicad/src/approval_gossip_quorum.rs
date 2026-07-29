use crate::{
    ApprovalLogAnchorProof, ApprovalLogConsistencyProof, SignedApprovalLogGossipReceipt,
    approval_log_consistency_proof_json_schema, approval_public_log_tree_head_sha256,
    signed_approval_log_gossip_receipt_json_schema, validate_approval_log_anchor_proof,
    validate_approval_log_gossip_receipt, verify_approval_log_gossip_receipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const MAX_GOSSIP_OBSERVATIONS: usize = 100;
const MAX_QUORUM_RECEIPT_AGE_SECONDS: u64 = 24 * 60 * 60;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipObservation {
    pub schema_version: u32,
    pub receipt: SignedApprovalLogGossipReceipt,
    pub consistency_proof: Option<ApprovalLogConsistencyProof>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipQuorumMember {
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
pub struct ApprovalLogGossipQuorumReport {
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
    pub members: Vec<ApprovalLogGossipQuorumMember>,
    pub all_consistent: bool,
    pub quorum_met: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_approval_log_gossip_quorum(
    local_anchor: &ApprovalLogAnchorProof,
    observations: &[ApprovalLogGossipObservation],
    organization_ids: &[String],
    trusted_observer_ids: &[String],
    trusted_observer_public_keys: &[[u8; 32]],
    minimum_organizations: u32,
    trusted_log_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<ApprovalLogGossipQuorumReport, String> {
    validate_approval_log_anchor_proof(local_anchor)?;
    if !(2..=MAX_GOSSIP_OBSERVATIONS as u32).contains(&minimum_organizations) {
        return Err("approval gossip quorum must require 2 to 100 organizations".into());
    }
    if observations.is_empty()
        || observations.len() > MAX_GOSSIP_OBSERVATIONS
        || observations.len() != organization_ids.len()
        || observations.len() != trusted_observer_ids.len()
        || observations.len() != trusted_observer_public_keys.len()
    {
        return Err(
            "approval gossip observations and trusted observer evidence must be non-empty, paired, and bounded"
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
        validate_approval_log_gossip_observation(observation)?;
        validate_slug(organization_id, "approval gossip organization id")?;
        validate_slug(observer_id, "trusted approval gossip observer id")?;
        let report = verify_approval_log_gossip_receipt(
            local_anchor,
            &observation.receipt,
            observation.consistency_proof.as_ref(),
            trusted_log_public_key,
            observer_id,
            observer_key,
            evaluated_at_unix,
        )?;
        if evaluated_at_unix - report.received_at_unix > MAX_QUORUM_RECEIPT_AGE_SECONDS {
            return Err(
                "approval gossip quorum receipt is older than the 24-hour quorum window".into(),
            );
        }
        let key = hex_encode(observer_key);
        if !organizations.insert(organization_id.clone()) {
            return Err("approval gossip quorum requires distinct organizations".into());
        }
        if !observers.insert(observer_id.clone()) {
            return Err("approval gossip quorum requires distinct observer identities".into());
        }
        if !keys.insert(key.clone()) {
            return Err("approval gossip quorum requires distinct observer keys".into());
        }
        if !receipts.insert(report.gossip_receipt_sha256.clone()) {
            return Err("approval gossip quorum rejects duplicate receipts".into());
        }
        members.push(ApprovalLogGossipQuorumMember {
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
    let valid_observations =
        u32::try_from(members.len()).map_err(|_| "approval gossip observation count overflow")?;
    let distinct_organizations = u32::try_from(organizations.len())
        .map_err(|_| "approval gossip organization count overflow")?;
    let quorum_met = distinct_organizations >= minimum_organizations;
    let head = &local_anchor.tree_head;
    let report = ApprovalLogGossipQuorumReport {
        schema_version: 1,
        status: if quorum_met {
            "gossip_quorum_met"
        } else {
            "insufficient_organizations"
        }
        .into(),
        log_id: head.log_id.clone(),
        local_tree_head_sha256: approval_public_log_tree_head_sha256(head)?,
        local_tree_size: head.tree_size,
        local_root_sha256: head.root_sha256.clone(),
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
    validate_approval_log_gossip_quorum_report(&report)?;
    Ok(report)
}

pub fn validate_approval_log_gossip_observation(
    observation: &ApprovalLogGossipObservation,
) -> Result<(), String> {
    if observation.schema_version != 1 {
        return Err("unsupported approval gossip observation".into());
    }
    validate_approval_log_gossip_receipt(&observation.receipt)?;
    Ok(())
}

pub fn validate_approval_log_gossip_quorum_report(
    report: &ApprovalLogGossipQuorumReport,
) -> Result<(), String> {
    let count = usize::try_from(report.valid_observations)
        .map_err(|_| "approval gossip observation count overflow")?;
    let quorum_met = report.distinct_organizations >= report.minimum_organizations;
    if report.schema_version != 1
        || !(2..=MAX_GOSSIP_OBSERVATIONS as u32).contains(&report.minimum_organizations)
        || count == 0
        || count > MAX_GOSSIP_OBSERVATIONS
        || count != report.members.len()
        || report.distinct_organizations != report.valid_observations
        || report.quorum_met != quorum_met
        || report.status
            != if quorum_met {
                "gossip_quorum_met"
            } else {
                "insufficient_organizations"
            }
        || !report.all_consistent
        || report.local_tree_size == 0
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
        return Err("invalid approval gossip quorum invariants".into());
    }
    validate_slug(&report.log_id, "approval gossip log id")?;
    validate_digest(&report.local_tree_head_sha256, "local tree-head SHA-256")?;
    validate_digest(&report.local_root_sha256, "local root SHA-256")?;
    let mut organizations = BTreeSet::new();
    let mut observers = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for member in &report.members {
        validate_slug(&member.organization_id, "approval gossip organization id")?;
        validate_slug(&member.observer_id, "approval gossip observer id")?;
        validate_digest(&member.observer_public_key, "approval gossip observer key")?;
        validate_digest(
            &member.gossip_receipt_sha256,
            "approval gossip receipt SHA-256",
        )?;
        validate_digest(
            &member.observed_tree_head_sha256,
            "observed tree-head SHA-256",
        )?;
        validate_digest(&member.observed_root_sha256, "observed root SHA-256")?;
        if member.observed_tree_size == 0
            || !matches!(
                member.relationship.as_str(),
                "same_tree" | "observed_precedes_local" | "local_precedes_observed"
            )
            || (member.relationship == "same_tree") != member.consistency_proof_sha256.is_none()
            || member.received_at_unix > report.evaluated_at_unix
            || report.evaluated_at_unix > member.expires_at_unix
            || report.evaluated_at_unix - member.received_at_unix > MAX_QUORUM_RECEIPT_AGE_SECONDS
        {
            return Err("invalid approval gossip quorum member".into());
        }
        if let Some(digest) = &member.consistency_proof_sha256 {
            validate_digest(digest, "approval gossip consistency proof SHA-256")?;
        }
        let order = (member.organization_id.as_str(), member.observer_id.as_str());
        if previous.is_some_and(|value| value >= order)
            || !organizations.insert(&member.organization_id)
            || !observers.insert(&member.observer_id)
            || !keys.insert(&member.observer_public_key)
            || !receipts.insert(&member.gossip_receipt_sha256)
        {
            return Err("approval gossip quorum members must be sorted and distinct".into());
        }
        previous = Some(order);
    }
    Ok(())
}

pub fn approval_log_gossip_quorum_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let slug = json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"});
    let member = json!({
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
            "observed_tree_size": {"type": "integer", "minimum": 1, "maximum": 100000},
            "observed_root_sha256": digest.clone(),
            "relationship": {"enum": ["same_tree", "observed_precedes_local", "local_precedes_observed"]},
            "consistency_proof_sha256": {"oneOf": [digest.clone(), {"type": "null"}]},
            "received_at_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-gossip-quorum-report-v1.json",
        "title": "pcbex approval public-log gossip quorum",
        "type": "object", "additionalProperties": false,
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
            "log_id": slug.clone(),
            "local_tree_head_sha256": digest.clone(),
            "local_tree_size": {"type": "integer", "minimum": 1, "maximum": 100000},
            "local_root_sha256": digest.clone(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "minimum_organizations": {"type": "integer", "minimum": 2, "maximum": 100},
            "valid_observations": {"type": "integer", "minimum": 1, "maximum": 100},
            "distinct_organizations": {"type": "integer", "minimum": 1, "maximum": 100},
            "freshest_received_at_unix": {"type": "integer", "minimum": 0},
            "earliest_expires_at_unix": {"type": "integer", "minimum": 1},
            "members": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": member
            },
            "all_consistent": {"const": true},
            "quorum_met": {"type": "boolean"}
        }
    })
}

pub fn approval_log_gossip_observation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-gossip-observation-v1.json",
        "title": "pcbex approval public-log gossip observation",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "receipt", "consistency_proof"],
        "properties": {
            "schema_version": {"const": 1},
            "receipt": signed_approval_log_gossip_receipt_json_schema(),
            "consistency_proof": {
                "oneOf": [
                    {"type": "null"},
                    approval_log_consistency_proof_json_schema()
                ]
            }
        }
    })
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit());
    valid
        .then_some(())
        .ok_or_else(|| format!("invalid {label}"))
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(())
    .ok_or_else(|| format!("{label} must be 64 lowercase hexadecimal digits"))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        create_approval_log_anchor_proof, new_approval_transparency_log,
        sign_approval_log_checkpoint, sign_approval_log_gossip_receipt,
        signed_approval_log_checkpoint_sha256,
    };
    use ed25519_dalek::SigningKey;

    fn fixture() -> (ApprovalLogAnchorProof, [u8; 32]) {
        let log = new_approval_transparency_log("approvals").unwrap();
        let checkpoint = sign_approval_log_checkpoint(&log, "origin", &[1; 32]).unwrap();
        let digest = signed_approval_log_checkpoint_sha256(&checkpoint).unwrap();
        let anchor = create_approval_log_anchor_proof(
            &checkpoint,
            &[digest],
            0,
            "public-approvals",
            100,
            &[9; 32],
        )
        .unwrap();
        let log_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        (anchor, log_key)
    }

    #[test]
    fn requires_distinct_fresh_organizations() {
        let (anchor, log_key) = fixture();
        let secrets = [[7_u8; 32], [8_u8; 32]];
        let observations = secrets
            .iter()
            .enumerate()
            .map(|(index, secret)| ApprovalLogGossipObservation {
                schema_version: 1,
                receipt: sign_approval_log_gossip_receipt(
                    &anchor,
                    &log_key,
                    &format!("observer-{index}"),
                    101,
                    200,
                    secret,
                )
                .unwrap(),
                consistency_proof: None,
            })
            .collect::<Vec<_>>();
        let keys = secrets
            .iter()
            .map(|secret| SigningKey::from_bytes(secret).verifying_key().to_bytes())
            .collect::<Vec<_>>();
        let report = verify_approval_log_gossip_quorum(
            &anchor,
            &observations,
            &["org-a".into(), "org-b".into()],
            &["observer-0".into(), "observer-1".into()],
            &keys,
            2,
            &log_key,
            150,
        )
        .unwrap();
        assert!(report.quorum_met);
        assert_eq!(report.distinct_organizations, 2);

        assert!(
            verify_approval_log_gossip_quorum(
                &anchor,
                &observations,
                &["org-a".into(), "org-a".into()],
                &["observer-0".into(), "observer-1".into()],
                &keys,
                2,
                &log_key,
                150,
            )
            .is_err()
        );
    }

    #[test]
    fn reports_insufficient_organizations_without_weakening_verification() {
        let (anchor, log_key) = fixture();
        let observer_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let observation = ApprovalLogGossipObservation {
            schema_version: 1,
            receipt: sign_approval_log_gossip_receipt(
                &anchor,
                &log_key,
                "observer-a",
                101,
                200,
                &[8; 32],
            )
            .unwrap(),
            consistency_proof: None,
        };
        let report = verify_approval_log_gossip_quorum(
            &anchor,
            &[observation],
            &["org-a".into()],
            &["observer-a".into()],
            &[observer_key],
            2,
            &log_key,
            150,
        )
        .unwrap();
        assert!(!report.quorum_met);
        assert_eq!(report.status, "insufficient_organizations");
    }

    #[test]
    fn schema_is_closed() {
        let schema = approval_log_gossip_quorum_report_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["members"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            approval_log_gossip_observation_json_schema()["additionalProperties"],
            false
        );
    }
}
