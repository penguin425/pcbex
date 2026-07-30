use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::{
    ApprovalArtifactKind, ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    ApprovalTransparencyLog, SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
    approval_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key,
    approval_transparency_log_sha256,
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state,
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state,
    verify_approval_log_gossip_organization_registry_history_checkpoint_witness_for_trust_state,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Duration,
};

const PROTOCOL: &str =
    "pcbex-approval-public-log-gossip-organization-registry-history-checkpoint-witness-v1";
const ADAPTER: &str = "remote-approval-gossip-registry-history-checkpoint-witness-https-v1";
const QUORUM_CHECKPOINT_DOMAIN: &str = "pcbex-approval-registry-receipt-quorum-log-checkpoint-v1";
const QUORUM_CHECKPOINT_WITNESS_DOMAIN: &str =
    "pcbex-approval-registry-receipt-quorum-log-checkpoint-witness-v1";
const MAXIMUM_QUORUM_CHECKPOINT_WITNESS_AGE_SECONDS: u64 = 86_400;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteApprovalRegistryHistoryCheckpointWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    checkpoint_trust_state: &'a ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalRegistryHistoryCheckpointWitnessReceipt {
    pub schema_version: u32,
    pub adapter: String,
    pub endpoint: String,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub checkpoint_trust_state_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub evaluated_at_unix: u64,
    pub witness_id: String,
    pub witness_public_key: String,
    pub witness_key_trust_state_sha256: Option<String>,
    pub witness_key_generation: Option<u64>,
    pub witnessed_at_unix: u64,
    pub verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumMember {
    pub witness_id: String,
    pub witness_public_key: String,
    pub witness_key_trust_state_sha256: Option<String>,
    pub witness_key_generation: Option<u64>,
    pub receipt_sha256: String,
    #[serde(default)]
    pub request_sha256: Option<String>,
    pub response_sha256: String,
    pub witnessed_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub checkpoint_trust_state_sha256: String,
    pub evaluated_at_unix: u64,
    pub minimum_witnesses: u32,
    pub valid_witnesses: u32,
    pub members: Vec<RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumMember>,
    pub quorum_met: bool,
    #[serde(default)]
    pub approval_log_id: Option<String>,
    #[serde(default)]
    pub approval_log_entry_count: Option<u64>,
    #[serde(default)]
    pub approval_log_head_sha256: Option<String>,
    #[serde(default)]
    pub approval_log_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint {
    pub schema_version: u32,
    pub quorum_report_sha256: String,
    pub registry_id: String,
    pub generation: u64,
    pub registry_checkpoint_sha256: String,
    pub approval_log_id: String,
    pub approval_log_entry_count: u64,
    pub approval_log_head_sha256: String,
    pub approval_log_sha256: String,
    pub minimum_witnesses: u32,
    pub valid_witnesses: u32,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointVerification {
    pub schema_version: u32,
    pub quorum_report_sha256: String,
    pub registry_id: String,
    pub generation: u64,
    pub approval_log_id: String,
    pub approval_log_entry_count: u64,
    pub approval_log_head_sha256: String,
    pub approval_log_sha256: String,
    pub signer_id: String,
    pub public_key: String,
    pub verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness {
    pub schema_version: u32,
    pub checkpoint_sha256: String,
    pub registry_id: String,
    pub generation: u64,
    pub approval_log_id: String,
    pub approval_log_entry_count: u64,
    pub approval_log_head_sha256: String,
    pub approval_log_sha256: String,
    pub witness_id: String,
    pub witnessed_at_unix: u64,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport {
    pub schema_version: u32,
    pub status: String,
    pub checkpoint_sha256: String,
    pub registry_id: String,
    pub generation: u64,
    pub approval_log_id: String,
    pub approval_log_entry_count: u64,
    pub approval_log_head_sha256: String,
    pub approval_log_sha256: String,
    pub evaluated_at_unix: u64,
    pub minimum_witnesses: u32,
    pub valid_witnesses: u32,
    pub witness_ids: Vec<String>,
    pub witness_public_keys: Vec<String>,
    pub quorum_met: bool,
}

pub fn remote_approval_registry_history_checkpoint_witness_receipt_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-approval-gossip-registry-history-checkpoint-witness-receipt-v1.json",
        "title": "pcbex remote approval registry-history checkpoint witness HTTPS receipt",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "registry_id", "generation",
            "checkpoint_sha256", "checkpoint_trust_state_sha256", "request_sha256",
            "response_sha256", "response_bytes", "evaluated_at_unix", "witness_id",
            "witness_public_key", "witness_key_trust_state_sha256",
            "witness_key_generation", "witnessed_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": ADAPTER},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "checkpoint_sha256": digest_schema(),
            "checkpoint_trust_state_sha256": digest_schema(),
            "request_sha256": digest_schema(),
            "response_sha256": digest_schema(),
            "response_bytes": {
                "type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES
            },
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "witness_id": slug_schema(),
            "witness_public_key": key_schema(),
            "witness_key_trust_state_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "witness_key_generation": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0}
                ]
            },
            "witnessed_at_unix": {"type": "integer", "minimum": 0},
            "verified": {"const": true}
        }
    })
}

pub fn remote_approval_registry_history_checkpoint_witness_receipt_quorum_report_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-approval-gossip-registry-history-checkpoint-witness-receipt-quorum-report-v1.json",
        "title": "pcbex verifier-bound remote approval registry-history witness receipt quorum",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "checkpoint_sha256",
            "checkpoint_trust_state_sha256", "evaluated_at_unix",
            "minimum_witnesses", "valid_witnesses", "members", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "checkpoint_sha256": digest_schema(),
            "checkpoint_trust_state_sha256": digest_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": 100},
            "valid_witnesses": {"type": "integer", "minimum": 0, "maximum": 100},
            "members": {
                "type": "array", "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "witness_id", "witness_public_key",
                        "witness_key_trust_state_sha256", "witness_key_generation",
                        "receipt_sha256", "response_sha256", "witnessed_at_unix"
                    ],
                    "properties": {
                        "witness_id": slug_schema(),
                        "witness_public_key": key_schema(),
                        "witness_key_trust_state_sha256": {
                            "oneOf": [{"type": "null"}, digest_schema()]
                        },
                        "witness_key_generation": {
                            "oneOf": [
                                {"type": "null"},
                                {"type": "integer", "minimum": 0}
                            ]
                        },
                        "receipt_sha256": digest_schema(),
                        "request_sha256": {
                            "oneOf": [{"type": "null"}, digest_schema()]
                        },
                        "response_sha256": digest_schema(),
                        "witnessed_at_unix": {"type": "integer", "minimum": 0}
                    }
                }
            },
            "quorum_met": {"type": "boolean"},
            "approval_log_id": {"oneOf": [{"type": "null"}, slug_schema()]},
            "approval_log_entry_count": {
                "oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]
            },
            "approval_log_head_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "approval_log_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            }
        }
    })
}

pub fn signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_json_schema() -> Value
{
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-v1.json",
        "title": "pcbex signed verifier-bound approval receipt quorum log checkpoint",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "quorum_report_sha256", "registry_id", "generation",
            "registry_checkpoint_sha256", "approval_log_id", "approval_log_entry_count",
            "approval_log_head_sha256", "approval_log_sha256", "minimum_witnesses",
            "valid_witnesses", "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "quorum_report_sha256": digest_schema(),
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "registry_checkpoint_sha256": digest_schema(),
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest_schema(),
            "approval_log_sha256": digest_schema(),
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": 100},
            "valid_witnesses": {"type": "integer", "minimum": 2, "maximum": 100},
            "signer_id": slug_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": key_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn remote_approval_registry_history_receipt_quorum_log_checkpoint_verification_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-approval-registry-history-receipt-quorum-log-checkpoint-verification-v1.json",
        "title": "pcbex verifier-bound approval receipt quorum log checkpoint verification",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "quorum_report_sha256", "registry_id", "generation",
            "approval_log_id", "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256", "signer_id", "public_key", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "quorum_report_sha256": digest_schema(),
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest_schema(),
            "approval_log_sha256": digest_schema(),
            "signer_id": slug_schema(),
            "public_key": key_schema(),
            "verified": {"const": true}
        }
    })
}

pub fn signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-v1.json",
        "title": "pcbex independent receipt-quorum log checkpoint witness",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "checkpoint_sha256", "registry_id", "generation",
            "approval_log_id", "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256", "witness_id", "witnessed_at_unix", "algorithm",
            "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "checkpoint_sha256": digest_schema(),
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest_schema(),
            "approval_log_sha256": digest_schema(),
            "witness_id": slug_schema(),
            "witnessed_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "public_key": key_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-approval-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report-v1.json",
        "title": "pcbex independent receipt-quorum checkpoint witness quorum",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "checkpoint_sha256", "registry_id",
            "generation", "approval_log_id", "approval_log_entry_count",
            "approval_log_head_sha256", "approval_log_sha256", "evaluated_at_unix",
            "minimum_witnesses", "valid_witnesses", "witness_ids",
            "witness_public_keys", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"enum": ["witness_quorum_met", "insufficient_witnesses"]},
            "checkpoint_sha256": digest_schema(),
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest_schema(),
            "approval_log_sha256": digest_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": 100},
            "valid_witnesses": {"type": "integer", "minimum": 0, "maximum": 100},
            "witness_ids": {
                "type": "array", "maxItems": 100, "uniqueItems": true,
                "items": slug_schema()
            },
            "witness_public_keys": {
                "type": "array", "maxItems": 100, "uniqueItems": true,
                "items": key_schema()
            },
            "quorum_met": {"type": "boolean"}
        }
    })
}

pub fn parse_remote_approval_registry_history_checkpoint_witness_receipt(
    source: &str,
) -> Result<RemoteApprovalRegistryHistoryCheckpointWitnessReceipt, String> {
    let receipt: RemoteApprovalRegistryHistoryCheckpointWitnessReceipt =
        serde_json::from_str(source)
            .map_err(|error| format!("invalid remote approval history witness receipt: {error}"))?;
    validate_remote_approval_registry_history_checkpoint_witness_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_remote_approval_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1
        || receipt.adapter != ADAPTER
        || !receipt.verified
        || receipt.response_bytes == 0
        || receipt.response_bytes > MAX_RESPONSE_BYTES
        || receipt.witnessed_at_unix > receipt.evaluated_at_unix
    {
        return Err("invalid remote approval history witness receipt invariants".into());
    }
    validate_endpoint(&receipt.endpoint, true)?;
    validate_slug(&receipt.registry_id, "approval registry id")?;
    for (digest, label) in [
        (&receipt.checkpoint_sha256, "checkpoint SHA-256"),
        (
            &receipt.checkpoint_trust_state_sha256,
            "checkpoint trust-state SHA-256",
        ),
        (&receipt.request_sha256, "request SHA-256"),
        (&receipt.response_sha256, "response SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    validate_slug(&receipt.witness_id, "approval history witness id")?;
    let key = decode_hex::<32>(&receipt.witness_public_key, "witness public key")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid approval history witness public key: {error}"))?;
    match (
        &receipt.witness_key_trust_state_sha256,
        receipt.witness_key_generation,
    ) {
        (None, None) => {}
        (Some(digest), Some(_)) => validate_digest(digest, "witness trust-state SHA-256")?,
        _ => return Err("remote approval witness trust-state binding is incomplete".into()),
    }
    Ok(())
}

pub fn parse_remote_approval_registry_history_checkpoint_witness_receipt_quorum_report(
    source: &str,
) -> Result<RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport, String> {
    let report: RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport =
        serde_json::from_str(source)
            .map_err(|error| format!("invalid remote approval receipt quorum report: {error}"))?;
    validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_report(&report)?;
    Ok(report)
}

pub fn validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_report(
    report: &RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || !(2..=100).contains(&report.minimum_witnesses)
        || report.members.len() > 100
        || report.valid_witnesses as usize != report.members.len()
        || report.quorum_met
            != (report.valid_witnesses >= report.minimum_witnesses && report.valid_witnesses > 0)
    {
        return Err("invalid remote approval receipt quorum invariants".into());
    }
    validate_slug(&report.registry_id, "approval registry id")?;
    validate_digest(&report.checkpoint_sha256, "checkpoint SHA-256")?;
    validate_digest(
        &report.checkpoint_trust_state_sha256,
        "checkpoint trust-state SHA-256",
    )?;
    match (
        &report.approval_log_id,
        report.approval_log_entry_count,
        &report.approval_log_head_sha256,
        &report.approval_log_sha256,
    ) {
        (None, None, None, None) => {}
        (Some(log_id), Some(_), Some(head), Some(log_digest)) => {
            validate_slug(log_id, "approval transparency log id")?;
            validate_digest(head, "approval transparency log head SHA-256")?;
            validate_digest(log_digest, "approval transparency log SHA-256")?;
        }
        _ => return Err("remote approval receipt quorum log binding is incomplete".into()),
    }
    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut responses = BTreeSet::new();
    for member in &report.members {
        validate_slug(&member.witness_id, "approval history witness id")?;
        if previous_id.is_some_and(|previous| previous >= member.witness_id.as_str())
            || !ids.insert(member.witness_id.as_str())
            || !keys.insert(member.witness_public_key.as_str())
            || !receipts.insert(member.receipt_sha256.as_str())
            || !responses.insert(member.response_sha256.as_str())
        {
            return Err(
                "remote approval receipt quorum members must be sorted and distinct".into(),
            );
        }
        previous_id = Some(&member.witness_id);
        let key = decode_hex::<32>(&member.witness_public_key, "witness public key")?;
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid approval history witness public key: {error}"))?;
        match (
            &member.witness_key_trust_state_sha256,
            member.witness_key_generation,
        ) {
            (None, None) => {}
            (Some(digest), Some(_)) => validate_digest(digest, "witness trust-state SHA-256")?,
            _ => return Err("remote approval receipt quorum trust binding is incomplete".into()),
        }
        validate_digest(&member.receipt_sha256, "receipt SHA-256")?;
        if let Some(request) = &member.request_sha256 {
            validate_digest(request, "request SHA-256")?;
        }
        validate_digest(&member.response_sha256, "response SHA-256")?;
        if member.witnessed_at_unix > report.evaluated_at_unix {
            return Err("remote approval receipt quorum member is future-dated".into());
        }
    }
    Ok(())
}

pub fn validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_for_log(
    report: &RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
) -> Result<(), String> {
    validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_report(report)?;
    approval_transparency_log_sha256(log)?;
    if !report.quorum_met {
        return Err("remote approval receipt quorum was not met".into());
    }
    let expected_log_sha256 = report
        .approval_log_sha256
        .as_deref()
        .ok_or_else(|| "receipt quorum report is not bound to an approval log".to_string())?;
    if report.approval_log_id.as_deref() != Some(log.log_id.as_str())
        || report.approval_log_entry_count != Some(log.entries.len() as u64)
        || report.approval_log_head_sha256 != log.head_sha256
        || approval_transparency_log_sha256(log)? != expected_log_sha256
    {
        return Err("approval log does not match the receipt quorum log binding".into());
    }
    let suffix_start = log
        .entries
        .len()
        .checked_sub(report.members.len())
        .ok_or_else(|| "approval log has fewer entries than the receipt quorum".to_string())?;
    for (entry, member) in log.entries[suffix_start..].iter().zip(&report.members) {
        if entry.event.artifact_kind
            != ApprovalArtifactKind::RemoteApprovalRegistryHistoryCheckpointWitnessReceipt
            || entry.event.artifact_sha256 != member.receipt_sha256
            || entry.event.subject_id != report.checkpoint_sha256
            || entry.event.request_sha256.as_deref() != member.request_sha256.as_deref()
            || entry.event.session_sha256.as_deref() != Some(member.response_sha256.as_str())
            || entry.event.signer_id.is_some()
            || entry.event.outcome != format!("verified-witness:{}", member.witness_id)
        {
            return Err(
                "approval log suffix does not exactly match the admitted receipt quorum".into(),
            );
        }
    }
    Ok(())
}

pub fn sign_remote_approval_registry_history_receipt_quorum_log_checkpoint(
    report: &RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint, String> {
    validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_for_log(
        report, log,
    )?;
    validate_slug(signer_id, "receipt quorum checkpoint signer id")?;
    let report_bytes = serde_json::to_vec(report)
        .map_err(|error| format!("serializing receipt quorum report: {error}"))?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let mut checkpoint = SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint {
        schema_version: 1,
        quorum_report_sha256: sha256(&report_bytes),
        registry_id: report.registry_id.clone(),
        generation: report.generation,
        registry_checkpoint_sha256: report.checkpoint_sha256.clone(),
        approval_log_id: log.log_id.clone(),
        approval_log_entry_count: log.entries.len() as u64,
        approval_log_head_sha256: log
            .head_sha256
            .clone()
            .ok_or_else(|| "quorum-bound approval log has no head".to_string())?,
        approval_log_sha256: approval_transparency_log_sha256(log)?,
        minimum_witnesses: report.minimum_witnesses,
        valid_witnesses: report.valid_witnesses,
        signer_id: signer_id.to_string(),
        algorithm: "ed25519".into(),
        public_key: encode_hex(&signing_key.verifying_key().to_bytes()),
        signature: String::new(),
    };
    let payload = quorum_checkpoint_payload(&checkpoint)?;
    checkpoint.signature = encode_hex(&signing_key.sign(&payload).to_bytes());
    validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint(&checkpoint)?;
    Ok(checkpoint)
}

pub fn verify_remote_approval_registry_history_receipt_quorum_log_checkpoint(
    report: &RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_public_key: &[u8; 32],
) -> Result<RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointVerification, String> {
    validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_for_log(
        report, log,
    )?;
    validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint(checkpoint)?;
    let report_bytes = serde_json::to_vec(report)
        .map_err(|error| format!("serializing receipt quorum report: {error}"))?;
    if checkpoint.quorum_report_sha256 != sha256(&report_bytes)
        || checkpoint.registry_id != report.registry_id
        || checkpoint.generation != report.generation
        || checkpoint.registry_checkpoint_sha256 != report.checkpoint_sha256
        || checkpoint.approval_log_id != log.log_id
        || checkpoint.approval_log_entry_count != log.entries.len() as u64
        || Some(checkpoint.approval_log_head_sha256.as_str()) != log.head_sha256.as_deref()
        || checkpoint.approval_log_sha256 != approval_transparency_log_sha256(log)?
        || checkpoint.minimum_witnesses != report.minimum_witnesses
        || checkpoint.valid_witnesses != report.valid_witnesses
    {
        return Err("signed receipt quorum checkpoint is bound to different evidence".into());
    }
    let public_key = decode_hex::<32>(&checkpoint.public_key, "receipt quorum checkpoint key")?;
    if &public_key != trusted_public_key {
        return Err("receipt quorum checkpoint key is not trusted".into());
    }
    let signature = decode_hex::<64>(&checkpoint.signature, "receipt quorum checkpoint signature")?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid receipt quorum checkpoint public key: {error}"))?
        .verify_strict(
            &quorum_checkpoint_payload(checkpoint)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| format!("invalid receipt quorum checkpoint signature: {error}"))?;
    Ok(
        RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointVerification {
            schema_version: 1,
            quorum_report_sha256: checkpoint.quorum_report_sha256.clone(),
            registry_id: checkpoint.registry_id.clone(),
            generation: checkpoint.generation,
            approval_log_id: checkpoint.approval_log_id.clone(),
            approval_log_entry_count: checkpoint.approval_log_entry_count,
            approval_log_head_sha256: checkpoint.approval_log_head_sha256.clone(),
            approval_log_sha256: checkpoint.approval_log_sha256.clone(),
            signer_id: checkpoint.signer_id.clone(),
            public_key: checkpoint.public_key.clone(),
            verified: true,
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sign_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness(
    report: &RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witness_id: &str,
    witnessed_at_unix: u64,
    secret_key: &[u8; 32],
) -> Result<SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    verify_remote_approval_registry_history_receipt_quorum_log_checkpoint(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
    )?;
    validate_slug(witness_id, "receipt quorum checkpoint witness id")?;
    if witnessed_at_unix < report.evaluated_at_unix {
        return Err("receipt quorum checkpoint witness predates its quorum report".into());
    }
    let checkpoint_sha256 = signed_receipt_quorum_log_checkpoint_sha256(checkpoint)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let mut witness = SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness {
        schema_version: 1,
        checkpoint_sha256,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        approval_log_id: checkpoint.approval_log_id.clone(),
        approval_log_entry_count: checkpoint.approval_log_entry_count,
        approval_log_head_sha256: checkpoint.approval_log_head_sha256.clone(),
        approval_log_sha256: checkpoint.approval_log_sha256.clone(),
        witness_id: witness_id.to_string(),
        witnessed_at_unix,
        algorithm: "ed25519".into(),
        public_key: encode_hex(&signing_key.verifying_key().to_bytes()),
        signature: String::new(),
    };
    let payload = quorum_checkpoint_witness_payload(&witness)?;
    witness.signature = encode_hex(&signing_key.sign(&payload).to_bytes());
    validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_remote_approval_registry_history_receipt_quorum_log_checkpoint_witnesses(
    report: &RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witnesses: &[SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness],
    trusted_witness_public_keys: &[[u8; 32]],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport, String> {
    verify_remote_approval_registry_history_receipt_quorum_log_checkpoint(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
    )?;
    if !(2..=100).contains(&minimum_witnesses) {
        return Err(
            "receipt quorum checkpoint witness quorum must require 2 to 100 witnesses".into(),
        );
    }
    if witnesses.len() != trusted_witness_public_keys.len() || witnesses.len() > 100 {
        return Err(
            "receipt quorum checkpoint witnesses and trusted keys must be paired and bounded"
                .into(),
        );
    }
    let checkpoint_sha256 = signed_receipt_quorum_log_checkpoint_sha256(checkpoint)?;
    let mut witness_ids = BTreeSet::new();
    let mut witness_public_keys = BTreeSet::new();
    for (witness, trusted_key) in witnesses.iter().zip(trusted_witness_public_keys) {
        verify_receipt_quorum_log_checkpoint_witness(
            checkpoint,
            &checkpoint_sha256,
            witness,
            trusted_key,
            report.evaluated_at_unix,
            evaluated_at_unix,
        )?;
        if !witness_ids.insert(witness.witness_id.clone())
            || !witness_public_keys.insert(encode_hex(trusted_key))
        {
            return Err(
                "receipt quorum checkpoint witnesses must use distinct identities and keys".into(),
            );
        }
    }
    let valid_witnesses = u32::try_from(witnesses.len())
        .map_err(|_| "receipt quorum checkpoint witness count overflow".to_string())?;
    let quorum_met = valid_witnesses >= minimum_witnesses;
    let quorum = RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport {
        schema_version: 1,
        status: if quorum_met {
            "witness_quorum_met"
        } else {
            "insufficient_witnesses"
        }
        .into(),
        checkpoint_sha256,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        approval_log_id: checkpoint.approval_log_id.clone(),
        approval_log_entry_count: checkpoint.approval_log_entry_count,
        approval_log_head_sha256: checkpoint.approval_log_head_sha256.clone(),
        approval_log_sha256: checkpoint.approval_log_sha256.clone(),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses,
        witness_ids: witness_ids.into_iter().collect(),
        witness_public_keys: witness_public_keys.into_iter().collect(),
        quorum_met,
    };
    validate_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
        &quorum,
    )?;
    Ok(quorum)
}

pub fn validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness(
    witness: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness,
) -> Result<(), String> {
    if witness.schema_version != 1
        || witness.algorithm != "ed25519"
        || witness.approval_log_entry_count < 2
    {
        return Err("invalid receipt quorum checkpoint witness invariants".into());
    }
    validate_digest(
        &witness.checkpoint_sha256,
        "receipt quorum checkpoint SHA-256",
    )?;
    validate_slug(&witness.registry_id, "approval registry id")?;
    validate_slug(&witness.approval_log_id, "approval transparency log id")?;
    validate_digest(
        &witness.approval_log_head_sha256,
        "approval log head SHA-256",
    )?;
    validate_digest(&witness.approval_log_sha256, "approval log SHA-256")?;
    validate_slug(&witness.witness_id, "receipt quorum checkpoint witness id")?;
    let public_key = decode_hex::<32>(
        &witness.public_key,
        "receipt quorum checkpoint witness public key",
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid receipt quorum checkpoint witness key: {error}"))?;
    decode_hex::<64>(
        &witness.signature,
        "receipt quorum checkpoint witness signature",
    )?;
    Ok(())
}

pub fn validate_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
    report: &RemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || !(2..=100).contains(&report.minimum_witnesses)
        || report.valid_witnesses as usize != report.witness_ids.len()
        || report.valid_witnesses as usize != report.witness_public_keys.len()
        || report.valid_witnesses > 100
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
        || report.status
            != if report.quorum_met {
                "witness_quorum_met"
            } else {
                "insufficient_witnesses"
            }
    {
        return Err("invalid receipt quorum checkpoint witness quorum invariants".into());
    }
    validate_digest(
        &report.checkpoint_sha256,
        "receipt quorum checkpoint SHA-256",
    )?;
    validate_slug(&report.registry_id, "approval registry id")?;
    validate_slug(&report.approval_log_id, "approval transparency log id")?;
    if report.approval_log_entry_count < 2 {
        return Err("receipt quorum checkpoint witness quorum log is too short".into());
    }
    validate_digest(
        &report.approval_log_head_sha256,
        "approval log head SHA-256",
    )?;
    validate_digest(&report.approval_log_sha256, "approval log SHA-256")?;
    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    for witness_id in &report.witness_ids {
        validate_slug(witness_id, "receipt quorum checkpoint witness id")?;
        if previous_id.is_some_and(|previous| previous >= witness_id.as_str())
            || !ids.insert(witness_id)
        {
            return Err("receipt quorum checkpoint witness ids must be sorted and distinct".into());
        }
        previous_id = Some(witness_id);
    }
    let mut previous_key: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for key in &report.witness_public_keys {
        let bytes = decode_hex::<32>(key, "receipt quorum checkpoint witness public key")?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|error| format!("invalid receipt quorum checkpoint witness key: {error}"))?;
        if previous_key.is_some_and(|previous| previous >= key.as_str()) || !keys.insert(key) {
            return Err(
                "receipt quorum checkpoint witness keys must be sorted and distinct".into(),
            );
        }
        previous_key = Some(key);
    }
    Ok(())
}

fn verify_receipt_quorum_log_checkpoint_witness(
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
    checkpoint_sha256: &str,
    witness: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness,
    trusted_public_key: &[u8; 32],
    earliest_witnessed_at_unix: u64,
    evaluated_at_unix: u64,
) -> Result<(), String> {
    validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness(
        witness,
    )?;
    if witness.checkpoint_sha256 != checkpoint_sha256
        || witness.registry_id != checkpoint.registry_id
        || witness.generation != checkpoint.generation
        || witness.approval_log_id != checkpoint.approval_log_id
        || witness.approval_log_entry_count != checkpoint.approval_log_entry_count
        || witness.approval_log_head_sha256 != checkpoint.approval_log_head_sha256
        || witness.approval_log_sha256 != checkpoint.approval_log_sha256
    {
        return Err("receipt quorum checkpoint witness is bound to different evidence".into());
    }
    if witness.public_key != encode_hex(trusted_public_key) {
        return Err("receipt quorum checkpoint witness key is not trusted".into());
    }
    if witness.witnessed_at_unix < earliest_witnessed_at_unix
        || evaluated_at_unix < witness.witnessed_at_unix
        || evaluated_at_unix - witness.witnessed_at_unix
            > MAXIMUM_QUORUM_CHECKPOINT_WITNESS_AGE_SECONDS
    {
        return Err("receipt quorum checkpoint witness is outside the 24-hour window".into());
    }
    let signature = decode_hex::<64>(
        &witness.signature,
        "receipt quorum checkpoint witness signature",
    )?;
    VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|error| format!("invalid receipt quorum checkpoint witness key: {error}"))?
        .verify_strict(
            &quorum_checkpoint_witness_payload(witness)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| format!("invalid receipt quorum checkpoint witness signature: {error}"))
}

pub fn validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint(
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
) -> Result<(), String> {
    if checkpoint.schema_version != 1
        || checkpoint.algorithm != "ed25519"
        || checkpoint.approval_log_entry_count < 2
        || !(2..=100).contains(&checkpoint.minimum_witnesses)
        || !(2..=100).contains(&checkpoint.valid_witnesses)
        || checkpoint.valid_witnesses < checkpoint.minimum_witnesses
    {
        return Err("invalid signed receipt quorum checkpoint invariants".into());
    }
    validate_slug(&checkpoint.registry_id, "approval registry id")?;
    validate_slug(&checkpoint.approval_log_id, "approval transparency log id")?;
    validate_slug(&checkpoint.signer_id, "receipt quorum checkpoint signer id")?;
    validate_digest(&checkpoint.quorum_report_sha256, "quorum report SHA-256")?;
    validate_digest(
        &checkpoint.registry_checkpoint_sha256,
        "registry checkpoint SHA-256",
    )?;
    validate_digest(
        &checkpoint.approval_log_head_sha256,
        "approval log head SHA-256",
    )?;
    validate_digest(&checkpoint.approval_log_sha256, "approval log SHA-256")?;
    let key = decode_hex::<32>(&checkpoint.public_key, "receipt quorum checkpoint key")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid receipt quorum checkpoint public key: {error}"))?;
    decode_hex::<64>(&checkpoint.signature, "receipt quorum checkpoint signature")?;
    Ok(())
}

fn quorum_checkpoint_payload(
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
) -> Result<Vec<u8>, String> {
    let body = json!({
        "schema_version": checkpoint.schema_version,
        "quorum_report_sha256": checkpoint.quorum_report_sha256,
        "registry_id": checkpoint.registry_id,
        "generation": checkpoint.generation,
        "registry_checkpoint_sha256": checkpoint.registry_checkpoint_sha256,
        "approval_log_id": checkpoint.approval_log_id,
        "approval_log_entry_count": checkpoint.approval_log_entry_count,
        "approval_log_head_sha256": checkpoint.approval_log_head_sha256,
        "approval_log_sha256": checkpoint.approval_log_sha256,
        "minimum_witnesses": checkpoint.minimum_witnesses,
        "valid_witnesses": checkpoint.valid_witnesses,
        "signer_id": checkpoint.signer_id,
        "algorithm": checkpoint.algorithm
    });
    let mut payload = QUORUM_CHECKPOINT_DOMAIN.as_bytes().to_vec();
    payload.push(0);
    payload.extend(
        serde_json::to_vec(&body)
            .map_err(|error| format!("serializing receipt quorum checkpoint payload: {error}"))?,
    );
    Ok(payload)
}

fn signed_receipt_quorum_log_checkpoint_sha256(
    checkpoint: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpoint,
) -> Result<String, String> {
    validate_signed_remote_approval_registry_history_receipt_quorum_log_checkpoint(checkpoint)?;
    serde_json::to_vec(checkpoint)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("serializing receipt quorum checkpoint: {error}"))
}

fn quorum_checkpoint_witness_payload(
    witness: &SignedRemoteApprovalRegistryHistoryReceiptQuorumLogCheckpointWitness,
) -> Result<Vec<u8>, String> {
    let body = json!({
        "schema_version": witness.schema_version,
        "checkpoint_sha256": witness.checkpoint_sha256,
        "registry_id": witness.registry_id,
        "generation": witness.generation,
        "approval_log_id": witness.approval_log_id,
        "approval_log_entry_count": witness.approval_log_entry_count,
        "approval_log_head_sha256": witness.approval_log_head_sha256,
        "approval_log_sha256": witness.approval_log_sha256,
        "witness_id": witness.witness_id,
        "witnessed_at_unix": witness.witnessed_at_unix,
        "algorithm": witness.algorithm
    });
    let mut payload = QUORUM_CHECKPOINT_WITNESS_DOMAIN.as_bytes().to_vec();
    payload.push(0);
    payload.extend(
        serde_json::to_vec(&body)
            .map_err(|error| format!("serializing receipt quorum checkpoint witness: {error}"))?,
    );
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
pub fn request_remote_approval_registry_history_checkpoint_witness(
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
        Vec<u8>,
    ),
    String,
> {
    request_remote(
        checkpoint_state,
        endpoint,
        trusted_public_key,
        None,
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn request_remote_approval_registry_history_checkpoint_witness_with_trust_state(
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    endpoint: &str,
    witness_trust_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
        Vec<u8>,
    ),
    String,
> {
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        witness_trust_state,
    )?;
    let key =
        approval_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            witness_trust_state,
        )?;
    let encoded = serde_json::to_vec(witness_trust_state)
        .map_err(|error| format!("serializing approval witness trust state: {error}"))?;
    let result = request_remote(
        checkpoint_state,
        endpoint,
        &key,
        Some((sha256(&encoded), witness_trust_state.generation)),
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )?;
    if result.0.witness_id != witness_trust_state.witness_id {
        return Err("remote approval history witness identity does not match trust state".into());
    }
    Ok(result)
}

pub fn verify_remote_approval_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness, String> {
    verify_remote_receipt(
        receipt,
        checkpoint_state,
        response_bytes,
        trusted_public_key,
        None,
        evaluated_at_unix,
    )
}

pub fn verify_remote_approval_registry_history_checkpoint_witness_receipt_with_trust_state(
    receipt: &RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    response_bytes: &[u8],
    witness_trust_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    evaluated_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness, String> {
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        witness_trust_state,
    )?;
    let trusted_public_key =
        approval_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            witness_trust_state,
        )?;
    let trust_state_bytes = serde_json::to_vec(witness_trust_state)
        .map_err(|error| format!("serializing approval witness trust state: {error}"))?;
    let witness = verify_remote_receipt(
        receipt,
        checkpoint_state,
        response_bytes,
        &trusted_public_key,
        Some((sha256(&trust_state_bytes), witness_trust_state.generation)),
        evaluated_at_unix,
    )?;
    if witness.witness_id != witness_trust_state.witness_id {
        return Err("remote approval history witness identity does not match trust state".into());
    }
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_remote_approval_registry_history_checkpoint_witness_receipt_quorum(
    receipts: &[RemoteApprovalRegistryHistoryCheckpointWitnessReceipt],
    response_documents: &[Vec<u8>],
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    trusted_witnesses: &[(String, [u8; 32])],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteApprovalRegistryHistoryCheckpointWitnessReceipt>,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    ),
    String,
> {
    if receipts.len() != trusted_witnesses.len() {
        return Err("remote approval receipt and trusted witness counts must match".into());
    }
    let trusted = trusted_witnesses
        .iter()
        .map(|(id, key)| {
            validate_slug(id, "approval history witness id")?;
            Ok((id.as_str(), key))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if trusted.len() != trusted_witnesses.len() {
        return Err("remote approval receipt quorum repeats a trusted witness identity".into());
    }
    verify_remote_receipt_quorum(
        receipts,
        response_documents,
        checkpoint_state,
        minimum_witnesses,
        evaluated_at_unix,
        |receipt, response| {
            let key = trusted.get(receipt.witness_id.as_str()).ok_or_else(|| {
                "remote approval receipt quorum witness identity is untrusted".to_string()
            })?;
            let witness = verify_remote_approval_registry_history_checkpoint_witness_receipt(
                receipt,
                checkpoint_state,
                response,
                key,
                evaluated_at_unix,
            )?;
            if witness.witness_id != receipt.witness_id {
                return Err("remote approval receipt quorum witness identity mismatch".into());
            }
            Ok(())
        },
    )
}

pub fn verify_remote_approval_registry_history_checkpoint_witness_receipt_quorum_with_trust_states(
    receipts: &[RemoteApprovalRegistryHistoryCheckpointWitnessReceipt],
    response_documents: &[Vec<u8>],
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    witness_trust_states: &[
        ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState
    ],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteApprovalRegistryHistoryCheckpointWitnessReceipt>,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    ),
    String,
> {
    if receipts.len() != witness_trust_states.len() {
        return Err("remote approval receipt and witness trust-state counts must match".into());
    }
    let trust_states = witness_trust_states
        .iter()
        .map(|state| {
            validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
                state,
            )?;
            Ok((state.witness_id.as_str(), state))
        })
        .collect::<Result<BTreeMap<_, _>, String>>()?;
    if trust_states.len() != witness_trust_states.len() {
        return Err("remote approval receipt quorum repeats a witness trust identity".into());
    }
    verify_remote_receipt_quorum(
        receipts,
        response_documents,
        checkpoint_state,
        minimum_witnesses,
        evaluated_at_unix,
        |receipt, response| {
            let state = trust_states
                .get(receipt.witness_id.as_str())
                .ok_or_else(|| {
                    "remote approval receipt quorum witness trust state is absent".to_string()
                })?;
            verify_remote_approval_registry_history_checkpoint_witness_receipt_with_trust_state(
                receipt,
                checkpoint_state,
                response,
                state,
                evaluated_at_unix,
            )?;
            Ok(())
        },
    )
}

fn verify_remote_receipt_quorum(
    receipts: &[RemoteApprovalRegistryHistoryCheckpointWitnessReceipt],
    response_documents: &[Vec<u8>],
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
    mut verify: impl FnMut(
        &RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
        &[u8],
    ) -> Result<(), String>,
) -> Result<
    (
        Vec<RemoteApprovalRegistryHistoryCheckpointWitnessReceipt>,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    ),
    String,
> {
    if !(2..=100).contains(&minimum_witnesses) {
        return Err("remote approval receipt quorum minimum must be 2..=100".into());
    }
    if receipts.is_empty() || receipts.len() > 100 || receipts.len() != response_documents.len() {
        return Err("remote approval receipt quorum input count is invalid".into());
    }
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state(
        checkpoint_state,
    )?;
    let checkpoint_bytes = serde_json::to_vec(checkpoint_state)
        .map_err(|error| format!("serializing approval checkpoint trust state: {error}"))?;
    let mut verified = Vec::with_capacity(receipts.len());
    for (receipt, response) in receipts.iter().zip(response_documents) {
        verify(receipt, response)?;
        let receipt_bytes = serde_json::to_vec(receipt)
            .map_err(|error| format!("serializing remote approval receipt: {error}"))?;
        verified.push((
            receipt.clone(),
            RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumMember {
                witness_id: receipt.witness_id.clone(),
                witness_public_key: receipt.witness_public_key.clone(),
                witness_key_trust_state_sha256: receipt.witness_key_trust_state_sha256.clone(),
                witness_key_generation: receipt.witness_key_generation,
                receipt_sha256: sha256(&receipt_bytes),
                request_sha256: Some(receipt.request_sha256.clone()),
                response_sha256: receipt.response_sha256.clone(),
                witnessed_at_unix: receipt.witnessed_at_unix,
            },
        ));
    }
    verified.sort_by(|left, right| left.1.witness_id.cmp(&right.1.witness_id));
    let members = verified
        .iter()
        .map(|(_, member)| member.clone())
        .collect::<Vec<_>>();
    let valid_witnesses = u32::try_from(members.len())
        .map_err(|_| "remote approval receipt quorum count overflow".to_string())?;
    let report = RemoteApprovalRegistryHistoryCheckpointWitnessReceiptQuorumReport {
        schema_version: 1,
        registry_id: checkpoint_state.registry_id.clone(),
        generation: checkpoint_state.accepted_generation,
        checkpoint_sha256: checkpoint_state.checkpoint_sha256.clone(),
        checkpoint_trust_state_sha256: sha256(&checkpoint_bytes),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses,
        members,
        quorum_met: valid_witnesses >= minimum_witnesses,
        approval_log_id: None,
        approval_log_entry_count: None,
        approval_log_head_sha256: None,
        approval_log_sha256: None,
    };
    validate_remote_approval_registry_history_checkpoint_witness_receipt_quorum_report(&report)?;
    Ok((
        verified.into_iter().map(|(receipt, _)| receipt).collect(),
        report,
    ))
}

fn verify_remote_receipt(
    receipt: &RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    witness_trust_binding: Option<(String, u64)>,
    evaluated_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness, String> {
    validate_remote_approval_registry_history_checkpoint_witness_receipt(receipt)?;
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state(
        checkpoint_state,
    )?;
    let checkpoint_bytes = serde_json::to_vec(checkpoint_state)
        .map_err(|error| format!("serializing approval checkpoint trust state: {error}"))?;
    let request_bytes =
        serde_json::to_vec(&RemoteApprovalRegistryHistoryCheckpointWitnessRequest {
            schema_version: 1,
            protocol: PROTOCOL,
            checkpoint_trust_state: checkpoint_state,
        })
        .map_err(|error| format!("serializing remote approval history request: {error}"))?;
    if receipt.registry_id != checkpoint_state.registry_id
        || receipt.generation != checkpoint_state.accepted_generation
        || receipt.checkpoint_sha256 != checkpoint_state.checkpoint_sha256
        || receipt.checkpoint_trust_state_sha256 != sha256(&checkpoint_bytes)
        || receipt.request_sha256 != sha256(&request_bytes)
    {
        return Err(
            "remote approval history receipt is bound to different checkpoint evidence".into(),
        );
    }
    if evaluated_at_unix < receipt.evaluated_at_unix {
        return Err("remote approval history receipt is future-dated at admission".into());
    }
    if response_bytes.is_empty()
        || response_bytes.len() as u64 > MAX_RESPONSE_BYTES
        || receipt.response_bytes != response_bytes.len() as u64
        || receipt.response_sha256 != sha256(response_bytes)
    {
        return Err("remote approval history receipt response binding is invalid".into());
    }
    let witness: SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness =
        serde_json::from_slice(response_bytes).map_err(|error| {
            format!("invalid retained remote approval history response: {error}")
        })?;
    if receipt.witness_id != witness.witness_id
        || receipt.witness_public_key != witness.public_key
        || receipt.witnessed_at_unix != witness.witnessed_at_unix
    {
        return Err("remote approval history receipt describes different witness evidence".into());
    }
    let expected_binding = witness_trust_binding
        .map(|(digest, generation)| (Some(digest), Some(generation)))
        .unwrap_or((None, None));
    if (
        receipt.witness_key_trust_state_sha256.clone(),
        receipt.witness_key_generation,
    ) != expected_binding
    {
        return Err("remote approval history receipt witness trust binding is invalid".into());
    }
    verify_approval_log_gossip_organization_registry_history_checkpoint_witness_for_trust_state(
        checkpoint_state,
        &witness,
        trusted_public_key,
        evaluated_at_unix,
    )?;
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
fn request_remote(
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    witness_trust_binding: Option<(String, u64)>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
        Vec<u8>,
    ),
    String,
> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err("remote approval history witness timeout must be 1..=600 seconds".into());
    }
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state(
        checkpoint_state,
    )?;
    validate_endpoint(endpoint, allow_http_loopback)?;
    let request = RemoteApprovalRegistryHistoryCheckpointWitnessRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        checkpoint_trust_state: checkpoint_state,
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("serializing remote approval history request: {error}"))?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .build();
    let agent: ureq::Agent = config.into();
    let mut call = agent
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    if let Some(variable) = bearer_token_env {
        validate_env_name(variable)?;
        let token = env::var(variable)
            .map_err(|_| format!("bearer-token environment {variable} is unset"))?;
        if token.trim().is_empty() {
            return Err(format!("bearer-token environment {variable} is empty"));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .send(request_bytes.clone())
        .map_err(|error| format!("remote approval history HTTPS request failed: {error}"))?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote approval history witness returned HTTP {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err("remote approval history response must be application/json".into());
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| format!("reading bounded remote approval history response: {error}"))?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("remote approval history response exceeds 1 MiB".into());
    }
    let witness: SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness =
        serde_json::from_slice(&response_bytes)
            .map_err(|error| format!("invalid remote approval history witness JSON: {error}"))?;
    verify_approval_log_gossip_organization_registry_history_checkpoint_witness_for_trust_state(
        checkpoint_state,
        &witness,
        trusted_public_key,
        evaluated_at_unix,
    )?;
    let checkpoint_bytes = serde_json::to_vec(checkpoint_state)
        .map_err(|error| format!("serializing approval checkpoint trust state: {error}"))?;
    let (trust_digest, trust_generation) = witness_trust_binding
        .map(|(digest, generation)| (Some(digest), Some(generation)))
        .unwrap_or((None, None));
    let receipt = RemoteApprovalRegistryHistoryCheckpointWitnessReceipt {
        schema_version: 1,
        adapter: ADAPTER.into(),
        endpoint: endpoint.into(),
        registry_id: checkpoint_state.registry_id.clone(),
        generation: checkpoint_state.accepted_generation,
        checkpoint_sha256: checkpoint_state.checkpoint_sha256.clone(),
        checkpoint_trust_state_sha256: sha256(&checkpoint_bytes),
        request_sha256: sha256(&request_bytes),
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        evaluated_at_unix,
        witness_id: witness.witness_id.clone(),
        witness_public_key: witness.public_key.clone(),
        witness_key_trust_state_sha256: trust_digest,
        witness_key_generation: trust_generation,
        witnessed_at_unix: witness.witnessed_at_unix,
        verified: true,
    };
    validate_remote_approval_registry_history_checkpoint_witness_receipt(&receipt)?;
    Ok((witness, receipt, response_bytes))
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint
        .parse()
        .map_err(|error| format!("invalid remote approval history endpoint: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "remote approval history endpoint requires a scheme".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "remote approval history endpoint requires an authority".to_string())?;
    if authority.as_str().contains('@') || uri.query().is_some() {
        return Err("remote approval history endpoint forbids userinfo and query".into());
    }
    if scheme == "https" {
        return Ok(());
    }
    let host = uri.host().unwrap_or_default();
    let loopback = host == "localhost"
        || host == "127.0.0.1"
        || host == "[::1]"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if scheme == "http" && allow_http_loopback && loopback {
        Ok(())
    } else {
        Err("remote approval history witness endpoint must use HTTPS".into())
    }
}

fn validate_env_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("bearer-token environment name is invalid".into());
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(format!("{label} is invalid"))
    }
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    decode_hex::<32>(value, label).map(|_| ())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be lowercase hexadecimal"));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]*$"
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn key_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_receipts_and_rejects_unsafe_transport_configuration() {
        assert_eq!(
            remote_approval_registry_history_checkpoint_witness_receipt_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            remote_approval_registry_history_checkpoint_witness_receipt_quorum_report_json_schema()
                ["additionalProperties"],
            false
        );
        assert_eq!(
            remote_approval_registry_history_checkpoint_witness_receipt_quorum_report_json_schema()
                ["properties"]["members"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            remote_approval_registry_history_receipt_quorum_log_checkpoint_verification_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            signed_remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            remote_approval_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema(
            )["additionalProperties"],
            false
        );
        assert!(validate_endpoint("https://witness.example/v1/history", false).is_ok());
        assert!(
            validate_endpoint("https://witness.example/v1/history?token=secret", false).is_err()
        );
        assert!(validate_endpoint("https://secret@witness.example/v1/history", false).is_err());
        assert!(validate_endpoint("http://example.com/v1/history", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/history", false).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/history", true).is_ok());
        assert!(validate_env_name("PCBEX_APPROVAL_HISTORY_WITNESS_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
    }
}
