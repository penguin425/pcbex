//! Bounded remote acquisition for one independent final-checkpoint witness.
//!
//! The v1.526 boundary preserves the v1.521 report, v1.523 checkpoint, v1.524
//! witness, and v1.525 trust-state wire contracts. It production-verifies the
//! complete public evidence before credential access or network I/O, sends one
//! bounded no-redirect HTTPS request, verifies the unchanged v1.524 response,
//! and emits a credential-free receipt that can replay the same decision
//! offline.
//!
//! The v1.529 boundary replays every retained input at an independent
//! admission time before emitting the unchanged v1.528 event. The v1.530
//! boundary verifies one shared checkpoint context and a bounded set of exact,
//! uniformly trusted receipt/response bindings, invokes the production witness
//! quorum once, sorts members by identity, and binds the unchanged event suffix
//! plus complete destination log to a closed report.
//!
//! A receipt records selected endpoint and evaluation metadata. It does not
//! prove trusted time, endpoint legal identity or availability, independent
//! operation, protected key custody, global publication, or non-equivocation.

use crate::factory_release_state_transparency_external_gossip_registry::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION;
use crate::factory_release_state_transparency_external_gossip_registry_checkpoint::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES;
use crate::remote_factory_release_final_checkpoint_witness::{
    MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES,
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
    parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state,
    parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness,
    remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses_after_checkpoint_verification,
};
use crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::{
    MAX_TIMESTAMP,
    RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint, decode_hex,
    digest_schema, parse_canonical, parse_remote_receipt_quorum_approval_log,
    parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report,
    parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint,
    render_bounded, sha256, slug_schema, validate_digest, validate_endpoint,
    validate_env_name, validate_nonweak_public_key,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint,
};
use pcbex_kicad::{
    ApprovalArtifactKind, ApprovalTransparencyLog, approval_transparency_log_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Duration,
};

const PROTOCOL: &str = "pcbex-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-v1";
const ADAPTER: &str = "remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-https-v1";
const MAX_REQUEST_BYTES: u64 = 129 * 1024 * 1024;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_ENV_NAME_BYTES: usize = 128;
const MAX_BEARER_TOKEN_BYTES: usize = 8 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAXIMUM_WITNESS_AGE_SECONDS: u64 = 86_400;

pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    expected_witness_id: &'a str,
    expected_witness_public_key: String,
    witness_key_trust_state_sha256: Option<&'a str>,
    witness_key_generation: Option<u64>,
    quorum_report: &'a RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    approval_log: &'a ApprovalTransparencyLog,
    checkpoint: &'a SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt
{
    pub(crate) schema_version: u32,
    pub(crate) adapter: String,
    pub(crate) endpoint: String,
    pub(crate) final_checkpoint_witness_receipt_quorum_report_sha256: String,
    pub(crate) final_checkpoint_witness_receipt_quorum_report_source_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) registry_checkpoint_sha256: String,
    pub(crate) receipt_quorum_checkpoint_sha256: String,
    pub(crate) checkpoint_witness_receipt_quorum_checkpoint_sha256: String,
    pub(crate) final_admission_log_id: String,
    pub(crate) final_admission_log_entry_count: u64,
    pub(crate) final_admission_log_head_sha256: String,
    pub(crate) final_admission_log_sha256: String,
    pub(crate) final_admission_log_source_sha256: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) checkpoint_source_sha256: String,
    pub(crate) checkpoint_public_key: String,
    pub(crate) request_sha256: String,
    pub(crate) response_sha256: String,
    pub(crate) response_bytes: u64,
    pub(crate) witness_sha256: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) witness_id: String,
    pub(crate) witness_public_key: String,
    pub(crate) witness_key_trust_state_sha256: Option<String>,
    pub(crate) witness_key_generation: Option<u64>,
    pub(crate) witnessed_at_unix: u64,
    pub(crate) verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumMember
{
    pub(crate) witness_id: String,
    pub(crate) witness_public_key: String,
    pub(crate) witness_key_trust_state_sha256: Option<String>,
    pub(crate) witness_key_generation: Option<u64>,
    pub(crate) receipt_sha256: String,
    pub(crate) request_sha256: String,
    pub(crate) response_sha256: String,
    pub(crate) witness_sha256: String,
    pub(crate) witnessed_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport
{
    pub(crate) schema_version: u32,
    pub(crate) final_checkpoint_witness_receipt_quorum_report_sha256: String,
    pub(crate) final_checkpoint_witness_receipt_quorum_report_source_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) registry_checkpoint_sha256: String,
    pub(crate) receipt_quorum_checkpoint_sha256: String,
    pub(crate) checkpoint_witness_receipt_quorum_checkpoint_sha256: String,
    pub(crate) final_admission_log_id: String,
    pub(crate) final_admission_log_entry_count: u64,
    pub(crate) final_admission_log_head_sha256: String,
    pub(crate) final_admission_log_sha256: String,
    pub(crate) final_admission_log_source_sha256: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) checkpoint_source_sha256: String,
    pub(crate) checkpoint_public_key: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) minimum_witnesses: u32,
    pub(crate) valid_witnesses: u32,
    pub(crate) members: Vec<
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumMember,
    >,
    pub(crate) quorum_met: bool,
    pub(crate) final_checkpoint_witness_receipt_admission_log_id: Option<String>,
    pub(crate) final_checkpoint_witness_receipt_admission_log_entry_count: Option<u64>,
    pub(crate) final_checkpoint_witness_receipt_admission_log_head_sha256: Option<String>,
    pub(crate) final_checkpoint_witness_receipt_admission_log_sha256: Option<String>,
}

struct VerificationContext {
    report:
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    approval_log: ApprovalTransparencyLog,
    checkpoint: SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
    report_source_sha256: String,
    approval_log_source_sha256: String,
    checkpoint_source_sha256: String,
    checkpoint_sha256: String,
    checkpoint_public_key: String,
    request_sha256: String,
    request_bytes: Vec<u8>,
}

struct SharedVerificationContext {
    report:
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    approval_log: ApprovalTransparencyLog,
    checkpoint: SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpoint,
    report_source_sha256: String,
    approval_log_source_sha256: String,
    checkpoint_source_sha256: String,
    checkpoint_sha256: String,
    checkpoint_public_key: String,
}

pub(crate) fn render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
    )?;
    render_bounded(
        receipt,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory final checkpoint-witness receipt quorum checkpoint witness receipt",
    )
}

pub(crate) fn parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    String,
> {
    let receipt = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory final checkpoint-witness receipt quorum checkpoint witness receipt",
    )?;
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
        &receipt,
    )?;
    Ok(receipt)
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-v1.json",
        "title": "pcbex remote independent factory final checkpoint-witness receipt-quorum checkpoint witness receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint",
            "final_checkpoint_witness_receipt_quorum_report_sha256",
            "final_checkpoint_witness_receipt_quorum_report_source_sha256",
            "registry_id", "generation", "registry_checkpoint_sha256",
            "receipt_quorum_checkpoint_sha256",
            "checkpoint_witness_receipt_quorum_checkpoint_sha256",
            "final_admission_log_id", "final_admission_log_entry_count",
            "final_admission_log_head_sha256", "final_admission_log_sha256",
            "final_admission_log_source_sha256", "checkpoint_sha256",
            "checkpoint_source_sha256", "checkpoint_public_key",
            "request_sha256", "response_sha256", "response_bytes",
            "witness_sha256", "evaluated_at_unix", "witness_id",
            "witness_public_key", "witness_key_trust_state_sha256",
            "witness_key_generation", "witnessed_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": ADAPTER},
            "endpoint": {
                "type": "string", "minLength": 1, "maxLength": MAX_ENDPOINT_BYTES,
                "anyOf": [
                    {"pattern": "^https://"},
                    {"pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "final_checkpoint_witness_receipt_quorum_report_sha256": digest.clone(),
            "final_checkpoint_witness_receipt_quorum_report_source_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "registry_checkpoint_sha256": digest.clone(),
            "receipt_quorum_checkpoint_sha256": digest.clone(),
            "checkpoint_witness_receipt_quorum_checkpoint_sha256": digest.clone(),
            "final_admission_log_id": slug_schema(),
            "final_admission_log_entry_count": {"type": "integer", "minimum": 2},
            "final_admission_log_head_sha256": digest.clone(),
            "final_admission_log_sha256": digest.clone(),
            "final_admission_log_source_sha256": digest.clone(),
            "checkpoint_sha256": digest.clone(),
            "checkpoint_source_sha256": digest.clone(),
            "checkpoint_public_key": digest.clone(),
            "request_sha256": digest.clone(),
            "response_sha256": digest.clone(),
            "response_bytes": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
            },
            "witness_sha256": digest.clone(),
            "evaluated_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "witness_id": slug_schema(),
            "witness_public_key": digest.clone(),
            "witness_key_trust_state_sha256": {
                "oneOf": [{"type": "null"}, digest]
            },
            "witness_key_generation": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "integer", "minimum": 0,
                        "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
                    }
                ]
            },
            "witnessed_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "verified": {"const": true}
        }
    })
}

pub(crate) fn validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1
        || receipt.adapter != ADAPTER
        || !receipt.verified
        || receipt.endpoint.is_empty()
        || receipt.endpoint.len() > MAX_ENDPOINT_BYTES
        || receipt.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || receipt.final_admission_log_entry_count < 2
        || receipt.response_bytes == 0
        || receipt.response_bytes
            > MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
        || receipt.witnessed_at_unix > receipt.evaluated_at_unix
        || receipt.evaluated_at_unix > MAX_TIMESTAMP
        || receipt.evaluated_at_unix - receipt.witnessed_at_unix
            > MAXIMUM_WITNESS_AGE_SECONDS
    {
        return Err(
            "remote factory final checkpoint-witness receipt quorum checkpoint witness receipt invariants are invalid"
                .into(),
        );
    }
    validate_endpoint(&receipt.endpoint, true)?;
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        &receipt.registry_id,
        "remote factory final checkpoint-witness receipt quorum checkpoint registry id",
    )?;
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        &receipt.final_admission_log_id,
        "remote factory final checkpoint-witness receipt quorum checkpoint admission log id",
    )?;
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        &receipt.witness_id,
        "remote factory final checkpoint-witness receipt quorum checkpoint witness id",
    )?;
    for (digest, label) in [
        (
            &receipt.final_checkpoint_witness_receipt_quorum_report_sha256,
            "factory final checkpoint-witness receipt quorum report SHA-256",
        ),
        (
            &receipt.final_checkpoint_witness_receipt_quorum_report_source_sha256,
            "factory final checkpoint-witness receipt quorum report source SHA-256",
        ),
        (
            &receipt.registry_checkpoint_sha256,
            "factory registry checkpoint SHA-256",
        ),
        (
            &receipt.receipt_quorum_checkpoint_sha256,
            "factory receipt quorum checkpoint SHA-256",
        ),
        (
            &receipt.checkpoint_witness_receipt_quorum_checkpoint_sha256,
            "factory checkpoint-witness receipt quorum checkpoint SHA-256",
        ),
        (
            &receipt.final_admission_log_head_sha256,
            "factory final checkpoint-witness admission log head SHA-256",
        ),
        (
            &receipt.final_admission_log_sha256,
            "factory final checkpoint-witness admission log SHA-256",
        ),
        (
            &receipt.final_admission_log_source_sha256,
            "factory final checkpoint-witness admission log source SHA-256",
        ),
        (
            &receipt.checkpoint_sha256,
            "factory final checkpoint-witness receipt quorum checkpoint SHA-256",
        ),
        (
            &receipt.checkpoint_source_sha256,
            "factory final checkpoint-witness receipt quorum checkpoint source SHA-256",
        ),
        (&receipt.request_sha256, "remote witness request SHA-256"),
        (&receipt.response_sha256, "remote witness response SHA-256"),
        (
            &receipt.witness_sha256,
            "remote final checkpoint witness SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let checkpoint_public_key = decode_hex::<32>(
        &receipt.checkpoint_public_key,
        "remote factory final checkpoint-witness receipt quorum checkpoint public key",
    )?;
    let witness_public_key = decode_hex::<32>(
        &receipt.witness_public_key,
        "remote factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &checkpoint_public_key,
        "remote factory final checkpoint-witness receipt quorum checkpoint public key",
    )?;
    validate_nonweak_public_key(
        &witness_public_key,
        "remote factory final checkpoint-witness receipt quorum checkpoint witness public key",
    )?;
    if checkpoint_public_key == witness_public_key {
        return Err(
            "remote factory final checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    match (
        &receipt.witness_key_trust_state_sha256,
        receipt.witness_key_generation,
    ) {
        (None, None) => {}
        (Some(digest), Some(generation)) => {
            validate_digest(
                digest,
                "remote factory final checkpoint witness trust-state SHA-256",
            )?;
            if generation
                > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            {
                return Err(
                    "remote factory final checkpoint witness trust generation exceeds its bound"
                        .into(),
                );
            }
        }
        _ => {
            return Err(
                "remote factory final checkpoint witness receipt trust binding is incomplete"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES,
        "remote factory final checkpoint witness receipt admission quorum report",
    )
}

pub(crate) fn parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES,
        "remote factory final checkpoint witness receipt admission quorum report",
    )?;
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-receipt-quorum-report-v1.json",
        "title": "pcbex verifier-bound final checkpoint witness receipt admission quorum",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version",
            "final_checkpoint_witness_receipt_quorum_report_sha256",
            "final_checkpoint_witness_receipt_quorum_report_source_sha256",
            "registry_id", "generation", "registry_checkpoint_sha256",
            "receipt_quorum_checkpoint_sha256",
            "checkpoint_witness_receipt_quorum_checkpoint_sha256",
            "final_admission_log_id", "final_admission_log_entry_count",
            "final_admission_log_head_sha256", "final_admission_log_sha256",
            "final_admission_log_source_sha256", "checkpoint_sha256",
            "checkpoint_source_sha256", "checkpoint_public_key",
            "evaluated_at_unix", "minimum_witnesses", "valid_witnesses",
            "members", "quorum_met",
            "final_checkpoint_witness_receipt_admission_log_id",
            "final_checkpoint_witness_receipt_admission_log_entry_count",
            "final_checkpoint_witness_receipt_admission_log_head_sha256",
            "final_checkpoint_witness_receipt_admission_log_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "final_checkpoint_witness_receipt_quorum_report_sha256": digest.clone(),
            "final_checkpoint_witness_receipt_quorum_report_source_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "registry_checkpoint_sha256": digest.clone(),
            "receipt_quorum_checkpoint_sha256": digest.clone(),
            "checkpoint_witness_receipt_quorum_checkpoint_sha256": digest.clone(),
            "final_admission_log_id": slug_schema(),
            "final_admission_log_entry_count": {"type": "integer", "minimum": 2},
            "final_admission_log_head_sha256": digest.clone(),
            "final_admission_log_sha256": digest.clone(),
            "final_admission_log_source_sha256": digest.clone(),
            "checkpoint_sha256": digest.clone(),
            "checkpoint_source_sha256": digest.clone(),
            "checkpoint_public_key": digest.clone(),
            "evaluated_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "minimum_witnesses": {
                "type": "integer", "minimum": 2,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
            },
            "valid_witnesses": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
            },
            "members": {
                "type": "array", "minItems": 1,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "witness_id", "witness_public_key",
                        "witness_key_trust_state_sha256", "witness_key_generation",
                        "receipt_sha256", "request_sha256", "response_sha256",
                        "witness_sha256", "witnessed_at_unix"
                    ],
                    "properties": {
                        "witness_id": slug_schema(),
                        "witness_public_key": digest.clone(),
                        "witness_key_trust_state_sha256": {
                            "oneOf": [{"type": "null"}, digest.clone()]
                        },
                        "witness_key_generation": {
                            "oneOf": [
                                {"type": "null"},
                                {
                                    "type": "integer", "minimum": 0,
                                    "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
                                }
                            ]
                        },
                        "receipt_sha256": digest.clone(),
                        "request_sha256": digest.clone(),
                        "response_sha256": digest.clone(),
                        "witness_sha256": digest.clone(),
                        "witnessed_at_unix": {
                            "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
                        }
                    }
                }
            },
            "quorum_met": {"type": "boolean"},
            "final_checkpoint_witness_receipt_admission_log_id": {
                "oneOf": [{"type": "null"}, slug_schema()]
            },
            "final_checkpoint_witness_receipt_admission_log_entry_count": {
                "oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]
            },
            "final_checkpoint_witness_receipt_admission_log_head_sha256": {
                "oneOf": [{"type": "null"}, digest.clone()]
            },
            "final_checkpoint_witness_receipt_admission_log_sha256": {
                "oneOf": [{"type": "null"}, digest]
            }
        }
    })
}

pub(crate) fn validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || report.final_admission_log_entry_count < 2
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&report.minimum_witnesses)
        || report.members.is_empty()
        || report.members.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || report.valid_witnesses as usize != report.members.len()
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
    {
        return Err(
            "remote factory final checkpoint witness receipt quorum report invariants are invalid"
                .into(),
        );
    }
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        &report.registry_id,
        "remote factory final checkpoint witness receipt quorum registry id",
    )?;
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        &report.final_admission_log_id,
        "remote factory final checkpoint witness receipt quorum source admission log id",
    )?;
    for (digest, label) in [
        (
            &report.final_checkpoint_witness_receipt_quorum_report_sha256,
            "final checkpoint witness receipt quorum report SHA-256",
        ),
        (
            &report.final_checkpoint_witness_receipt_quorum_report_source_sha256,
            "final checkpoint witness receipt quorum report source SHA-256",
        ),
        (
            &report.registry_checkpoint_sha256,
            "registry checkpoint SHA-256",
        ),
        (
            &report.receipt_quorum_checkpoint_sha256,
            "receipt quorum checkpoint SHA-256",
        ),
        (
            &report.checkpoint_witness_receipt_quorum_checkpoint_sha256,
            "checkpoint witness receipt quorum checkpoint SHA-256",
        ),
        (
            &report.final_admission_log_head_sha256,
            "final admission log head SHA-256",
        ),
        (
            &report.final_admission_log_sha256,
            "final admission log SHA-256",
        ),
        (
            &report.final_admission_log_source_sha256,
            "final admission log source SHA-256",
        ),
        (&report.checkpoint_sha256, "final checkpoint SHA-256"),
        (
            &report.checkpoint_source_sha256,
            "final checkpoint source SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let checkpoint_public_key = decode_hex::<32>(
        &report.checkpoint_public_key,
        "remote factory final checkpoint public key",
    )?;
    validate_nonweak_public_key(
        &checkpoint_public_key,
        "remote factory final checkpoint public key",
    )?;
    match (
        &report.final_checkpoint_witness_receipt_admission_log_id,
        report.final_checkpoint_witness_receipt_admission_log_entry_count,
        &report.final_checkpoint_witness_receipt_admission_log_head_sha256,
        &report.final_checkpoint_witness_receipt_admission_log_sha256,
    ) {
        (None, None, None, None) => {}
        (Some(log_id), Some(entry_count), Some(head), Some(log_sha256)) => {
            if !report.quorum_met {
                return Err(
                    "remote factory final checkpoint witness receipt quorum cannot bind an admission log before quorum"
                        .into(),
                );
            }
            crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
                log_id,
                "remote factory final checkpoint witness receipt admission log id",
            )?;
            if entry_count < report.members.len() as u64 {
                return Err(
                    "remote factory final checkpoint witness receipt quorum admission log has too few entries"
                        .into(),
                );
            }
            validate_digest(
                head,
                "remote factory final checkpoint witness receipt admission log head SHA-256",
            )?;
            validate_digest(
                log_sha256,
                "remote factory final checkpoint witness receipt admission log SHA-256",
            )?;
        }
        _ => {
            return Err(
                "remote factory final checkpoint witness receipt quorum admission log binding is incomplete"
                    .into(),
            );
        }
    }
    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut trust_states = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut requests = BTreeSet::new();
    let mut responses = BTreeSet::new();
    let mut witnesses = BTreeSet::new();
    let mut uses_trust_state: Option<bool> = None;
    for member in &report.members {
        crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
            &member.witness_id,
            "remote factory final checkpoint witness id",
        )?;
        let witness_public_key = decode_hex::<32>(
            &member.witness_public_key,
            "remote factory final checkpoint witness public key",
        )?;
        validate_nonweak_public_key(
            &witness_public_key,
            "remote factory final checkpoint witness public key",
        )?;
        if witness_public_key == checkpoint_public_key {
            return Err(
                "remote factory final checkpoint witness key must be independent from the checkpoint signing key"
                    .into(),
            );
        }
        if previous_id.is_some_and(|previous| previous >= member.witness_id.as_str())
            || !ids.insert(member.witness_id.as_str())
            || !keys.insert(member.witness_public_key.as_str())
            || !receipts.insert(member.receipt_sha256.as_str())
            || !requests.insert(member.request_sha256.as_str())
            || !responses.insert(member.response_sha256.as_str())
            || !witnesses.insert(member.witness_sha256.as_str())
        {
            return Err(
                "remote factory final checkpoint witness receipt quorum members must be sorted and distinct"
                    .into(),
            );
        }
        previous_id = Some(&member.witness_id);
        match (
            &member.witness_key_trust_state_sha256,
            member.witness_key_generation,
        ) {
            (None, None) => {
                if uses_trust_state == Some(true) {
                    return Err(
                        "remote factory final checkpoint witness receipt quorum cannot mix witness key modes"
                            .into(),
                    );
                }
                uses_trust_state = Some(false);
            }
            (Some(digest), Some(generation)) => {
                if uses_trust_state == Some(false) || !trust_states.insert(digest.as_str()) {
                    return Err(
                        "remote factory final checkpoint witness receipt quorum trust states must be distinct and cannot mix key modes"
                            .into(),
                    );
                }
                uses_trust_state = Some(true);
                validate_digest(digest, "final witness key trust-state SHA-256")?;
                if generation
                    > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
                {
                    return Err(
                        "remote factory final checkpoint witness receipt quorum witness key generation exceeds its bound"
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "remote factory final checkpoint witness receipt quorum trust-state binding is incomplete"
                        .into(),
                );
            }
        }
        for (digest, label) in [
            (&member.receipt_sha256, "final witness receipt SHA-256"),
            (
                &member.request_sha256,
                "remote final witness request SHA-256",
            ),
            (
                &member.response_sha256,
                "remote final witness response SHA-256",
            ),
            (&member.witness_sha256, "final checkpoint witness SHA-256"),
        ] {
            validate_digest(digest, label)?;
        }
        if member.witnessed_at_unix > report.evaluated_at_unix
            || report.evaluated_at_unix - member.witnessed_at_unix > MAXIMUM_WITNESS_AGE_SECONDS
        {
            return Err(
                "remote factory final checkpoint witness receipt quorum member is outside the 24-hour window"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_for_log(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
) -> Result<(), String> {
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        report,
    )?;
    if !report.quorum_met {
        return Err("remote factory final checkpoint witness receipt quorum was not met".into());
    }
    let expected_log_sha256 = report
        .final_checkpoint_witness_receipt_admission_log_sha256
        .as_deref()
        .ok_or_else(|| {
            "remote factory final checkpoint witness receipt quorum report is not bound to an admission log"
                .to_string()
        })?;
    if report
        .final_checkpoint_witness_receipt_admission_log_id
        .as_deref()
        != Some(log.log_id.as_str())
        || report.final_checkpoint_witness_receipt_admission_log_entry_count
            != Some(log.entries.len() as u64)
        || report
            .final_checkpoint_witness_receipt_admission_log_head_sha256
            .as_deref()
            != log.head_sha256.as_deref()
        || approval_transparency_log_sha256(log)? != expected_log_sha256
    {
        return Err(
            "approval log does not match the remote factory final checkpoint witness receipt quorum admission binding"
                .into(),
        );
    }
    let suffix_start = log
        .entries
        .len()
        .checked_sub(report.members.len())
        .ok_or_else(|| {
            "approval log has fewer entries than the remote factory final checkpoint witness receipt quorum"
                .to_string()
        })?;
    for (entry, member) in log.entries[suffix_start..].iter().zip(&report.members) {
        if entry.event.artifact_kind
            != ApprovalArtifactKind::RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt
            || entry.event.artifact_sha256 != member.receipt_sha256
            || entry.event.subject_id != report.checkpoint_sha256
            || entry.event.request_sha256.as_deref() != Some(member.request_sha256.as_str())
            || entry.event.session_sha256.as_deref() != Some(member.response_sha256.as_str())
            || entry.event.signer_id.is_some()
            || entry.event.outcome != format!("verified-witness:{}", member.witness_id)
        {
            return Err(
                "approval log suffix does not exactly match the admitted remote factory final checkpoint witness receipt quorum"
                    .into(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    endpoint: &str,
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    ),
    String,
> {
    request_remote_witness(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        endpoint,
        expected_witness_id,
        trusted_witness_public_key,
        None,
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_with_trust_state(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    endpoint: &str,
    expected_witness_id: &str,
    witness_trust_state_source: &[u8],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    ),
    String,
> {
    let state = parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        witness_trust_state_source,
    )?;
    if state.witness_id != expected_witness_id {
        return Err(
            "remote factory final checkpoint witness identity does not match its trust state"
                .into(),
        );
    }
    let trusted_witness_public_key = remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
        &state,
    )?;
    request_remote_witness(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        endpoint,
        expected_witness_id,
        &trusted_witness_public_key,
        Some((&state, sha256(witness_trust_state_source))),
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

pub(crate) fn preflight_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_request(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<(), String> {
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory final checkpoint witness evaluation time is outside its bound".into(),
        );
    }
    let context = prepare_shared_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
    )?;
    if evaluated_at_unix < context.report.evaluated_at_unix {
        return Err(
            "remote factory final checkpoint witness evaluation predates its quorum report".into(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_source: &[u8],
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    verify_receipt(
        receipt,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_source,
        expected_witness_id,
        trusted_witness_public_key,
        None,
        receipt.evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_for_admission(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_source: &[u8],
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    verify_receipt(
        receipt,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_source,
        expected_witness_id,
        trusted_witness_public_key,
        None,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_with_trust_state(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_source: &[u8],
    expected_witness_id: &str,
    witness_trust_state_source: &[u8],
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    let state = parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        witness_trust_state_source,
    )?;
    if state.witness_id != expected_witness_id {
        return Err(
            "remote factory final checkpoint witness identity does not match its trust state"
                .into(),
        );
    }
    let trusted_witness_public_key = remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
        &state,
    )?;
    verify_receipt(
        receipt,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_source,
        expected_witness_id,
        &trusted_witness_public_key,
        Some((&state, sha256(witness_trust_state_source))),
        receipt.evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_for_admission_with_trust_state(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_source: &[u8],
    expected_witness_id: &str,
    witness_trust_state_source: &[u8],
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    let state = parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
        witness_trust_state_source,
    )?;
    if state.witness_id != expected_witness_id {
        return Err(
            "remote factory final checkpoint witness identity does not match its trust state"
                .into(),
        );
    }
    let trusted_witness_public_key = remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
        &state,
    )?;
    verify_receipt(
        receipt,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_source,
        expected_witness_id,
        &trusted_witness_public_key,
        Some((&state, sha256(witness_trust_state_source))),
        evaluated_at_unix,
    )
}

struct TrustedWitnessBinding {
    public_key: [u8; 32],
    trust_state: Option<
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    >,
    trust_state_sha256: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum(
    receipts: &[RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt],
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_documents: &[Vec<u8>],
    trusted_witnesses: &[(String, [u8; 32])],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt>,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    ),
    String,
>{
    if receipts.len() != trusted_witnesses.len() {
        return Err(
            "remote factory final checkpoint witness receipt and trusted witness counts must match"
                .into(),
        );
    }
    let mut bindings = BTreeMap::new();
    for (witness_id, public_key) in trusted_witnesses {
        crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
            witness_id,
            "remote factory final checkpoint witness id",
        )?;
        validate_nonweak_public_key(
            public_key,
            "trusted remote factory final checkpoint witness key",
        )?;
        if bindings
            .insert(
                witness_id.clone(),
                TrustedWitnessBinding {
                    public_key: *public_key,
                    trust_state: None,
                    trust_state_sha256: None,
                },
            )
            .is_some()
        {
            return Err(
                "remote factory final checkpoint witness receipt quorum repeats a trusted witness identity"
                    .into(),
            );
        }
    }
    verify_final_checkpoint_witness_receipt_quorum(
        receipts,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_documents,
        &bindings,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_with_trust_states(
    receipts: &[RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt],
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_documents: &[Vec<u8>],
    witness_key_trust_state_sources: &[Vec<u8>],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt>,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    ),
    String,
>{
    if receipts.len() != witness_key_trust_state_sources.len() {
        return Err(
            "remote factory final checkpoint witness receipt and witness trust-state counts must match"
                .into(),
        );
    }
    let mut bindings = BTreeMap::new();
    for source in witness_key_trust_state_sources {
        let state = parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
            source,
        )?;
        let public_key = remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trusted_public_key(
            &state,
        )?;
        let witness_id = state.witness_id.clone();
        if bindings
            .insert(
                witness_id,
                TrustedWitnessBinding {
                    public_key,
                    trust_state: Some(state),
                    trust_state_sha256: Some(sha256(source)),
                },
            )
            .is_some()
        {
            return Err(
                "remote factory final checkpoint witness receipt quorum repeats a witness trust identity"
                    .into(),
            );
        }
    }
    verify_final_checkpoint_witness_receipt_quorum(
        receipts,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_documents,
        &bindings,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_final_checkpoint_witness_receipt_quorum(
    receipts: &[RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt],
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_documents: &[Vec<u8>],
    trusted_witnesses: &BTreeMap<String, TrustedWitnessBinding>,
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt>,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    ),
    String,
>{
    if !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
        .contains(&minimum_witnesses)
        || receipts.is_empty()
        || receipts.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || receipts.len() != response_documents.len()
        || receipts.len() != trusted_witnesses.len()
    {
        return Err(
            "remote factory final checkpoint witness receipt quorum input count is invalid".into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory final checkpoint witness receipt quorum admission time is outside its bound"
                .into(),
        );
    }
    let context = prepare_shared_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
    )?;
    let mut verified = Vec::with_capacity(receipts.len());
    for (receipt, response) in receipts.iter().zip(response_documents) {
        let binding = trusted_witnesses.get(&receipt.witness_id).ok_or_else(|| {
            "remote factory final checkpoint witness receipt quorum witness identity is untrusted"
                .to_string()
        })?;
        let trust_binding = binding
            .trust_state
            .as_ref()
            .zip(binding.trust_state_sha256.clone());
        let witness = verify_receipt_binding_after_shared_verification(
            receipt,
            &context,
            response,
            trusted_checkpoint_public_key,
            &binding.public_key,
            trust_binding,
            evaluated_at_unix,
        )?;
        let receipt_source = serde_json::to_vec(receipt).map_err(|error| {
            format!("serializing remote factory final checkpoint witness receipt: {error}")
        })?;
        verified.push((
            receipt.clone(),
            witness,
            binding.public_key,
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumMember {
                witness_id: receipt.witness_id.clone(),
                witness_public_key: receipt.witness_public_key.clone(),
                witness_key_trust_state_sha256: receipt
                    .witness_key_trust_state_sha256
                    .clone(),
                witness_key_generation: receipt.witness_key_generation,
                receipt_sha256: sha256(&receipt_source),
                request_sha256: receipt.request_sha256.clone(),
                response_sha256: receipt.response_sha256.clone(),
                witness_sha256: receipt.witness_sha256.clone(),
                witnessed_at_unix: receipt.witnessed_at_unix,
            },
        ));
    }
    let witnesses = verified
        .iter()
        .map(|(_, witness, _, _)| witness.clone())
        .collect::<Vec<_>>();
    let trusted_keys = verified
        .iter()
        .map(|(_, _, key, _)| *key)
        .collect::<Vec<_>>();
    let witness_report = verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses_after_checkpoint_verification(
        &context.report,
        &context.checkpoint,
        trusted_checkpoint_public_key,
        &witnesses,
        &trusted_keys,
        minimum_witnesses,
        evaluated_at_unix,
    )?;
    verified.sort_by(|left, right| left.3.witness_id.cmp(&right.3.witness_id));
    let members = verified
        .iter()
        .map(|(_, _, _, member)| member.clone())
        .collect::<Vec<_>>();
    if witness_report
        .witness_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != members
            .iter()
            .map(|member| member.witness_id.clone())
            .collect::<BTreeSet<_>>()
        || witness_report
            .witness_public_keys
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != members
                .iter()
                .map(|member| member.witness_public_key.clone())
                .collect::<BTreeSet<_>>()
    {
        return Err(
            "remote factory final checkpoint witness receipt quorum does not match its witness quorum"
                .into(),
        );
    }
    let report = RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport {
        schema_version: 1,
        final_checkpoint_witness_receipt_quorum_report_sha256: context
            .checkpoint
            .final_checkpoint_witness_receipt_quorum_report_sha256
            .clone(),
        final_checkpoint_witness_receipt_quorum_report_source_sha256: context
            .report_source_sha256
            .clone(),
        registry_id: context.checkpoint.registry_id.clone(),
        generation: context.checkpoint.generation,
        registry_checkpoint_sha256: context.checkpoint.registry_checkpoint_sha256.clone(),
        receipt_quorum_checkpoint_sha256: context
            .checkpoint
            .receipt_quorum_checkpoint_sha256
            .clone(),
        checkpoint_witness_receipt_quorum_checkpoint_sha256: context
            .checkpoint
            .checkpoint_witness_receipt_quorum_checkpoint_sha256
            .clone(),
        final_admission_log_id: context.checkpoint.final_admission_log_id.clone(),
        final_admission_log_entry_count: context.checkpoint.final_admission_log_entry_count,
        final_admission_log_head_sha256: context
            .checkpoint
            .final_admission_log_head_sha256
            .clone(),
        final_admission_log_sha256: context.checkpoint.final_admission_log_sha256.clone(),
        final_admission_log_source_sha256: context.approval_log_source_sha256.clone(),
        checkpoint_sha256: context.checkpoint_sha256.clone(),
        checkpoint_source_sha256: context.checkpoint_source_sha256.clone(),
        checkpoint_public_key: context.checkpoint_public_key.clone(),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses: witness_report.valid_witnesses,
        members,
        quorum_met: witness_report.quorum_met,
        final_checkpoint_witness_receipt_admission_log_id: None,
        final_checkpoint_witness_receipt_admission_log_entry_count: None,
        final_checkpoint_witness_receipt_admission_log_head_sha256: None,
        final_checkpoint_witness_receipt_admission_log_sha256: None,
    };
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        &report,
    )?;
    Ok((
        verified
            .into_iter()
            .map(|(receipt, _, _, _)| receipt)
            .collect(),
        report,
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_receipt_binding_after_shared_verification(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    context: &SharedVerificationContext,
    response_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    trusted_witness_public_key: &[u8; 32],
    witness_trust_state: Option<(
        &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
    )?;
    if evaluated_at_unix > MAX_TIMESTAMP || evaluated_at_unix < receipt.evaluated_at_unix {
        return Err(
            "remote factory final checkpoint witness receipt is future-dated or admission time is outside its bound"
                .into(),
        );
    }
    let request_sha256 = request_sha256_for_shared_context(
        context,
        trusted_checkpoint_public_key,
        &receipt.witness_id,
        trusted_witness_public_key,
        witness_trust_state
            .as_ref()
            .map(|(state, digest)| (*state, digest.as_str())),
    )?;
    if receipt.final_checkpoint_witness_receipt_quorum_report_sha256
        != context
            .checkpoint
            .final_checkpoint_witness_receipt_quorum_report_sha256
        || receipt.final_checkpoint_witness_receipt_quorum_report_source_sha256
            != context.report_source_sha256
        || receipt.registry_id != context.checkpoint.registry_id
        || receipt.generation != context.checkpoint.generation
        || receipt.registry_checkpoint_sha256 != context.checkpoint.registry_checkpoint_sha256
        || receipt.receipt_quorum_checkpoint_sha256
            != context.checkpoint.receipt_quorum_checkpoint_sha256
        || receipt.checkpoint_witness_receipt_quorum_checkpoint_sha256
            != context
                .checkpoint
                .checkpoint_witness_receipt_quorum_checkpoint_sha256
        || receipt.final_admission_log_id != context.checkpoint.final_admission_log_id
        || receipt.final_admission_log_entry_count
            != context.checkpoint.final_admission_log_entry_count
        || receipt.final_admission_log_head_sha256
            != context.checkpoint.final_admission_log_head_sha256
        || receipt.final_admission_log_sha256 != context.checkpoint.final_admission_log_sha256
        || receipt.final_admission_log_source_sha256 != context.approval_log_source_sha256
        || receipt.checkpoint_sha256 != context.checkpoint_sha256
        || receipt.checkpoint_source_sha256 != context.checkpoint_source_sha256
        || receipt.checkpoint_public_key != context.checkpoint_public_key
        || receipt.request_sha256 != request_sha256
        || receipt.witness_public_key != hex::encode(trusted_witness_public_key)
    {
        return Err(
            "remote factory final checkpoint witness receipt is bound to different retained evidence"
                .into(),
        );
    }
    if response_source.is_empty()
        || response_source.len() as u64
            > MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
        || receipt.response_bytes != response_source.len() as u64
        || receipt.response_sha256 != sha256(response_source)
    {
        return Err(
            "remote factory final checkpoint witness receipt response binding is invalid".into(),
        );
    }
    let witness = parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        response_source,
    )?;
    if receipt.witness_sha256
        != canonical_sha256(&witness, "remote factory final checkpoint witness")?
        || receipt.witness_id != witness.witness_id
        || receipt.witness_public_key != witness.public_key
        || receipt.witnessed_at_unix != witness.witnessed_at_unix
    {
        return Err(
            "remote factory final checkpoint witness receipt describes different witness evidence"
                .into(),
        );
    }
    let expected_trust_binding = witness_trust_state
        .as_ref()
        .map(|(state, digest)| (Some(digest.clone()), Some(state.generation)))
        .unwrap_or((None, None));
    if (
        receipt.witness_key_trust_state_sha256.clone(),
        receipt.witness_key_generation,
    ) != expected_trust_binding
    {
        return Err(
            "remote factory final checkpoint witness receipt trust binding is invalid".into(),
        );
    }
    Ok(witness)
}

fn request_bytes_for_shared_context(
    context: &SharedVerificationContext,
    trusted_checkpoint_public_key: &[u8; 32],
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    witness_trust_state: Option<(
        &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
        &str,
    )>,
) -> Result<Vec<u8>, String> {
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        expected_witness_id,
        "expected remote factory final checkpoint witness id",
    )?;
    validate_nonweak_public_key(
        trusted_witness_public_key,
        "trusted remote factory final checkpoint witness key",
    )?;
    if trusted_checkpoint_public_key == trusted_witness_public_key {
        return Err(
            "remote factory final checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    if let Some((state, digest)) = witness_trust_state {
        if state.witness_id != expected_witness_id
            || state.current_public_key != hex::encode(trusted_witness_public_key)
        {
            return Err(
                "remote factory final checkpoint witness trust state does not match its expected identity and key"
                    .into(),
            );
        }
        validate_digest(
            digest,
            "remote factory final checkpoint witness trust-state SHA-256",
        )?;
    }
    let expected_witness_public_key = hex::encode(trusted_witness_public_key);
    let (trust_digest, trust_generation) = witness_trust_state
        .map(|(state, digest)| (Some(digest), Some(state.generation)))
        .unwrap_or((None, None));
    let request =
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessRequest {
            schema_version: 1,
            protocol: PROTOCOL,
            expected_witness_id,
            expected_witness_public_key,
            witness_key_trust_state_sha256: trust_digest,
            witness_key_generation: trust_generation,
            quorum_report: &context.report,
            approval_log: &context.approval_log,
            checkpoint: &context.checkpoint,
        };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        format!("serializing remote factory final checkpoint witness request: {error}")
    })?;
    if request_bytes.is_empty() || request_bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(format!(
            "remote factory final checkpoint witness request exceeds {MAX_REQUEST_BYTES} bytes"
        ));
    }
    Ok(request_bytes)
}

fn request_sha256_for_shared_context(
    context: &SharedVerificationContext,
    trusted_checkpoint_public_key: &[u8; 32],
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    witness_trust_state: Option<(
        &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
        &str,
    )>,
) -> Result<String, String> {
    request_bytes_for_shared_context(
        context,
        trusted_checkpoint_public_key,
        expected_witness_id,
        trusted_witness_public_key,
        witness_trust_state,
    )
    .map(|request| sha256(&request))
}

#[allow(clippy::too_many_arguments)]
fn request_remote_witness(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    endpoint: &str,
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    witness_trust_state: Option<(
        &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
        String,
    )>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    ),
    String,
> {
    validate_request_configuration(
        endpoint,
        expected_witness_id,
        trusted_checkpoint_public_key,
        trusted_witness_public_key,
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )?;
    let context = prepare_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        expected_witness_id,
        trusted_witness_public_key,
        witness_trust_state
            .as_ref()
            .map(|(state, digest)| (*state, digest.as_str())),
    )?;
    if evaluated_at_unix < context.report.evaluated_at_unix {
        return Err(
            "remote factory final checkpoint witness evaluation predates its quorum report".into(),
        );
    }

    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .http_status_as_error(false)
        .https_only(!allow_http_loopback)
        .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
        .build();
    let agent: ureq::Agent = config.into();
    let mut call = agent
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    if let Some(variable) = bearer_token_env {
        let token = env::var(variable).map_err(|_| {
            format!(
                "remote factory final checkpoint witness bearer-token environment {variable} is unset"
            )
        })?;
        if token.trim().is_empty()
            || token.len() > MAX_BEARER_TOKEN_BYTES
            || token.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(format!(
                "remote factory final checkpoint witness bearer-token environment {variable} is invalid"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .send(context.request_bytes.as_slice())
        .map_err(|error| {
            format!("remote factory final checkpoint witness HTTPS request failed: {error}")
        })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote factory final checkpoint witness returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err(
            "remote factory final checkpoint witness response Content-Type must be application/json"
                .into(),
        );
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(
            MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
                + 1,
        )
        .read_to_vec()
        .map_err(|error| {
            format!("reading bounded remote factory final checkpoint witness response: {error}")
        })?;
    if response_bytes.len() as u64
        > MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
    {
        return Err(format!(
            "remote factory final checkpoint witness response exceeds {} bytes",
            MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
        ));
    }
    let witness = parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        &response_bytes,
    )?;
    if witness.witness_id != expected_witness_id {
        return Err(
            "remote factory final checkpoint witness identity does not match the requested identity"
                .into(),
        );
    }
    let single = verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
        &context.report,
        &context.approval_log,
        &context.checkpoint,
        trusted_checkpoint_public_key,
        std::slice::from_ref(&witness),
        std::slice::from_ref(trusted_witness_public_key),
        2,
        evaluated_at_unix,
    )?;
    if single.valid_witnesses != 1 || single.quorum_met {
        return Err(
            "remote factory final checkpoint witness verification produced an invalid single-witness result"
                .into(),
        );
    }
    let (witness_key_trust_state_sha256, witness_key_generation) = witness_trust_state
        .map(|(state, digest)| (Some(digest), Some(state.generation)))
        .unwrap_or((None, None));
    let receipt =
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: ADAPTER.into(),
            endpoint: endpoint.into(),
            final_checkpoint_witness_receipt_quorum_report_sha256: context
                .checkpoint
                .final_checkpoint_witness_receipt_quorum_report_sha256
                .clone(),
            final_checkpoint_witness_receipt_quorum_report_source_sha256: context
                .report_source_sha256,
            registry_id: context.checkpoint.registry_id.clone(),
            generation: context.checkpoint.generation,
            registry_checkpoint_sha256: context.checkpoint.registry_checkpoint_sha256.clone(),
            receipt_quorum_checkpoint_sha256: context
                .checkpoint
                .receipt_quorum_checkpoint_sha256
                .clone(),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: context
                .checkpoint
                .checkpoint_witness_receipt_quorum_checkpoint_sha256
                .clone(),
            final_admission_log_id: context.checkpoint.final_admission_log_id.clone(),
            final_admission_log_entry_count: context.checkpoint.final_admission_log_entry_count,
            final_admission_log_head_sha256: context
                .checkpoint
                .final_admission_log_head_sha256
                .clone(),
            final_admission_log_sha256: context.checkpoint.final_admission_log_sha256.clone(),
            final_admission_log_source_sha256: context.approval_log_source_sha256,
            checkpoint_sha256: context.checkpoint_sha256,
            checkpoint_source_sha256: context.checkpoint_source_sha256,
            checkpoint_public_key: context.checkpoint_public_key,
            request_sha256: context.request_sha256,
            response_sha256: sha256(&response_bytes),
            response_bytes: response_bytes.len() as u64,
            witness_sha256: canonical_sha256(&witness, "remote factory final checkpoint witness")?,
            evaluated_at_unix,
            witness_id: witness.witness_id.clone(),
            witness_public_key: witness.public_key.clone(),
            witness_key_trust_state_sha256,
            witness_key_generation,
            witnessed_at_unix: witness.witnessed_at_unix,
            verified: true,
        };
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
        &receipt,
    )?;
    Ok((witness, receipt))
}

#[allow(clippy::too_many_arguments)]
fn verify_receipt(
    receipt: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_source: &[u8],
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    witness_trust_state: Option<(
        &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness, String>
{
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
    )?;
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory final checkpoint witness admission time is outside its bound".into(),
        );
    }
    if evaluated_at_unix < receipt.evaluated_at_unix {
        return Err(
            "remote factory final checkpoint witness receipt is future-dated at admission".into(),
        );
    }
    let context = prepare_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        expected_witness_id,
        trusted_witness_public_key,
        witness_trust_state
            .as_ref()
            .map(|(state, digest)| (*state, digest.as_str())),
    )?;
    if receipt.final_checkpoint_witness_receipt_quorum_report_sha256
        != context
            .checkpoint
            .final_checkpoint_witness_receipt_quorum_report_sha256
        || receipt.final_checkpoint_witness_receipt_quorum_report_source_sha256
            != context.report_source_sha256
        || receipt.registry_id != context.checkpoint.registry_id
        || receipt.generation != context.checkpoint.generation
        || receipt.registry_checkpoint_sha256 != context.checkpoint.registry_checkpoint_sha256
        || receipt.receipt_quorum_checkpoint_sha256
            != context.checkpoint.receipt_quorum_checkpoint_sha256
        || receipt.checkpoint_witness_receipt_quorum_checkpoint_sha256
            != context
                .checkpoint
                .checkpoint_witness_receipt_quorum_checkpoint_sha256
        || receipt.final_admission_log_id != context.checkpoint.final_admission_log_id
        || receipt.final_admission_log_entry_count
            != context.checkpoint.final_admission_log_entry_count
        || receipt.final_admission_log_head_sha256
            != context.checkpoint.final_admission_log_head_sha256
        || receipt.final_admission_log_sha256 != context.checkpoint.final_admission_log_sha256
        || receipt.final_admission_log_source_sha256 != context.approval_log_source_sha256
        || receipt.checkpoint_sha256 != context.checkpoint_sha256
        || receipt.checkpoint_source_sha256 != context.checkpoint_source_sha256
        || receipt.checkpoint_public_key != context.checkpoint_public_key
        || receipt.request_sha256 != context.request_sha256
        || receipt.witness_id != expected_witness_id
    {
        return Err(
            "remote factory final checkpoint witness receipt is bound to different retained evidence"
                .into(),
        );
    }
    if response_source.is_empty()
        || response_source.len() as u64
            > MAX_SIGNED_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
        || receipt.response_bytes != response_source.len() as u64
        || receipt.response_sha256 != sha256(response_source)
    {
        return Err(
            "remote factory final checkpoint witness receipt response binding is invalid".into(),
        );
    }
    let witness = parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
        response_source,
    )?;
    if receipt.witness_sha256
        != canonical_sha256(&witness, "remote factory final checkpoint witness")?
        || receipt.witness_id != witness.witness_id
        || receipt.witness_public_key != witness.public_key
        || receipt.witnessed_at_unix != witness.witnessed_at_unix
    {
        return Err(
            "remote factory final checkpoint witness receipt describes different witness evidence"
                .into(),
        );
    }
    let expected_trust_binding = witness_trust_state
        .as_ref()
        .map(|(state, digest)| (Some(digest.clone()), Some(state.generation)))
        .unwrap_or((None, None));
    if (
        receipt.witness_key_trust_state_sha256.clone(),
        receipt.witness_key_generation,
    ) != expected_trust_binding
    {
        return Err(
            "remote factory final checkpoint witness receipt trust binding is invalid".into(),
        );
    }
    let single = verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
        &context.report,
        &context.approval_log,
        &context.checkpoint,
        trusted_checkpoint_public_key,
        std::slice::from_ref(&witness),
        std::slice::from_ref(trusted_witness_public_key),
        2,
        evaluated_at_unix,
    )?;
    if single.valid_witnesses != 1 || single.quorum_met {
        return Err(
            "remote factory final checkpoint witness receipt replay produced an invalid single-witness result"
                .into(),
        );
    }
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
fn prepare_verification_context(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    expected_witness_id: &str,
    trusted_witness_public_key: &[u8; 32],
    witness_trust_state: Option<(
        &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
        &str,
    )>,
) -> Result<VerificationContext, String> {
    let shared = prepare_shared_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
    )?;
    let request_bytes = request_bytes_for_shared_context(
        &shared,
        trusted_checkpoint_public_key,
        expected_witness_id,
        trusted_witness_public_key,
        witness_trust_state,
    )?;
    Ok(VerificationContext {
        report: shared.report,
        approval_log: shared.approval_log,
        checkpoint: shared.checkpoint,
        report_source_sha256: shared.report_source_sha256,
        approval_log_source_sha256: shared.approval_log_source_sha256,
        checkpoint_source_sha256: shared.checkpoint_source_sha256,
        checkpoint_sha256: shared.checkpoint_sha256,
        checkpoint_public_key: shared.checkpoint_public_key,
        request_sha256: sha256(&request_bytes),
        request_bytes,
    })
}

fn prepare_shared_verification_context(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
) -> Result<SharedVerificationContext, String> {
    validate_nonweak_public_key(
        trusted_checkpoint_public_key,
        "trusted factory final checkpoint-witness receipt quorum checkpoint key",
    )?;
    let report = parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        quorum_report_source,
    )?;
    let approval_log = parse_remote_receipt_quorum_approval_log(approval_log_source)?;
    let checkpoint =
        parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
            checkpoint_source,
        )?;
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
        &report,
        &approval_log,
        &checkpoint,
        trusted_checkpoint_public_key,
    )?;
    Ok(SharedVerificationContext {
        report,
        approval_log,
        checkpoint_sha256: canonical_sha256(
            &checkpoint,
            "factory final checkpoint-witness receipt quorum checkpoint",
        )?,
        checkpoint,
        report_source_sha256: sha256(quorum_report_source),
        approval_log_source_sha256: sha256(approval_log_source),
        checkpoint_source_sha256: sha256(checkpoint_source),
        checkpoint_public_key: hex::encode(trusted_checkpoint_public_key),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_request_configuration(
    endpoint: &str,
    expected_witness_id: &str,
    trusted_checkpoint_public_key: &[u8; 32],
    trusted_witness_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<(), String> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(format!(
            "remote factory final checkpoint witness endpoint must contain 1 to {MAX_ENDPOINT_BYTES} bytes"
        ));
    }
    validate_endpoint(endpoint, allow_http_loopback)?;
    crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::validate_slug(
        expected_witness_id,
        "expected remote factory final checkpoint witness id",
    )?;
    validate_nonweak_public_key(
        trusted_checkpoint_public_key,
        "trusted factory final checkpoint-witness receipt quorum checkpoint key",
    )?;
    validate_nonweak_public_key(
        trusted_witness_public_key,
        "trusted remote factory final checkpoint witness key",
    )?;
    if trusted_checkpoint_public_key == trusted_witness_public_key {
        return Err(
            "remote factory final checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    if !(1..=600).contains(&timeout_seconds) {
        return Err(
            "remote factory final checkpoint witness timeout must be between 1 and 600 seconds"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory final checkpoint witness evaluation time is outside its bound".into(),
        );
    }
    if let Some(variable) = bearer_token_env {
        if variable.len() > MAX_ENV_NAME_BYTES {
            return Err(
                "remote factory final checkpoint witness bearer-token environment name is too long"
                    .into(),
            );
        }
        validate_env_name(variable)?;
    }
    Ok(())
}

fn canonical_sha256(value: &impl Serialize, label: &str) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|source| sha256(&source))
        .map_err(|error| format!("serializing {label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use pcbex_kicad::{
        ApprovalEventDescriptor, append_approval_transparency_event, new_approval_transparency_log,
    };

    fn receipt()
    -> RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt {
        let checkpoint_key = SigningKey::from_bytes(&[151; 32]);
        let witness_key = SigningKey::from_bytes(&[152; 32]);
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: ADAPTER.into(),
            endpoint: "https://witness.example/v1/final-checkpoint".into(),
            final_checkpoint_witness_receipt_quorum_report_sha256: "1".repeat(64),
            final_checkpoint_witness_receipt_quorum_report_source_sha256: "2".repeat(64),
            registry_id: "factory-registry".into(),
            generation: 7,
            registry_checkpoint_sha256: "3".repeat(64),
            receipt_quorum_checkpoint_sha256: "4".repeat(64),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: "5".repeat(64),
            final_admission_log_id: "final-admission".into(),
            final_admission_log_entry_count: 2,
            final_admission_log_head_sha256: "6".repeat(64),
            final_admission_log_sha256: "7".repeat(64),
            final_admission_log_source_sha256: "8".repeat(64),
            checkpoint_sha256: "9".repeat(64),
            checkpoint_source_sha256: "a".repeat(64),
            checkpoint_public_key: hex::encode(checkpoint_key.verifying_key().to_bytes()),
            request_sha256: "b".repeat(64),
            response_sha256: "c".repeat(64),
            response_bytes: 1_024,
            witness_sha256: "d".repeat(64),
            evaluated_at_unix: 2_100,
            witness_id: "final-witness-a".into(),
            witness_public_key: hex::encode(witness_key.verifying_key().to_bytes()),
            witness_key_trust_state_sha256: None,
            witness_key_generation: None,
            witnessed_at_unix: 2_000,
            verified: true,
        }
    }

    fn receipt_quorum_report()
    -> RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport
    {
        let first = receipt();
        let second_key = SigningKey::from_bytes(&[155; 32]);
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport {
            schema_version: 1,
            final_checkpoint_witness_receipt_quorum_report_sha256: first
                .final_checkpoint_witness_receipt_quorum_report_sha256
                .clone(),
            final_checkpoint_witness_receipt_quorum_report_source_sha256: first
                .final_checkpoint_witness_receipt_quorum_report_source_sha256
                .clone(),
            registry_id: first.registry_id.clone(),
            generation: first.generation,
            registry_checkpoint_sha256: first.registry_checkpoint_sha256.clone(),
            receipt_quorum_checkpoint_sha256: first.receipt_quorum_checkpoint_sha256.clone(),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: first
                .checkpoint_witness_receipt_quorum_checkpoint_sha256
                .clone(),
            final_admission_log_id: first.final_admission_log_id.clone(),
            final_admission_log_entry_count: first.final_admission_log_entry_count,
            final_admission_log_head_sha256: first.final_admission_log_head_sha256.clone(),
            final_admission_log_sha256: first.final_admission_log_sha256.clone(),
            final_admission_log_source_sha256: first.final_admission_log_source_sha256.clone(),
            checkpoint_sha256: first.checkpoint_sha256.clone(),
            checkpoint_source_sha256: first.checkpoint_source_sha256.clone(),
            checkpoint_public_key: first.checkpoint_public_key.clone(),
            evaluated_at_unix: 2_100,
            minimum_witnesses: 2,
            valid_witnesses: 2,
            members: vec![
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumMember {
                    witness_id: first.witness_id,
                    witness_public_key: first.witness_public_key,
                    witness_key_trust_state_sha256: None,
                    witness_key_generation: None,
                    receipt_sha256: "e".repeat(64),
                    request_sha256: first.request_sha256,
                    response_sha256: first.response_sha256,
                    witness_sha256: first.witness_sha256,
                    witnessed_at_unix: first.witnessed_at_unix,
                },
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumMember {
                    witness_id: "final-witness-b".into(),
                    witness_public_key: hex::encode(second_key.verifying_key().to_bytes()),
                    witness_key_trust_state_sha256: None,
                    witness_key_generation: None,
                    receipt_sha256: "f".repeat(64),
                    request_sha256: "0".repeat(64),
                    response_sha256: "1".repeat(64),
                    witness_sha256: "2".repeat(64),
                    witnessed_at_unix: 2_001,
                },
            ],
            quorum_met: true,
            final_checkpoint_witness_receipt_admission_log_id: None,
            final_checkpoint_witness_receipt_admission_log_entry_count: None,
            final_checkpoint_witness_receipt_admission_log_head_sha256: None,
            final_checkpoint_witness_receipt_admission_log_sha256: None,
        }
    }

    #[test]
    fn receipt_quorum_report_is_closed_distinct_and_exactly_log_bound() {
        let report = receipt_quorum_report();
        let source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
            &report,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &source,
            )
            .unwrap(),
            report
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report_json_schema(
            )["additionalProperties"],
            false
        );
        assert!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &serde_json::to_vec(&report).unwrap(),
            )
            .is_err()
        );

        for mutate in [
            |candidate: &mut RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport| {
                candidate.members[1].receipt_sha256 = candidate.members[0].receipt_sha256.clone();
            },
            |candidate: &mut RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport| {
                candidate.members[1].request_sha256 = candidate.members[0].request_sha256.clone();
            },
            |candidate: &mut RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport| {
                candidate.members[1].response_sha256 = candidate.members[0].response_sha256.clone();
            },
            |candidate: &mut RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceiptQuorumReport| {
                candidate.members[1].witness_sha256 = candidate.members[0].witness_sha256.clone();
            },
        ] {
            let mut candidate = report.clone();
            mutate(&mut candidate);
            assert!(
                validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                    &candidate,
                )
                .is_err()
            );
        }
        let mut unsorted = report.clone();
        unsorted.members.reverse();
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &unsorted,
            )
            .is_err()
        );
        let mut mixed = report.clone();
        mixed.members[1].witness_key_trust_state_sha256 = Some("3".repeat(64));
        mixed.members[1].witness_key_generation = Some(1);
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &mixed,
            )
            .is_err()
        );

        let mut log = new_approval_transparency_log("final-witness-receipts").unwrap();
        for member in &report.members {
            append_approval_transparency_event(
                &mut log,
                ApprovalEventDescriptor {
                    artifact_kind: ApprovalArtifactKind::RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
                    artifact_sha256: member.receipt_sha256.clone(),
                    subject_id: report.checkpoint_sha256.clone(),
                    request_sha256: Some(member.request_sha256.clone()),
                    session_sha256: Some(member.response_sha256.clone()),
                    signer_id: None,
                    outcome: format!("verified-witness:{}", member.witness_id),
                },
                2_100,
            )
            .unwrap();
        }
        let mut bound = report.clone();
        bound.final_checkpoint_witness_receipt_admission_log_id = Some(log.log_id.clone());
        bound.final_checkpoint_witness_receipt_admission_log_entry_count =
            Some(log.entries.len() as u64);
        bound.final_checkpoint_witness_receipt_admission_log_head_sha256 = log.head_sha256.clone();
        bound.final_checkpoint_witness_receipt_admission_log_sha256 =
            Some(approval_transparency_log_sha256(&log).unwrap());
        validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_for_log(
            &bound,
            &log,
        )
        .unwrap();
        let mut changed = log;
        changed.entries.last_mut().unwrap().event.outcome = "verified-witness:other".into();
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_for_log(
                &bound,
                &changed,
            )
            .is_err()
        );
    }

    #[test]
    fn receipt_contract_is_canonical_closed_and_completely_bound() {
        let receipt = receipt();
        let source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
            &receipt,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &source,
            )
            .unwrap(),
            receipt
        );
        assert!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &serde_json::to_vec(&receipt).unwrap(),
            )
            .is_err()
        );
        let mut unknown = serde_json::to_value(&receipt).unwrap();
        unknown["credential"] = json!("must-not-be-retained");
        let mut unknown_source = serde_json::to_vec_pretty(&unknown).unwrap();
        unknown_source.push(b'\n');
        assert!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &unknown_source,
            )
            .is_err()
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_json_schema(
            )["additionalProperties"],
            false
        );

        let mut partial_trust = receipt.clone();
        partial_trust.witness_key_trust_state_sha256 = Some("e".repeat(64));
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &partial_trust,
            )
            .is_err()
        );
        let mut partial_generation = receipt.clone();
        partial_generation.witness_key_generation = Some(3);
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &partial_generation,
            )
            .is_err()
        );
        let mut complete_trust = receipt.clone();
        complete_trust.witness_key_trust_state_sha256 = Some("e".repeat(64));
        complete_trust.witness_key_generation = Some(3);
        validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
            &complete_trust,
        )
        .unwrap();
        let mut stale = receipt.clone();
        stale.evaluated_at_unix = stale.witnessed_at_unix + MAXIMUM_WITNESS_AGE_SECONDS + 1;
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &stale,
            )
            .is_err()
        );
        let mut same_role = receipt;
        same_role.witness_public_key = same_role.checkpoint_public_key.clone();
        assert!(
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                &same_role,
            )
            .is_err()
        );
    }

    #[test]
    fn transport_configuration_is_strictly_bounded_before_network_access() {
        let checkpoint_key = SigningKey::from_bytes(&[153; 32]);
        let witness_key = SigningKey::from_bytes(&[154; 32]);
        let checkpoint_public_key = checkpoint_key.verifying_key().to_bytes();
        let witness_public_key = witness_key.verifying_key().to_bytes();
        validate_request_configuration(
            "https://witness.example/v1/final-checkpoint",
            "final-witness-a",
            &checkpoint_public_key,
            &witness_public_key,
            Some("PCBEX_WITNESS_TOKEN"),
            30,
            2_000,
            false,
        )
        .unwrap();
        assert!(
            validate_request_configuration(
                "https://witness.example/v1/final-checkpoint?redirect=https://evil.example",
                "final-witness-a",
                &checkpoint_public_key,
                &witness_public_key,
                None,
                30,
                2_000,
                false,
            )
            .is_err()
        );
        assert!(
            validate_request_configuration(
                "http://witness.example/v1/final-checkpoint",
                "final-witness-a",
                &checkpoint_public_key,
                &witness_public_key,
                None,
                30,
                2_000,
                false,
            )
            .is_err()
        );
        assert!(
            validate_request_configuration(
                "http://127.0.0.1:3000/v1/final-checkpoint",
                "final-witness-a",
                &checkpoint_public_key,
                &witness_public_key,
                None,
                30,
                2_000,
                false,
            )
            .is_err()
        );
        validate_request_configuration(
            "http://127.0.0.1:3000/v1/final-checkpoint",
            "final-witness-a",
            &checkpoint_public_key,
            &witness_public_key,
            None,
            30,
            2_000,
            true,
        )
        .unwrap();
        assert!(
            validate_request_configuration(
                "https://witness.example/v1/final-checkpoint",
                "final-witness-a",
                &checkpoint_public_key,
                &checkpoint_public_key,
                None,
                30,
                2_000,
                false,
            )
            .is_err()
        );
        for timeout_seconds in [0, 601] {
            assert!(
                validate_request_configuration(
                    "https://witness.example/v1/final-checkpoint",
                    "final-witness-a",
                    &checkpoint_public_key,
                    &witness_public_key,
                    None,
                    timeout_seconds,
                    2_000,
                    false,
                )
                .is_err()
            );
        }
        assert!(
            validate_request_configuration(
                "https://witness.example/v1/final-checkpoint",
                "final-witness-a",
                &checkpoint_public_key,
                &witness_public_key,
                None,
                30,
                MAX_TIMESTAMP + 1,
                false,
            )
            .is_err()
        );
        assert!(
            validate_request_configuration(
                "https://witness.example/v1/final-checkpoint",
                "final-witness-a",
                &checkpoint_public_key,
                &VerifyingKey::from_bytes(&[0; 32]).unwrap().to_bytes(),
                None,
                30,
                2_000,
                false,
            )
            .is_err()
        );
        assert!(
            validate_request_configuration(
                "https://witness.example/v1/final-checkpoint",
                "final-witness-a",
                &checkpoint_public_key,
                &witness_public_key,
                Some(&"A".repeat(MAX_ENV_NAME_BYTES + 1)),
                30,
                2_000,
                false,
            )
            .is_err()
        );
    }
}
