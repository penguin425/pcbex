//! Bounded remote witnesses for portable factory-release registry checkpoints.
//!
//! The v1.501 boundary sends one accepted v1.500 checkpoint trust state over a
//! bounded HTTPS adapter. The returned canonical witness is immediately
//! verified against the complete local registry history and either a directly
//! pinned key or a generation-chained witness trust state. A hash-bound
//! transport receipt records exactly which local history, request, and response
//! were used. This remains selected-witness evidence: it does not establish
//! global non-equivocation, trusted time, endpoint legal identity, or
//! independent witness operation.
//!
//! The v1.506 boundary signs an exact successful receipt-quorum report and its
//! bound approval-log state beneath a factory-specific domain. It preserves the
//! earlier receipt, report, event, log, and generic checkpoint contracts.
//!
//! The v1.507 boundary independently witnesses that dedicated checkpoint after
//! re-verifying the exact v1.506 evidence. Its quorum requires fresh, distinct,
//! non-weak witness keys that cannot reuse the checkpoint signing key.
//!
//! The v1.508 boundary binds each dedicated-checkpoint witness identity to a
//! generation-zero trust state and advances its key only through a dual-signed,
//! digest-chained, one-generation rotation. The unchanged v1.507 quorum can
//! consume either direct key pins or current trust states.
//!
//! The v1.509 boundary acquires one unchanged v1.507 dedicated-checkpoint
//! witness through bounded HTTPS. It sends the exact public report, approval
//! log, and checkpoint only after local v1.506 verification, then verifies the
//! canonical response against either a direct key or the current v1.508 trust
//! state before retaining the witness and a hash-bound transport receipt.
//!
//! The v1.510 boundary maps one validated transport receipt into the existing
//! approval-log event contract. The v1.511 boundary adds an admission path that
//! replays every retained input before emitting that unchanged event.
//!
//! The v1.512 boundary verifies one shared checkpoint context and a bounded set
//! of exact receipt/response/trust bindings, then reuses the production witness
//! quorum once. It sorts distinct members by witness identity and binds the
//! unchanged event suffix plus complete destination log to a canonical report.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_state_transparency_external_gossip_registry::{
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION,
    parse_factory_release_state_transparency_external_gossip_organization_registry_history,
};
use crate::factory_release_state_transparency_external_gossip_registry_checkpoint::{
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint,
    factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key,
    parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state,
    parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state,
    parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness,
    signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256,
    verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::{
    ApprovalArtifactKind, ApprovalTransparencyLog, approval_transparency_log_sha256,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    time::Duration,
};

const PROTOCOL: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-v1";
const ADAPTER: &str = "remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-https-v1";
const RECEIPT_QUORUM_LOG_CHECKPOINT_DOMAIN: &str =
    "pcbex-factory-release-registry-receipt-quorum-log-checkpoint-v1";
const RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_DOMAIN: &str =
    "pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-v1";
const RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_DOMAIN: &str =
    "pcbex-factory-release-registry-receipt-quorum-log-checkpoint-witness-key-rotation-v1";
const RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_PROTOCOL: &str =
    "pcbex-remote-factory-release-registry-receipt-quorum-log-checkpoint-witness-v1";
const RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_ADAPTER: &str =
    "remote-factory-release-registry-receipt-quorum-log-checkpoint-witness-https-v1";
const MAXIMUM_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_AGE_SECONDS: u64 = 86_400;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_APPROVAL_LOG_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_REQUEST_BYTES: u64 = 129 * 1024 * 1024;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_BYTES:
    u64 = 64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_VERIFICATION_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_TRUST_STATE_BYTES: u64 =
    32 * 1024;
pub(crate) const MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_BYTES: u64 =
    32 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES: u64 =
    128 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteRegistryHistoryCheckpointWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    checkpoint_trust_state:
        &'a FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    quorum_report: &'a RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    approval_log: &'a ApprovalTransparencyLog,
    checkpoint: &'a SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt
{
    pub(crate) schema_version: u32,
    pub(crate) adapter: String,
    pub(crate) endpoint: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) history_sha256: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) checkpoint_trust_state_sha256: String,
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
pub(crate) struct RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember
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
pub(crate) struct RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport
{
    pub(crate) schema_version: u32,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) history_sha256: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) checkpoint_trust_state_sha256: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) minimum_witnesses: u32,
    pub(crate) valid_witnesses: u32,
    pub(crate) members: Vec<RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember>,
    pub(crate) quorum_met: bool,
    pub(crate) approval_log_id: Option<String>,
    pub(crate) approval_log_entry_count: Option<u64>,
    pub(crate) approval_log_head_sha256: Option<String>,
    pub(crate) approval_log_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint {
    pub(crate) schema_version: u32,
    pub(crate) quorum_report_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) registry_checkpoint_sha256: String,
    pub(crate) approval_log_id: String,
    pub(crate) approval_log_entry_count: u64,
    pub(crate) approval_log_head_sha256: String,
    pub(crate) approval_log_sha256: String,
    pub(crate) minimum_witnesses: u32,
    pub(crate) valid_witnesses: u32,
    pub(crate) signer_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointVerification {
    pub(crate) schema_version: u32,
    pub(crate) quorum_report_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) approval_log_id: String,
    pub(crate) approval_log_entry_count: u64,
    pub(crate) approval_log_head_sha256: String,
    pub(crate) approval_log_sha256: String,
    pub(crate) signer_id: String,
    pub(crate) public_key: String,
    pub(crate) verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness {
    pub(crate) schema_version: u32,
    pub(crate) checkpoint_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) approval_log_id: String,
    pub(crate) approval_log_entry_count: u64,
    pub(crate) approval_log_head_sha256: String,
    pub(crate) approval_log_sha256: String,
    pub(crate) witness_id: String,
    pub(crate) witnessed_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) approval_log_id: String,
    pub(crate) approval_log_entry_count: u64,
    pub(crate) approval_log_head_sha256: String,
    pub(crate) approval_log_sha256: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) minimum_witnesses: u32,
    pub(crate) valid_witnesses: u32,
    pub(crate) witness_ids: Vec<String>,
    pub(crate) witness_public_keys: Vec<String>,
    pub(crate) quorum_met: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState {
    pub(crate) schema_version: u32,
    pub(crate) witness_id: String,
    pub(crate) generation: u64,
    pub(crate) current_public_key: String,
    pub(crate) last_rotation_sha256: Option<String>,
    pub(crate) last_rotated_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation
{
    pub(crate) schema_version: u32,
    pub(crate) witness_id: String,
    pub(crate) from_generation: u64,
    pub(crate) to_generation: u64,
    pub(crate) previous_rotation_sha256: Option<String>,
    pub(crate) old_public_key: String,
    pub(crate) new_public_key: String,
    pub(crate) rotated_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) old_signature: String,
    pub(crate) new_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt {
    pub(crate) schema_version: u32,
    pub(crate) adapter: String,
    pub(crate) endpoint: String,
    pub(crate) quorum_report_sha256: String,
    pub(crate) quorum_report_source_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) registry_checkpoint_sha256: String,
    pub(crate) approval_log_id: String,
    pub(crate) approval_log_entry_count: u64,
    pub(crate) approval_log_head_sha256: String,
    pub(crate) approval_log_sha256: String,
    pub(crate) approval_log_source_sha256: String,
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
pub(crate) struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumMember
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
pub(crate) struct RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport
{
    pub(crate) schema_version: u32,
    pub(crate) quorum_report_sha256: String,
    pub(crate) quorum_report_source_sha256: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) registry_checkpoint_sha256: String,
    pub(crate) approval_log_id: String,
    pub(crate) approval_log_entry_count: u64,
    pub(crate) approval_log_head_sha256: String,
    pub(crate) approval_log_sha256: String,
    pub(crate) approval_log_source_sha256: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) checkpoint_source_sha256: String,
    pub(crate) checkpoint_public_key: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) minimum_witnesses: u32,
    pub(crate) valid_witnesses: u32,
    pub(crate) members: Vec<
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumMember,
    >,
    pub(crate) quorum_met: bool,
    pub(crate) admission_log_id: Option<String>,
    pub(crate) admission_log_entry_count: Option<u64>,
    pub(crate) admission_log_head_sha256: Option<String>,
    pub(crate) admission_log_sha256: Option<String>,
}

struct RemoteReceiptVerificationContext {
    history: FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistory,
    checkpoint_state:
        FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
    history_sha256: String,
    checkpoint_trust_state_sha256: String,
    request_sha256: String,
}

struct RemoteReceiptQuorumLogCheckpointWitnessVerificationContext {
    report: RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    checkpoint: SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    quorum_report_source_sha256: String,
    approval_log_source_sha256: String,
    checkpoint_source_sha256: String,
    checkpoint_sha256: String,
    checkpoint_public_key: String,
    request_sha256: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
>{
    request_remote_witness(
        history_source,
        checkpoint_trust_state_source,
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
pub(crate) fn request_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_with_trust_state(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    endpoint: &str,
    witness_key_trust_state_source: &[u8],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
>{
    let trust_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state(
            witness_key_trust_state_source,
        )?;
    let trusted_public_key =
        factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            &trust_state,
        )?;
    request_remote_witness(
        history_source,
        checkpoint_trust_state_source,
        endpoint,
        &trusted_public_key,
        Some((&trust_state, sha256(witness_key_trust_state_source))),
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    verify_remote_receipt(
        receipt,
        history_source,
        checkpoint_trust_state_source,
        response_bytes,
        trusted_public_key,
        None,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_with_trust_state(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_bytes: &[u8],
    witness_key_trust_state_source: &[u8],
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    let trust_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state(
            witness_key_trust_state_source,
        )?;
    let trusted_public_key =
        factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            &trust_state,
        )?;
    verify_remote_receipt(
        receipt,
        history_source,
        checkpoint_trust_state_source,
        response_bytes,
        &trusted_public_key,
        Some((&trust_state, sha256(witness_key_trust_state_source))),
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum(
    receipts: &[RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt],
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_documents: &[Vec<u8>],
    trusted_witnesses: &[(String, [u8; 32])],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt>,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    ),
    String,
>{
    if receipts.len() != trusted_witnesses.len() {
        return Err("remote factory release receipt and trusted witness counts must match".into());
    }
    let mut trusted = BTreeMap::new();
    for (witness_id, public_key) in trusted_witnesses {
        validate_slug(witness_id, "registry history witness id")?;
        validate_nonweak_public_key(public_key, "trusted registry history witness key")?;
        if trusted.insert(witness_id.as_str(), public_key).is_some() {
            return Err(
                "remote factory release receipt quorum repeats a trusted witness identity".into(),
            );
        }
    }
    let context =
        prepare_remote_receipt_verification_context(history_source, checkpoint_trust_state_source)?;
    verify_remote_receipt_quorum(
        receipts,
        response_documents,
        &context,
        trusted_witnesses,
        minimum_witnesses,
        evaluated_at_unix,
        |receipt, response| {
            let public_key = trusted.get(receipt.witness_id.as_str()).ok_or_else(|| {
                "remote factory release receipt quorum witness identity is untrusted".to_string()
            })?;
            verify_remote_receipt_binding(
                receipt,
                &context,
                response,
                public_key,
                None,
                evaluated_at_unix,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_with_trust_states(
    receipts: &[RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt],
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_documents: &[Vec<u8>],
    witness_key_trust_state_sources: &[Vec<u8>],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<
    (
        Vec<RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt>,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    ),
    String,
>{
    if receipts.len() != witness_key_trust_state_sources.len() {
        return Err(
            "remote factory release receipt and witness trust-state counts must match".into(),
        );
    }
    let mut trust_states = BTreeMap::new();
    for source in witness_key_trust_state_sources {
        let state =
            parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state(
                source,
            )?;
        let public_key =
            factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
                &state,
            )?;
        let witness_id = state.witness_id.clone();
        if trust_states
            .insert(witness_id, (state, sha256(source), public_key))
            .is_some()
        {
            return Err(
                "remote factory release receipt quorum repeats a witness trust identity".into(),
            );
        }
    }
    let trusted_witnesses = trust_states
        .iter()
        .map(|(witness_id, (_, _, public_key))| (witness_id.clone(), *public_key))
        .collect::<Vec<_>>();
    let context =
        prepare_remote_receipt_verification_context(history_source, checkpoint_trust_state_source)?;
    verify_remote_receipt_quorum(
        receipts,
        response_documents,
        &context,
        &trusted_witnesses,
        minimum_witnesses,
        evaluated_at_unix,
        |receipt, response| {
            let (state, digest, public_key) = trust_states
                .get(receipt.witness_id.as_str())
                .ok_or_else(|| {
                    "remote factory release receipt quorum witness trust state is absent"
                        .to_string()
                })?;
            verify_remote_receipt_binding(
                receipt,
                &context,
                response,
                public_key,
                Some((state, digest.clone())),
                evaluated_at_unix,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt_quorum(
    receipts: &[RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt],
    response_documents: &[Vec<u8>],
    context: &RemoteReceiptVerificationContext,
    trusted_witnesses: &[(String, [u8; 32])],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
    mut verify: impl FnMut(
        &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
        &[u8],
    ) -> Result<
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        String,
    >,
) -> Result<
    (
        Vec<RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt>,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    ),
    String,
>{
    if !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
        .contains(&minimum_witnesses)
        || receipts.is_empty()
        || receipts.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || receipts.len() != response_documents.len()
    {
        return Err("remote factory release receipt quorum input count is invalid".into());
    }
    let mut verified = Vec::with_capacity(receipts.len());
    for (receipt, response) in receipts.iter().zip(response_documents) {
        let witness = verify(receipt, response)?;
        let receipt_source = serde_json::to_vec(receipt).map_err(|error| {
            format!("serializing remote factory release witness receipt: {error}")
        })?;
        verified.push((
            receipt.clone(),
            witness,
            RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember {
                witness_id: receipt.witness_id.clone(),
                witness_public_key: receipt.witness_public_key.clone(),
                witness_key_trust_state_sha256: receipt.witness_key_trust_state_sha256.clone(),
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
        .map(|(_, witness, _)| witness.clone())
        .collect::<Vec<_>>();
    let witness_report =
        verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &context.history,
            &context.checkpoint_state.signed_checkpoint,
            &witnesses,
            trusted_witnesses,
            minimum_witnesses,
            evaluated_at_unix,
        )?;
    verified.sort_by(|left, right| left.2.witness_id.cmp(&right.2.witness_id));
    let members = verified
        .iter()
        .map(|(_, _, member)| member.clone())
        .collect::<Vec<_>>();
    if witness_report.members.len() != members.len()
        || witness_report
            .members
            .iter()
            .zip(&members)
            .any(|(witness, receipt)| {
                witness.witness_id != receipt.witness_id
                    || witness.public_key != receipt.witness_public_key
                    || witness.witness_sha256 != receipt.witness_sha256
            })
    {
        return Err(
            "remote factory release receipt quorum does not match its witness quorum".into(),
        );
    }
    let report = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport {
        schema_version: 1,
        registry_id: context.checkpoint_state.registry_id.clone(),
        generation: context.checkpoint_state.accepted_generation,
        history_sha256: context.history_sha256.clone(),
        checkpoint_sha256: context.checkpoint_state.checkpoint_sha256.clone(),
        checkpoint_trust_state_sha256: context.checkpoint_trust_state_sha256.clone(),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses: witness_report.valid_witnesses,
        members,
        quorum_met: witness_report.quorum_met,
        approval_log_id: None,
        approval_log_entry_count: None,
        approval_log_head_sha256: None,
        approval_log_sha256: None,
    };
    validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
        &report,
    )?;
    Ok((
        verified
            .into_iter()
            .map(|(receipt, _, _)| receipt)
            .collect(),
        report,
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    let context =
        prepare_remote_receipt_verification_context(history_source, checkpoint_trust_state_source)?;
    let witness = verify_remote_receipt_binding(
        receipt,
        &context,
        response_bytes,
        trusted_public_key,
        witness_key_trust_state,
        evaluated_at_unix,
    )?;
    let trusted_witnesses = vec![(witness.witness_id.clone(), *trusted_public_key)];
    let report =
        verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &context.history,
            &context.checkpoint_state.signed_checkpoint,
            std::slice::from_ref(&witness),
            &trusted_witnesses,
            2,
            evaluated_at_unix,
        )?;
    if report.valid_witnesses != 1 || report.quorum_met {
        return Err(
            "remote factory release registry history checkpoint witness admission produced an invalid single-witness result"
                .into(),
        );
    }
    Ok(witness)
}

fn prepare_remote_receipt_verification_context(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
) -> Result<RemoteReceiptVerificationContext, String> {
    let history =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history(
            history_source,
        )?;
    let checkpoint_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
            checkpoint_trust_state_source,
        )?;
    let reconstructed =
        accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history,
            &checkpoint_state.signed_checkpoint,
            None,
            checkpoint_state.accepted_at_unix,
        )?;
    if reconstructed != checkpoint_state {
        return Err(
            "factory release registry history checkpoint trust state does not match the complete history"
                .into(),
        );
    }
    let request_bytes =
        serde_json::to_vec(&RemoteRegistryHistoryCheckpointWitnessRequest {
            schema_version: 1,
            protocol: PROTOCOL,
            checkpoint_trust_state: &checkpoint_state,
        })
        .map_err(|error| {
            format!(
                "serializing remote factory release registry history checkpoint witness request: {error}"
            )
        })?;
    Ok(RemoteReceiptVerificationContext {
        history,
        checkpoint_state,
        history_sha256: sha256(history_source),
        checkpoint_trust_state_sha256: sha256(checkpoint_trust_state_source),
        request_sha256: sha256(&request_bytes),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt_binding(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    context: &RemoteReceiptVerificationContext,
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    validate_remote_receipt(receipt)?;
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release registry history checkpoint witness admission time is outside its bound"
                .into(),
        );
    }
    if evaluated_at_unix < receipt.evaluated_at_unix {
        return Err(
            "remote factory release registry history checkpoint witness receipt is future-dated at admission"
                .into(),
        );
    }
    validate_nonweak_public_key(trusted_public_key, "trusted registry history witness key")?;

    if receipt.registry_id != context.checkpoint_state.registry_id
        || receipt.generation != context.checkpoint_state.accepted_generation
        || receipt.history_sha256 != context.history_sha256
        || receipt.checkpoint_sha256 != context.checkpoint_state.checkpoint_sha256
        || receipt.checkpoint_trust_state_sha256 != context.checkpoint_trust_state_sha256
        || receipt.request_sha256 != context.request_sha256
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt is bound to different retained evidence"
                .into(),
        );
    }
    if response_bytes.is_empty()
        || response_bytes.len() as u64 > MAX_RESPONSE_BYTES
        || receipt.response_bytes != response_bytes.len() as u64
        || receipt.response_sha256 != sha256(response_bytes)
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt response binding is invalid"
                .into(),
        );
    }
    let witness =
        parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            response_bytes,
        )?;
    if receipt.witness_sha256
        != signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256(
            &witness,
        )?
        || receipt.witness_id != witness.witness_id
        || receipt.witness_public_key != witness.public_key
        || receipt.witnessed_at_unix != witness.witnessed_at_unix
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt describes different witness evidence"
                .into(),
        );
    }
    let expected_trust_binding = witness_key_trust_state
        .as_ref()
        .map(|(state, digest)| (Some(digest.clone()), Some(state.generation)))
        .unwrap_or((None, None));
    if (
        receipt.witness_key_trust_state_sha256.clone(),
        receipt.witness_key_generation,
    ) != expected_trust_binding
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt trust binding is invalid"
                .into(),
        );
    }
    if let Some((trust_state, _)) = &witness_key_trust_state
        && witness.witness_id != trust_state.witness_id
    {
        return Err(
            "remote factory release registry history checkpoint witness identity does not match its trust state"
                .into(),
        );
    }

    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
fn request_remote_witness(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
        String,
    )>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
>{
    if !(1..=600).contains(&timeout_seconds) {
        return Err(
            "remote factory release registry history checkpoint witness timeout must be between 1 and 600 seconds"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release registry history checkpoint witness evaluation time is outside its bound"
                .into(),
        );
    }
    validate_nonweak_public_key(trusted_public_key, "trusted registry history witness key")?;
    validate_endpoint(endpoint, allow_http_loopback)?;

    // Audit before performing network I/O. The equality check proves that the
    // supplied trust state is the canonical acceptance result for this exact
    // complete history and embedded retained-root checkpoint.
    let history =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history(
            history_source,
        )?;
    let checkpoint_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
            checkpoint_trust_state_source,
        )?;
    let reconstructed =
        accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history,
            &checkpoint_state.signed_checkpoint,
            None,
            checkpoint_state.accepted_at_unix,
        )?;
    if reconstructed != checkpoint_state {
        return Err(
            "factory release registry history checkpoint trust state does not match the complete history"
                .into(),
        );
    }

    let request = RemoteRegistryHistoryCheckpointWitnessRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        checkpoint_trust_state: &checkpoint_state,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        format!("serializing remote factory release registry history checkpoint witness request: {error}")
    })?;
    let request_sha256 = sha256(&request_bytes);
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
        let token = env::var(variable).map_err(|_| {
            format!(
                "remote factory release registry history checkpoint witness bearer-token environment {variable} is unset"
            )
        })?;
        if token.trim().is_empty() {
            return Err(format!(
                "remote factory release registry history checkpoint witness bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call.send(request_bytes).map_err(|error| {
        format!(
            "remote factory release registry history checkpoint witness HTTPS request failed: {error}"
        )
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote factory release registry history checkpoint witness returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err(
            "remote factory release registry history checkpoint witness response Content-Type must be application/json"
                .into(),
        );
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| {
            format!(
                "reading bounded remote factory release registry history checkpoint witness response: {error}"
            )
        })?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "remote factory release registry history checkpoint witness response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let witness =
        parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            &response_bytes,
        )?;
    if let Some((trust_state, _)) = &witness_key_trust_state
        && witness.witness_id != trust_state.witness_id
    {
        return Err(
            "remote factory release registry history checkpoint witness identity does not match its trust state"
                .into(),
        );
    }
    let trusted_witnesses = vec![(witness.witness_id.clone(), *trusted_public_key)];
    let report =
        verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &history,
            &checkpoint_state.signed_checkpoint,
            std::slice::from_ref(&witness),
            &trusted_witnesses,
            2,
            evaluated_at_unix,
        )?;
    if report.valid_witnesses != 1 || report.quorum_met {
        return Err(
            "remote factory release registry history checkpoint witness verification produced an invalid single-witness result"
                .into(),
        );
    }

    let (witness_key_trust_state_sha256, witness_key_generation) = witness_key_trust_state
        .map(|(state, digest)| (Some(digest), Some(state.generation)))
        .unwrap_or((None, None));
    let receipt = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt {
        schema_version: 1,
        adapter: ADAPTER.into(),
        endpoint: endpoint.into(),
        registry_id: checkpoint_state.registry_id.clone(),
        generation: checkpoint_state.accepted_generation,
        history_sha256: sha256(history_source),
        checkpoint_sha256: checkpoint_state.checkpoint_sha256.clone(),
        checkpoint_trust_state_sha256: sha256(checkpoint_trust_state_source),
        request_sha256,
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        witness_sha256:
            signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256(
                &witness,
            )?,
        evaluated_at_unix,
        witness_id: witness.witness_id.clone(),
        witness_public_key: witness.public_key.clone(),
        witness_key_trust_state_sha256,
        witness_key_generation,
        witnessed_at_unix: witness.witnessed_at_unix,
        verified: true,
    };
    validate_remote_receipt(&receipt)?;
    Ok((witness, receipt))
}

pub(crate) fn render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
) -> Result<Vec<u8>, String> {
    validate_remote_receipt(receipt)?;
    render_bounded(
        receipt,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory release registry history checkpoint witness receipt",
    )
}

pub(crate) fn parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    String,
>{
    let receipt = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory release registry history checkpoint witness receipt",
    )?;
    validate_remote_receipt(&receipt)?;
    Ok(receipt)
}

pub(crate) fn render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES,
        "remote factory release registry history checkpoint witness receipt quorum report",
    )
}

pub(crate) fn parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    String,
>{
    let report = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES,
        "remote factory release registry history checkpoint witness receipt quorum report",
    )?;
    validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
) -> Result<Vec<u8>, String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        checkpoint,
    )?;
    render_bounded(
        checkpoint,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_BYTES,
        "signed remote factory release registry history receipt quorum log checkpoint",
    )
}

pub(crate) fn parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    source: &[u8],
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint, String> {
    let checkpoint = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_BYTES,
        "signed remote factory release registry history receipt quorum log checkpoint",
    )?;
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        &checkpoint,
    )?;
    Ok(checkpoint)
}

pub(crate) fn render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
    verification: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointVerification,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
        verification,
    )?;
    render_bounded(
        verification,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_VERIFICATION_BYTES,
        "remote factory release registry history receipt quorum log checkpoint verification",
    )
}

#[cfg(test)]
fn parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
    source: &[u8],
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointVerification, String> {
    let verification = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_VERIFICATION_BYTES,
        "remote factory release registry history receipt quorum log checkpoint verification",
    )?;
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
        &verification,
    )?;
    Ok(verification)
}

pub(crate) fn render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
    witness: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
) -> Result<Vec<u8>, String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
        witness,
    )?;
    render_bounded(
        witness,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES,
        "signed remote factory release registry history receipt quorum log checkpoint witness",
    )
}

pub(crate) fn parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
    source: &[u8],
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    let witness = parse_canonical(
        source,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES,
        "signed remote factory release registry history receipt quorum log checkpoint witness",
    )?;
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

pub(crate) fn render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES,
        "remote factory release registry history receipt quorum log checkpoint witness quorum report",
    )
}

pub(crate) fn parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
    source: &[u8],
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport, String>
{
    let report = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_REPORT_BYTES,
        "remote factory release registry history receipt quorum log checkpoint witness quorum report",
    )?;
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
    state: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    render_bounded(
        state,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_TRUST_STATE_BYTES,
        "remote factory release receipt quorum checkpoint witness trust state",
    )
}

pub(crate) fn parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
    source: &[u8],
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState, String>
{
    let state = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_TRUST_STATE_BYTES,
        "remote factory release receipt quorum checkpoint witness trust state",
    )?;
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        &state,
    )?;
    Ok(state)
}

pub(crate) fn render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    rotation: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<Vec<u8>, String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
        rotation,
    )?;
    render_bounded(
        rotation,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_BYTES,
        "signed remote factory release receipt quorum checkpoint witness key rotation",
    )
}

pub(crate) fn parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    source: &[u8],
) -> Result<
    SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
    String,
> {
    let rotation = parse_canonical(
        source,
        MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_BYTES,
        "signed remote factory release receipt quorum checkpoint witness key rotation",
    )?;
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    endpoint: &str,
    trusted_witness_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    ),
    String,
> {
    request_remote_receipt_quorum_log_checkpoint_witness(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        endpoint,
        trusted_witness_public_key,
        None,
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_with_trust_state(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    endpoint: &str,
    witness_key_trust_state_source: &[u8],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    ),
    String,
> {
    let trust_state =
        parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
            witness_key_trust_state_source,
        )?;
    let trusted_witness_public_key =
        remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trusted_public_key(
            &trust_state,
        )?;
    request_remote_receipt_quorum_log_checkpoint_witness(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        endpoint,
        &trusted_witness_public_key,
        Some((&trust_state, sha256(witness_key_trust_state_source))),
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_bytes: &[u8],
    trusted_witness_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    verify_remote_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_bytes,
        trusted_witness_public_key,
        None,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_with_trust_state(
    receipt: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_bytes: &[u8],
    witness_key_trust_state_source: &[u8],
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    let trust_state =
        parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
            witness_key_trust_state_source,
        )?;
    let trusted_witness_public_key =
        remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trusted_public_key(
            &trust_state,
        )?;
    verify_remote_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        response_bytes,
        &trusted_witness_public_key,
        Some((&trust_state, sha256(witness_key_trust_state_source))),
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    response_bytes: &[u8],
    trusted_witness_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    let context = prepare_remote_receipt_quorum_log_checkpoint_witness_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
    )?;
    let witness = verify_remote_receipt_quorum_log_checkpoint_witness_receipt_binding(
        receipt,
        &context,
        response_bytes,
        trusted_checkpoint_public_key,
        trusted_witness_public_key,
        witness_key_trust_state,
        evaluated_at_unix,
    )?;
    let single = verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_after_checkpoint_verification(
        &context.report,
        &context.checkpoint,
        trusted_checkpoint_public_key,
        std::slice::from_ref(&witness),
        std::slice::from_ref(trusted_witness_public_key),
        2,
        evaluated_at_unix,
    )?;
    if single.valid_witnesses != 1 || single.quorum_met {
        return Err(
            "remote factory release receipt quorum checkpoint witness admission produced an invalid single-witness result"
                .into(),
        );
    }
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum(
    receipts: &[RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt],
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
        Vec<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt>,
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    ),
    String,
> {
    if receipts.len() != trusted_witnesses.len() {
        return Err(
            "remote factory release checkpoint-witness receipt and trusted witness counts must match"
                .into(),
        );
    }
    let mut trusted = BTreeMap::new();
    for (witness_id, public_key) in trusted_witnesses {
        validate_slug(
            witness_id,
            "factory release receipt quorum checkpoint witness id",
        )?;
        validate_nonweak_public_key(
            public_key,
            "trusted factory release receipt quorum checkpoint witness key",
        )?;
        if trusted.insert(witness_id.as_str(), public_key).is_some() {
            return Err(
                "remote factory release checkpoint-witness receipt quorum repeats a trusted witness identity"
                    .into(),
            );
        }
    }
    let context = prepare_remote_receipt_quorum_log_checkpoint_witness_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
    )?;
    verify_remote_receipt_quorum_log_checkpoint_witness_receipt_quorum(
        receipts,
        response_documents,
        &context,
        trusted_checkpoint_public_key,
        minimum_witnesses,
        evaluated_at_unix,
        |receipt, response| {
            let public_key = trusted.get(receipt.witness_id.as_str()).ok_or_else(|| {
                "remote factory release checkpoint-witness receipt quorum witness identity is untrusted"
                    .to_string()
            })?;
            let witness = verify_remote_receipt_quorum_log_checkpoint_witness_receipt_binding(
                receipt,
                &context,
                response,
                trusted_checkpoint_public_key,
                public_key,
                None,
                evaluated_at_unix,
            )?;
            Ok((witness, **public_key))
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_with_trust_states(
    receipts: &[RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt],
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
        Vec<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt>,
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    ),
    String,
> {
    if receipts.len() != witness_key_trust_state_sources.len() {
        return Err(
            "remote factory release checkpoint-witness receipt and witness trust-state counts must match"
                .into(),
        );
    }
    let mut trust_states = BTreeMap::new();
    for source in witness_key_trust_state_sources {
        let state =
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                source,
            )?;
        let public_key =
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trusted_public_key(
                &state,
            )?;
        let witness_id = state.witness_id.clone();
        if trust_states
            .insert(witness_id, (state, sha256(source), public_key))
            .is_some()
        {
            return Err(
                "remote factory release checkpoint-witness receipt quorum repeats a witness trust identity"
                    .into(),
            );
        }
    }
    let context = prepare_remote_receipt_quorum_log_checkpoint_witness_verification_context(
        quorum_report_source,
        approval_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
    )?;
    verify_remote_receipt_quorum_log_checkpoint_witness_receipt_quorum(
        receipts,
        response_documents,
        &context,
        trusted_checkpoint_public_key,
        minimum_witnesses,
        evaluated_at_unix,
        |receipt, response| {
            let (state, digest, public_key) = trust_states
                .get(receipt.witness_id.as_str())
                .ok_or_else(|| {
                    "remote factory release checkpoint-witness receipt quorum witness trust state is absent"
                        .to_string()
                })?;
            let witness = verify_remote_receipt_quorum_log_checkpoint_witness_receipt_binding(
                receipt,
                &context,
                response,
                trusted_checkpoint_public_key,
                public_key,
                Some((state, digest.clone())),
                evaluated_at_unix,
            )?;
            Ok((witness, *public_key))
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt_quorum_log_checkpoint_witness_receipt_quorum(
    receipts: &[RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt],
    response_documents: &[Vec<u8>],
    context: &RemoteReceiptQuorumLogCheckpointWitnessVerificationContext,
    trusted_checkpoint_public_key: &[u8; 32],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
    mut verify: impl FnMut(
        &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
        &[u8],
    ) -> Result<
        (
            SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
            [u8; 32],
        ),
        String,
    >,
) -> Result<
    (
        Vec<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt>,
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    ),
    String,
> {
    if !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
        .contains(&minimum_witnesses)
        || receipts.is_empty()
        || receipts.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || receipts.len() != response_documents.len()
    {
        return Err(
            "remote factory release checkpoint-witness receipt quorum input count is invalid"
                .into(),
        );
    }
    let mut verified = Vec::with_capacity(receipts.len());
    for (receipt, response) in receipts.iter().zip(response_documents) {
        let (witness, trusted_key) = verify(receipt, response)?;
        let receipt_source = serde_json::to_vec(receipt).map_err(|error| {
            format!("serializing remote factory release checkpoint-witness receipt: {error}")
        })?;
        verified.push((
            receipt.clone(),
            witness,
            trusted_key,
            RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumMember {
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
        .map(|(_, _, trusted_key, _)| *trusted_key)
        .collect::<Vec<_>>();
    let witness_report = verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_after_checkpoint_verification(
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
    let member_ids = members
        .iter()
        .map(|member| member.witness_id.clone())
        .collect::<BTreeSet<_>>();
    let member_keys = members
        .iter()
        .map(|member| member.witness_public_key.clone())
        .collect::<BTreeSet<_>>();
    if witness_report
        .witness_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != member_ids
        || witness_report
            .witness_public_keys
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            != member_keys
    {
        return Err(
            "remote factory release checkpoint-witness receipt quorum does not match its witness quorum"
                .into(),
        );
    }
    let report =
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport {
            schema_version: 1,
            quorum_report_sha256: context.checkpoint.quorum_report_sha256.clone(),
            quorum_report_source_sha256: context.quorum_report_source_sha256.clone(),
            registry_id: context.checkpoint.registry_id.clone(),
            generation: context.checkpoint.generation,
            registry_checkpoint_sha256: context.checkpoint.registry_checkpoint_sha256.clone(),
            approval_log_id: context.checkpoint.approval_log_id.clone(),
            approval_log_entry_count: context.checkpoint.approval_log_entry_count,
            approval_log_head_sha256: context.checkpoint.approval_log_head_sha256.clone(),
            approval_log_sha256: context.checkpoint.approval_log_sha256.clone(),
            approval_log_source_sha256: context.approval_log_source_sha256.clone(),
            checkpoint_sha256: context.checkpoint_sha256.clone(),
            checkpoint_source_sha256: context.checkpoint_source_sha256.clone(),
            checkpoint_public_key: context.checkpoint_public_key.clone(),
            evaluated_at_unix,
            minimum_witnesses,
            valid_witnesses: witness_report.valid_witnesses,
            members,
            quorum_met: witness_report.quorum_met,
            admission_log_id: None,
            admission_log_entry_count: None,
            admission_log_head_sha256: None,
            admission_log_sha256: None,
        };
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
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

fn prepare_remote_receipt_quorum_log_checkpoint_witness_verification_context(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
) -> Result<RemoteReceiptQuorumLogCheckpointWitnessVerificationContext, String> {
    validate_nonweak_public_key(
        trusted_checkpoint_public_key,
        "trusted factory release receipt quorum checkpoint key",
    )?;
    let report = parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
        quorum_report_source,
    )?;
    let approval_log = parse_remote_receipt_quorum_approval_log(approval_log_source)?;
    let checkpoint =
        parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
            checkpoint_source,
        )?;
    verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        &report,
        &approval_log,
        &checkpoint,
        trusted_checkpoint_public_key,
    )?;
    let request_bytes = serde_json::to_vec(
        &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessRequest {
            schema_version: 1,
            protocol: RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_PROTOCOL,
            quorum_report: &report,
            approval_log: &approval_log,
            checkpoint: &checkpoint,
        },
    )
    .map_err(|error| {
        format!(
            "serializing remote factory release receipt quorum checkpoint witness request: {error}"
        )
    })?;
    if request_bytes.is_empty()
        || request_bytes.len() as u64 > MAX_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_REQUEST_BYTES
    {
        return Err(format!(
            "remote factory release receipt quorum checkpoint witness request exceeds {MAX_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_REQUEST_BYTES} bytes"
        ));
    }
    Ok(RemoteReceiptQuorumLogCheckpointWitnessVerificationContext {
        quorum_report_source_sha256: sha256(quorum_report_source),
        approval_log_source_sha256: sha256(approval_log_source),
        checkpoint_source_sha256: sha256(checkpoint_source),
        checkpoint_sha256:
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_sha256(
                &checkpoint,
            )?,
        checkpoint_public_key: hex::encode(trusted_checkpoint_public_key),
        request_sha256: sha256(&request_bytes),
        report,
        checkpoint,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt_quorum_log_checkpoint_witness_receipt_binding(
    receipt: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    context: &RemoteReceiptQuorumLogCheckpointWitnessVerificationContext,
    response_bytes: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    trusted_witness_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
    )?;
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release receipt quorum checkpoint witness admission time is outside its bound"
                .into(),
        );
    }
    if evaluated_at_unix < receipt.evaluated_at_unix {
        return Err(
            "remote factory release receipt quorum checkpoint witness receipt is future-dated at admission"
                .into(),
        );
    }
    validate_nonweak_public_key(
        trusted_witness_public_key,
        "trusted factory release receipt quorum checkpoint witness key",
    )?;
    if trusted_checkpoint_public_key == trusted_witness_public_key {
        return Err(
            "factory release receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }

    if receipt.quorum_report_sha256 != context.checkpoint.quorum_report_sha256
        || receipt.quorum_report_source_sha256 != context.quorum_report_source_sha256
        || receipt.registry_id != context.checkpoint.registry_id
        || receipt.generation != context.checkpoint.generation
        || receipt.registry_checkpoint_sha256 != context.checkpoint.registry_checkpoint_sha256
        || receipt.approval_log_id != context.checkpoint.approval_log_id
        || receipt.approval_log_entry_count != context.checkpoint.approval_log_entry_count
        || receipt.approval_log_head_sha256 != context.checkpoint.approval_log_head_sha256
        || receipt.approval_log_sha256 != context.checkpoint.approval_log_sha256
        || receipt.approval_log_source_sha256 != context.approval_log_source_sha256
        || receipt.checkpoint_sha256 != context.checkpoint_sha256
        || receipt.checkpoint_source_sha256 != context.checkpoint_source_sha256
        || receipt.checkpoint_public_key != context.checkpoint_public_key
        || receipt.request_sha256 != context.request_sha256
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness receipt is bound to different retained evidence"
                .into(),
        );
    }
    if response_bytes.is_empty()
        || response_bytes.len() as u64
            > MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
        || receipt.response_bytes != response_bytes.len() as u64
        || receipt.response_sha256 != sha256(response_bytes)
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness receipt response binding is invalid"
                .into(),
        );
    }
    let witness =
        parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
            response_bytes,
        )?;
    if receipt.witness_sha256
        != signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_sha256(
            &witness,
        )?
        || receipt.witness_id != witness.witness_id
        || receipt.witness_public_key != witness.public_key
        || receipt.witnessed_at_unix != witness.witnessed_at_unix
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness receipt describes different witness evidence"
                .into(),
        );
    }
    let expected_trust_binding = witness_key_trust_state
        .as_ref()
        .map(|(state, digest)| (Some(digest.clone()), Some(state.generation)))
        .unwrap_or((None, None));
    if (
        receipt.witness_key_trust_state_sha256.clone(),
        receipt.witness_key_generation,
    ) != expected_trust_binding
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness receipt trust binding is invalid"
                .into(),
        );
    }
    if let Some((trust_state, _)) = &witness_key_trust_state
        && witness.witness_id != trust_state.witness_id
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness identity does not match its trust state"
                .into(),
        );
    }

    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
fn request_remote_receipt_quorum_log_checkpoint_witness(
    quorum_report_source: &[u8],
    approval_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    endpoint: &str,
    trusted_witness_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
        String,
    )>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
    ),
    String,
> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err(
            "remote factory release receipt quorum checkpoint witness timeout must be between 1 and 600 seconds"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release receipt quorum checkpoint witness evaluation time is outside its bound"
                .into(),
        );
    }
    validate_nonweak_public_key(
        trusted_checkpoint_public_key,
        "trusted factory release receipt quorum checkpoint key",
    )?;
    validate_nonweak_public_key(
        trusted_witness_public_key,
        "trusted factory release receipt quorum checkpoint witness key",
    )?;
    if trusted_checkpoint_public_key == trusted_witness_public_key {
        return Err(
            "factory release receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    validate_endpoint(endpoint, allow_http_loopback)?;

    // Re-verify every public input before network I/O or credential access.
    let report = parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
        quorum_report_source,
    )?;
    let approval_log = parse_remote_receipt_quorum_approval_log(approval_log_source)?;
    let checkpoint =
        parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
            checkpoint_source,
        )?;
    verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        &report,
        &approval_log,
        &checkpoint,
        trusted_checkpoint_public_key,
    )?;
    if evaluated_at_unix < report.evaluated_at_unix {
        return Err(
            "remote factory release receipt quorum checkpoint witness evaluation predates its quorum report"
                .into(),
        );
    }

    let request = RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessRequest {
        schema_version: 1,
        protocol: RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_PROTOCOL,
        quorum_report: &report,
        approval_log: &approval_log,
        checkpoint: &checkpoint,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        format!(
            "serializing remote factory release receipt quorum checkpoint witness request: {error}"
        )
    })?;
    if request_bytes.is_empty()
        || request_bytes.len() as u64 > MAX_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_REQUEST_BYTES
    {
        return Err(format!(
            "remote factory release receipt quorum checkpoint witness request exceeds {MAX_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_REQUEST_BYTES} bytes"
        ));
    }
    let request_sha256 = sha256(&request_bytes);
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
        let token = env::var(variable).map_err(|_| {
            format!(
                "remote factory release receipt quorum checkpoint witness bearer-token environment {variable} is unset"
            )
        })?;
        if token.trim().is_empty()
            || token.len() > 8 * 1024
            || token.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(format!(
                "remote factory release receipt quorum checkpoint witness bearer-token environment {variable} is invalid"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call.send(request_bytes).map_err(|error| {
        format!(
            "remote factory release receipt quorum checkpoint witness HTTPS request failed: {error}"
        )
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote factory release receipt quorum checkpoint witness returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err(
            "remote factory release receipt quorum checkpoint witness response Content-Type must be application/json"
                .into(),
        );
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| {
            format!(
                "reading bounded remote factory release receipt quorum checkpoint witness response: {error}"
            )
        })?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "remote factory release receipt quorum checkpoint witness response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let witness =
        parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
            &response_bytes,
        )?;
    if let Some((trust_state, _)) = &witness_key_trust_state
        && witness.witness_id != trust_state.witness_id
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness identity does not match its trust state"
                .into(),
        );
    }
    let single =
        verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
            &report,
            &approval_log,
            &checkpoint,
            trusted_checkpoint_public_key,
            std::slice::from_ref(&witness),
            std::slice::from_ref(trusted_witness_public_key),
            2,
            evaluated_at_unix,
        )?;
    if single.valid_witnesses != 1 || single.quorum_met {
        return Err(
            "remote factory release receipt quorum checkpoint witness verification produced an invalid single-witness result"
                .into(),
        );
    }

    let checkpoint_sha256 =
        signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_sha256(
            &checkpoint,
        )?;
    let (witness_key_trust_state_sha256, witness_key_generation) = witness_key_trust_state
        .map(|(state, digest)| (Some(digest), Some(state.generation)))
        .unwrap_or((None, None));
    let receipt =
        RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_ADAPTER.into(),
            endpoint: endpoint.into(),
            quorum_report_sha256: checkpoint.quorum_report_sha256.clone(),
            quorum_report_source_sha256: sha256(quorum_report_source),
            registry_id: checkpoint.registry_id.clone(),
            generation: checkpoint.generation,
            registry_checkpoint_sha256: checkpoint.registry_checkpoint_sha256.clone(),
            approval_log_id: checkpoint.approval_log_id.clone(),
            approval_log_entry_count: checkpoint.approval_log_entry_count,
            approval_log_head_sha256: checkpoint.approval_log_head_sha256.clone(),
            approval_log_sha256: checkpoint.approval_log_sha256.clone(),
            approval_log_source_sha256: sha256(approval_log_source),
            checkpoint_sha256,
            checkpoint_source_sha256: sha256(checkpoint_source),
            checkpoint_public_key: hex::encode(trusted_checkpoint_public_key),
            request_sha256,
            response_sha256: sha256(&response_bytes),
            response_bytes: response_bytes.len() as u64,
            witness_sha256:
                signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_sha256(
                    &witness,
                )?,
            evaluated_at_unix,
            witness_id: witness.witness_id.clone(),
            witness_public_key: witness.public_key.clone(),
            witness_key_trust_state_sha256,
            witness_key_generation,
            witnessed_at_unix: witness.witnessed_at_unix,
            verified: true,
        };
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
        &receipt,
    )?;
    Ok((witness, receipt))
}

fn parse_remote_receipt_quorum_approval_log(
    source: &[u8],
) -> Result<ApprovalTransparencyLog, String> {
    if source.is_empty() || source.len() as u64 > MAX_APPROVAL_LOG_SOURCE_BYTES {
        return Err(format!(
            "approval transparency log must contain 1 to {MAX_APPROVAL_LOG_SOURCE_BYTES} bytes"
        ));
    }
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid approval transparency log JSON: {error:#}"))?;
    let log: ApprovalTransparencyLog = serde_json::from_slice(source)
        .map_err(|error| format!("invalid approval transparency log JSON: {error}"))?;
    approval_transparency_log_sha256(&log)?;
    Ok(log)
}

pub(crate) fn render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
        receipt,
    )?;
    render_bounded(
        receipt,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory release receipt quorum checkpoint witness receipt",
    )
}

pub(crate) fn parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
    source: &[u8],
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt, String> {
    let receipt = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory release receipt quorum checkpoint witness receipt",
    )?;
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
        &receipt,
    )?;
    Ok(receipt)
}

pub(crate) fn render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
) -> Result<Vec<u8>, String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        report,
    )?;
    render_bounded(
        report,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES,
        "remote factory release receipt quorum checkpoint witness receipt quorum report",
    )
}

pub(crate) fn parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    String,
> {
    let report = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_RECEIPT_QUORUM_REPORT_BYTES,
        "remote factory release receipt quorum checkpoint witness receipt quorum report",
    )?;
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub(crate) fn remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-v1.json",
        "title": "pcbex remote factory-release registry-history checkpoint witness receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "registry_id", "generation",
            "history_sha256", "checkpoint_sha256", "checkpoint_trust_state_sha256",
            "request_sha256", "response_sha256", "response_bytes", "witness_sha256",
            "evaluated_at_unix", "witness_id", "witness_public_key",
            "witness_key_trust_state_sha256", "witness_key_generation",
            "witnessed_at_unix", "verified"
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
            "generation": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION},
            "history_sha256": digest.clone(),
            "checkpoint_sha256": digest.clone(),
            "checkpoint_trust_state_sha256": digest.clone(),
            "request_sha256": digest.clone(),
            "response_sha256": digest.clone(),
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "witness_sha256": digest.clone(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "witness_id": slug_schema(),
            "witness_public_key": digest.clone(),
            "witness_key_trust_state_sha256": {"oneOf": [{"type": "null"}, digest]},
            "witness_key_generation": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION}
                ]
            },
            "witnessed_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "verified": {"const": true}
        }
    })
}

pub(crate) fn remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-quorum-report-v1.json",
        "title": "pcbex verifier-bound remote factory-release registry-history witness receipt quorum",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "history_sha256",
            "checkpoint_sha256", "checkpoint_trust_state_sha256",
            "evaluated_at_unix", "minimum_witnesses", "valid_witnesses",
            "members", "quorum_met", "approval_log_id",
            "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "history_sha256": digest.clone(),
            "checkpoint_sha256": digest.clone(),
            "checkpoint_trust_state_sha256": digest.clone(),
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
                "type": "array",
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
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
            "approval_log_id": {"oneOf": [{"type": "null"}, slug_schema()]},
            "approval_log_entry_count": {
                "oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]
            },
            "approval_log_head_sha256": {
                "oneOf": [{"type": "null"}, digest.clone()]
            },
            "approval_log_sha256": {
                "oneOf": [{"type": "null"}, digest]
            }
        }
    })
}

pub(crate) fn signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-v1.json",
        "title": "pcbex signed verifier-bound factory-release receipt-quorum log checkpoint",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "quorum_report_sha256", "registry_id", "generation",
            "registry_checkpoint_sha256", "approval_log_id", "approval_log_entry_count",
            "approval_log_head_sha256", "approval_log_sha256", "minimum_witnesses",
            "valid_witnesses", "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "quorum_report_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "registry_checkpoint_sha256": digest.clone(),
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest.clone(),
            "approval_log_sha256": digest.clone(),
            "minimum_witnesses": {
                "type": "integer", "minimum": 2,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
            },
            "valid_witnesses": {
                "type": "integer", "minimum": 2,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
            },
            "signer_id": slug_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-registry-history-receipt-quorum-log-checkpoint-verification-v1.json",
        "title": "pcbex verifier-bound factory-release receipt-quorum log checkpoint verification",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "quorum_report_sha256", "registry_id", "generation",
            "approval_log_id", "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256", "signer_id", "public_key", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "quorum_report_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest.clone(),
            "approval_log_sha256": digest.clone(),
            "signer_id": slug_schema(),
            "public_key": digest,
            "verified": {"const": true}
        }
    })
}

pub(crate) fn signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-v1.json",
        "title": "pcbex independent factory receipt-quorum checkpoint witness",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "checkpoint_sha256", "registry_id", "generation",
            "approval_log_id", "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256", "witness_id", "witnessed_at_unix", "algorithm",
            "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "checkpoint_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest.clone(),
            "approval_log_sha256": digest.clone(),
            "witness_id": slug_schema(),
            "witnessed_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-v1.json",
        "title": "pcbex remote factory receipt-quorum checkpoint witness receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "quorum_report_sha256",
            "quorum_report_source_sha256", "registry_id", "generation",
            "registry_checkpoint_sha256", "approval_log_id",
            "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256", "approval_log_source_sha256",
            "checkpoint_sha256", "checkpoint_source_sha256",
            "checkpoint_public_key", "request_sha256", "response_sha256",
            "response_bytes", "witness_sha256", "evaluated_at_unix",
            "witness_id", "witness_public_key",
            "witness_key_trust_state_sha256", "witness_key_generation",
            "witnessed_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_ADAPTER},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "quorum_report_sha256": digest.clone(),
            "quorum_report_source_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "registry_checkpoint_sha256": digest.clone(),
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest.clone(),
            "approval_log_sha256": digest.clone(),
            "approval_log_source_sha256": digest.clone(),
            "checkpoint_sha256": digest.clone(),
            "checkpoint_source_sha256": digest.clone(),
            "checkpoint_public_key": digest.clone(),
            "request_sha256": digest.clone(),
            "response_sha256": digest.clone(),
            "response_bytes": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
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

pub(crate) fn remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-receipt-quorum-report-v1.json",
        "title": "pcbex verifier-bound factory checkpoint-witness receipt admission quorum",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "quorum_report_sha256",
            "quorum_report_source_sha256", "registry_id", "generation",
            "registry_checkpoint_sha256", "approval_log_id",
            "approval_log_entry_count", "approval_log_head_sha256",
            "approval_log_sha256", "approval_log_source_sha256",
            "checkpoint_sha256", "checkpoint_source_sha256",
            "checkpoint_public_key", "evaluated_at_unix", "minimum_witnesses",
            "valid_witnesses", "members", "quorum_met", "admission_log_id",
            "admission_log_entry_count", "admission_log_head_sha256",
            "admission_log_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "quorum_report_sha256": digest.clone(),
            "quorum_report_source_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "registry_checkpoint_sha256": digest.clone(),
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest.clone(),
            "approval_log_sha256": digest.clone(),
            "approval_log_source_sha256": digest.clone(),
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
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
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
            "admission_log_id": {"oneOf": [{"type": "null"}, slug_schema()]},
            "admission_log_entry_count": {
                "oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]
            },
            "admission_log_head_sha256": {
                "oneOf": [{"type": "null"}, digest.clone()]
            },
            "admission_log_sha256": {
                "oneOf": [{"type": "null"}, digest]
            }
        }
    })
}

pub(crate) fn remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-quorum-report-v1.json",
        "title": "pcbex independent factory receipt-quorum checkpoint witness quorum",
        "type": "object",
        "additionalProperties": false,
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
            "checkpoint_sha256": digest.clone(),
            "registry_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "approval_log_id": slug_schema(),
            "approval_log_entry_count": {"type": "integer", "minimum": 2},
            "approval_log_head_sha256": digest.clone(),
            "approval_log_sha256": digest.clone(),
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
            "witness_ids": {
                "type": "array",
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "uniqueItems": true,
                "items": slug_schema()
            },
            "witness_public_keys": {
                "type": "array",
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES,
                "uniqueItems": true,
                "items": digest
            },
            "quorum_met": {"type": "boolean"}
        }
    })
}

pub(crate) fn remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-trust-state-v1.json",
        "title": "pcbex generation-chained factory receipt-quorum checkpoint witness trust state",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "generation", "current_public_key",
            "last_rotation_sha256", "last_rotated_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "current_public_key": digest.clone(),
            "last_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest]
            },
            "last_rotated_at_unix": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}
                ]
            }
        }
    })
}

pub(crate) fn signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-remote-factory-release-registry-history-receipt-quorum-log-checkpoint-witness-key-rotation-v1.json",
        "title": "pcbex dual-signed factory receipt-quorum checkpoint witness key rotation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "from_generation", "to_generation",
            "previous_rotation_sha256", "old_public_key", "new_public_key",
            "rotated_at_unix", "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            },
            "previous_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest.clone()]
            },
            "old_public_key": digest.clone(),
            "new_public_key": digest,
            "rotated_at_unix": {
                "type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP
            },
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || report.approval_log_entry_count < 2
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
            "remote factory release checkpoint-witness receipt quorum report invariants are invalid"
                .into(),
        );
    }
    validate_slug(&report.registry_id, "factory release registry id")?;
    validate_slug(
        &report.approval_log_id,
        "factory release receipt approval log id",
    )?;
    for (digest, label) in [
        (
            &report.quorum_report_sha256,
            "receipt quorum report SHA-256",
        ),
        (
            &report.quorum_report_source_sha256,
            "receipt quorum report source SHA-256",
        ),
        (
            &report.registry_checkpoint_sha256,
            "registry history checkpoint SHA-256",
        ),
        (
            &report.approval_log_head_sha256,
            "receipt approval log head SHA-256",
        ),
        (&report.approval_log_sha256, "receipt approval log SHA-256"),
        (
            &report.approval_log_source_sha256,
            "receipt approval log source SHA-256",
        ),
        (
            &report.checkpoint_sha256,
            "receipt quorum checkpoint SHA-256",
        ),
        (
            &report.checkpoint_source_sha256,
            "receipt quorum checkpoint source SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let checkpoint_public_key = decode_hex::<32>(
        &report.checkpoint_public_key,
        "receipt quorum checkpoint public key",
    )?;
    validate_nonweak_public_key(
        &checkpoint_public_key,
        "receipt quorum checkpoint public key",
    )?;

    match (
        &report.admission_log_id,
        report.admission_log_entry_count,
        &report.admission_log_head_sha256,
        &report.admission_log_sha256,
    ) {
        (None, None, None, None) => {}
        (Some(log_id), Some(entry_count), Some(head), Some(log_sha256)) => {
            if !report.quorum_met {
                return Err(
                    "remote factory release checkpoint-witness receipt quorum cannot bind an admission log before quorum"
                        .into(),
                );
            }
            validate_slug(log_id, "admission approval log id")?;
            if entry_count < report.members.len() as u64 {
                return Err(
                    "remote factory release checkpoint-witness receipt quorum admission log has too few entries"
                        .into(),
                );
            }
            validate_digest(head, "admission approval log head SHA-256")?;
            validate_digest(log_sha256, "admission approval log SHA-256")?;
        }
        _ => {
            return Err(
                "remote factory release checkpoint-witness receipt quorum admission log binding is incomplete"
                    .into(),
            );
        }
    }

    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut responses = BTreeSet::new();
    let mut witnesses = BTreeSet::new();
    let mut request_sha256: Option<&str> = None;
    let mut uses_trust_state: Option<bool> = None;
    for member in &report.members {
        validate_slug(
            &member.witness_id,
            "factory release receipt quorum checkpoint witness id",
        )?;
        let witness_public_key = decode_hex::<32>(
            &member.witness_public_key,
            "factory release receipt quorum checkpoint witness public key",
        )?;
        validate_nonweak_public_key(
            &witness_public_key,
            "factory release receipt quorum checkpoint witness public key",
        )?;
        if witness_public_key == checkpoint_public_key {
            return Err(
                "factory release receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                    .into(),
            );
        }
        if previous_id.is_some_and(|previous| previous >= member.witness_id.as_str())
            || !ids.insert(member.witness_id.as_str())
            || !keys.insert(member.witness_public_key.as_str())
            || !receipts.insert(member.receipt_sha256.as_str())
            || !responses.insert(member.response_sha256.as_str())
            || !witnesses.insert(member.witness_sha256.as_str())
        {
            return Err(
                "remote factory release checkpoint-witness receipt quorum members must be sorted and distinct"
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
                        "remote factory release checkpoint-witness receipt quorum cannot mix witness key modes"
                            .into(),
                    );
                }
                uses_trust_state = Some(false);
            }
            (Some(digest), Some(generation)) => {
                if uses_trust_state == Some(false) {
                    return Err(
                        "remote factory release checkpoint-witness receipt quorum cannot mix witness key modes"
                            .into(),
                    );
                }
                uses_trust_state = Some(true);
                validate_digest(digest, "witness key trust-state SHA-256")?;
                if generation
                    > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
                {
                    return Err(
                        "remote factory release checkpoint-witness receipt quorum witness key generation is outside its bound"
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "remote factory release checkpoint-witness receipt quorum trust-state binding is incomplete"
                        .into(),
                );
            }
        }
        for (digest, label) in [
            (&member.receipt_sha256, "checkpoint-witness receipt SHA-256"),
            (&member.request_sha256, "remote witness request SHA-256"),
            (&member.response_sha256, "remote witness response SHA-256"),
            (&member.witness_sha256, "checkpoint witness SHA-256"),
        ] {
            validate_digest(digest, label)?;
        }
        if request_sha256.is_some_and(|request| request != member.request_sha256) {
            return Err(
                "remote factory release checkpoint-witness receipt quorum members use different requests"
                    .into(),
            );
        }
        request_sha256 = Some(&member.request_sha256);
        if member.witnessed_at_unix > report.evaluated_at_unix
            || report.evaluated_at_unix - member.witnessed_at_unix
                > MAXIMUM_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_AGE_SECONDS
        {
            return Err(
                "remote factory release checkpoint-witness receipt quorum member is outside the 24-hour window"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_for_log(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
) -> Result<(), String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        report,
    )?;
    if !report.quorum_met {
        return Err("remote factory release checkpoint-witness receipt quorum was not met".into());
    }
    let expected_log_sha256 = report.admission_log_sha256.as_deref().ok_or_else(|| {
        "remote factory release checkpoint-witness receipt quorum report is not bound to an admission log"
            .to_string()
    })?;
    if report.admission_log_id.as_deref() != Some(log.log_id.as_str())
        || report.admission_log_entry_count != Some(log.entries.len() as u64)
        || report.admission_log_head_sha256.as_deref() != log.head_sha256.as_deref()
        || approval_transparency_log_sha256(log)? != expected_log_sha256
    {
        return Err(
            "approval log does not match the remote factory release checkpoint-witness receipt quorum admission binding"
                .into(),
        );
    }
    let suffix_start = log
        .entries
        .len()
        .checked_sub(report.members.len())
        .ok_or_else(|| {
            "approval log has fewer entries than the remote factory release checkpoint-witness receipt quorum"
                .to_string()
        })?;
    for (entry, member) in log.entries[suffix_start..].iter().zip(&report.members) {
        if entry.event.artifact_kind
            != ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt
            || entry.event.artifact_sha256 != member.receipt_sha256
            || entry.event.subject_id != report.checkpoint_sha256
            || entry.event.request_sha256.as_deref() != Some(member.request_sha256.as_str())
            || entry.event.session_sha256.as_deref() != Some(member.response_sha256.as_str())
            || entry.event.signer_id.is_some()
            || entry.event.outcome != format!("verified-witness:{}", member.witness_id)
        {
            return Err(
                "approval log suffix does not exactly match the admitted remote factory release checkpoint-witness receipt quorum"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&report.minimum_witnesses)
        || report.members.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || report.valid_witnesses as usize != report.members.len()
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
    {
        return Err(
            "remote factory release receipt quorum report invariants are invalid".into(),
        );
    }
    validate_slug(&report.registry_id, "registry id")?;
    for (digest, label) in [
        (&report.history_sha256, "registry history SHA-256"),
        (
            &report.checkpoint_sha256,
            "registry history checkpoint SHA-256",
        ),
        (
            &report.checkpoint_trust_state_sha256,
            "registry history checkpoint trust-state SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    match (
        &report.approval_log_id,
        report.approval_log_entry_count,
        &report.approval_log_head_sha256,
        &report.approval_log_sha256,
    ) {
        (None, None, None, None) => {}
        (Some(log_id), Some(entry_count), Some(head), Some(log_digest)) => {
            if !report.quorum_met {
                return Err(
                    "remote factory release receipt quorum cannot bind a log before quorum".into(),
                );
            }
            validate_slug(log_id, "approval transparency log id")?;
            if entry_count < report.valid_witnesses as u64 {
                return Err("remote factory release receipt quorum log has too few entries".into());
            }
            validate_digest(head, "approval transparency log head SHA-256")?;
            validate_digest(log_digest, "approval transparency log SHA-256")?;
        }
        _ => {
            return Err("remote factory release receipt quorum log binding is incomplete".into());
        }
    }
    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut responses = BTreeSet::new();
    let mut witnesses = BTreeSet::new();
    let mut request_sha256: Option<&str> = None;
    let mut uses_trust_state: Option<bool> = None;
    for member in &report.members {
        validate_slug(&member.witness_id, "registry history witness id")?;
        let public_key = decode_hex::<32>(&member.witness_public_key, "witness public key")?;
        validate_nonweak_public_key(&public_key, "witness public key")?;
        if previous_id.is_some_and(|previous| previous >= member.witness_id.as_str())
            || !ids.insert(member.witness_id.as_str())
            || !keys.insert(member.witness_public_key.as_str())
            || !receipts.insert(member.receipt_sha256.as_str())
            || !responses.insert(member.response_sha256.as_str())
            || !witnesses.insert(member.witness_sha256.as_str())
        {
            return Err(
                "remote factory release receipt quorum members must be sorted and distinct".into(),
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
                        "remote factory release receipt quorum cannot mix witness key modes".into(),
                    );
                }
                uses_trust_state = Some(false);
            }
            (Some(digest), Some(generation)) => {
                if uses_trust_state == Some(false) {
                    return Err(
                        "remote factory release receipt quorum cannot mix witness key modes".into(),
                    );
                }
                uses_trust_state = Some(true);
                validate_digest(digest, "witness key trust-state SHA-256")?;
                if generation
                    > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
                {
                    return Err(
                        "remote factory release receipt quorum witness key generation is outside its bound"
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "remote factory release receipt quorum trust-state binding is incomplete"
                        .into(),
                );
            }
        }
        for (digest, label) in [
            (&member.receipt_sha256, "receipt SHA-256"),
            (&member.request_sha256, "request SHA-256"),
            (&member.response_sha256, "response SHA-256"),
            (&member.witness_sha256, "witness SHA-256"),
        ] {
            validate_digest(digest, label)?;
        }
        if request_sha256.is_some_and(|request| request != member.request_sha256) {
            return Err(
                "remote factory release receipt quorum members use different requests".into(),
            );
        }
        request_sha256 = Some(&member.request_sha256);
        if member.witnessed_at_unix > report.evaluated_at_unix {
            return Err("remote factory release receipt quorum member is future-dated".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
) -> Result<(), String> {
    validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
        report,
    )?;
    let log_sha256 = approval_transparency_log_sha256(log)?;
    if !report.quorum_met {
        return Err("remote factory release receipt quorum was not met".into());
    }
    let expected_log_sha256 = report.approval_log_sha256.as_deref().ok_or_else(|| {
        "remote factory release receipt quorum report is not bound to an approval log".to_string()
    })?;
    if report.approval_log_id.as_deref() != Some(log.log_id.as_str())
        || report.approval_log_entry_count != Some(log.entries.len() as u64)
        || report.approval_log_head_sha256 != log.head_sha256
        || log_sha256 != expected_log_sha256
    {
        return Err(
            "approval log does not match the remote factory release receipt quorum log binding"
                .into(),
        );
    }
    let suffix_start = log
        .entries
        .len()
        .checked_sub(report.members.len())
        .ok_or_else(|| {
            "approval log has fewer entries than the remote factory release receipt quorum"
                .to_string()
        })?;
    for (entry, member) in log.entries[suffix_start..].iter().zip(&report.members) {
        if entry.event.artifact_kind
            != ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryCheckpointWitnessReceipt
            || entry.event.artifact_sha256 != member.receipt_sha256
            || entry.event.subject_id != report.checkpoint_sha256
            || entry.event.request_sha256.as_deref() != Some(member.request_sha256.as_str())
            || entry.event.session_sha256.as_deref() != Some(member.response_sha256.as_str())
            || entry.event.signer_id.is_some()
            || entry.event.outcome != format!("verified-witness:{}", member.witness_id)
        {
            return Err(
                "approval log suffix does not exactly match the admitted remote factory release receipt quorum"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint, String> {
    validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
        report, log,
    )?;
    validate_slug(
        signer_id,
        "factory release receipt quorum checkpoint signer id",
    )?;
    let report_bytes = serde_json::to_vec(report)
        .map_err(|error| format!("serializing factory release receipt quorum report: {error}"))?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let mut checkpoint = SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint {
        schema_version: 1,
        quorum_report_sha256: sha256(&report_bytes),
        registry_id: report.registry_id.clone(),
        generation: report.generation,
        registry_checkpoint_sha256: report.checkpoint_sha256.clone(),
        approval_log_id: log.log_id.clone(),
        approval_log_entry_count: log.entries.len() as u64,
        approval_log_head_sha256: log.head_sha256.clone().ok_or_else(|| {
            "quorum-bound factory release receipt approval log has no head".to_string()
        })?,
        approval_log_sha256: approval_transparency_log_sha256(log)?,
        minimum_witnesses: report.minimum_witnesses,
        valid_witnesses: report.valid_witnesses,
        signer_id: signer_id.to_string(),
        algorithm: "ed25519".into(),
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        signature: String::new(),
    };
    let payload = factory_release_receipt_quorum_log_checkpoint_payload(&checkpoint)?;
    checkpoint.signature = hex::encode(signing_key.sign(&payload).to_bytes());
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        &checkpoint,
    )?;
    Ok(checkpoint)
}

pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_public_key: &[u8; 32],
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointVerification, String> {
    validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
        report, log,
    )?;
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        checkpoint,
    )?;
    validate_nonweak_public_key(
        trusted_public_key,
        "trusted factory release receipt quorum checkpoint key",
    )?;
    let report_bytes = serde_json::to_vec(report)
        .map_err(|error| format!("serializing factory release receipt quorum report: {error}"))?;
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
        return Err(
            "signed factory release receipt quorum checkpoint is bound to different evidence"
                .into(),
        );
    }
    let public_key = decode_hex::<32>(
        &checkpoint.public_key,
        "factory release receipt quorum checkpoint public key",
    )?;
    if &public_key != trusted_public_key {
        return Err("factory release receipt quorum checkpoint key is not trusted".into());
    }
    let signature = decode_hex::<64>(
        &checkpoint.signature,
        "factory release receipt quorum checkpoint signature",
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| {
            format!("invalid factory release receipt quorum checkpoint public key: {error}")
        })?
        .verify_strict(
            &factory_release_receipt_quorum_log_checkpoint_payload(checkpoint)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| {
            format!("invalid factory release receipt quorum checkpoint signature: {error}")
        })?;
    let verification = RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointVerification {
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
    };
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
        &verification,
    )?;
    Ok(verification)
}

pub(crate) fn new_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
    witness_id: &str,
    public_key: &[u8; 32],
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState, String>
{
    let state = RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState {
        schema_version: 1,
        witness_id: witness_id.to_string(),
        generation: 0,
        current_public_key: hex::encode(public_key),
        last_rotation_sha256: None,
        last_rotated_at_unix: None,
    };
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        &state,
    )?;
    Ok(state)
}

pub(crate) fn remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trusted_public_key(
    state: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
) -> Result<[u8; 32], String> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    decode_hex::<32>(
        &state.current_public_key,
        "current factory release receipt quorum checkpoint witness public key",
    )
}

pub(crate) fn sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    state: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<
    SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
    String,
> {
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    if rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release receipt quorum checkpoint witness rotation time exceeds its bound"
                .into(),
        );
    }
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key_bytes = old_key.verifying_key().to_bytes();
    let new_public_key_bytes = new_key.verifying_key().to_bytes();
    validate_nonweak_public_key(
        &old_public_key_bytes,
        "old factory release receipt quorum checkpoint witness key",
    )?;
    validate_nonweak_public_key(
        &new_public_key_bytes,
        "new factory release receipt quorum checkpoint witness key",
    )?;
    let old_public_key = hex::encode(old_public_key_bytes);
    let new_public_key = hex::encode(new_public_key_bytes);
    if old_public_key != state.current_public_key {
        return Err(
            "old factory release receipt quorum checkpoint witness key is not currently trusted"
                .into(),
        );
    }
    if new_public_key == old_public_key {
        return Err("new factory release receipt quorum checkpoint witness key must differ".into());
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err(
            "factory release receipt quorum checkpoint witness rotation time moved backwards"
                .into(),
        );
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release receipt quorum checkpoint witness generation overflow".to_string()
        })?;
    let mut rotation =
        SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation {
            schema_version: 1,
            witness_id: state.witness_id.clone(),
            from_generation: state.generation,
            to_generation,
            previous_rotation_sha256: state.last_rotation_sha256.clone(),
            old_public_key,
            new_public_key,
            rotated_at_unix,
            algorithm: "ed25519".into(),
            old_signature: String::new(),
            new_signature: String::new(),
        };
    let payload =
        factory_release_receipt_quorum_log_checkpoint_witness_key_rotation_payload(&rotation)?;
    rotation.old_signature = hex::encode(old_key.sign(&payload).to_bytes());
    rotation.new_signature = hex::encode(new_key.sign(&payload).to_bytes());
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    state: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
    rotation: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState, String>
{
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        state,
    )?;
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
        rotation,
    )?;
    let expected_generation = state
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        })
        .ok_or_else(|| {
            "factory release receipt quorum checkpoint witness generation overflow".to_string()
        })?;
    if rotation.witness_id != state.witness_id
        || rotation.from_generation != state.generation
        || rotation.to_generation != expected_generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
        || state
            .last_rotated_at_unix
            .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err(
            "factory release receipt quorum checkpoint witness rotation does not extend retained trust"
                .into(),
        );
    }
    let next = RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState {
        schema_version: 1,
        witness_id: state.witness_id.clone(),
        generation: rotation.to_generation,
        current_public_key: rotation.new_public_key.clone(),
        last_rotation_sha256: Some(
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_rotated_at_unix: Some(rotation.rotated_at_unix),
    };
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
        &next,
    )?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witness_id: &str,
    witnessed_at_unix: u64,
    secret_key: &[u8; 32],
) -> Result<SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness, String> {
    verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
    )?;
    validate_slug(
        witness_id,
        "factory release receipt quorum checkpoint witness id",
    )?;
    if witnessed_at_unix > MAX_TIMESTAMP || witnessed_at_unix < report.evaluated_at_unix {
        return Err(
            "factory release receipt quorum checkpoint witness predates its quorum report or exceeds the timestamp bound"
                .into(),
        );
    }
    let signing_key = SigningKey::from_bytes(secret_key);
    let witness_public_key = signing_key.verifying_key().to_bytes();
    validate_nonweak_public_key(
        &witness_public_key,
        "factory release receipt quorum checkpoint witness key",
    )?;
    if &witness_public_key == trusted_checkpoint_public_key {
        return Err(
            "factory release receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    let mut witness = SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness {
        schema_version: 1,
        checkpoint_sha256:
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_sha256(
                checkpoint,
            )?,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        approval_log_id: checkpoint.approval_log_id.clone(),
        approval_log_entry_count: checkpoint.approval_log_entry_count,
        approval_log_head_sha256: checkpoint.approval_log_head_sha256.clone(),
        approval_log_sha256: checkpoint.approval_log_sha256.clone(),
        witness_id: witness_id.to_string(),
        witnessed_at_unix,
        algorithm: "ed25519".into(),
        public_key: hex::encode(witness_public_key),
        signature: String::new(),
    };
    let payload = factory_release_receipt_quorum_log_checkpoint_witness_payload(&witness)?;
    witness.signature = hex::encode(signing_key.sign(&payload).to_bytes());
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witnesses: &[SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness],
    trusted_witness_public_keys: &[[u8; 32]],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport, String>
{
    verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
    )?;
    verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_after_checkpoint_verification(
        report,
        checkpoint,
        trusted_checkpoint_public_key,
        witnesses,
        trusted_witness_public_keys,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_after_checkpoint_verification(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witnesses: &[SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness],
    trusted_witness_public_keys: &[[u8; 32]],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport, String>
{
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release receipt quorum checkpoint witness evaluation time exceeds its bound"
                .into(),
        );
    }
    if !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
        .contains(&minimum_witnesses)
    {
        return Err(
            "factory release receipt quorum checkpoint witness quorum must require 2 to 100 witnesses"
                .into(),
        );
    }
    if witnesses.len() != trusted_witness_public_keys.len()
        || witnesses.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
    {
        return Err(
            "factory release receipt quorum checkpoint witnesses and trusted keys must be paired and bounded"
                .into(),
        );
    }
    let checkpoint_sha256 =
        signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_sha256(
            checkpoint,
        )?;
    let mut witness_ids = BTreeSet::new();
    let mut witness_public_keys = BTreeSet::new();
    for (witness, trusted_key) in witnesses.iter().zip(trusted_witness_public_keys) {
        validate_nonweak_public_key(
            trusted_key,
            "trusted factory release receipt quorum checkpoint witness key",
        )?;
        if trusted_key == trusted_checkpoint_public_key {
            return Err(
                "factory release receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                    .into(),
            );
        }
        verify_factory_release_receipt_quorum_log_checkpoint_witness(
            checkpoint,
            &checkpoint_sha256,
            witness,
            trusted_key,
            report.evaluated_at_unix,
            evaluated_at_unix,
        )?;
        if !witness_ids.insert(witness.witness_id.clone())
            || !witness_public_keys.insert(hex::encode(trusted_key))
        {
            return Err(
                "factory release receipt quorum checkpoint witnesses must use distinct identities and keys"
                    .into(),
            );
        }
    }
    let valid_witnesses = u32::try_from(witnesses.len()).map_err(|_| {
        "factory release receipt quorum checkpoint witness count overflow".to_string()
    })?;
    let quorum_met = valid_witnesses >= minimum_witnesses;
    let quorum = RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport {
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
    validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
        &quorum,
    )?;
    Ok(quorum)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
    report: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport,
    log: &ApprovalTransparencyLog,
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    trusted_checkpoint_public_key: &[u8; 32],
    witnesses: &[SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness],
    witness_trust_states: &[RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport, String>
{
    if witnesses.len() != witness_trust_states.len()
        || witnesses.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
    {
        return Err(
            "factory release receipt quorum checkpoint witnesses and trust states must be paired and bounded"
                .into(),
        );
    }
    for (witness, state) in witnesses.iter().zip(witness_trust_states) {
        validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
            state,
        )?;
        if witness.witness_id != state.witness_id {
            return Err(
                "factory release receipt quorum checkpoint witness identity does not match retained trust"
                    .into(),
            );
        }
    }
    let trusted_keys = witness_trust_states
        .iter()
        .map(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trusted_public_key,
        )
        .collect::<Result<Vec<_>, _>>()?;
    verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
        report,
        log,
        checkpoint,
        trusted_checkpoint_public_key,
        witnesses,
        &trusted_keys,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

pub(crate) fn validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
) -> Result<(), String> {
    if checkpoint.schema_version != 1
        || checkpoint.algorithm != "ed25519"
        || checkpoint.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || checkpoint.approval_log_entry_count < 2
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&checkpoint.minimum_witnesses)
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&checkpoint.valid_witnesses)
        || checkpoint.valid_witnesses < checkpoint.minimum_witnesses
    {
        return Err(
            "signed factory release receipt quorum checkpoint invariants are invalid".into(),
        );
    }
    validate_slug(&checkpoint.registry_id, "factory release registry id")?;
    validate_slug(
        &checkpoint.approval_log_id,
        "factory release receipt approval log id",
    )?;
    validate_slug(
        &checkpoint.signer_id,
        "factory release receipt quorum checkpoint signer id",
    )?;
    for (digest, label) in [
        (
            &checkpoint.quorum_report_sha256,
            "receipt quorum report SHA-256",
        ),
        (
            &checkpoint.registry_checkpoint_sha256,
            "registry history checkpoint SHA-256",
        ),
        (
            &checkpoint.approval_log_head_sha256,
            "approval log head SHA-256",
        ),
        (&checkpoint.approval_log_sha256, "approval log SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    let public_key = decode_hex::<32>(
        &checkpoint.public_key,
        "factory release receipt quorum checkpoint public key",
    )?;
    validate_nonweak_public_key(
        &public_key,
        "factory release receipt quorum checkpoint public key",
    )?;
    decode_hex::<64>(
        &checkpoint.signature,
        "factory release receipt quorum checkpoint signature",
    )?;
    Ok(())
}

pub(crate) fn validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
    witness: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
) -> Result<(), String> {
    if witness.schema_version != 1
        || witness.algorithm != "ed25519"
        || witness.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || witness.approval_log_entry_count < 2
        || witness.witnessed_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "signed factory release receipt quorum checkpoint witness invariants are invalid"
                .into(),
        );
    }
    validate_slug(&witness.registry_id, "factory release registry id")?;
    validate_slug(
        &witness.approval_log_id,
        "factory release receipt approval log id",
    )?;
    validate_slug(
        &witness.witness_id,
        "factory release receipt quorum checkpoint witness id",
    )?;
    for (digest, label) in [
        (
            &witness.checkpoint_sha256,
            "factory release receipt quorum checkpoint SHA-256",
        ),
        (
            &witness.approval_log_head_sha256,
            "approval log head SHA-256",
        ),
        (&witness.approval_log_sha256, "approval log SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    let public_key = decode_hex::<32>(
        &witness.public_key,
        "factory release receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &public_key,
        "factory release receipt quorum checkpoint witness public key",
    )?;
    decode_hex::<64>(
        &witness.signature,
        "factory release receipt quorum checkpoint witness signature",
    )?;
    Ok(())
}

pub(crate) fn validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
    state: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessTrustState,
) -> Result<(), String> {
    if state.schema_version != 1
        || state.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || state
            .last_rotated_at_unix
            .is_some_and(|timestamp| timestamp > MAX_TIMESTAMP)
    {
        return Err(
            "factory release receipt quorum checkpoint witness trust-state invariants are invalid"
                .into(),
        );
    }
    validate_slug(
        &state.witness_id,
        "factory release receipt quorum checkpoint witness id",
    )?;
    let public_key = decode_hex::<32>(
        &state.current_public_key,
        "current factory release receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &public_key,
        "current factory release receipt quorum checkpoint witness public key",
    )?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) => Ok(()),
        (0, _, _) => Err(
            "initial factory release receipt quorum checkpoint witness trust state references rotation"
                .into(),
        ),
        (_, Some(digest), Some(_)) => validate_digest(
            digest,
            "factory release receipt quorum checkpoint witness rotation SHA-256",
        ),
        _ => Err(
            "rotated factory release receipt quorum checkpoint witness trust state is incomplete"
                .into(),
        ),
    }
}

pub(crate) fn validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
    rotation: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<(), String> {
    let expected_generation = rotation.from_generation.checked_add(1).ok_or_else(|| {
        "factory release receipt quorum checkpoint witness generation overflow".to_string()
    })?;
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.from_generation
            >= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.to_generation != expected_generation
        || rotation.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || rotation.rotated_at_unix > MAX_TIMESTAMP
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err(
            "factory release receipt quorum checkpoint witness key-rotation invariants are invalid"
                .into(),
        );
    }
    validate_slug(
        &rotation.witness_id,
        "factory release receipt quorum checkpoint witness id",
    )?;
    match (rotation.from_generation, &rotation.previous_rotation_sha256) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err(
                "initial factory release receipt quorum checkpoint witness rotation cannot reference a predecessor"
                    .into(),
            );
        }
        (_, Some(digest)) => validate_digest(
            digest,
            "previous factory release receipt quorum checkpoint witness rotation SHA-256",
        )?,
        (_, None) => {
            return Err(
                "advanced factory release receipt quorum checkpoint witness rotation requires predecessor evidence"
                    .into(),
            );
        }
    }
    let old_key = decode_hex::<32>(
        &rotation.old_public_key,
        "old factory release receipt quorum checkpoint witness public key",
    )?;
    let new_key = decode_hex::<32>(
        &rotation.new_public_key,
        "new factory release receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &old_key,
        "old factory release receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &new_key,
        "new factory release receipt quorum checkpoint witness public key",
    )?;
    let payload =
        factory_release_receipt_quorum_log_checkpoint_witness_key_rotation_payload(rotation)?;
    for (key, signature, label) in [
        (
            &old_key,
            &rotation.old_signature,
            "old factory release receipt quorum checkpoint witness rotation",
        ),
        (
            &new_key,
            &rotation.new_signature,
            "new factory release receipt quorum checkpoint witness rotation",
        ),
    ] {
        let signature = decode_hex::<64>(signature, label)?;
        VerifyingKey::from_bytes(key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &Signature::from_bytes(&signature))
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    Ok(())
}

fn signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation_sha256(
    rotation: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<String, String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
        rotation,
    )?;
    serde_json::to_vec(rotation)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| {
            format!(
                "serializing factory release receipt quorum checkpoint witness rotation: {error}"
            )
        })
}

pub(crate) fn validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
    report: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES as u32)
            .contains(&report.minimum_witnesses)
        || report.valid_witnesses as usize != report.witness_ids.len()
        || report.valid_witnesses as usize != report.witness_public_keys.len()
        || report.valid_witnesses as usize
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESSES
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
        || report.status
            != if report.quorum_met {
                "witness_quorum_met"
            } else {
                "insufficient_witnesses"
            }
    {
        return Err(
            "factory release receipt quorum checkpoint witness quorum invariants are invalid"
                .into(),
        );
    }
    validate_slug(&report.registry_id, "factory release registry id")?;
    validate_slug(
        &report.approval_log_id,
        "factory release receipt approval log id",
    )?;
    if report.approval_log_entry_count < 2 {
        return Err(
            "factory release receipt quorum checkpoint witness quorum log is too short".into(),
        );
    }
    for (digest, label) in [
        (
            &report.checkpoint_sha256,
            "factory release receipt quorum checkpoint SHA-256",
        ),
        (
            &report.approval_log_head_sha256,
            "approval log head SHA-256",
        ),
        (&report.approval_log_sha256, "approval log SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    let mut previous_id: Option<&str> = None;
    let mut ids = BTreeSet::new();
    for witness_id in &report.witness_ids {
        validate_slug(
            witness_id,
            "factory release receipt quorum checkpoint witness id",
        )?;
        if previous_id.is_some_and(|previous| previous >= witness_id.as_str())
            || !ids.insert(witness_id)
        {
            return Err(
                "factory release receipt quorum checkpoint witness ids must be sorted and distinct"
                    .into(),
            );
        }
        previous_id = Some(witness_id);
    }
    let mut previous_key: Option<&str> = None;
    let mut keys = BTreeSet::new();
    for key in &report.witness_public_keys {
        let bytes = decode_hex::<32>(
            key,
            "factory release receipt quorum checkpoint witness public key",
        )?;
        validate_nonweak_public_key(
            &bytes,
            "factory release receipt quorum checkpoint witness public key",
        )?;
        if previous_key.is_some_and(|previous| previous >= key.as_str()) || !keys.insert(key) {
            return Err(
                "factory release receipt quorum checkpoint witness keys must be sorted and distinct"
                    .into(),
            );
        }
        previous_key = Some(key);
    }
    Ok(())
}

fn validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
    verification: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointVerification,
) -> Result<(), String> {
    if verification.schema_version != 1
        || !verification.verified
        || verification.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || verification.approval_log_entry_count < 2
    {
        return Err(
            "factory release receipt quorum checkpoint verification invariants are invalid".into(),
        );
    }
    validate_slug(&verification.registry_id, "factory release registry id")?;
    validate_slug(
        &verification.approval_log_id,
        "factory release receipt approval log id",
    )?;
    validate_slug(
        &verification.signer_id,
        "factory release receipt quorum checkpoint signer id",
    )?;
    for (digest, label) in [
        (
            &verification.quorum_report_sha256,
            "receipt quorum report SHA-256",
        ),
        (
            &verification.approval_log_head_sha256,
            "approval log head SHA-256",
        ),
        (&verification.approval_log_sha256, "approval log SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    let public_key = decode_hex::<32>(
        &verification.public_key,
        "factory release receipt quorum checkpoint public key",
    )?;
    validate_nonweak_public_key(
        &public_key,
        "factory release receipt quorum checkpoint public key",
    )
}

fn factory_release_receipt_quorum_log_checkpoint_payload(
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
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
    let mut payload = RECEIPT_QUORUM_LOG_CHECKPOINT_DOMAIN.as_bytes().to_vec();
    payload.push(0);
    payload.extend(serde_json::to_vec(&body).map_err(|error| {
        format!("serializing factory release receipt quorum checkpoint payload: {error}")
    })?);
    Ok(payload)
}

fn signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_sha256(
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
) -> Result<String, String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
        checkpoint,
    )?;
    serde_json::to_vec(checkpoint)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| format!("serializing factory release receipt quorum checkpoint: {error}"))
}

fn signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_sha256(
    witness: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
) -> Result<String, String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
        witness,
    )?;
    serde_json::to_vec(witness)
        .map(|bytes| sha256(&bytes))
        .map_err(|error| {
            format!("serializing factory release receipt quorum checkpoint witness: {error}")
        })
}

fn factory_release_receipt_quorum_log_checkpoint_witness_payload(
    witness: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
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
    let mut payload = RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_DOMAIN
        .as_bytes()
        .to_vec();
    payload.push(0);
    payload.extend(serde_json::to_vec(&body).map_err(|error| {
        format!("serializing factory release receipt quorum checkpoint witness: {error}")
    })?);
    Ok(payload)
}

fn factory_release_receipt_quorum_log_checkpoint_witness_key_rotation_payload(
    rotation: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessKeyRotation,
) -> Result<Vec<u8>, String> {
    let body = json!({
        "schema_version": rotation.schema_version,
        "witness_id": rotation.witness_id,
        "from_generation": rotation.from_generation,
        "to_generation": rotation.to_generation,
        "previous_rotation_sha256": rotation.previous_rotation_sha256,
        "old_public_key": rotation.old_public_key,
        "new_public_key": rotation.new_public_key,
        "rotated_at_unix": rotation.rotated_at_unix,
        "algorithm": rotation.algorithm
    });
    let mut payload = RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_DOMAIN
        .as_bytes()
        .to_vec();
    payload.push(0);
    payload.extend(serde_json::to_vec(&body).map_err(|error| {
        format!("serializing factory release receipt quorum checkpoint witness rotation: {error}")
    })?);
    Ok(payload)
}

fn verify_factory_release_receipt_quorum_log_checkpoint_witness(
    checkpoint: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpoint,
    checkpoint_sha256: &str,
    witness: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
    trusted_public_key: &[u8; 32],
    earliest_witnessed_at_unix: u64,
    evaluated_at_unix: u64,
) -> Result<(), String> {
    validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
        witness,
    )?;
    validate_nonweak_public_key(
        trusted_public_key,
        "trusted factory release receipt quorum checkpoint witness key",
    )?;
    if witness.checkpoint_sha256 != checkpoint_sha256
        || witness.registry_id != checkpoint.registry_id
        || witness.generation != checkpoint.generation
        || witness.approval_log_id != checkpoint.approval_log_id
        || witness.approval_log_entry_count != checkpoint.approval_log_entry_count
        || witness.approval_log_head_sha256 != checkpoint.approval_log_head_sha256
        || witness.approval_log_sha256 != checkpoint.approval_log_sha256
    {
        return Err(
            "factory release receipt quorum checkpoint witness is bound to different evidence"
                .into(),
        );
    }
    if witness.public_key != hex::encode(trusted_public_key) {
        return Err("factory release receipt quorum checkpoint witness key is not trusted".into());
    }
    if witness.witnessed_at_unix < earliest_witnessed_at_unix
        || evaluated_at_unix < witness.witnessed_at_unix
        || evaluated_at_unix - witness.witnessed_at_unix
            > MAXIMUM_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_AGE_SECONDS
    {
        return Err(
            "factory release receipt quorum checkpoint witness is outside the 24-hour window"
                .into(),
        );
    }
    let signature = decode_hex::<64>(
        &witness.signature,
        "factory release receipt quorum checkpoint witness signature",
    )?;
    VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|error| {
            format!("invalid factory release receipt quorum checkpoint witness key: {error}")
        })?
        .verify_strict(
            &factory_release_receipt_quorum_log_checkpoint_witness_payload(witness)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| {
            format!("invalid factory release receipt quorum checkpoint witness signature: {error}")
        })
}

fn validate_remote_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1
        || receipt.adapter != ADAPTER
        || !receipt.verified
        || receipt.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || receipt.response_bytes == 0
        || receipt.response_bytes > MAX_RESPONSE_BYTES
        || receipt.witnessed_at_unix > receipt.evaluated_at_unix
        || receipt.evaluated_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt invariants are invalid"
                .into(),
        );
    }
    validate_endpoint(&receipt.endpoint, true)?;
    validate_slug(&receipt.registry_id, "registry id")?;
    validate_slug(&receipt.witness_id, "registry history witness id")?;
    for (digest, label) in [
        (&receipt.history_sha256, "registry history SHA-256"),
        (
            &receipt.checkpoint_sha256,
            "registry history checkpoint SHA-256",
        ),
        (
            &receipt.checkpoint_trust_state_sha256,
            "registry history checkpoint trust-state SHA-256",
        ),
        (&receipt.request_sha256, "remote witness request SHA-256"),
        (&receipt.response_sha256, "remote witness response SHA-256"),
        (&receipt.witness_sha256, "registry history witness SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    let public_key = decode_hex::<32>(&receipt.witness_public_key, "witness public key")?;
    validate_nonweak_public_key(&public_key, "witness public key")?;
    match (
        &receipt.witness_key_trust_state_sha256,
        receipt.witness_key_generation,
    ) {
        (None, None) => {}
        (Some(digest), Some(generation)) => {
            validate_digest(digest, "witness key trust-state SHA-256")?;
            if generation
                > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            {
                return Err("remote witness receipt key generation is outside its bound".into());
            }
        }
        _ => return Err("remote witness receipt trust-state binding is incomplete".into()),
    }
    Ok(())
}

fn validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1
        || receipt.adapter != RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_ADAPTER
        || !receipt.verified
        || receipt.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || receipt.approval_log_entry_count < 2
        || receipt.response_bytes == 0
        || receipt.response_bytes
            > MAX_SIGNED_REMOTE_FACTORY_RELEASE_REGISTRY_HISTORY_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_BYTES
        || receipt.witnessed_at_unix > receipt.evaluated_at_unix
        || receipt.evaluated_at_unix > MAX_TIMESTAMP
        || receipt.evaluated_at_unix - receipt.witnessed_at_unix
            > MAXIMUM_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_AGE_SECONDS
    {
        return Err(
            "remote factory release receipt quorum checkpoint witness receipt invariants are invalid"
                .into(),
        );
    }
    validate_endpoint(&receipt.endpoint, true)?;
    validate_slug(&receipt.registry_id, "factory release registry id")?;
    validate_slug(
        &receipt.approval_log_id,
        "factory release receipt approval log id",
    )?;
    validate_slug(
        &receipt.witness_id,
        "factory release receipt quorum checkpoint witness id",
    )?;
    for (digest, label) in [
        (
            &receipt.quorum_report_sha256,
            "receipt quorum report SHA-256",
        ),
        (
            &receipt.quorum_report_source_sha256,
            "receipt quorum report source SHA-256",
        ),
        (
            &receipt.registry_checkpoint_sha256,
            "registry history checkpoint SHA-256",
        ),
        (
            &receipt.approval_log_head_sha256,
            "approval log head SHA-256",
        ),
        (&receipt.approval_log_sha256, "approval log SHA-256"),
        (
            &receipt.approval_log_source_sha256,
            "approval log source SHA-256",
        ),
        (
            &receipt.checkpoint_sha256,
            "factory release receipt quorum checkpoint SHA-256",
        ),
        (
            &receipt.checkpoint_source_sha256,
            "factory release receipt quorum checkpoint source SHA-256",
        ),
        (&receipt.request_sha256, "remote witness request SHA-256"),
        (&receipt.response_sha256, "remote witness response SHA-256"),
        (
            &receipt.witness_sha256,
            "factory release receipt quorum checkpoint witness SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let checkpoint_public_key = decode_hex::<32>(
        &receipt.checkpoint_public_key,
        "factory release receipt quorum checkpoint public key",
    )?;
    validate_nonweak_public_key(
        &checkpoint_public_key,
        "factory release receipt quorum checkpoint public key",
    )?;
    let witness_public_key = decode_hex::<32>(
        &receipt.witness_public_key,
        "factory release receipt quorum checkpoint witness public key",
    )?;
    validate_nonweak_public_key(
        &witness_public_key,
        "factory release receipt quorum checkpoint witness public key",
    )?;
    if checkpoint_public_key == witness_public_key {
        return Err(
            "factory release receipt quorum checkpoint witness key must be independent from the checkpoint signing key"
                .into(),
        );
    }
    match (
        &receipt.witness_key_trust_state_sha256,
        receipt.witness_key_generation,
    ) {
        (None, None) => {}
        (Some(digest), Some(generation)) => {
            validate_digest(digest, "witness key trust-state SHA-256")?;
            if generation
                > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            {
                return Err(
                    "remote receipt quorum checkpoint witness receipt key generation is outside its bound"
                        .into(),
                );
            }
        }
        _ => {
            return Err(
                "remote receipt quorum checkpoint witness receipt trust-state binding is incomplete"
                    .into(),
            );
        }
    }
    Ok(())
}

fn render_bounded(value: &impl Serialize, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut source =
        serde_json::to_vec_pretty(value).map_err(|error| format!("rendering {label}: {error}"))?;
    source.push(b'\n');
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    Ok(source)
}

fn parse_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    source: &[u8],
    maximum: u64,
    label: &str,
) -> Result<T, String> {
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} must contain 1 to {maximum} bytes"));
    }
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid {label} JSON: {error:#}"))?;
    let value: T =
        serde_json::from_slice(source).map_err(|error| format!("invalid {label} JSON: {error}"))?;
    if render_bounded(&value, maximum, label)? != source {
        return Err(format!("{label} is not canonical pretty JSON"));
    }
    Ok(value)
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint.parse().map_err(|error| {
        format!(
            "invalid remote factory release registry history checkpoint witness endpoint: {error}"
        )
    })?;
    let scheme = uri.scheme_str().ok_or_else(|| {
        "remote factory release registry history checkpoint witness endpoint must have a scheme"
            .to_string()
    })?;
    if uri.authority().is_none() {
        return Err(
            "remote factory release registry history checkpoint witness endpoint must have an authority"
                .into(),
        );
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(
            "remote factory release registry history checkpoint witness endpoint must not contain userinfo"
                .into(),
        );
    }
    if uri.query().is_some() {
        return Err(
            "remote factory release registry history checkpoint witness endpoint must not contain a query"
                .into(),
        );
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
        Err(
            "remote factory release registry history checkpoint witness endpoint must use HTTPS"
                .into(),
        )
    }
}

fn validate_env_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if !matches!(first, Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("bearer-token environment name is invalid".into());
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'-' => index != 0,
            _ => false,
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    decode_hex::<32>(value, label).map(|_| ())
}

fn validate_nonweak_public_key(value: &[u8; 32], label: &str) -> Result<(), String> {
    let key =
        VerifyingKey::from_bytes(value).map_err(|error| format!("invalid {label}: {error}"))?;
    if key.is_weak() {
        return Err(format!("{label} is weak"));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "{label} must contain {} lowercase hexadecimal digits",
            N * 2
        ));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
}

fn sha256(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pcbex_kicad::{
        ApprovalEventDescriptor, append_approval_transparency_event, new_approval_transparency_log,
    };

    #[test]
    fn closes_receipts_and_rejects_unsafe_transport_configuration() {
        assert_eq!(
            remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_json_schema()["additionalProperties"],
            false
        );
        assert!(
            validate_endpoint(
                "https://witness.example/v1/factory-registry-history-checkpoint",
                false
            )
            .is_ok()
        );
        assert!(
            validate_endpoint(
                "https://witness.example/v1/factory-registry-history-checkpoint?token=secret",
                false
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "https://secret@witness.example/v1/factory-registry-history-checkpoint",
                false
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "http://example.com/v1/factory-registry-history-checkpoint",
                true
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "http://127.0.0.1:1234/v1/factory-registry-history-checkpoint",
                false
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "http://127.0.0.1:1234/v1/factory-registry-history-checkpoint",
                true
            )
            .is_ok()
        );
        assert!(validate_env_name("PCBEX_FACTORY_REGISTRY_WITNESS_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
    }

    #[test]
    fn round_trips_only_exact_canonical_complete_receipts() {
        let public_key = hex::encode(SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes());
        let receipt = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: ADAPTER.into(),
            endpoint: "https://witness.example/v1/factory-registry-history-checkpoint".into(),
            registry_id: "factory-registry".into(),
            generation: 5,
            history_sha256: "1".repeat(64),
            checkpoint_sha256: "2".repeat(64),
            checkpoint_trust_state_sha256: "3".repeat(64),
            request_sha256: "4".repeat(64),
            response_sha256: "5".repeat(64),
            response_bytes: 512,
            witness_sha256: "6".repeat(64),
            evaluated_at_unix: 1_000,
            witness_id: "witness-a".into(),
            witness_public_key: public_key,
            witness_key_trust_state_sha256: Some("7".repeat(64)),
            witness_key_generation: Some(3),
            witnessed_at_unix: 999,
            verified: true,
        };
        let source = render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
            &receipt,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                &source,
            )
            .unwrap(),
            receipt
        );

        let compact = serde_json::to_vec(&receipt).unwrap();
        assert!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                &compact,
            )
            .is_err()
        );
        let duplicate = String::from_utf8(source.clone()).unwrap().replacen(
            "  \"schema_version\": 1,",
            "  \"schema_version\": 1,\n  \"schema_version\": 1,",
            1,
        );
        assert!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                duplicate.as_bytes(),
            )
            .is_err()
        );
        let unknown =
            String::from_utf8(source)
                .unwrap()
                .replacen("{\n", "{\n  \"unexpected\": true,\n", 1);
        assert!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                unknown.as_bytes(),
            )
            .is_err()
        );

        let mut incomplete = receipt;
        incomplete.witness_key_generation = None;
        assert!(validate_remote_receipt(&incomplete).is_err());

        let report = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport {
            schema_version: 1,
            registry_id: "factory-registry".into(),
            generation: 5,
            history_sha256: "1".repeat(64),
            checkpoint_sha256: "2".repeat(64),
            checkpoint_trust_state_sha256: "3".repeat(64),
            evaluated_at_unix: 1_000,
            minimum_witnesses: 2,
            valid_witnesses: 2,
            members: vec![
                RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember {
                    witness_id: "witness-a".into(),
                    witness_public_key: hex::encode(
                        SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes(),
                    ),
                    witness_key_trust_state_sha256: None,
                    witness_key_generation: None,
                    receipt_sha256: "4".repeat(64),
                    request_sha256: "5".repeat(64),
                    response_sha256: "6".repeat(64),
                    witness_sha256: "7".repeat(64),
                    witnessed_at_unix: 999,
                },
                RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember {
                    witness_id: "witness-b".into(),
                    witness_public_key: hex::encode(
                        SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes(),
                    ),
                    witness_key_trust_state_sha256: None,
                    witness_key_generation: None,
                    receipt_sha256: "9".repeat(64),
                    request_sha256: "5".repeat(64),
                    response_sha256: "a".repeat(64),
                    witness_sha256: "b".repeat(64),
                    witnessed_at_unix: 998,
                },
            ],
            quorum_met: true,
            approval_log_id: Some("factory-receipts".into()),
            approval_log_entry_count: Some(2),
            approval_log_head_sha256: Some("c".repeat(64)),
            approval_log_sha256: Some("d".repeat(64)),
        };
        let source = render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
            &report,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
                &source,
            )
            .unwrap(),
            report
        );
        let mut duplicate = report.clone();
        duplicate.members[1].witness_public_key = duplicate.members[0].witness_public_key.clone();
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
                &duplicate,
            )
            .is_err()
        );

        for field in ["receipt", "response", "witness"] {
            let mut duplicate = report.clone();
            match field {
                "receipt" => {
                    duplicate.members[1].receipt_sha256 =
                        duplicate.members[0].receipt_sha256.clone();
                }
                "response" => {
                    duplicate.members[1].response_sha256 =
                        duplicate.members[0].response_sha256.clone();
                }
                "witness" => {
                    duplicate.members[1].witness_sha256 =
                        duplicate.members[0].witness_sha256.clone();
                }
                _ => unreachable!(),
            }
            assert!(
                validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
                    &duplicate,
                )
                .is_err(),
                "accepted duplicate {field} digest"
            );
        }

        let mut mixed_key_modes = report.clone();
        mixed_key_modes.members[1].witness_key_trust_state_sha256 = Some("8".repeat(64));
        mixed_key_modes.members[1].witness_key_generation = Some(1);
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
                &mixed_key_modes,
            )
            .is_err()
        );

        let mut different_request = report.clone();
        different_request.members[1].request_sha256 = "e".repeat(64);
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
                &different_request,
            )
            .is_err()
        );

        let mut bound_without_quorum = report;
        bound_without_quorum.minimum_witnesses = 3;
        bound_without_quorum.quorum_met = false;
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
                &bound_without_quorum,
            )
            .is_err()
        );
    }

    #[test]
    fn round_trips_only_exact_remote_receipt_quorum_checkpoint_witness_receipts() {
        let checkpoint_public_key =
            hex::encode(SigningKey::from_bytes(&[93; 32]).verifying_key().to_bytes());
        let witness_public_key =
            hex::encode(SigningKey::from_bytes(&[94; 32]).verifying_key().to_bytes());
        let receipt = RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_ADAPTER.into(),
            endpoint: "https://witness.example/v1/factory-receipt-quorum-checkpoint".into(),
            quorum_report_sha256: "1".repeat(64),
            quorum_report_source_sha256: "2".repeat(64),
            registry_id: "factory-registry".into(),
            generation: 5,
            registry_checkpoint_sha256: "3".repeat(64),
            approval_log_id: "factory-receipts".into(),
            approval_log_entry_count: 2,
            approval_log_head_sha256: "4".repeat(64),
            approval_log_sha256: "5".repeat(64),
            approval_log_source_sha256: "6".repeat(64),
            checkpoint_sha256: "7".repeat(64),
            checkpoint_source_sha256: "8".repeat(64),
            checkpoint_public_key: checkpoint_public_key.clone(),
            request_sha256: "9".repeat(64),
            response_sha256: "a".repeat(64),
            response_bytes: 512,
            witness_sha256: "b".repeat(64),
            evaluated_at_unix: 1_000,
            witness_id: "checkpoint-witness-a".into(),
            witness_public_key: witness_public_key.clone(),
            witness_key_trust_state_sha256: None,
            witness_key_generation: None,
            witnessed_at_unix: 999,
            verified: true,
        };
        let source = render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
            &receipt,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                &source,
            )
            .unwrap(),
            receipt
        );
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_json_schema(
            )["additionalProperties"],
            false
        );
        assert!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                &serde_json::to_vec(&receipt).unwrap(),
            )
            .is_err()
        );
        let duplicate = String::from_utf8(source.clone()).unwrap().replacen(
            "  \"schema_version\": 1,",
            "  \"schema_version\": 1,\n  \"schema_version\": 1,",
            1,
        );
        assert!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                duplicate.as_bytes(),
            )
            .is_err()
        );
        let unknown =
            String::from_utf8(source)
                .unwrap()
                .replacen("{\n", "{\n  \"unexpected\": true,\n", 1);
        assert!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                unknown.as_bytes(),
            )
            .is_err()
        );

        let mut trusted = receipt.clone();
        trusted.witness_key_trust_state_sha256 = Some("c".repeat(64));
        trusted.witness_key_generation = Some(3);
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                &trusted,
            )
            .is_ok()
        );
        trusted.witness_key_generation = None;
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                &trusted,
            )
            .is_err()
        );

        let mut reused_role_key = receipt.clone();
        reused_role_key.witness_public_key = checkpoint_public_key;
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                &reused_role_key,
            )
            .is_err()
        );
        let mut wrong_adapter = receipt;
        wrong_adapter.adapter = "wrong".into();
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt(
                &wrong_adapter,
            )
            .is_err()
        );
    }

    #[test]
    fn binds_only_the_exact_factory_receipt_quorum_log_and_suffix() {
        let members = vec![
            RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember {
                witness_id: "witness-a".into(),
                witness_public_key: hex::encode(
                    SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes(),
                ),
                witness_key_trust_state_sha256: None,
                witness_key_generation: None,
                receipt_sha256: "4".repeat(64),
                request_sha256: "5".repeat(64),
                response_sha256: "6".repeat(64),
                witness_sha256: "7".repeat(64),
                witnessed_at_unix: 999,
            },
            RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumMember {
                witness_id: "witness-b".into(),
                witness_public_key: hex::encode(
                    SigningKey::from_bytes(&[92; 32]).verifying_key().to_bytes(),
                ),
                witness_key_trust_state_sha256: None,
                witness_key_generation: None,
                receipt_sha256: "9".repeat(64),
                request_sha256: "5".repeat(64),
                response_sha256: "a".repeat(64),
                witness_sha256: "b".repeat(64),
                witnessed_at_unix: 998,
            },
        ];
        let mut report = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceiptQuorumReport {
            schema_version: 1,
            registry_id: "factory-registry".into(),
            generation: 5,
            history_sha256: "1".repeat(64),
            checkpoint_sha256: "2".repeat(64),
            checkpoint_trust_state_sha256: "3".repeat(64),
            evaluated_at_unix: 1_000,
            minimum_witnesses: 2,
            valid_witnesses: 2,
            members,
            quorum_met: true,
            approval_log_id: None,
            approval_log_entry_count: None,
            approval_log_head_sha256: None,
            approval_log_sha256: None,
        };
        let mut log = new_approval_transparency_log("factory-receipts").unwrap();
        for member in &report.members {
            append_approval_transparency_event(
                &mut log,
                ApprovalEventDescriptor {
                    artifact_kind: ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryCheckpointWitnessReceipt,
                    artifact_sha256: member.receipt_sha256.clone(),
                    subject_id: report.checkpoint_sha256.clone(),
                    request_sha256: Some(member.request_sha256.clone()),
                    session_sha256: Some(member.response_sha256.clone()),
                    signer_id: None,
                    outcome: format!("verified-witness:{}", member.witness_id),
                },
                1_000,
            )
            .unwrap();
        }
        report.approval_log_id = Some(log.log_id.clone());
        report.approval_log_entry_count = Some(log.entries.len() as u64);
        report.approval_log_head_sha256 = log.head_sha256.clone();
        report.approval_log_sha256 = Some(approval_transparency_log_sha256(&log).unwrap());
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
                &report, &log,
            )
            .is_ok()
        );

        let checkpoint_key = SigningKey::from_bytes(&[93; 32]);
        let checkpoint =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                &report,
                &log,
                "factory-receipt-quorum-log",
                &checkpoint_key.to_bytes(),
            )
            .unwrap();
        let checkpoint_source =
            render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                &checkpoint,
            )
            .unwrap();
        assert_eq!(
            parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                &checkpoint_source,
            )
            .unwrap(),
            checkpoint
        );
        let verification =
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert!(verification.verified);
        let verification_source =
            render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
                &verification,
            )
            .unwrap();
        assert_eq!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification(
                &verification_source,
            )
            .unwrap(),
            verification
        );
        assert_eq!(
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_verification_json_schema(
            )["additionalProperties"],
            false
        );

        let witness_a_key = SigningKey::from_bytes(&[94; 32]);
        let witness_b_key = SigningKey::from_bytes(&[95; 32]);
        let witness_a =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                "checkpoint-witness-a",
                1_100,
                &witness_a_key.to_bytes(),
            )
            .unwrap();
        let witness_b =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                "checkpoint-witness-b",
                1_101,
                &witness_b_key.to_bytes(),
            )
            .unwrap();
        let witness_source =
            render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
                &witness_a,
            )
            .unwrap();
        assert_eq!(
            parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
                &witness_source,
            )
            .unwrap(),
            witness_a
        );
        let witness_quorum =
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_b.clone(), witness_a.clone()],
                &[
                    witness_b_key.verifying_key().to_bytes(),
                    witness_a_key.verifying_key().to_bytes(),
                ],
                2,
                1_200,
            )
            .unwrap();
        assert!(witness_quorum.quorum_met);
        assert_eq!(
            witness_quorum.witness_ids,
            vec!["checkpoint-witness-a", "checkpoint-witness-b"]
        );
        let witness_quorum_source =
            render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
                &witness_quorum,
            )
            .unwrap();
        assert_eq!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report(
                &witness_quorum_source,
            )
            .unwrap(),
            witness_quorum
        );
        assert_eq!(
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema(
            )["additionalProperties"],
            false
        );

        let quorum_report_source = render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_report(
            &report,
        )
        .unwrap();
        let approval_log_source = serde_json::to_vec_pretty(&log).unwrap();
        let witness_b_source = render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
            &witness_b,
        )
        .unwrap();
        let request_source = serde_json::to_vec(
            &RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessRequest {
                schema_version: 1,
                protocol: RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_PROTOCOL,
                quorum_report: &report,
                approval_log: &log,
                checkpoint: &checkpoint,
            },
        )
        .unwrap();
        let checkpoint_sha256 =
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_sha256(
                &checkpoint,
            )
            .unwrap();
        let make_receipt = |
            witness: &SignedRemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitness,
            response: &[u8],
            trust_binding: Option<(String, u64)>,
        | {
            let (witness_key_trust_state_sha256, witness_key_generation) = trust_binding
                .map(|(digest, generation)| (Some(digest), Some(generation)))
                .unwrap_or((None, None));
            RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt {
                schema_version: 1,
                adapter: RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_ADAPTER.into(),
                endpoint: "https://witness.example/v1/factory-receipt-quorum-checkpoint".into(),
                quorum_report_sha256: checkpoint.quorum_report_sha256.clone(),
                quorum_report_source_sha256: sha256(&quorum_report_source),
                registry_id: checkpoint.registry_id.clone(),
                generation: checkpoint.generation,
                registry_checkpoint_sha256: checkpoint.registry_checkpoint_sha256.clone(),
                approval_log_id: checkpoint.approval_log_id.clone(),
                approval_log_entry_count: checkpoint.approval_log_entry_count,
                approval_log_head_sha256: checkpoint.approval_log_head_sha256.clone(),
                approval_log_sha256: checkpoint.approval_log_sha256.clone(),
                approval_log_source_sha256: sha256(&approval_log_source),
                checkpoint_sha256: checkpoint_sha256.clone(),
                checkpoint_source_sha256: sha256(&checkpoint_source),
                checkpoint_public_key: hex::encode(checkpoint_key.verifying_key().to_bytes()),
                request_sha256: sha256(&request_source),
                response_sha256: sha256(response),
                response_bytes: response.len() as u64,
                witness_sha256:
                    signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_sha256(
                        witness,
                    )
                    .unwrap(),
                evaluated_at_unix: 1_200,
                witness_id: witness.witness_id.clone(),
                witness_public_key: witness.public_key.clone(),
                witness_key_trust_state_sha256,
                witness_key_generation,
                witnessed_at_unix: witness.witnessed_at_unix,
                verified: true,
            }
        };
        let receipt_a = make_receipt(&witness_a, &witness_source, None);
        let receipt_b = make_receipt(&witness_b, &witness_b_source, None);
        let (verified_receipts, mut admission_report) =
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum(
                &[receipt_b.clone(), receipt_a.clone()],
                &quorum_report_source,
                &approval_log_source,
                &checkpoint_source,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_b_source.clone(), witness_source.clone()],
                &[
                    (
                        "checkpoint-witness-b".into(),
                        witness_b_key.verifying_key().to_bytes(),
                    ),
                    (
                        "checkpoint-witness-a".into(),
                        witness_a_key.verifying_key().to_bytes(),
                    ),
                ],
                2,
                1_200,
            )
            .unwrap();
        assert!(admission_report.quorum_met);
        assert_eq!(
            verified_receipts
                .iter()
                .map(|receipt| receipt.witness_id.as_str())
                .collect::<Vec<_>>(),
            vec!["checkpoint-witness-a", "checkpoint-witness-b"]
        );
        assert_eq!(
            admission_report
                .members
                .iter()
                .map(|member| member.witness_id.as_str())
                .collect::<Vec<_>>(),
            vec!["checkpoint-witness-a", "checkpoint-witness-b"]
        );
        let unbound_report_source = render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
            &admission_report,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &unbound_report_source,
            )
            .unwrap(),
            admission_report
        );
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report_json_schema(
            )["properties"]["members"]["minItems"],
            1
        );
        assert!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &serde_json::to_vec(&admission_report).unwrap(),
            )
            .is_err()
        );

        let mut admission_log =
            new_approval_transparency_log("factory-checkpoint-witness-receipts").unwrap();
        for receipt in &verified_receipts {
            append_approval_transparency_event(
                &mut admission_log,
                ApprovalEventDescriptor {
                    artifact_kind: ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt,
                    artifact_sha256: sha256(&serde_json::to_vec(receipt).unwrap()),
                    subject_id: receipt.checkpoint_sha256.clone(),
                    request_sha256: Some(receipt.request_sha256.clone()),
                    session_sha256: Some(receipt.response_sha256.clone()),
                    signer_id: None,
                    outcome: format!("verified-witness:{}", receipt.witness_id),
                },
                1_200,
            )
            .unwrap();
        }
        admission_report.admission_log_id = Some(admission_log.log_id.clone());
        admission_report.admission_log_entry_count = Some(admission_log.entries.len() as u64);
        admission_report.admission_log_head_sha256 = admission_log.head_sha256.clone();
        admission_report.admission_log_sha256 =
            Some(approval_transparency_log_sha256(&admission_log).unwrap());
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_for_log(
                &admission_report,
                &admission_log,
            )
            .is_ok()
        );

        let mut duplicate_response_report = admission_report.clone();
        duplicate_response_report.members[1].response_sha256 =
            duplicate_response_report.members[0].response_sha256.clone();
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
                &duplicate_response_report,
            )
            .is_err()
        );
        let mut substituted_log =
            new_approval_transparency_log("factory-checkpoint-witness-receipts").unwrap();
        for (index, member) in admission_report.members.iter().enumerate() {
            append_approval_transparency_event(
                &mut substituted_log,
                ApprovalEventDescriptor {
                    artifact_kind: if index == 0 {
                        ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryCheckpointWitnessReceipt
                    } else {
                        ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryReceiptQuorumLogCheckpointWitnessReceipt
                    },
                    artifact_sha256: member.receipt_sha256.clone(),
                    subject_id: admission_report.checkpoint_sha256.clone(),
                    request_sha256: Some(member.request_sha256.clone()),
                    session_sha256: Some(member.response_sha256.clone()),
                    signer_id: None,
                    outcome: format!("verified-witness:{}", member.witness_id),
                },
                1_200,
            )
            .unwrap();
        }
        let mut substituted_report = admission_report.clone();
        substituted_report.admission_log_head_sha256 = substituted_log.head_sha256.clone();
        substituted_report.admission_log_sha256 =
            Some(approval_transparency_log_sha256(&substituted_log).unwrap());
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_for_log(
                &substituted_report,
                &substituted_log,
            )
            .is_err()
        );
        let mut altered_response = witness_b_source.clone();
        altered_response.push(b' ');
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum(
                &[receipt_a.clone(), receipt_b.clone()],
                &quorum_report_source,
                &approval_log_source,
                &checkpoint_source,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_source.clone(), altered_response],
                &[
                    (
                        "checkpoint-witness-a".into(),
                        witness_a_key.verifying_key().to_bytes(),
                    ),
                    (
                        "checkpoint-witness-b".into(),
                        witness_b_key.verifying_key().to_bytes(),
                    ),
                ],
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum(
                &[receipt_a.clone(), receipt_a.clone()],
                &quorum_report_source,
                &approval_log_source,
                &checkpoint_source,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_source.clone(), witness_source.clone()],
                &[
                    (
                        "checkpoint-witness-a".into(),
                        witness_a_key.verifying_key().to_bytes(),
                    ),
                    (
                        "checkpoint-witness-b".into(),
                        witness_b_key.verifying_key().to_bytes(),
                    ),
                ],
                2,
                1_200,
            )
            .is_err()
        );

        let initial_witness_a_trust =
            new_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                "checkpoint-witness-a",
                &witness_a_key.verifying_key().to_bytes(),
            )
            .unwrap();
        let witness_b_trust =
            new_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                "checkpoint-witness-b",
                &witness_b_key.verifying_key().to_bytes(),
            )
            .unwrap();
        let initial_trust_source =
            render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                &initial_witness_a_trust,
            )
            .unwrap();
        assert_eq!(
            parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                &initial_trust_source,
            )
            .unwrap(),
            initial_witness_a_trust
        );
        let witness_b_trust_source = render_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
            &witness_b_trust,
        )
        .unwrap();
        let trusted_receipt_a = make_receipt(
            &witness_a,
            &witness_source,
            Some((
                sha256(&initial_trust_source),
                initial_witness_a_trust.generation,
            )),
        );
        let trusted_receipt_b = make_receipt(
            &witness_b,
            &witness_b_source,
            Some((sha256(&witness_b_trust_source), witness_b_trust.generation)),
        );
        let (_, trust_bound_admission_report) =
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_with_trust_states(
                &[trusted_receipt_b.clone(), trusted_receipt_a.clone()],
                &quorum_report_source,
                &approval_log_source,
                &checkpoint_source,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_b_source.clone(), witness_source.clone()],
                &[witness_b_trust_source.clone(), initial_trust_source.clone()],
                2,
                1_200,
            )
            .unwrap();
        assert!(trust_bound_admission_report.quorum_met);
        assert!(
            trust_bound_admission_report
                .members
                .iter()
                .all(|member| member.witness_key_trust_state_sha256.is_some())
        );
        let mut wrong_trust_receipt_a = trusted_receipt_a.clone();
        wrong_trust_receipt_a.witness_key_trust_state_sha256 =
            Some(sha256(&witness_b_trust_source));
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_with_trust_states(
                &[wrong_trust_receipt_a, trusted_receipt_b],
                &quorum_report_source,
                &approval_log_source,
                &checkpoint_source,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_source.clone(), witness_b_source.clone()],
                &[initial_trust_source.clone(), witness_b_trust_source],
                2,
                1_200,
            )
            .is_err()
        );
        let rotated_witness_a_key = SigningKey::from_bytes(&[96; 32]);
        let witness_a_rotation =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial_witness_a_trust,
                &witness_a_key.to_bytes(),
                &rotated_witness_a_key.to_bytes(),
                1_150,
            )
            .unwrap();
        let rotation_source =
            render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &witness_a_rotation,
            )
            .unwrap();
        assert_eq!(
            parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &rotation_source,
            )
            .unwrap(),
            witness_a_rotation
        );
        let rotated_witness_a_trust =
            apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial_witness_a_trust,
                &witness_a_rotation,
            )
            .unwrap();
        assert_eq!(rotated_witness_a_trust.generation, 1);
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trusted_public_key(
                &rotated_witness_a_trust,
            )
            .unwrap(),
            rotated_witness_a_key.verifying_key().to_bytes()
        );
        let rotated_witness_a =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                "checkpoint-witness-a",
                1_151,
                &rotated_witness_a_key.to_bytes(),
            )
            .unwrap();
        let rotated_quorum =
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_b.clone(), rotated_witness_a.clone()],
                &[witness_b_trust.clone(), rotated_witness_a_trust.clone()],
                2,
                1_200,
            )
            .unwrap();
        assert!(rotated_quorum.quorum_met);
        assert_eq!(rotated_quorum.witness_ids, witness_quorum.witness_ids);
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_a.clone(), witness_b.clone()],
                &[rotated_witness_a_trust.clone(), witness_b_trust.clone()],
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[rotated_witness_a, witness_b.clone()],
                &[initial_witness_a_trust.clone(), witness_b_trust.clone()],
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                std::slice::from_ref(&witness_a),
                std::slice::from_ref(&witness_b_trust),
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            new_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                "weak-witness",
                &[0; 32],
            )
            .is_err()
        );
        assert_eq!(
            remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state_json_schema(
            )["additionalProperties"],
            false
        );
        assert_eq!(
            signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation_json_schema(
            )["additionalProperties"],
            false
        );

        let below_threshold =
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_a.clone(), witness_b.clone()],
                &[
                    witness_a_key.verifying_key().to_bytes(),
                    witness_b_key.verifying_key().to_bytes(),
                ],
                3,
                1_200,
            )
            .unwrap();
        assert!(!below_threshold.quorum_met);
        assert_eq!(below_threshold.status, "insufficient_witnesses");

        assert!(
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                "checkpoint-signer-reused",
                1_100,
                &checkpoint_key.to_bytes(),
            )
            .is_err()
        );
        let mut forged_checkpoint_key_witness = witness_a.clone();
        forged_checkpoint_key_witness.witness_id = "checkpoint-signer-reused".into();
        forged_checkpoint_key_witness.public_key =
            hex::encode(checkpoint_key.verifying_key().to_bytes());
        forged_checkpoint_key_witness.signature = hex::encode(
            checkpoint_key
                .sign(
                    &factory_release_receipt_quorum_log_checkpoint_witness_payload(
                        &forged_checkpoint_key_witness,
                    )
                    .unwrap(),
                )
                .to_bytes(),
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[forged_checkpoint_key_witness.clone()],
                &[checkpoint_key.verifying_key().to_bytes()],
                2,
                1_200,
            )
            .is_err()
        );
        let checkpoint_role_trust =
            new_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                "checkpoint-signer-reused",
                &checkpoint_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses_with_trust_states(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[forged_checkpoint_key_witness],
                &[checkpoint_role_trust],
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                std::slice::from_ref(&witness_a),
                &[[0; 32]],
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_a.clone(), witness_a.clone()],
                &[
                    witness_a_key.verifying_key().to_bytes(),
                    witness_a_key.verifying_key().to_bytes(),
                ],
                2,
                1_200,
            )
            .is_err()
        );
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[witness_a.clone(), witness_b.clone()],
                &[
                    witness_a_key.verifying_key().to_bytes(),
                    witness_b_key.verifying_key().to_bytes(),
                ],
                2,
                1_100 + MAXIMUM_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_AGE_SECONDS + 1,
            )
            .is_err()
        );

        let mut wrong_witness_domain = witness_a.clone();
        let mut wrong_witness_domain_payload =
            factory_release_receipt_quorum_log_checkpoint_witness_payload(&wrong_witness_domain)
                .unwrap();
        wrong_witness_domain_payload.splice(
            ..RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_DOMAIN.len(),
            b"pcbex-approval-registry-receipt-quorum-log-checkpoint-witness-v1"
                .iter()
                .copied(),
        );
        wrong_witness_domain.signature =
            hex::encode(witness_a_key.sign(&wrong_witness_domain_payload).to_bytes());
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witnesses(
                &report,
                &log,
                &checkpoint,
                &checkpoint_key.verifying_key().to_bytes(),
                &[wrong_witness_domain],
                &[witness_a_key.verifying_key().to_bytes()],
                2,
                1_200,
            )
            .is_err()
        );

        let mut wrong_domain = checkpoint.clone();
        let mut wrong_domain_payload =
            factory_release_receipt_quorum_log_checkpoint_payload(&wrong_domain).unwrap();
        wrong_domain_payload.splice(
            ..RECEIPT_QUORUM_LOG_CHECKPOINT_DOMAIN.len(),
            b"pcbex-approval-registry-receipt-quorum-log-checkpoint-v1"
                .iter()
                .copied(),
        );
        wrong_domain.signature = hex::encode(checkpoint_key.sign(&wrong_domain_payload).to_bytes());
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                &report,
                &log,
                &wrong_domain,
                &checkpoint_key.verifying_key().to_bytes(),
            )
            .is_err()
        );

        let mut mutated_threshold = checkpoint;
        mutated_threshold.valid_witnesses = 3;
        assert!(
            verify_remote_factory_release_registry_history_receipt_quorum_log_checkpoint(
                &report,
                &log,
                &mutated_threshold,
                &checkpoint_key.verifying_key().to_bytes(),
            )
            .is_err()
        );

        let mut partial = log.clone();
        partial.entries.pop();
        partial.head_sha256 = partial
            .entries
            .last()
            .map(|entry| entry.entry_sha256.clone());
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
                &report, &partial,
            )
            .is_err()
        );

        let mut extended = log.clone();
        append_approval_transparency_event(
            &mut extended,
            ApprovalEventDescriptor {
                artifact_kind: ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryCheckpointWitnessReceipt,
                artifact_sha256: "c".repeat(64),
                subject_id: report.checkpoint_sha256.clone(),
                request_sha256: Some("5".repeat(64)),
                session_sha256: Some("d".repeat(64)),
                signer_id: None,
                outcome: "verified-witness:witness-c".into(),
            },
            1_001,
        )
        .unwrap();
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
                &report, &extended,
            )
            .is_err()
        );

        let mut unbound = report.clone();
        unbound.approval_log_id = None;
        unbound.approval_log_entry_count = None;
        unbound.approval_log_head_sha256 = None;
        unbound.approval_log_sha256 = None;
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
                &unbound, &log,
            )
            .is_err()
        );

        let mut substituted = new_approval_transparency_log("factory-receipts").unwrap();
        for (index, member) in report.members.iter().enumerate() {
            append_approval_transparency_event(
                &mut substituted,
                ApprovalEventDescriptor {
                    artifact_kind: if index == 0 {
                        ApprovalArtifactKind::RemoteApprovalRegistryHistoryCheckpointWitnessReceipt
                    } else {
                        ApprovalArtifactKind::RemoteFactoryReleaseRegistryHistoryCheckpointWitnessReceipt
                    },
                    artifact_sha256: member.receipt_sha256.clone(),
                    subject_id: report.checkpoint_sha256.clone(),
                    request_sha256: Some(member.request_sha256.clone()),
                    session_sha256: Some(member.response_sha256.clone()),
                    signer_id: None,
                    outcome: format!("verified-witness:{}", member.witness_id),
                },
                1_000,
            )
            .unwrap();
        }
        let mut substituted_report = report;
        substituted_report.approval_log_head_sha256 = substituted.head_sha256.clone();
        substituted_report.approval_log_sha256 =
            Some(approval_transparency_log_sha256(&substituted).unwrap());
        assert!(
            validate_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_quorum_for_log(
                &substituted_report, &substituted,
            )
            .is_err()
        );
    }

    #[test]
    fn rotates_factory_receipt_quorum_checkpoint_witness_trust_as_one_digest_chain() {
        let old_secret = [101; 32];
        let next_secret = [102; 32];
        let final_secret = [103; 32];
        let initial =
            new_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                "checkpoint-witness-a",
                &SigningKey::from_bytes(&old_secret).verifying_key().to_bytes(),
            )
            .unwrap();
        assert_eq!(initial.generation, 0);
        assert!(
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial,
                &next_secret,
                &final_secret,
                1_000,
            )
            .is_err()
        );
        assert!(
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial,
                &old_secret,
                &old_secret,
                1_000,
            )
            .is_err()
        );
        assert!(
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial,
                &old_secret,
                &next_secret,
                MAX_TIMESTAMP + 1,
            )
            .is_err()
        );

        let first =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial,
                &old_secret,
                &next_secret,
                1_000,
            )
            .unwrap();
        let first_source =
            render_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &first,
            )
            .unwrap();
        assert_eq!(
            parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &first_source,
            )
            .unwrap(),
            first
        );
        assert!(
            parse_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &serde_json::to_vec(&first).unwrap(),
            )
            .is_err()
        );

        let rotated =
            apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &initial,
                &first,
            )
            .unwrap();
        assert_eq!(rotated.generation, 1);
        assert_eq!(
            rotated.last_rotation_sha256,
            Some(
                signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation_sha256(
                    &first,
                )
                .unwrap()
            )
        );
        assert!(
            apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &rotated,
                &first,
            )
            .is_err()
        );
        assert!(
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &rotated,
                &next_secret,
                &final_secret,
                999,
            )
            .is_err()
        );

        let second =
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &rotated,
                &next_secret,
                &final_secret,
                1_001,
            )
            .unwrap();
        let final_state =
            apply_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &rotated,
                &second,
            )
            .unwrap();
        assert_eq!(final_state.generation, 2);

        let mut tampered_signature = second.clone();
        let replacement = if tampered_signature.new_signature.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        tampered_signature
            .new_signature
            .replace_range(..2, replacement);
        assert!(
            validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &tampered_signature,
            )
            .is_err()
        );

        let mut skipped = second.clone();
        skipped.to_generation += 1;
        assert!(
            validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &skipped,
            )
            .is_err()
        );
        let mut unchained = second.clone();
        unchained.previous_rotation_sha256 = None;
        assert!(
            validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &unchained,
            )
            .is_err()
        );
        let mut weak = second.clone();
        weak.new_public_key = "0".repeat(64);
        assert!(
            validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &weak,
            )
            .is_err()
        );

        let old_key = SigningKey::from_bytes(&old_secret);
        let next_key = SigningKey::from_bytes(&next_secret);
        let mut wrong_domain = first.clone();
        let mut wrong_domain_payload =
            factory_release_receipt_quorum_log_checkpoint_witness_key_rotation_payload(
                &wrong_domain,
            )
            .unwrap();
        wrong_domain_payload.splice(
            ..RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_KEY_ROTATION_DOMAIN.len(),
            b"pcbex-approval-registry-receipt-quorum-log-checkpoint-witness-key-rotation-v1"
                .iter()
                .copied(),
        );
        wrong_domain.old_signature = hex::encode(old_key.sign(&wrong_domain_payload).to_bytes());
        wrong_domain.new_signature = hex::encode(next_key.sign(&wrong_domain_payload).to_bytes());
        assert!(
            validate_signed_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &wrong_domain,
            )
            .is_err()
        );

        let mut incomplete = initial;
        incomplete.generation = 1;
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                &incomplete,
            )
            .is_err()
        );
        let mut exhausted = final_state;
        exhausted.generation =
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION;
        assert!(
            validate_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_trust_state(
                &exhausted,
            )
            .is_ok()
        );
        assert!(
            sign_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_key_rotation(
                &exhausted,
                &final_secret,
                &[104; 32],
                1_002,
            )
            .is_err()
        );
    }
}
