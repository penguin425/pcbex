//! Independent gossip for externally anchored factory-release transparency.
//!
//! The v1.490 boundary compares the exact latest, fully verified v1.489
//! external-log head with one independently observer-signed view. Identical
//! trees need no consistency proof. Different tree sizes require a bounded
//! proof in the correct direction, while different roots at one size are a
//! split view and fail closed. A successful comparison is evidence only for
//! the selected local and observer views. It does not establish global
//! non-equivocation, real organizational independence, ledger rollback
//! resistance, trusted time, transport identity, ordering, payment, or
//! exactly-once execution.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_adapter_monotonic_state::MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE;
use crate::factory_release_state_transparency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE;
use crate::factory_release_state_transparency_consistency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION;
use crate::factory_release_state_transparency_external_anchor::{
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
    SignedFactoryReleaseTransparencyExternalTreeHead, external_tree_head_schema,
    external_tree_head_sha256, factory_release_state_transparency_external_anchor_policy_sha256,
    parse_factory_release_state_transparency_external_anchor_policy,
    render_factory_release_state_transparency_external_anchor_policy,
    validate_external_tree_head_shape, verify_external_tree_head_signature,
};
use crate::factory_release_state_transparency_external_consistency::{
    FactoryReleaseStateTransparencyExternalConsistencyProof,
    FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES,
    factory_release_state_transparency_external_consistency_proof_json_schema,
    factory_release_state_transparency_external_consistency_report_json_schema,
    parse_factory_release_state_transparency_external_consistency_proof,
    parse_factory_release_state_transparency_external_consistency_report,
    render_factory_release_state_transparency_external_consistency_proof,
    render_factory_release_state_transparency_external_consistency_report, validate_head_pair,
    verify_consistency_path,
};
use ed25519_dalek::{Signature, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_SCOPE: &str =
    "factory-release-state-transparency-external-log-gossip-receipt-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_VERIFICATION_SCOPE: &str =
    "verified-factory-release-state-transparency-external-log-gossip-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REPORT_BYTES: u64 =
    16 * 1024 * 1024;

const MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const GOSSIP_RECEIPT_SIGNATURE_DOMAIN: &str =
    "pcbex-factory-release-state-transparency-external-log-gossip-receipt-v1";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-report:v1\0";
const FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-filename:v1\0";

const RELATIONSHIP_SAME_TREE: &str = "same_tree";
const RELATIONSHIP_LOCAL_PRECEDES_OBSERVED: &str = "local_precedes_observed";
const RELATIONSHIP_OBSERVED_PRECEDES_LOCAL: &str = "observed_precedes_local";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseTransparencyExternalGossipReceipt {
    pub(crate) schema_version: u32,
    pub(crate) receipt_scope: String,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) external_log_id: String,
    pub(crate) observer_id: String,
    pub(crate) observed_tree_head_sha256: String,
    pub(crate) observed_tree_head: SignedFactoryReleaseTransparencyExternalTreeHead,
    pub(crate) received_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) observer_public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) monotonic_state_chain_verified: bool,
    pub(crate) source_checkpoint_inclusion_verified: bool,
    pub(crate) complete_source_consistency_chain_verified: bool,
    pub(crate) source_log_append_only_consistency_verified: bool,
    pub(crate) witness_quorum_verified: bool,
    pub(crate) external_anchor_verified: bool,
    pub(crate) complete_external_consistency_chain_verified: bool,
    pub(crate) external_log_append_only_consistency_verified: bool,
    pub(crate) local_external_consistency_report_identity_verified: bool,
    pub(crate) gossip_receipt_identity_verified: bool,
    pub(crate) external_anchor_policy_pin_matched: bool,
    pub(crate) external_log_policy_matched: bool,
    pub(crate) local_external_tree_head_signature_verified: bool,
    pub(crate) observed_external_tree_head_signature_verified: bool,
    pub(crate) observer_pin_matched: bool,
    pub(crate) observer_receipt_signature_verified: bool,
    pub(crate) observer_log_and_witness_role_separation_verified: bool,
    pub(crate) external_tree_relationship_verified: bool,
    pub(crate) selected_observer_view_consistency_verified: bool,
    pub(crate) observed_external_checkpoint_fresh_at_evaluation: bool,
    pub(crate) external_consistency_proof_required: bool,
    pub(crate) external_consistency_proof_verified: bool,
    pub(crate) local_external_consistency_extension_available: bool,
    pub(crate) split_view_detected: bool,
    pub(crate) selected_ledger_external_gossip_report_committed: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) endpoint_transport_authenticity_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) server_side_idempotency_enforced: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) idempotency_key: String,
    pub(crate) source_log_id: String,
    pub(crate) anchor_checkpoint_generation: u64,
    pub(crate) anchor_state_sequence: u64,
    pub(crate) witness_policy_sha256: String,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) external_log_id: String,
    pub(crate) local_external_consistency_generation: u64,
    pub(crate) observer_id: String,
    pub(crate) observer_public_key: String,
    pub(crate) relationship: String,
    pub(crate) local_external_tree_head_sha256: String,
    pub(crate) observed_external_tree_head_sha256: String,
    pub(crate) local_external_tree_size: u64,
    pub(crate) observed_external_tree_size: u64,
    pub(crate) local_external_root_sha256: String,
    pub(crate) observed_external_root_sha256: String,
    pub(crate) local_external_tree_head_observed_at_unix: u64,
    pub(crate) observed_external_tree_head_observed_at_unix: u64,
    pub(crate) observer_received_at_unix: u64,
    pub(crate) observer_expires_at_unix: u64,
    pub(crate) local_external_consistency_report_artifact: ExactArtifactIdentity,
    pub(crate) external_anchor_policy_artifact: ExactArtifactIdentity,
    pub(crate) gossip_receipt_artifact: ExactArtifactIdentity,
    pub(crate) consistency_proof_artifact: Option<ExactArtifactIdentity>,
    pub(crate) local_external_consistency_report:
        FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    pub(crate) gossip_receipt: SignedFactoryReleaseTransparencyExternalGossipReceipt,
    pub(crate) consistency_proof: Option<FactoryReleaseStateTransparencyExternalConsistencyProof>,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct GossipReceiptSignaturePayload<'a> {
    domain: &'static str,
    schema_version: u32,
    receipt_scope: &'a str,
    external_anchor_policy_sha256: &'a str,
    external_log_id: &'a str,
    observer_id: &'a str,
    observed_tree_head_sha256: &'a str,
    observed_tree_size: u64,
    observed_root_sha256: &'a str,
    observed_tree_head_observed_at_unix: u64,
    external_log_public_key: &'a str,
    received_at_unix: u64,
    expires_at_unix: u64,
    algorithm: &'a str,
    observer_public_key: &'a str,
}

#[derive(Serialize)]
struct FilenameContext<'a> {
    source_log_id: &'a str,
    witness_policy_sha256: &'a str,
    external_log_id: &'a str,
    external_anchor_policy_sha256: &'a str,
    local_external_consistency_generation: u64,
    observer_id: &'a str,
    observer_public_key: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_external_gossip(
    local_external_consistency_report_source: &[u8],
    external_anchor_policy_source: &[u8],
    expected_external_anchor_policy_sha256: &str,
    expected_external_log_id: &str,
    complete_factory_release_chain_verified: bool,
    complete_external_consistency_chain_verified: bool,
    expected_observer_id: &str,
    expected_observer_public_key: &str,
    gossip_receipt_source: &[u8],
    consistency_proof_source: Option<&[u8]>,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyExternalGossipVerificationReport, String> {
    if !complete_factory_release_chain_verified || !complete_external_consistency_chain_verified {
        return Err(
            "factory release transparency external gossip requires complete verified local chains"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip evaluation time is outside its bound"
                .into(),
        );
    }
    validate_slug(
        expected_external_log_id,
        "expected factory release transparency external log id",
    )?;
    validate_observer_slug(
        expected_observer_id,
        "expected factory release transparency external gossip observer id",
    )?;
    validate_digest(
        expected_external_anchor_policy_sha256,
        "expected factory release transparency external-anchor policy SHA-256",
    )?;
    validate_nonweak_public_key(
        expected_observer_public_key,
        "expected factory release transparency external gossip observer public key",
    )?;

    let local_report = parse_factory_release_state_transparency_external_consistency_report(
        local_external_consistency_report_source,
    )?;
    let local_external_consistency_report_artifact =
        exact_identity(local_external_consistency_report_source);
    if local_report.external_log_id != expected_external_log_id
        || local_report.external_anchor_policy_sha256 != expected_external_anchor_policy_sha256
    {
        return Err(
            "factory release transparency external gossip local report binds a different context"
                .into(),
        );
    }

    let external_anchor_policy = parse_factory_release_state_transparency_external_anchor_policy(
        external_anchor_policy_source,
    )?;
    let external_anchor_policy_artifact = exact_identity(external_anchor_policy_source);
    let actual_external_anchor_policy_sha256 =
        factory_release_state_transparency_external_anchor_policy_sha256(&external_anchor_policy)?;
    if actual_external_anchor_policy_sha256 != expected_external_anchor_policy_sha256 {
        return Err(
            "factory release transparency external gossip policy pin does not match".into(),
        );
    }
    if local_report.external_anchor_policy_artifact != external_anchor_policy_artifact
        || local_report.external_anchor_report.external_anchor_policy != external_anchor_policy
    {
        return Err(
            "factory release transparency external gossip local report uses a different policy"
                .into(),
        );
    }
    let trusted_log = external_anchor_policy
        .trusted_logs
        .iter()
        .find(|trusted| trusted.log_id == expected_external_log_id)
        .ok_or_else(|| {
            "factory release transparency external gossip log is not trusted by policy".to_string()
        })?;

    let receipt =
        parse_factory_release_state_transparency_external_gossip_receipt(gossip_receipt_source)?;
    let gossip_receipt_artifact = exact_identity(gossip_receipt_source);
    if receipt.external_anchor_policy_sha256 != actual_external_anchor_policy_sha256
        || receipt.external_log_id != expected_external_log_id
    {
        return Err(
            "factory release transparency external gossip receipt binds a different context".into(),
        );
    }
    if receipt.observer_id != expected_observer_id
        || receipt.observer_public_key != expected_observer_public_key
    {
        return Err(
            "factory release transparency external gossip receipt does not match the pinned observer"
                .into(),
        );
    }

    let local_head = &local_report.consistency_proof.current_tree_head;
    let observed_head = &receipt.observed_tree_head;
    for head in [local_head, observed_head] {
        if head.log_id != trusted_log.log_id
            || head.algorithm != trusted_log.algorithm
            || head.public_key != trusted_log.public_key
        {
            return Err(
                "factory release transparency external gossip tree head does not match the selected policy log"
                    .into(),
            );
        }
    }

    // Authenticate the local and independently observed log views, then the
    // observer receipt, before interpreting any size, time, or Merkle claim.
    verify_external_tree_head_signature(local_head)?;
    verify_external_tree_head_signature(observed_head)?;
    let local_tree_head_sha256 = external_tree_head_sha256(local_head)?;
    let observed_tree_head_sha256 = external_tree_head_sha256(observed_head)?;
    if local_report.current_external_tree_head_sha256 != local_tree_head_sha256
        || receipt.observed_tree_head_sha256 != observed_tree_head_sha256
    {
        return Err(
            "factory release transparency external gossip binds different tree-head identities"
                .into(),
        );
    }
    verify_external_gossip_receipt_signature(&receipt)?;
    verify_observer_role_separation(&local_report, &receipt)?;
    validate_receipt_window(
        &receipt,
        external_anchor_policy.maximum_checkpoint_age_seconds,
        local_report.evaluated_at_unix,
        evaluated_at_unix,
    )?;

    let (consistency_proof, consistency_proof_artifact) = if let Some(source) =
        consistency_proof_source
    {
        let proof = parse_factory_release_state_transparency_external_consistency_proof(source)?;
        (Some(proof), Some(exact_identity(source)))
    } else {
        (None, None)
    };
    let relationship = verify_tree_relationship(
        local_head,
        observed_head,
        consistency_proof.as_ref(),
        &actual_external_anchor_policy_sha256,
        expected_external_log_id,
    )?;
    let proof_required = relationship != RELATIONSHIP_SAME_TREE;
    let extension_available = relationship == RELATIONSHIP_LOCAL_PRECEDES_OBSERVED;

    let mut report = FactoryReleaseStateTransparencyExternalGossipVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_VERIFICATION_SCOPE
            .into(),
        status: "verified".into(),
        monotonic_state_chain_verified: true,
        source_checkpoint_inclusion_verified: true,
        complete_source_consistency_chain_verified: true,
        source_log_append_only_consistency_verified: true,
        witness_quorum_verified: true,
        external_anchor_verified: true,
        complete_external_consistency_chain_verified: true,
        external_log_append_only_consistency_verified: true,
        local_external_consistency_report_identity_verified: true,
        gossip_receipt_identity_verified: true,
        external_anchor_policy_pin_matched: true,
        external_log_policy_matched: true,
        local_external_tree_head_signature_verified: true,
        observed_external_tree_head_signature_verified: true,
        observer_pin_matched: true,
        observer_receipt_signature_verified: true,
        observer_log_and_witness_role_separation_verified: true,
        external_tree_relationship_verified: true,
        selected_observer_view_consistency_verified: true,
        observed_external_checkpoint_fresh_at_evaluation: true,
        external_consistency_proof_required: proof_required,
        external_consistency_proof_verified: proof_required,
        local_external_consistency_extension_available: extension_available,
        split_view_detected: false,
        selected_ledger_external_gossip_report_committed: false,
        global_non_equivocation_verified: false,
        selected_ledger_rollback_resistance_verified: false,
        trusted_time_verified: false,
        independent_organization_operation_verified: false,
        endpoint_transport_authenticity_verified: false,
        factory_legal_identity_verified: false,
        server_side_idempotency_enforced: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        idempotency_key: local_report.idempotency_key.clone(),
        source_log_id: local_report.source_log_id.clone(),
        anchor_checkpoint_generation: local_report.anchor_checkpoint_generation,
        anchor_state_sequence: local_report.anchor_state_sequence,
        witness_policy_sha256: local_report.witness_policy_sha256.clone(),
        external_anchor_policy_sha256: actual_external_anchor_policy_sha256,
        external_log_id: expected_external_log_id.into(),
        local_external_consistency_generation: local_report.external_consistency_generation,
        observer_id: expected_observer_id.into(),
        observer_public_key: expected_observer_public_key.into(),
        relationship: relationship.into(),
        local_external_tree_head_sha256: local_tree_head_sha256,
        observed_external_tree_head_sha256: observed_tree_head_sha256,
        local_external_tree_size: local_head.tree_size,
        observed_external_tree_size: observed_head.tree_size,
        local_external_root_sha256: local_head.root_sha256.clone(),
        observed_external_root_sha256: observed_head.root_sha256.clone(),
        local_external_tree_head_observed_at_unix: local_head.observed_at_unix,
        observed_external_tree_head_observed_at_unix: observed_head.observed_at_unix,
        observer_received_at_unix: receipt.received_at_unix,
        observer_expires_at_unix: receipt.expires_at_unix,
        local_external_consistency_report_artifact,
        external_anchor_policy_artifact,
        gossip_receipt_artifact,
        consistency_proof_artifact,
        local_external_consistency_report: local_report,
        gossip_receipt: receipt,
        consistency_proof,
        evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_report_shape(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_receipt(
    receipt: &SignedFactoryReleaseTransparencyExternalGossipReceipt,
) -> Result<Vec<u8>, String> {
    validate_receipt_shape(receipt)?;
    render_bounded(
        receipt,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
        "factory release state transparency external gossip receipt",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_receipt(
    source: &[u8],
) -> Result<SignedFactoryReleaseTransparencyExternalGossipReceipt, String> {
    let receipt = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
        "factory release state transparency external gossip receipt",
    )?;
    validate_receipt_shape(&receipt)?;
    Ok(receipt)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_report(
    report: &FactoryReleaseStateTransparencyExternalGossipVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REPORT_BYTES,
        "factory release state transparency external gossip verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REPORT_BYTES,
        "factory release state transparency external gossip verification report",
    )?;
    validate_report_self_contained(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn factory_release_state_transparency_external_gossip_filename(
    idempotency_key: &str,
    source_log_id: &str,
    witness_policy_sha256: &str,
    external_log_id: &str,
    external_anchor_policy_sha256: &str,
    local_external_consistency_generation: u64,
    observer_id: &str,
    observer_public_key: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_slug(source_log_id, "factory release transparency source log id")?;
    validate_digest(
        witness_policy_sha256,
        "factory release transparency witness policy SHA-256",
    )?;
    validate_slug(
        external_log_id,
        "factory release transparency external log id",
    )?;
    validate_digest(
        external_anchor_policy_sha256,
        "factory release transparency external-anchor policy SHA-256",
    )?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION)
        .contains(&local_external_consistency_generation)
    {
        return Err(
            "factory release transparency external gossip local generation is outside its bound"
                .into(),
        );
    }
    validate_observer_slug(
        observer_id,
        "factory release transparency external gossip observer id",
    )?;
    validate_nonweak_public_key(
        observer_public_key,
        "factory release transparency external gossip observer public key",
    )?;
    let context = FilenameContext {
        source_log_id,
        witness_policy_sha256,
        external_log_id,
        external_anchor_policy_sha256,
        local_external_consistency_generation,
        observer_id,
        observer_public_key,
    };
    let context_sha256 = domain_hash(
        FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-v1-{idempotency_key}-{local_external_consistency_generation:04}-{}.json",
        &context_sha256[..32]
    ))
}

pub(crate) fn external_gossip_receipt_signature_payload(
    receipt: &SignedFactoryReleaseTransparencyExternalGossipReceipt,
) -> Result<Vec<u8>, String> {
    validate_receipt_shape(receipt)?;
    let head = &receipt.observed_tree_head;
    serde_json::to_vec(&GossipReceiptSignaturePayload {
        domain: GOSSIP_RECEIPT_SIGNATURE_DOMAIN,
        schema_version: receipt.schema_version,
        receipt_scope: &receipt.receipt_scope,
        external_anchor_policy_sha256: &receipt.external_anchor_policy_sha256,
        external_log_id: &receipt.external_log_id,
        observer_id: &receipt.observer_id,
        observed_tree_head_sha256: &receipt.observed_tree_head_sha256,
        observed_tree_size: head.tree_size,
        observed_root_sha256: &head.root_sha256,
        observed_tree_head_observed_at_unix: head.observed_at_unix,
        external_log_public_key: &head.public_key,
        received_at_unix: receipt.received_at_unix,
        expires_at_unix: receipt.expires_at_unix,
        algorithm: &receipt.algorithm,
        observer_public_key: &receipt.observer_public_key,
    })
    .map_err(|error| {
        format!("serializing factory release transparency external gossip receipt: {error}")
    })
}

fn verify_external_gossip_receipt_signature(
    receipt: &SignedFactoryReleaseTransparencyExternalGossipReceipt,
) -> Result<(), String> {
    let key = validate_nonweak_public_key(
        &receipt.observer_public_key,
        "factory release transparency external gossip observer public key",
    )?;
    let signature = decode_hex::<64>(
        &receipt.signature,
        "factory release transparency external gossip receipt signature",
    )?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| {
            format!("invalid factory release transparency external gossip observer key: {error}")
        })?
        .verify_strict(
            &external_gossip_receipt_signature_payload(receipt)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|error| {
            format!(
                "invalid factory release transparency external gossip receipt signature: {error}"
            )
        })
}

fn verify_tree_relationship(
    local_head: &SignedFactoryReleaseTransparencyExternalTreeHead,
    observed_head: &SignedFactoryReleaseTransparencyExternalTreeHead,
    proof: Option<&FactoryReleaseStateTransparencyExternalConsistencyProof>,
    expected_external_anchor_policy_sha256: &str,
    expected_external_log_id: &str,
) -> Result<&'static str, String> {
    let same_tree = local_head.tree_size == observed_head.tree_size
        && local_head.root_sha256 == observed_head.root_sha256;
    if same_tree {
        if proof.is_some() {
            return Err(
                "factory release transparency external gossip consistency proof is redundant for an identical tree"
                    .into(),
            );
        }
        return Ok(RELATIONSHIP_SAME_TREE);
    }
    if local_head.tree_size == observed_head.tree_size {
        return Err(
            "factory release transparency external gossip detected split-view roots at one tree size"
                .into(),
        );
    }
    let proof = proof.ok_or_else(|| {
        "factory release transparency external gossip requires a consistency proof for different tree sizes"
            .to_string()
    })?;
    if proof.external_anchor_policy_sha256 != expected_external_anchor_policy_sha256
        || proof.external_log_id != expected_external_log_id
    {
        return Err(
            "factory release transparency external gossip consistency proof binds a different context"
                .into(),
        );
    }
    let (expected_previous, expected_current, relationship) =
        if local_head.tree_size < observed_head.tree_size {
            (
                local_head,
                observed_head,
                RELATIONSHIP_LOCAL_PRECEDES_OBSERVED,
            )
        } else {
            (
                observed_head,
                local_head,
                RELATIONSHIP_OBSERVED_PRECEDES_LOCAL,
            )
        };
    if proof.previous_tree_head != *expected_previous
        || proof.current_tree_head != *expected_current
        || proof.previous_tree_head_sha256 != external_tree_head_sha256(expected_previous)?
        || proof.current_tree_head_sha256 != external_tree_head_sha256(expected_current)?
    {
        return Err(
            "factory release transparency external gossip consistency proof does not bind the compared heads"
                .into(),
        );
    }
    validate_head_pair(&proof.previous_tree_head, &proof.current_tree_head)?;
    verify_consistency_path(
        &proof.previous_tree_head,
        &proof.current_tree_head,
        &proof.consistency_path,
    )?;
    Ok(relationship)
}

fn verify_observer_role_separation(
    local_report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    receipt: &SignedFactoryReleaseTransparencyExternalGossipReceipt,
) -> Result<(), String> {
    let anchor = &local_report.external_anchor_report;
    let witness_report = &anchor.witness_quorum_report;
    let current_transparency_report = &witness_report
        .consistency_report
        .current_transparency_report;
    let mut assigned_ids = HashSet::new();
    assigned_ids.insert(local_report.source_log_id.as_str());
    assigned_ids.insert(local_report.external_log_id.as_str());
    assigned_ids.insert(current_transparency_report.factory_id.as_str());
    for trusted in &anchor.external_anchor_policy.trusted_logs {
        assigned_ids.insert(trusted.log_id.as_str());
    }
    for member in &witness_report.members {
        assigned_ids.insert(member.organization_id.as_str());
        assigned_ids.insert(member.witness_id.as_str());
    }
    if assigned_ids.contains(receipt.observer_id.as_str()) {
        return Err(
            "factory release transparency external gossip observer identity is assigned to a log, witness, or factory role"
                .into(),
        );
    }

    let inner_head = &witness_report
        .consistency_report
        .current_transparency_report
        .transparency_receipt
        .tree_head;
    let mut assigned_keys = HashSet::new();
    assigned_keys.insert(inner_head.public_key.as_str());
    for trusted in &anchor.external_anchor_policy.trusted_logs {
        assigned_keys.insert(trusted.public_key.as_str());
    }
    for member in &witness_report.members {
        assigned_keys.insert(member.witness_public_key.as_str());
    }
    if assigned_keys.contains(receipt.observer_public_key.as_str()) {
        return Err(
            "factory release transparency external gossip observer key is assigned to a log or witness role"
                .into(),
        );
    }
    Ok(())
}

fn validate_receipt_window(
    receipt: &SignedFactoryReleaseTransparencyExternalGossipReceipt,
    maximum_checkpoint_age_seconds: u64,
    local_report_evaluated_at_unix: u64,
    evaluated_at_unix: u64,
) -> Result<(), String> {
    let head = &receipt.observed_tree_head;
    if receipt.received_at_unix < head.observed_at_unix {
        return Err(
            "factory release transparency external gossip receipt predates its observed head"
                .into(),
        );
    }
    let lifetime = receipt
        .expires_at_unix
        .checked_sub(receipt.received_at_unix)
        .ok_or_else(|| {
            "factory release transparency external gossip receipt expiry precedes receipt time"
                .to_string()
        })?;
    if lifetime == 0 || lifetime > MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS {
        return Err(format!(
            "factory release transparency external gossip receipt lifetime must be 1 to {MAX_GOSSIP_RECEIPT_LIFETIME_SECONDS} seconds"
        ));
    }
    if evaluated_at_unix < local_report_evaluated_at_unix
        || evaluated_at_unix < receipt.received_at_unix
        || evaluated_at_unix > receipt.expires_at_unix
        || evaluated_at_unix < head.observed_at_unix
        || evaluated_at_unix - head.observed_at_unix > maximum_checkpoint_age_seconds
    {
        return Err(
            "factory release transparency external gossip receipt is stale, future-dated, expired, or precedes the selected local report"
                .into(),
        );
    }
    Ok(())
}

fn validate_receipt_shape(
    receipt: &SignedFactoryReleaseTransparencyExternalGossipReceipt,
) -> Result<(), String> {
    if receipt.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_SCHEMA_VERSION
        || receipt.receipt_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_SCOPE
        || receipt.algorithm != "ed25519"
        || receipt.received_at_unix > MAX_TIMESTAMP
        || receipt.expires_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "factory release transparency external gossip receipt invariants are invalid".into(),
        );
    }
    validate_digest(
        &receipt.external_anchor_policy_sha256,
        "factory release transparency external gossip policy SHA-256",
    )?;
    validate_slug(
        &receipt.external_log_id,
        "factory release transparency external gossip log id",
    )?;
    validate_observer_slug(
        &receipt.observer_id,
        "factory release transparency external gossip observer id",
    )?;
    validate_digest(
        &receipt.observed_tree_head_sha256,
        "factory release transparency external gossip observed tree-head SHA-256",
    )?;
    validate_external_tree_head_shape(&receipt.observed_tree_head)?;
    validate_nonweak_public_key(
        &receipt.observer_public_key,
        "factory release transparency external gossip observer public key",
    )?;
    decode_hex::<64>(
        &receipt.signature,
        "factory release transparency external gossip receipt signature",
    )?;
    Ok(())
}

fn validate_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipVerificationReport,
) -> Result<(), String> {
    let positives = [
        report.monotonic_state_chain_verified,
        report.source_checkpoint_inclusion_verified,
        report.complete_source_consistency_chain_verified,
        report.source_log_append_only_consistency_verified,
        report.witness_quorum_verified,
        report.external_anchor_verified,
        report.complete_external_consistency_chain_verified,
        report.external_log_append_only_consistency_verified,
        report.local_external_consistency_report_identity_verified,
        report.gossip_receipt_identity_verified,
        report.external_anchor_policy_pin_matched,
        report.external_log_policy_matched,
        report.local_external_tree_head_signature_verified,
        report.observed_external_tree_head_signature_verified,
        report.observer_pin_matched,
        report.observer_receipt_signature_verified,
        report.observer_log_and_witness_role_separation_verified,
        report.external_tree_relationship_verified,
        report.selected_observer_view_consistency_verified,
        report.observed_external_checkpoint_fresh_at_evaluation,
    ];
    let negatives = [
        report.split_view_detected,
        report.selected_ledger_external_gossip_report_committed,
        report.global_non_equivocation_verified,
        report.selected_ledger_rollback_resistance_verified,
        report.trusted_time_verified,
        report.independent_organization_operation_verified,
        report.endpoint_transport_authenticity_verified,
        report.factory_legal_identity_verified,
        report.server_side_idempotency_enforced,
        report.capacity_reserved,
        report.order_placed,
        report.payment_performed,
        report.exactly_once_execution_verified,
    ];
    let proof_required = report.relationship != RELATIONSHIP_SAME_TREE;
    if report.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_VERIFICATION_SCOPE
        || report.status != "verified"
        || positives.contains(&false)
        || negatives.contains(&true)
        || report.external_consistency_proof_required != proof_required
        || report.external_consistency_proof_verified != proof_required
        || report.consistency_proof.is_some() != proof_required
        || report.consistency_proof_artifact.is_some() != proof_required
        || report.local_external_consistency_extension_available
            != (report.relationship == RELATIONSHIP_LOCAL_PRECEDES_OBSERVED)
        || !matches!(
            report.relationship.as_str(),
            RELATIONSHIP_SAME_TREE
                | RELATIONSHIP_LOCAL_PRECEDES_OBSERVED
                | RELATIONSHIP_OBSERVED_PRECEDES_LOCAL
        )
        || report.binding_sha256 != report_binding(report)?
    {
        return Err(
            "factory release transparency external gossip report claims are invalid".into(),
        );
    }
    validate_digest(&report.idempotency_key, "factory release idempotency key")?;
    validate_slug(
        &report.source_log_id,
        "factory release transparency source log id",
    )?;
    validate_digest(
        &report.witness_policy_sha256,
        "factory release transparency witness policy SHA-256",
    )?;
    validate_digest(
        &report.external_anchor_policy_sha256,
        "factory release transparency external-anchor policy SHA-256",
    )?;
    validate_slug(
        &report.external_log_id,
        "factory release transparency external log id",
    )?;
    validate_observer_slug(
        &report.observer_id,
        "factory release transparency external gossip observer id",
    )?;
    validate_nonweak_public_key(
        &report.observer_public_key,
        "factory release transparency external gossip observer public key",
    )?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION)
        .contains(&report.anchor_checkpoint_generation)
        || report.anchor_state_sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        || !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION)
            .contains(&report.local_external_consistency_generation)
        || report.local_external_tree_size == 0
        || report.observed_external_tree_size == 0
        || report.local_external_tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || report.observed_external_tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || report.local_external_tree_head_observed_at_unix > MAX_TIMESTAMP
        || report.observed_external_tree_head_observed_at_unix > MAX_TIMESTAMP
        || report.observer_received_at_unix > MAX_TIMESTAMP
        || report.observer_expires_at_unix > MAX_TIMESTAMP
        || report.evaluated_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "factory release transparency external gossip report bounds are invalid".into(),
        );
    }
    match report.relationship.as_str() {
        RELATIONSHIP_SAME_TREE => {
            if report.local_external_tree_size != report.observed_external_tree_size
                || report.local_external_root_sha256 != report.observed_external_root_sha256
            {
                return Err(
                    "factory release transparency external gossip identical-tree relationship is invalid"
                        .into(),
                );
            }
        }
        RELATIONSHIP_LOCAL_PRECEDES_OBSERVED => {
            if report.local_external_tree_size >= report.observed_external_tree_size {
                return Err(
                    "factory release transparency external gossip local-precedes relationship is invalid"
                        .into(),
                );
            }
        }
        RELATIONSHIP_OBSERVED_PRECEDES_LOCAL => {
            if report.observed_external_tree_size >= report.local_external_tree_size {
                return Err(
                    "factory release transparency external gossip observed-precedes relationship is invalid"
                        .into(),
                );
            }
        }
        _ => unreachable!(),
    }
    for (value, label) in [
        (
            &report.local_external_tree_head_sha256,
            "factory release transparency local external tree-head SHA-256",
        ),
        (
            &report.observed_external_tree_head_sha256,
            "factory release transparency observed external tree-head SHA-256",
        ),
        (
            &report.local_external_root_sha256,
            "factory release transparency local external root SHA-256",
        ),
        (
            &report.observed_external_root_sha256,
            "factory release transparency observed external root SHA-256",
        ),
        (
            &report.binding_sha256,
            "factory release transparency external gossip report binding",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_artifact_identity(
        &report.local_external_consistency_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES,
        "factory release transparency external consistency report",
    )?;
    validate_artifact_identity(
        &report.external_anchor_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
        "factory release transparency external-anchor policy",
    )?;
    validate_artifact_identity(
        &report.gossip_receipt_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
        "factory release transparency external gossip receipt",
    )?;
    if let Some(identity) = &report.consistency_proof_artifact {
        validate_artifact_identity(
            identity,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
            "factory release transparency external gossip consistency proof",
        )?;
    }
    Ok(())
}

fn validate_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipVerificationReport,
) -> Result<(), String> {
    validate_report_shape(report)?;
    let local_source = render_factory_release_state_transparency_external_consistency_report(
        &report.local_external_consistency_report,
    )?;
    let policy_source = render_factory_release_state_transparency_external_anchor_policy(
        &report
            .local_external_consistency_report
            .external_anchor_report
            .external_anchor_policy,
    )?;
    let receipt_source =
        render_factory_release_state_transparency_external_gossip_receipt(&report.gossip_receipt)?;
    let proof_source = report
        .consistency_proof
        .as_ref()
        .map(render_factory_release_state_transparency_external_consistency_proof)
        .transpose()?;
    if exact_identity(&local_source) != report.local_external_consistency_report_artifact
        || exact_identity(&policy_source) != report.external_anchor_policy_artifact
        || exact_identity(&receipt_source) != report.gossip_receipt_artifact
        || proof_source.as_deref().map(exact_identity) != report.consistency_proof_artifact
    {
        return Err(
            "factory release transparency external gossip embedded artifact identity is invalid"
                .into(),
        );
    }
    let expected = verify_factory_release_state_transparency_external_gossip(
        &local_source,
        &policy_source,
        &report.external_anchor_policy_sha256,
        &report.external_log_id,
        true,
        true,
        &report.observer_id,
        &report.observer_public_key,
        &receipt_source,
        proof_source.as_deref(),
        report.evaluated_at_unix,
    )?;
    if &expected != report {
        return Err(
            "factory release transparency external gossip report binding is invalid".into(),
        );
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipVerificationReport,
) -> Result<String, String> {
    let mut unbound = report.clone();
    unbound.binding_sha256.clear();
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &unbound,
        "factory release transparency external gossip report binding",
    )
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

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    maximum: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum {
        return Err(format!("{label} byte count is outside its bound"));
    }
    validate_digest(&identity.sha256, &format!("{label} SHA-256"))
}

fn domain_hash(domain: &[u8], value: &impl Serialize, label: &str) -> Result<String, String> {
    let source =
        serde_json::to_vec(value).map_err(|error| format!("serializing {label}: {error}"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(source);
    Ok(hex::encode(hash.finalize()))
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

fn validate_observer_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'-' | b'_' => index != 0,
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

fn validate_nonweak_public_key(value: &str, label: &str) -> Result<[u8; 32], String> {
    let key = decode_hex::<32>(value, label)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key).map_err(|error| format!("invalid {label}: {error}"))?;
    if verifying_key.is_weak() {
        return Err(format!("{label} is weak"));
    }
    Ok(key)
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} must be lowercase hexadecimal"));
    }
    let bytes = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))
}

pub(crate) fn factory_release_state_transparency_external_gossip_receipt_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-receipt-v1.json",
        "title": "pcbex factory-release state transparency external-log gossip receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "receipt_scope", "external_anchor_policy_sha256",
            "external_log_id", "observer_id", "observed_tree_head_sha256",
            "observed_tree_head", "received_at_unix", "expires_at_unix",
            "algorithm", "observer_public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_SCHEMA_VERSION},
            "receipt_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_SCOPE},
            "external_anchor_policy_sha256": digest_schema(),
            "external_log_id": slug_schema(),
            "observer_id": observer_slug_schema(),
            "observed_tree_head_sha256": digest_schema(),
            "observed_tree_head": external_tree_head_schema(),
            "received_at_unix": timestamp_schema(),
            "expires_at_unix": timestamp_schema(),
            "algorithm": {"const": "ed25519"},
            "observer_public_key": digest_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_report_json_schema() -> Value {
    let digest = digest_schema();
    let mut local_report =
        factory_release_state_transparency_external_consistency_report_json_schema();
    remove_schema_metadata(&mut local_report);
    let mut receipt = factory_release_state_transparency_external_gossip_receipt_json_schema();
    remove_schema_metadata(&mut receipt);
    let mut proof = factory_release_state_transparency_external_consistency_proof_json_schema();
    remove_schema_metadata(&mut proof);
    let nullable_proof = json!({"oneOf": [proof.clone(), {"type": "null"}]});
    let nullable_proof_artifact = json!({
        "oneOf": [
            artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES),
            {"type": "null"}
        ]
    });
    let positive = [
        "monotonic_state_chain_verified",
        "source_checkpoint_inclusion_verified",
        "complete_source_consistency_chain_verified",
        "source_log_append_only_consistency_verified",
        "witness_quorum_verified",
        "external_anchor_verified",
        "complete_external_consistency_chain_verified",
        "external_log_append_only_consistency_verified",
        "local_external_consistency_report_identity_verified",
        "gossip_receipt_identity_verified",
        "external_anchor_policy_pin_matched",
        "external_log_policy_matched",
        "local_external_tree_head_signature_verified",
        "observed_external_tree_head_signature_verified",
        "observer_pin_matched",
        "observer_receipt_signature_verified",
        "observer_log_and_witness_role_separation_verified",
        "external_tree_relationship_verified",
        "selected_observer_view_consistency_verified",
        "observed_external_checkpoint_fresh_at_evaluation",
    ];
    let negative = [
        "split_view_detected",
        "selected_ledger_external_gossip_report_committed",
        "global_non_equivocation_verified",
        "selected_ledger_rollback_resistance_verified",
        "trusted_time_verified",
        "independent_organization_operation_verified",
        "endpoint_transport_authenticity_verified",
        "factory_legal_identity_verified",
        "server_side_idempotency_enforced",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ];
    let mut properties = serde_json::Map::new();
    properties.insert("schema_version".into(), json!({"const": 1}));
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_VERIFICATION_SCOPE}),
    );
    properties.insert("status".into(), json!({"const": "verified"}));
    for name in positive {
        properties.insert(name.into(), json!({"const": true}));
    }
    for name in negative {
        properties.insert(name.into(), json!({"const": false}));
    }
    for name in [
        "external_consistency_proof_required",
        "external_consistency_proof_verified",
        "local_external_consistency_extension_available",
    ] {
        properties.insert(name.into(), json!({"type": "boolean"}));
    }
    properties.insert("idempotency_key".into(), digest.clone());
    properties.insert("source_log_id".into(), slug_schema());
    properties.insert(
        "anchor_checkpoint_generation".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION}),
    );
    properties.insert(
        "anchor_state_sequence".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE}),
    );
    properties.insert("witness_policy_sha256".into(), digest.clone());
    properties.insert("external_anchor_policy_sha256".into(), digest.clone());
    properties.insert("external_log_id".into(), slug_schema());
    properties.insert(
        "local_external_consistency_generation".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION}),
    );
    properties.insert("observer_id".into(), observer_slug_schema());
    properties.insert("observer_public_key".into(), digest.clone());
    properties.insert(
        "relationship".into(),
        json!({"enum": [
            RELATIONSHIP_SAME_TREE,
            RELATIONSHIP_LOCAL_PRECEDES_OBSERVED,
            RELATIONSHIP_OBSERVED_PRECEDES_LOCAL
        ]}),
    );
    for name in [
        "local_external_tree_head_sha256",
        "observed_external_tree_head_sha256",
        "local_external_root_sha256",
        "observed_external_root_sha256",
        "binding_sha256",
    ] {
        properties.insert(name.into(), digest.clone());
    }
    for name in ["local_external_tree_size", "observed_external_tree_size"] {
        properties.insert(
            name.into(),
            json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE}),
        );
    }
    for name in [
        "local_external_tree_head_observed_at_unix",
        "observed_external_tree_head_observed_at_unix",
        "observer_received_at_unix",
        "observer_expires_at_unix",
        "evaluated_at_unix",
    ] {
        properties.insert(name.into(), timestamp_schema());
    }
    properties.insert(
        "local_external_consistency_report_artifact".into(),
        artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES),
    );
    properties.insert(
        "external_anchor_policy_artifact".into(),
        artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES),
    );
    properties.insert(
        "gossip_receipt_artifact".into(),
        artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES),
    );
    properties.insert("consistency_proof_artifact".into(), nullable_proof_artifact);
    properties.insert("local_external_consistency_report".into(), local_report);
    properties.insert("gossip_receipt".into(), receipt);
    properties.insert("consistency_proof".into(), nullable_proof);
    let required = properties
        .keys()
        .cloned()
        .map(Value::String)
        .collect::<Vec<_>>();
    Value::Object(serde_json::Map::from_iter([
        (
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        ),
        (
            "$id".into(),
            json!(
                "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-verification-report-v1.json"
            ),
        ),
        (
            "title".into(),
            json!(
                "pcbex factory-release state transparency external-log gossip verification report"
            ),
        ),
        ("type".into(), json!("object")),
        ("additionalProperties".into(), json!(false)),
        ("required".into(), Value::Array(required)),
        ("properties".into(), Value::Object(properties)),
    ]))
}

fn slug_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]*$"
    })
}

fn observer_slug_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]*$"
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn timestamp_schema() -> Value {
    json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP})
}

fn artifact_schema(maximum: u64) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
            "sha256": digest_schema()
        }
    })
}

fn remove_schema_metadata(value: &mut Value) {
    if let Some(object) = value.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
        object.remove("title");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_release_state_transparency_external_anchor::{
        FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION,
        FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE,
        external_tree_head_signature_payload,
    };
    use crate::factory_release_state_transparency_external_consistency::FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_SCOPE;
    use ed25519_dalek::{Signer, SigningKey};

    fn leaf(value: u8) -> [u8; 32] {
        Sha256::digest([value]).into()
    }

    fn merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut source = Vec::with_capacity(65);
        source.push(1);
        source.extend_from_slice(&left);
        source.extend_from_slice(&right);
        Sha256::digest(source).into()
    }

    fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let split = 1_usize << (usize::BITS - (leaves.len() - 1).leading_zeros() - 1);
        merkle_node(root(&leaves[..split]), root(&leaves[split..]))
    }

    fn consistency_path(leaves: &[[u8; 32]], old_size: usize) -> Vec<[u8; 32]> {
        fn subproof(old_size: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
            if old_size == leaves.len() {
                return if complete {
                    Vec::new()
                } else {
                    vec![root(leaves)]
                };
            }
            let split = 1_usize << (usize::BITS - (leaves.len() - 1).leading_zeros() - 1);
            if old_size <= split {
                let mut proof = subproof(old_size, &leaves[..split], complete);
                proof.push(root(&leaves[split..]));
                proof
            } else {
                let mut proof = subproof(old_size - split, &leaves[split..], false);
                proof.push(root(&leaves[..split]));
                proof
            }
        }
        subproof(old_size, leaves, true)
    }

    fn signed_head(
        key: &SigningKey,
        leaves: &[[u8; 32]],
        size: usize,
        observed_at_unix: u64,
    ) -> SignedFactoryReleaseTransparencyExternalTreeHead {
        let mut head = SignedFactoryReleaseTransparencyExternalTreeHead {
            schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION,
            tree_head_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE
                .into(),
            log_id: "public-log".into(),
            tree_size: size as u64,
            root_sha256: hex::encode(root(&leaves[..size])),
            observed_at_unix,
            algorithm: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        head.signature = hex::encode(
            key.sign(&external_tree_head_signature_payload(&head).unwrap())
                .to_bytes(),
        );
        head
    }

    fn proof(
        previous: &SignedFactoryReleaseTransparencyExternalTreeHead,
        current: &SignedFactoryReleaseTransparencyExternalTreeHead,
        leaves: &[[u8; 32]],
    ) -> FactoryReleaseStateTransparencyExternalConsistencyProof {
        FactoryReleaseStateTransparencyExternalConsistencyProof {
            schema_version: 1,
            proof_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_SCOPE.into(),
            external_anchor_policy_sha256: "ab".repeat(32),
            external_log_id: "public-log".into(),
            previous_tree_head_sha256: external_tree_head_sha256(previous).unwrap(),
            current_tree_head_sha256: external_tree_head_sha256(current).unwrap(),
            previous_tree_head: previous.clone(),
            current_tree_head: current.clone(),
            consistency_path: consistency_path(leaves, previous.tree_size as usize)
                .into_iter()
                .map(hex::encode)
                .collect(),
        }
    }

    fn receipt(
        observer: &SigningKey,
        head: SignedFactoryReleaseTransparencyExternalTreeHead,
    ) -> SignedFactoryReleaseTransparencyExternalGossipReceipt {
        let mut receipt = SignedFactoryReleaseTransparencyExternalGossipReceipt {
            schema_version: 1,
            receipt_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_SCOPE.into(),
            external_anchor_policy_sha256: "ab".repeat(32),
            external_log_id: "public-log".into(),
            observer_id: "observer-a".into(),
            observed_tree_head_sha256: external_tree_head_sha256(&head).unwrap(),
            observed_tree_head: head,
            received_at_unix: 110,
            expires_at_unix: 210,
            algorithm: "ed25519".into(),
            observer_public_key: hex::encode(observer.verifying_key().to_bytes()),
            signature: "00".repeat(64),
        };
        receipt.signature = hex::encode(
            observer
                .sign(&external_gossip_receipt_signature_payload(&receipt).unwrap())
                .to_bytes(),
        );
        receipt
    }

    #[test]
    fn verifies_observer_signature_and_all_consistent_relationships() {
        let log = SigningKey::from_bytes(&[31; 32]);
        let observer = SigningKey::from_bytes(&[32; 32]);
        let leaves = (0..5).map(leaf).collect::<Vec<_>>();
        let old = signed_head(&log, &leaves, 3, 100);
        let new = signed_head(&log, &leaves, 5, 101);
        let proof = proof(&old, &new, &leaves);
        let signed_receipt = receipt(&observer, new.clone());
        verify_external_tree_head_signature(&signed_receipt.observed_tree_head).unwrap();
        verify_external_gossip_receipt_signature(&signed_receipt).unwrap();
        assert_eq!(
            verify_tree_relationship(&old, &new, Some(&proof), &"ab".repeat(32), "public-log")
                .unwrap(),
            RELATIONSHIP_LOCAL_PRECEDES_OBSERVED
        );
        assert_eq!(
            verify_tree_relationship(&new, &old, Some(&proof), &"ab".repeat(32), "public-log")
                .unwrap(),
            RELATIONSHIP_OBSERVED_PRECEDES_LOCAL
        );
        assert_eq!(
            verify_tree_relationship(&new, &new, None, &"ab".repeat(32), "public-log").unwrap(),
            RELATIONSHIP_SAME_TREE
        );
    }

    #[test]
    fn rejects_tampering_split_views_missing_redundant_proofs_and_bad_time() {
        let log = SigningKey::from_bytes(&[31; 32]);
        let observer = SigningKey::from_bytes(&[32; 32]);
        let leaves = (0..5).map(leaf).collect::<Vec<_>>();
        let old = signed_head(&log, &leaves, 3, 100);
        let new = signed_head(&log, &leaves, 5, 101);
        let proof = proof(&old, &new, &leaves);
        let mut tampered = receipt(&observer, new.clone());
        tampered.signature = "11".repeat(64);
        assert!(verify_external_gossip_receipt_signature(&tampered).is_err());

        let alternate_leaves = (20..25).map(leaf).collect::<Vec<_>>();
        let split = signed_head(&log, &alternate_leaves, 5, 101);
        assert!(
            verify_tree_relationship(&new, &split, None, &"ab".repeat(32), "public-log")
                .unwrap_err()
                .contains("split-view")
        );
        assert!(
            verify_tree_relationship(&old, &new, None, &"ab".repeat(32), "public-log").is_err()
        );
        assert!(
            verify_tree_relationship(&new, &new, Some(&proof), &"ab".repeat(32), "public-log")
                .is_err()
        );
        let mut bad_proof = proof;
        bad_proof.consistency_path[0] = "22".repeat(32);
        assert!(
            verify_tree_relationship(&old, &new, Some(&bad_proof), &"ab".repeat(32), "public-log",)
                .is_err()
        );

        let signed_receipt = receipt(&observer, new);
        assert!(validate_receipt_window(&signed_receipt, 300, 100, 120).is_ok());
        assert!(validate_receipt_window(&signed_receipt, 5, 100, 120).is_err());
        assert!(validate_receipt_window(&signed_receipt, 300, 121, 120).is_err());
        assert!(validate_receipt_window(&signed_receipt, 300, 100, 211).is_err());
    }

    #[test]
    fn receipt_parser_rejects_noncanonical_duplicate_and_uppercase_json() {
        let log = SigningKey::from_bytes(&[31; 32]);
        let observer = SigningKey::from_bytes(&[32; 32]);
        let leaves = (0..3).map(leaf).collect::<Vec<_>>();
        let receipt = receipt(&observer, signed_head(&log, &leaves, 3, 100));
        let canonical =
            render_factory_release_state_transparency_external_gossip_receipt(&receipt).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_gossip_receipt(&canonical).unwrap(),
            receipt
        );
        assert!(
            parse_factory_release_state_transparency_external_gossip_receipt(
                &serde_json::to_vec(&receipt).unwrap(),
            )
            .is_err()
        );
        let duplicate = String::from_utf8(canonical).unwrap().replacen(
            "{\n",
            "{\n  \"schema_version\": 1,\n",
            1,
        );
        assert!(
            parse_factory_release_state_transparency_external_gossip_receipt(duplicate.as_bytes())
                .is_err()
        );
        let mut uppercase = receipt;
        uppercase.observed_tree_head_sha256 = uppercase.observed_tree_head_sha256.to_uppercase();
        assert!(validate_receipt_shape(&uppercase).is_err());
    }

    #[test]
    fn schemas_are_recursively_closed_and_arrays_bounded() {
        fn walk(value: &Value) {
            match value {
                Value::Object(object) => {
                    if object.get("type") == Some(&json!("object")) {
                        assert_eq!(object.get("additionalProperties"), Some(&json!(false)));
                    }
                    if object.get("type") == Some(&json!("array")) {
                        assert!(object.contains_key("maxItems"));
                    }
                    for value in object.values() {
                        walk(value);
                    }
                }
                Value::Array(values) => values.iter().for_each(walk),
                _ => {}
            }
        }
        for schema in [
            factory_release_state_transparency_external_gossip_receipt_json_schema(),
            factory_release_state_transparency_external_gossip_report_json_schema(),
        ] {
            walk(&schema);
        }
    }

    #[test]
    fn filename_is_bounded_and_binds_observer_and_local_generation() {
        let key = "ab".repeat(32);
        let witness = "cd".repeat(32);
        let policy = "ef".repeat(32);
        let observer = hex::encode(SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes());
        let name = factory_release_state_transparency_external_gossip_filename(
            &key,
            "source-log",
            &witness,
            "public-log",
            &policy,
            2,
            "observer-a",
            &observer,
        )
        .unwrap();
        assert!(name.len() < 255);
        assert!(name.contains(&format!("-{key}-0002-")));
        let changed = factory_release_state_transparency_external_gossip_filename(
            &key,
            "source-log",
            &witness,
            "public-log",
            &policy,
            2,
            "observer-b",
            &observer,
        )
        .unwrap();
        assert_ne!(name, changed);
    }
}
