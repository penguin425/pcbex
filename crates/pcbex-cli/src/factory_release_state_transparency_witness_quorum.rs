//! Independent witness quorum for retained factory-release transparency checkpoints.
//!
//! The v1.487 boundary requires policy-pinned Ed25519 receipts from distinct
//! configured organizations over one exact, fully verified v1.486 consistency
//! report and its current signed tree head. It proves agreement only among the
//! selected witnesses. It does not prove global non-equivocation, independent
//! legal identity or operation, rollback resistance for the selected ledger,
//! trusted time, transport identity, ordering, or payment.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_adapter_monotonic_state::MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE;
use crate::factory_release_state_transparency::{
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE,
    SignedFactoryReleaseStateTransparencyTreeHead,
    factory_release_state_transparency_receipt_json_schema, tree_head_sha256,
    validate_tree_head_shape, verify_tree_head_signature,
};
use crate::factory_release_state_transparency_consistency::{
    FactoryReleaseStateTransparencyConsistencyVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_REPORT_BYTES,
    factory_release_state_transparency_consistency_report_json_schema,
    parse_factory_release_state_transparency_consistency_report,
    render_factory_release_state_transparency_consistency_report,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_SCOPE: &str =
    "factory-release-state-transparency-witness-policy-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_SCOPE: &str =
    "factory-release-state-transparency-witness-receipt-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_VERIFICATION_SCOPE: &str =
    "verified-factory-release-state-transparency-witness-quorum-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_REPORT_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES: usize = 100;

const MAX_WITNESS_RECEIPT_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const WITNESS_RECEIPT_SIGNATURE_DOMAIN: &str =
    "pcbex-factory-release-state-transparency-witness-receipt-v1";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-witness-quorum-report:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedFactoryReleaseTransparencyWitness {
    pub(crate) organization_id: String,
    pub(crate) witness_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyWitnessPolicy {
    pub(crate) schema_version: u32,
    pub(crate) policy_scope: String,
    pub(crate) policy_id: String,
    pub(crate) minimum_organizations: u32,
    pub(crate) maximum_receipt_age_seconds: u64,
    pub(crate) trusted_witnesses: Vec<TrustedFactoryReleaseTransparencyWitness>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyWitnessReceipt {
    pub(crate) schema_version: u32,
    pub(crate) receipt_scope: String,
    pub(crate) witness_policy_sha256: String,
    pub(crate) organization_id: String,
    pub(crate) witness_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) checkpoint_generation: u64,
    pub(crate) consistency_report_sha256: String,
    pub(crate) tree_head_sha256: String,
    pub(crate) tree_head: SignedFactoryReleaseStateTransparencyTreeHead,
    pub(crate) witnessed_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) witness_public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyWitnessQuorumMember {
    pub(crate) organization_id: String,
    pub(crate) witness_id: String,
    pub(crate) witness_public_key: String,
    pub(crate) receipt_artifact: ExactArtifactIdentity,
    pub(crate) witnessed_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) receipt: SignedFactoryReleaseStateTransparencyWitnessReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyWitnessQuorumVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) monotonic_state_chain_verified: bool,
    pub(crate) current_checkpoint_inclusion_verified: bool,
    pub(crate) complete_consistency_chain_verified: bool,
    pub(crate) selected_log_append_only_consistency_verified: bool,
    pub(crate) consistency_report_identity_verified: bool,
    pub(crate) witness_policy_pin_matched: bool,
    pub(crate) witness_log_key_role_separation_verified: bool,
    pub(crate) witness_receipt_signatures_verified: bool,
    pub(crate) distinct_organization_quorum_verified: bool,
    pub(crate) selected_witness_checkpoint_agreement_verified: bool,
    pub(crate) selected_witness_split_view_detected: bool,
    pub(crate) selected_ledger_witness_quorum_report_committed: bool,
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
    pub(crate) log_id: String,
    pub(crate) checkpoint_generation: u64,
    pub(crate) current_state_sequence: u64,
    pub(crate) current_tree_head_sha256: String,
    pub(crate) current_tree_size: u64,
    pub(crate) current_root_sha256: String,
    pub(crate) policy_pack_sha256: String,
    pub(crate) transparency_policy_sha256: String,
    pub(crate) consistency_report_artifact: ExactArtifactIdentity,
    pub(crate) consistency_report: FactoryReleaseStateTransparencyConsistencyVerificationReport,
    pub(crate) witness_policy_artifact: ExactArtifactIdentity,
    pub(crate) witness_policy_sha256: String,
    pub(crate) witness_policy: FactoryReleaseStateTransparencyWitnessPolicy,
    pub(crate) minimum_organizations: u32,
    pub(crate) valid_receipts: u32,
    pub(crate) distinct_organizations: u32,
    pub(crate) freshest_witnessed_at_unix: u64,
    pub(crate) earliest_expires_at_unix: u64,
    pub(crate) members: Vec<FactoryReleaseStateTransparencyWitnessQuorumMember>,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct WitnessReceiptPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    receipt_scope: &'a str,
    witness_policy_sha256: &'a str,
    organization_id: &'a str,
    witness_id: &'a str,
    idempotency_key: &'a str,
    checkpoint_generation: u64,
    consistency_report_sha256: &'a str,
    tree_head_sha256: &'a str,
    tree_head: &'a SignedFactoryReleaseStateTransparencyTreeHead,
    witnessed_at_unix: u64,
    expires_at_unix: u64,
    algorithm: &'a str,
    witness_public_key: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_factory_release_state_transparency_witness_receipt(
    consistency_report_source: &[u8],
    witness_policy_source: &[u8],
    expected_witness_policy_sha256: &str,
    organization_id: &str,
    witness_id: &str,
    witnessed_at_unix: u64,
    expires_at_unix: u64,
    witness_secret_key: &[u8; 32],
) -> Result<SignedFactoryReleaseStateTransparencyWitnessReceipt, String> {
    let consistency_report =
        parse_factory_release_state_transparency_consistency_report(consistency_report_source)?;
    let policy = parse_factory_release_state_transparency_witness_policy(witness_policy_source)?;
    validate_digest(
        expected_witness_policy_sha256,
        "expected factory release transparency witness policy SHA-256",
    )?;
    let actual_policy_sha256 = factory_release_state_transparency_witness_policy_sha256(&policy)?;
    if actual_policy_sha256 != expected_witness_policy_sha256 {
        return Err("factory release transparency witness policy pin does not match".into());
    }
    let trusted = policy
        .trusted_witnesses
        .iter()
        .find(|trusted| {
            trusted.organization_id == organization_id && trusted.witness_id == witness_id
        })
        .ok_or_else(|| {
            "factory release transparency witness is not trusted by policy".to_string()
        })?;
    let signing_key = SigningKey::from_bytes(witness_secret_key);
    let witness_public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if witness_public_key != trusted.public_key {
        return Err(
            "factory release transparency witness private key does not match policy".into(),
        );
    }
    let selected_head = selected_tree_head(&consistency_report)?;
    validate_policy_role_separation(&policy, selected_head)?;
    validate_receipt_window(selected_head, witnessed_at_unix, expires_at_unix)?;
    let consistency_report_artifact = exact_identity(consistency_report_source);
    let mut receipt = SignedFactoryReleaseStateTransparencyWitnessReceipt {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION,
        receipt_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_SCOPE.into(),
        witness_policy_sha256: actual_policy_sha256,
        organization_id: organization_id.into(),
        witness_id: witness_id.into(),
        idempotency_key: consistency_report.idempotency_key.clone(),
        checkpoint_generation: consistency_report.checkpoint_generation,
        consistency_report_sha256: consistency_report_artifact.sha256,
        tree_head_sha256: tree_head_sha256(selected_head)?,
        tree_head: selected_head.clone(),
        witnessed_at_unix,
        expires_at_unix,
        algorithm: "ed25519".into(),
        witness_public_key,
        signature: String::new(),
    };
    receipt.signature = hex::encode(
        signing_key
            .sign(&witness_receipt_payload(&receipt)?)
            .to_bytes(),
    );
    validate_witness_receipt_shape(&receipt)?;
    verify_witness_receipt_signature(&receipt)?;
    Ok(receipt)
}

pub(crate) fn verify_factory_release_state_transparency_witness_quorum(
    consistency_report_source: &[u8],
    witness_policy_source: &[u8],
    expected_witness_policy_sha256: &str,
    witness_receipt_sources: &[Vec<u8>],
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyWitnessQuorumVerificationReport, String> {
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency witness evaluation time is outside its bound".into(),
        );
    }
    let consistency_report =
        parse_factory_release_state_transparency_consistency_report(consistency_report_source)?;
    let consistency_report_artifact = exact_identity(consistency_report_source);
    let policy = parse_factory_release_state_transparency_witness_policy(witness_policy_source)?;
    validate_digest(
        expected_witness_policy_sha256,
        "expected factory release transparency witness policy SHA-256",
    )?;
    let actual_policy_sha256 = factory_release_state_transparency_witness_policy_sha256(&policy)?;
    if actual_policy_sha256 != expected_witness_policy_sha256 {
        return Err("factory release transparency witness policy pin does not match".into());
    }
    let selected_head = selected_tree_head(&consistency_report)?;
    verify_tree_head_signature(selected_head)?;
    validate_policy_role_separation(&policy, selected_head)?;
    let minimum = usize::try_from(policy.minimum_organizations)
        .map_err(|_| "factory release transparency witness threshold overflow".to_string())?;
    if witness_receipt_sources.len() < minimum
        || witness_receipt_sources.len() > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES
    {
        return Err(format!(
            "factory release transparency witness quorum requires {} to {} receipts",
            policy.minimum_organizations, MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES
        ));
    }

    let mut organizations = HashSet::new();
    let mut witnesses = HashSet::new();
    let mut keys = HashSet::new();
    let mut artifacts = HashSet::new();
    let mut members = Vec::with_capacity(witness_receipt_sources.len());
    for source in witness_receipt_sources {
        let member = verify_witness_receipt(
            source,
            &consistency_report,
            &consistency_report_artifact,
            &policy,
            &actual_policy_sha256,
            evaluated_at_unix,
        )?;
        if !organizations.insert(member.organization_id.clone()) {
            return Err(
                "factory release transparency witness quorum requires distinct organizations"
                    .into(),
            );
        }
        if !witnesses.insert(member.witness_id.clone()) {
            return Err(
                "factory release transparency witness quorum requires distinct witness identities"
                    .into(),
            );
        }
        if !keys.insert(member.witness_public_key.clone()) {
            return Err(
                "factory release transparency witness quorum requires distinct witness keys".into(),
            );
        }
        if !artifacts.insert(member.receipt_artifact.sha256.clone()) {
            return Err(
                "factory release transparency witness quorum rejects duplicate receipts".into(),
            );
        }
        members.push(member);
    }
    members.sort_by(|left, right| {
        (&left.organization_id, &left.witness_id).cmp(&(&right.organization_id, &right.witness_id))
    });
    let count = u32::try_from(members.len())
        .map_err(|_| "factory release transparency witness count overflow".to_string())?;
    if count < policy.minimum_organizations {
        return Err("factory release transparency witness organization quorum was not met".into());
    }
    let witness_policy_artifact = exact_identity(witness_policy_source);
    let mut report = FactoryReleaseStateTransparencyWitnessQuorumVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_VERIFICATION_SCOPE.into(),
        status: "verified".into(),
        monotonic_state_chain_verified: true,
        current_checkpoint_inclusion_verified: true,
        complete_consistency_chain_verified: true,
        selected_log_append_only_consistency_verified: true,
        consistency_report_identity_verified: true,
        witness_policy_pin_matched: true,
        witness_log_key_role_separation_verified: true,
        witness_receipt_signatures_verified: true,
        distinct_organization_quorum_verified: true,
        selected_witness_checkpoint_agreement_verified: true,
        selected_witness_split_view_detected: false,
        selected_ledger_witness_quorum_report_committed: false,
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
        idempotency_key: consistency_report.idempotency_key.clone(),
        log_id: consistency_report.log_id.clone(),
        checkpoint_generation: consistency_report.checkpoint_generation,
        current_state_sequence: consistency_report.current_state_sequence,
        current_tree_head_sha256: consistency_report.current_tree_head_sha256.clone(),
        current_tree_size: consistency_report.current_tree_size,
        current_root_sha256: consistency_report.current_root_sha256.clone(),
        policy_pack_sha256: consistency_report.policy_pack_sha256.clone(),
        transparency_policy_sha256: consistency_report.transparency_policy_sha256.clone(),
        consistency_report_artifact,
        consistency_report,
        witness_policy_artifact,
        witness_policy_sha256: actual_policy_sha256,
        witness_policy: policy.clone(),
        minimum_organizations: policy.minimum_organizations,
        valid_receipts: count,
        distinct_organizations: count,
        freshest_witnessed_at_unix: members
            .iter()
            .map(|member| member.witnessed_at_unix)
            .max()
            .unwrap_or(0),
        earliest_expires_at_unix: members
            .iter()
            .map(|member| member.expires_at_unix)
            .min()
            .unwrap_or(0),
        members,
        evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_witness_quorum_report_shape(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn verify_witness_receipt(
    source: &[u8],
    consistency_report: &FactoryReleaseStateTransparencyConsistencyVerificationReport,
    consistency_report_artifact: &ExactArtifactIdentity,
    policy: &FactoryReleaseStateTransparencyWitnessPolicy,
    witness_policy_sha256: &str,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyWitnessQuorumMember, String> {
    let receipt = parse_factory_release_state_transparency_witness_receipt(source)?;
    let selected_head = selected_tree_head(consistency_report)?;
    if receipt.witness_policy_sha256 != witness_policy_sha256
        || receipt.idempotency_key != consistency_report.idempotency_key
        || receipt.checkpoint_generation != consistency_report.checkpoint_generation
        || receipt.consistency_report_sha256 != consistency_report_artifact.sha256
    {
        return Err(
            "factory release transparency witness receipt binds a different verification context"
                .into(),
        );
    }
    let trusted = policy
        .trusted_witnesses
        .iter()
        .find(|trusted| {
            trusted.organization_id == receipt.organization_id
                && trusted.witness_id == receipt.witness_id
        })
        .ok_or_else(|| {
            "factory release transparency receipt signer is not trusted by witness policy"
                .to_string()
        })?;
    if receipt.witness_public_key != trusted.public_key {
        return Err(
            "factory release transparency receipt key does not match witness policy".into(),
        );
    }
    if receipt.witness_public_key == selected_head.public_key {
        return Err(
            "factory release transparency witness key must be independent from the log key".into(),
        );
    }
    if evaluated_at_unix < receipt.witnessed_at_unix {
        return Err("factory release transparency witness receipt is not valid yet".into());
    }
    if evaluated_at_unix > receipt.expires_at_unix {
        return Err("factory release transparency witness receipt has expired".into());
    }
    if evaluated_at_unix - receipt.witnessed_at_unix > policy.maximum_receipt_age_seconds {
        return Err("factory release transparency witness receipt is stale at evaluation".into());
    }
    verify_tree_head_signature(&receipt.tree_head)?;
    verify_witness_receipt_signature(&receipt)?;
    if receipt.tree_head != *selected_head {
        if receipt.tree_head.log_id == selected_head.log_id
            && receipt.tree_head.public_key == selected_head.public_key
            && receipt.tree_head.tree_size == selected_head.tree_size
            && receipt.tree_head.root_sha256 != selected_head.root_sha256
        {
            return Err(
                "factory release transparency witness detected a split-view root at the selected tree size"
                    .into(),
            );
        }
        return Err(
            "factory release transparency witness receipt attests a different checkpoint".into(),
        );
    }
    Ok(FactoryReleaseStateTransparencyWitnessQuorumMember {
        organization_id: receipt.organization_id.clone(),
        witness_id: receipt.witness_id.clone(),
        witness_public_key: receipt.witness_public_key.clone(),
        receipt_artifact: exact_identity(source),
        witnessed_at_unix: receipt.witnessed_at_unix,
        expires_at_unix: receipt.expires_at_unix,
        receipt,
    })
}

fn selected_tree_head(
    report: &FactoryReleaseStateTransparencyConsistencyVerificationReport,
) -> Result<&SignedFactoryReleaseStateTransparencyTreeHead, String> {
    let head = &report
        .current_transparency_report
        .transparency_receipt
        .tree_head;
    validate_tree_head_shape(head)?;
    if report.current_tree_head_sha256 != tree_head_sha256(head)?
        || report.log_id != head.log_id
        || report.current_tree_size != head.tree_size
        || report.current_root_sha256 != head.root_sha256
    {
        return Err(
            "factory release transparency consistency report current head is inconsistent".into(),
        );
    }
    Ok(head)
}

fn validate_policy_role_separation(
    policy: &FactoryReleaseStateTransparencyWitnessPolicy,
    selected_head: &SignedFactoryReleaseStateTransparencyTreeHead,
) -> Result<(), String> {
    validate_witness_policy(policy)?;
    if policy
        .trusted_witnesses
        .iter()
        .any(|trusted| trusted.public_key == selected_head.public_key)
    {
        return Err(
            "factory release transparency witness policy reuses the log signing key".into(),
        );
    }
    Ok(())
}

fn validate_receipt_window(
    head: &SignedFactoryReleaseStateTransparencyTreeHead,
    witnessed_at_unix: u64,
    expires_at_unix: u64,
) -> Result<(), String> {
    if witnessed_at_unix > MAX_TIMESTAMP || expires_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency witness receipt time is outside its bound".into(),
        );
    }
    if witnessed_at_unix < head.observed_at_unix {
        return Err(
            "factory release transparency witness receipt predates its signed tree head".into(),
        );
    }
    let lifetime = expires_at_unix
        .checked_sub(witnessed_at_unix)
        .ok_or_else(|| {
            "factory release transparency witness receipt expiry precedes witness time".to_string()
        })?;
    if lifetime == 0 || lifetime > MAX_WITNESS_RECEIPT_LIFETIME_SECONDS {
        return Err(format!(
            "factory release transparency witness receipt lifetime must be 1 to {MAX_WITNESS_RECEIPT_LIFETIME_SECONDS} seconds"
        ));
    }
    Ok(())
}

fn witness_receipt_payload(
    receipt: &SignedFactoryReleaseStateTransparencyWitnessReceipt,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WitnessReceiptPayload {
        domain: WITNESS_RECEIPT_SIGNATURE_DOMAIN,
        schema_version: receipt.schema_version,
        receipt_scope: &receipt.receipt_scope,
        witness_policy_sha256: &receipt.witness_policy_sha256,
        organization_id: &receipt.organization_id,
        witness_id: &receipt.witness_id,
        idempotency_key: &receipt.idempotency_key,
        checkpoint_generation: receipt.checkpoint_generation,
        consistency_report_sha256: &receipt.consistency_report_sha256,
        tree_head_sha256: &receipt.tree_head_sha256,
        tree_head: &receipt.tree_head,
        witnessed_at_unix: receipt.witnessed_at_unix,
        expires_at_unix: receipt.expires_at_unix,
        algorithm: &receipt.algorithm,
        witness_public_key: &receipt.witness_public_key,
    })
    .map_err(|error| format!("serializing factory release transparency witness receipt: {error}"))
}

fn verify_witness_receipt_signature(
    receipt: &SignedFactoryReleaseStateTransparencyWitnessReceipt,
) -> Result<(), String> {
    validate_witness_receipt_shape(receipt)?;
    let public_key = decode_hex::<32>(
        &receipt.witness_public_key,
        "factory release transparency witness public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid factory release transparency witness key: {error}"))?;
    if verifying_key.is_weak() {
        return Err("factory release transparency witness key is weak".into());
    }
    let signature = Signature::from_bytes(&decode_hex::<64>(
        &receipt.signature,
        "factory release transparency witness receipt signature",
    )?);
    verifying_key
        .verify_strict(&witness_receipt_payload(receipt)?, &signature)
        .map_err(|error| {
            format!("invalid factory release transparency witness receipt signature: {error}")
        })
}

pub(crate) fn render_factory_release_state_transparency_witness_policy(
    policy: &FactoryReleaseStateTransparencyWitnessPolicy,
) -> Result<Vec<u8>, String> {
    validate_witness_policy(policy)?;
    render_bounded(
        policy,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_BYTES,
        "factory release state transparency witness policy",
    )
}

pub(crate) fn parse_factory_release_state_transparency_witness_policy(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyWitnessPolicy, String> {
    let policy = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_BYTES,
        "factory release state transparency witness policy",
    )?;
    validate_witness_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn factory_release_state_transparency_witness_policy_sha256(
    policy: &FactoryReleaseStateTransparencyWitnessPolicy,
) -> Result<String, String> {
    validate_witness_policy(policy)?;
    let source = serde_json::to_vec(policy).map_err(|error| {
        format!("serializing factory release transparency witness policy: {error}")
    })?;
    Ok(hex::encode(Sha256::digest(source)))
}

pub(crate) fn render_factory_release_state_transparency_witness_receipt(
    receipt: &SignedFactoryReleaseStateTransparencyWitnessReceipt,
) -> Result<Vec<u8>, String> {
    validate_witness_receipt_shape(receipt)?;
    verify_witness_receipt_signature(receipt)?;
    render_bounded(
        receipt,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_BYTES,
        "factory release state transparency witness receipt",
    )
}

pub(crate) fn parse_factory_release_state_transparency_witness_receipt(
    source: &[u8],
) -> Result<SignedFactoryReleaseStateTransparencyWitnessReceipt, String> {
    let receipt = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_BYTES,
        "factory release state transparency witness receipt",
    )?;
    validate_witness_receipt_shape(&receipt)?;
    Ok(receipt)
}

pub(crate) fn render_factory_release_state_transparency_witness_quorum_report(
    report: &FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_witness_quorum_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_REPORT_BYTES,
        "factory release state transparency witness quorum report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_witness_quorum_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyWitnessQuorumVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_REPORT_BYTES,
        "factory release state transparency witness quorum report",
    )?;
    validate_witness_quorum_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn factory_release_state_transparency_witness_quorum_filename(
    idempotency_key: &str,
    log_id: &str,
    checkpoint_generation: u64,
    witness_policy_sha256: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_slug(log_id, "factory release transparency log id")?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION)
        .contains(&checkpoint_generation)
    {
        return Err(
            "factory release transparency witness checkpoint generation is outside its bound"
                .into(),
        );
    }
    validate_digest(
        witness_policy_sha256,
        "factory release transparency witness policy SHA-256",
    )?;
    Ok(format!(
        "factory-release-state-transparency-witness-quorum-v1-{idempotency_key}-{log_id}-{checkpoint_generation:04}-{witness_policy_sha256}.json"
    ))
}

fn validate_witness_policy(
    policy: &FactoryReleaseStateTransparencyWitnessPolicy,
) -> Result<(), String> {
    let count = policy.trusted_witnesses.len();
    if policy.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION
        || policy.policy_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_SCOPE
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES as u32)
            .contains(&policy.minimum_organizations)
        || !(1..=MAX_WITNESS_RECEIPT_LIFETIME_SECONDS).contains(&policy.maximum_receipt_age_seconds)
        || count < policy.minimum_organizations as usize
        || count > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES
    {
        return Err(
            "factory release state transparency witness policy invariants are invalid".into(),
        );
    }
    validate_slug(
        &policy.policy_id,
        "factory release transparency witness policy id",
    )?;
    let mut organizations = HashSet::new();
    let mut witnesses = HashSet::new();
    let mut keys = HashSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for trusted in &policy.trusted_witnesses {
        validate_slug(
            &trusted.organization_id,
            "factory release transparency witness organization id",
        )?;
        validate_slug(
            &trusted.witness_id,
            "factory release transparency witness id",
        )?;
        if trusted.algorithm != "ed25519" {
            return Err("factory release transparency witness algorithm is unsupported".into());
        }
        let key = decode_hex::<32>(
            &trusted.public_key,
            "factory release transparency witness public key",
        )?;
        let verifying_key = VerifyingKey::from_bytes(&key).map_err(|error| {
            format!("invalid factory release transparency witness public key: {error}")
        })?;
        if verifying_key.is_weak() {
            return Err("factory release transparency witness public key is weak".into());
        }
        let order = (
            trusted.organization_id.as_str(),
            trusted.witness_id.as_str(),
        );
        if previous.is_some_and(|previous| previous >= order) {
            return Err(
                "factory release transparency trusted witnesses are not canonically ordered".into(),
            );
        }
        previous = Some(order);
        if !organizations.insert(&trusted.organization_id) {
            return Err(
                "factory release transparency witness policy requires distinct organizations"
                    .into(),
            );
        }
        if !witnesses.insert(&trusted.witness_id) {
            return Err(
                "factory release transparency witness policy requires distinct witness identities"
                    .into(),
            );
        }
        if !keys.insert(&trusted.public_key) {
            return Err(
                "factory release transparency witness policy requires distinct witness keys".into(),
            );
        }
    }
    Ok(())
}

fn validate_witness_receipt_shape(
    receipt: &SignedFactoryReleaseStateTransparencyWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION
        || receipt.receipt_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_SCOPE
        || receipt.algorithm != "ed25519"
        || !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION)
            .contains(&receipt.checkpoint_generation)
    {
        return Err("factory release transparency witness receipt invariants are invalid".into());
    }
    validate_slug(
        &receipt.organization_id,
        "factory release transparency witness organization id",
    )?;
    validate_slug(
        &receipt.witness_id,
        "factory release transparency witness id",
    )?;
    for (value, label) in [
        (
            &receipt.witness_policy_sha256,
            "factory release transparency witness policy SHA-256",
        ),
        (
            &receipt.idempotency_key,
            "factory release transparency witness idempotency key",
        ),
        (
            &receipt.consistency_report_sha256,
            "factory release transparency consistency report SHA-256",
        ),
        (
            &receipt.tree_head_sha256,
            "factory release transparency witness tree-head SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_tree_head_shape(&receipt.tree_head)?;
    if receipt.tree_head_sha256 != tree_head_sha256(&receipt.tree_head)? {
        return Err(
            "factory release transparency witness receipt tree-head digest does not match".into(),
        );
    }
    validate_receipt_window(
        &receipt.tree_head,
        receipt.witnessed_at_unix,
        receipt.expires_at_unix,
    )?;
    decode_hex::<32>(
        &receipt.witness_public_key,
        "factory release transparency witness public key",
    )?;
    decode_hex::<64>(
        &receipt.signature,
        "factory release transparency witness receipt signature",
    )?;
    Ok(())
}

fn validate_witness_quorum_report_shape(
    report: &FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
) -> Result<(), String> {
    let positives = [
        report.monotonic_state_chain_verified,
        report.current_checkpoint_inclusion_verified,
        report.complete_consistency_chain_verified,
        report.selected_log_append_only_consistency_verified,
        report.consistency_report_identity_verified,
        report.witness_policy_pin_matched,
        report.witness_log_key_role_separation_verified,
        report.witness_receipt_signatures_verified,
        report.distinct_organization_quorum_verified,
        report.selected_witness_checkpoint_agreement_verified,
    ];
    let negatives = [
        report.selected_witness_split_view_detected,
        report.selected_ledger_witness_quorum_report_committed,
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
    let count = usize::try_from(report.valid_receipts)
        .map_err(|_| "factory release transparency witness count overflow".to_string())?;
    if report.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_VERIFICATION_SCOPE
        || report.status != "verified"
        || positives.contains(&false)
        || negatives.contains(&true)
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES).contains(&count)
        || count != report.members.len()
        || report.distinct_organizations != report.valid_receipts
        || report.valid_receipts < report.minimum_organizations
        || report.minimum_organizations != report.witness_policy.minimum_organizations
        || report.freshest_witnessed_at_unix
            != report
                .members
                .iter()
                .map(|member| member.witnessed_at_unix)
                .max()
                .unwrap_or(0)
        || report.earliest_expires_at_unix
            != report
                .members
                .iter()
                .map(|member| member.expires_at_unix)
                .min()
                .unwrap_or(0)
        || report.binding_sha256 != report_binding(report)?
    {
        return Err(
            "factory release transparency witness quorum report invariants are invalid".into(),
        );
    }
    validate_digest(&report.idempotency_key, "factory release idempotency key")?;
    validate_slug(&report.log_id, "factory release transparency log id")?;
    for (value, label) in [
        (
            &report.current_tree_head_sha256,
            "factory release transparency current tree-head SHA-256",
        ),
        (
            &report.current_root_sha256,
            "factory release transparency current Merkle root",
        ),
        (&report.policy_pack_sha256, "organization policy SHA-256"),
        (
            &report.transparency_policy_sha256,
            "factory release transparency policy SHA-256",
        ),
        (
            &report.witness_policy_sha256,
            "factory release transparency witness policy SHA-256",
        ),
        (
            &report.binding_sha256,
            "factory release transparency witness report binding",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_artifact_identity(
        &report.consistency_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_REPORT_BYTES,
        "factory release transparency consistency report",
    )?;
    validate_artifact_identity(
        &report.witness_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_BYTES,
        "factory release transparency witness policy",
    )?;
    let selected_head = selected_tree_head(&report.consistency_report)?;
    if report.idempotency_key != report.consistency_report.idempotency_key
        || report.log_id != report.consistency_report.log_id
        || report.checkpoint_generation != report.consistency_report.checkpoint_generation
        || report.current_state_sequence != report.consistency_report.current_state_sequence
        || report.current_tree_head_sha256 != report.consistency_report.current_tree_head_sha256
        || report.current_tree_size != report.consistency_report.current_tree_size
        || report.current_root_sha256 != report.consistency_report.current_root_sha256
        || report.policy_pack_sha256 != report.consistency_report.policy_pack_sha256
        || report.transparency_policy_sha256 != report.consistency_report.transparency_policy_sha256
        || report.current_tree_head_sha256 != tree_head_sha256(selected_head)?
        || report.witness_policy_sha256
            != factory_release_state_transparency_witness_policy_sha256(&report.witness_policy)?
    {
        return Err("factory release transparency witness report context is inconsistent".into());
    }
    validate_policy_role_separation(&report.witness_policy, selected_head)?;
    let mut organizations = HashSet::new();
    let mut witnesses = HashSet::new();
    let mut keys = HashSet::new();
    let mut artifacts = HashSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for member in &report.members {
        validate_artifact_identity(
            &member.receipt_artifact,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_BYTES,
            "factory release transparency witness receipt",
        )?;
        validate_witness_receipt_shape(&member.receipt)?;
        let order = (member.organization_id.as_str(), member.witness_id.as_str());
        if previous.is_some_and(|previous| previous >= order)
            || member.organization_id != member.receipt.organization_id
            || member.witness_id != member.receipt.witness_id
            || member.witness_public_key != member.receipt.witness_public_key
            || member.witnessed_at_unix != member.receipt.witnessed_at_unix
            || member.expires_at_unix != member.receipt.expires_at_unix
            || member.witnessed_at_unix > report.evaluated_at_unix
            || member.expires_at_unix < report.evaluated_at_unix
            || report.evaluated_at_unix - member.witnessed_at_unix
                > report.witness_policy.maximum_receipt_age_seconds
            || !organizations.insert(&member.organization_id)
            || !witnesses.insert(&member.witness_id)
            || !keys.insert(&member.witness_public_key)
            || !artifacts.insert(&member.receipt_artifact.sha256)
        {
            return Err("factory release transparency witness quorum member is invalid".into());
        }
        previous = Some(order);
    }
    Ok(())
}

fn validate_witness_quorum_report_self_contained(
    report: &FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
) -> Result<(), String> {
    validate_witness_quorum_report_shape(report)?;
    let consistency_source =
        render_factory_release_state_transparency_consistency_report(&report.consistency_report)?;
    let policy_source =
        render_factory_release_state_transparency_witness_policy(&report.witness_policy)?;
    let receipt_sources = report
        .members
        .iter()
        .map(|member| render_factory_release_state_transparency_witness_receipt(&member.receipt))
        .collect::<Result<Vec<_>, _>>()?;
    let expected = verify_factory_release_state_transparency_witness_quorum(
        &consistency_source,
        &policy_source,
        &report.witness_policy_sha256,
        &receipt_sources,
        report.evaluated_at_unix,
    )?;
    if &expected != report {
        return Err("factory release transparency witness quorum report binding is invalid".into());
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
) -> Result<String, String> {
    let mut unbound = report.clone();
    unbound.binding_sha256.clear();
    let source = serde_json::to_vec(&unbound).map_err(|error| {
        format!("serializing factory release transparency witness report binding: {error}")
    })?;
    let mut hash = Sha256::new();
    hash.update(REPORT_BINDING_DOMAIN);
    hash.update(source);
    Ok(hex::encode(hash.finalize()))
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

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{label} {value:?} must match [a-z0-9][a-z0-9.-]{{0,127}}"
        ))
    }
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        ))
    }
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

pub(crate) fn factory_release_state_transparency_witness_policy_json_schema() -> Value {
    let slug = slug_schema();
    let key = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-witness-policy-v1.json",
        "title": "pcbex factory-release state transparency witness policy",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "policy_scope", "policy_id", "minimum_organizations",
            "maximum_receipt_age_seconds", "trusted_witnesses"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION},
            "policy_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_SCOPE},
            "policy_id": slug.clone(),
            "minimum_organizations": {"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES},
            "maximum_receipt_age_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_WITNESS_RECEIPT_LIFETIME_SECONDS},
            "trusted_witnesses": {
                "type": "array", "minItems": 2, "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["organization_id", "witness_id", "algorithm", "public_key"],
                    "properties": {
                        "organization_id": slug.clone(),
                        "witness_id": slug,
                        "algorithm": {"const": "ed25519"},
                        "public_key": key
                    }
                }
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_witness_receipt_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let mut tree_head =
        factory_release_state_transparency_receipt_json_schema()["properties"]["tree_head"].clone();
    remove_schema_metadata(&mut tree_head);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-witness-receipt-v1.json",
        "title": "pcbex signed factory-release state transparency witness receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "receipt_scope", "witness_policy_sha256",
            "organization_id", "witness_id", "idempotency_key",
            "checkpoint_generation", "consistency_report_sha256", "tree_head_sha256",
            "tree_head", "witnessed_at_unix", "expires_at_unix", "algorithm",
            "witness_public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_SCHEMA_VERSION},
            "receipt_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_SCOPE},
            "witness_policy_sha256": digest.clone(),
            "organization_id": slug_schema(),
            "witness_id": slug_schema(),
            "idempotency_key": digest.clone(),
            "checkpoint_generation": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION},
            "consistency_report_sha256": digest.clone(),
            "tree_head_sha256": digest.clone(),
            "tree_head": tree_head,
            "witnessed_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "expires_at_unix": {"type": "integer", "minimum": 1, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "witness_public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn factory_release_state_transparency_witness_quorum_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let artifact = artifact_schema();
    let mut consistency = factory_release_state_transparency_consistency_report_json_schema();
    remove_schema_metadata(&mut consistency);
    let mut policy = factory_release_state_transparency_witness_policy_json_schema();
    remove_schema_metadata(&mut policy);
    let mut receipt = factory_release_state_transparency_witness_receipt_json_schema();
    remove_schema_metadata(&mut receipt);
    let positive = [
        "monotonic_state_chain_verified",
        "current_checkpoint_inclusion_verified",
        "complete_consistency_chain_verified",
        "selected_log_append_only_consistency_verified",
        "consistency_report_identity_verified",
        "witness_policy_pin_matched",
        "witness_log_key_role_separation_verified",
        "witness_receipt_signatures_verified",
        "distinct_organization_quorum_verified",
        "selected_witness_checkpoint_agreement_verified",
    ];
    let negative = [
        "selected_witness_split_view_detected",
        "selected_ledger_witness_quorum_report_committed",
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
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_VERIFICATION_SCOPE}),
    );
    properties.insert("status".into(), json!({"const": "verified"}));
    for name in positive {
        properties.insert(name.into(), json!({"const": true}));
    }
    for name in negative {
        properties.insert(name.into(), json!({"const": false}));
    }
    properties.insert("idempotency_key".into(), digest.clone());
    properties.insert("log_id".into(), slug_schema());
    properties.insert("checkpoint_generation".into(), json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION}));
    properties.insert(
        "current_state_sequence".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE}),
    );
    properties.insert("current_tree_head_sha256".into(), digest.clone());
    properties.insert(
        "current_tree_size".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE}),
    );
    properties.insert("current_root_sha256".into(), digest.clone());
    properties.insert("policy_pack_sha256".into(), digest.clone());
    properties.insert("transparency_policy_sha256".into(), digest.clone());
    properties.insert("consistency_report_artifact".into(), artifact.clone());
    properties.insert("consistency_report".into(), consistency);
    properties.insert("witness_policy_artifact".into(), artifact.clone());
    properties.insert("witness_policy_sha256".into(), digest.clone());
    properties.insert("witness_policy".into(), policy);
    properties.insert("minimum_organizations".into(), json!({"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES}));
    properties.insert("valid_receipts".into(), json!({"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES}));
    properties.insert("distinct_organizations".into(), json!({"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES}));
    properties.insert("freshest_witnessed_at_unix".into(), timestamp_schema());
    properties.insert("earliest_expires_at_unix".into(), timestamp_schema());
    properties.insert(
        "members".into(),
        json!({
            "type": "array", "minItems": 2, "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESSES,
            "items": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "organization_id", "witness_id", "witness_public_key",
                    "receipt_artifact", "witnessed_at_unix", "expires_at_unix", "receipt"
                ],
                "properties": {
                    "organization_id": slug_schema(),
                    "witness_id": slug_schema(),
                    "witness_public_key": digest.clone(),
                    "receipt_artifact": artifact,
                    "witnessed_at_unix": timestamp_schema(),
                    "expires_at_unix": timestamp_schema(),
                    "receipt": receipt
                }
            }
        }),
    );
    properties.insert("evaluated_at_unix".into(), timestamp_schema());
    properties.insert("binding_sha256".into(), digest);
    let required = properties.keys().cloned().map(Value::String).collect();
    Value::Object(serde_json::Map::from_iter([
        (
            "$schema".into(),
            json!("https://json-schema.org/draft/2020-12/schema"),
        ),
        (
            "$id".into(),
            json!(
                "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-witness-quorum-verification-report-v1.json"
            ),
        ),
        (
            "title".into(),
            json!("pcbex factory-release state transparency witness quorum verification report"),
        ),
        ("type".into(), json!("object")),
        ("additionalProperties".into(), json!(false)),
        ("required".into(), Value::Array(required)),
        ("properties".into(), Value::Object(properties)),
    ]))
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    })
}

fn artifact_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
}

fn timestamp_schema() -> Value {
    json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP})
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

    fn policy() -> FactoryReleaseStateTransparencyWitnessPolicy {
        let first = SigningKey::from_bytes(&[1; 32]);
        let second = SigningKey::from_bytes(&[2; 32]);
        FactoryReleaseStateTransparencyWitnessPolicy {
            schema_version: 1,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_POLICY_SCOPE.into(),
            policy_id: "release-witnesses".into(),
            minimum_organizations: 2,
            maximum_receipt_age_seconds: 300,
            trusted_witnesses: vec![
                TrustedFactoryReleaseTransparencyWitness {
                    organization_id: "org-a".into(),
                    witness_id: "witness-a".into(),
                    algorithm: "ed25519".into(),
                    public_key: hex::encode(first.verifying_key().to_bytes()),
                },
                TrustedFactoryReleaseTransparencyWitness {
                    organization_id: "org-b".into(),
                    witness_id: "witness-b".into(),
                    algorithm: "ed25519".into(),
                    public_key: hex::encode(second.verifying_key().to_bytes()),
                },
            ],
        }
    }

    fn signed_receipt() -> SignedFactoryReleaseStateTransparencyWitnessReceipt {
        let log_key = SigningKey::from_bytes(&[9; 32]);
        let witness_key = SigningKey::from_bytes(&[1; 32]);
        let head = SignedFactoryReleaseStateTransparencyTreeHead {
            schema_version: 1,
            tree_head_scope: "signed-factory-release-state-transparency-tree-head-v1".into(),
            log_id: "factory-log".into(),
            tree_size: 7,
            root_sha256: "12".repeat(32),
            observed_at_unix: 100,
            algorithm: "ed25519".into(),
            public_key: hex::encode(log_key.verifying_key().to_bytes()),
            signature: "34".repeat(64),
        };
        let mut receipt = SignedFactoryReleaseStateTransparencyWitnessReceipt {
            schema_version: 1,
            receipt_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_RECEIPT_SCOPE.into(),
            witness_policy_sha256: "45".repeat(32),
            organization_id: "org-a".into(),
            witness_id: "witness-a".into(),
            idempotency_key: "56".repeat(32),
            checkpoint_generation: 2,
            consistency_report_sha256: "67".repeat(32),
            tree_head_sha256: tree_head_sha256(&head).unwrap(),
            tree_head: head,
            witnessed_at_unix: 101,
            expires_at_unix: 201,
            algorithm: "ed25519".into(),
            witness_public_key: hex::encode(witness_key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        receipt.signature = hex::encode(
            witness_key
                .sign(&witness_receipt_payload(&receipt).unwrap())
                .to_bytes(),
        );
        receipt
    }

    #[test]
    fn policy_is_canonical_pinned_and_role_distinct() {
        let policy = policy();
        let source = render_factory_release_state_transparency_witness_policy(&policy).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_witness_policy(&source).unwrap(),
            policy
        );
        assert_eq!(
            factory_release_state_transparency_witness_policy_sha256(&policy)
                .unwrap()
                .len(),
            64
        );
        let mut reversed = policy.clone();
        reversed.trusted_witnesses.reverse();
        assert!(validate_witness_policy(&reversed).is_err());
        let mut duplicate = policy.clone();
        duplicate.trusted_witnesses[1].organization_id = "org-a".into();
        assert!(validate_witness_policy(&duplicate).is_err());
        let mut uppercase_key = policy.clone();
        uppercase_key.trusted_witnesses[0].public_key =
            uppercase_key.trusted_witnesses[0].public_key.to_uppercase();
        assert!(validate_witness_policy(&uppercase_key).is_err());
    }

    #[test]
    fn schemas_are_closed_and_bounded() {
        let policy = factory_release_state_transparency_witness_policy_json_schema();
        let receipt = factory_release_state_transparency_witness_receipt_json_schema();
        let report = factory_release_state_transparency_witness_quorum_report_json_schema();
        assert_eq!(policy["additionalProperties"], false);
        assert_eq!(
            policy["properties"]["trusted_witnesses"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(receipt["additionalProperties"], false);
        assert_eq!(report["additionalProperties"], false);
        assert_eq!(report["properties"]["members"]["maxItems"], 100);
    }

    #[test]
    fn filename_binds_release_log_generation_and_policy() {
        let digest = "ab".repeat(32);
        let name = factory_release_state_transparency_witness_quorum_filename(
            &digest,
            "factory-log",
            7,
            &"cd".repeat(32),
        )
        .unwrap();
        assert!(name.contains("factory-log-0007"));
        assert!(name.ends_with(&format!("{}.json", "cd".repeat(32))));
        assert!(
            factory_release_state_transparency_witness_quorum_filename(
                &digest,
                "factory-log",
                0,
                &"cd".repeat(32),
            )
            .is_err()
        );
    }

    #[test]
    fn witness_signature_binds_report_head_identity_and_window() {
        let receipt = signed_receipt();
        verify_witness_receipt_signature(&receipt).unwrap();
        let source = render_factory_release_state_transparency_witness_receipt(&receipt).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_witness_receipt(&source).unwrap(),
            receipt
        );

        let mut tampered = receipt.clone();
        tampered.consistency_report_sha256 = "89".repeat(32);
        assert!(verify_witness_receipt_signature(&tampered).is_err());

        let mut reversed = receipt;
        reversed.expires_at_unix = reversed.witnessed_at_unix;
        assert!(validate_witness_receipt_shape(&reversed).is_err());

        let mut uppercase_signature = signed_receipt();
        uppercase_signature.signature = uppercase_signature.signature.to_uppercase();
        assert!(validate_witness_receipt_shape(&uppercase_signature).is_err());
    }

    #[test]
    fn receipt_parser_rejects_noncanonical_and_duplicate_json() {
        let receipt = signed_receipt();
        let compact = serde_json::to_vec(&receipt).unwrap();
        assert!(parse_factory_release_state_transparency_witness_receipt(&compact).is_err());
        let canonical =
            render_factory_release_state_transparency_witness_receipt(&receipt).unwrap();
        let duplicate = String::from_utf8(canonical).unwrap().replacen(
            "{\n",
            "{\n  \"schema_version\": 1,\n",
            1,
        );
        assert!(
            parse_factory_release_state_transparency_witness_receipt(duplicate.as_bytes()).is_err()
        );
    }
}
