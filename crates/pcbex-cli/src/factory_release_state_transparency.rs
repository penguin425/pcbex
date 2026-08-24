//! Policy-pinned transparency receipts for authenticated factory-release state.
//!
//! The v1.485 boundary binds the exact current v1.484 state entry into an
//! RFC 6962-shaped Merkle inclusion proof under a separately trusted Ed25519
//! log key. It proves inclusion in one signed log view. It does not prove that
//! every observer received the same view, protect the selected local ledger
//! from rollback, establish trusted time, or authorize an order or payment.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory::FactoryProvider;
use crate::factory_release_adapter_monotonic_state::{
    FactoryReleaseAdapterMonotonicStateEntry, MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES,
    MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_ENTRY_BYTES,
    MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE,
    parse_factory_release_adapter_monotonic_state_entry,
};
use crate::policy_pack::{OrganizationPolicyPack, policy_pack_sha256, validate_policy_pack};
use crate::signed_factory_receipt_release_submission::FactoryReleaseAdapterStatus;
use ed25519_dalek::{Signature, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_SCOPE: &str =
    "policy-pinned-factory-release-state-transparency-receipt-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_HEAD_SCOPE: &str =
    "signed-factory-release-state-transparency-tree-head-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_VERIFICATION_SCOPE: &str =
    "verified-policy-pinned-factory-release-state-transparency-inclusion-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_SCOPE: &str =
    "factory-release-state-transparency-trust-policy-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_BYTES: u64 = 32 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_BYTES: u64 = 32 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_REPORT_BYTES: u64 = 96 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE: u64 = 100_000;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_AUDIT_PATH: usize = 64;

const LEAF_BINDING_DOMAIN: &[u8] = b"pcbex:factory-release-state-transparency-leaf:v1\0";
const MERKLE_LEAF_DOMAIN: &[u8] = b"pcbex:factory-release-state-transparency-merkle-leaf:v1\0";
const TREE_HEAD_SIGNATURE_DOMAIN: &str = "pcbex-factory-release-state-transparency-tree-head-v1";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-verification-report:v1\0";
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedFactoryReleaseTransparencyLog {
    pub(crate) log_id: String,
    pub(crate) public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyPolicy {
    pub(crate) schema_version: u32,
    pub(crate) policy_scope: String,
    pub(crate) maximum_checkpoint_age_seconds: u64,
    pub(crate) trusted_logs: Vec<TrustedFactoryReleaseTransparencyLog>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyTreeHead {
    pub(crate) schema_version: u32,
    pub(crate) tree_head_scope: String,
    pub(crate) log_id: String,
    pub(crate) tree_size: u64,
    pub(crate) root_sha256: String,
    pub(crate) observed_at_unix: u64,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyReceipt {
    pub(crate) schema_version: u32,
    pub(crate) receipt_scope: String,
    pub(crate) state_entry_sha256: String,
    pub(crate) leaf_sha256: String,
    pub(crate) leaf_index: u64,
    pub(crate) audit_path: Vec<String>,
    pub(crate) tree_head: SignedFactoryReleaseStateTransparencyTreeHead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) monotonic_state_chain_verified: bool,
    pub(crate) state_entry_identity_verified: bool,
    pub(crate) observation_identity_verified: bool,
    pub(crate) policy_pack_pin_matched: bool,
    pub(crate) transparency_policy_pin_matched: bool,
    pub(crate) transparency_log_policy_matched: bool,
    pub(crate) tree_head_signature_verified: bool,
    pub(crate) inclusion_proof_verified: bool,
    pub(crate) transparency_inclusion_verified: bool,
    pub(crate) checkpoint_fresh_at_evaluation: bool,
    pub(crate) selected_ledger_transparency_report_committed: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) endpoint_transport_authenticity_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) server_side_idempotency_enforced: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) state_entry: ExactArtifactIdentity,
    pub(crate) observation: ExactArtifactIdentity,
    pub(crate) state_sequence: u64,
    pub(crate) state_sha256: String,
    pub(crate) state_status: FactoryReleaseAdapterStatus,
    pub(crate) idempotency_key: String,
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) release_subject_sha256: String,
    pub(crate) manufacturing_package_sha256: String,
    pub(crate) policy_pack_sha256: String,
    pub(crate) transparency_policy_sha256: String,
    pub(crate) receipt_artifact: ExactArtifactIdentity,
    pub(crate) transparency_receipt: FactoryReleaseStateTransparencyReceipt,
    pub(crate) tree_head_sha256: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct LeafBinding<'a> {
    state_entry_sha256: &'a str,
    observation_sha256: &'a str,
    state_sequence: u64,
    state_sha256: &'a str,
    state_status: FactoryReleaseAdapterStatus,
    idempotency_key: &'a str,
    factory_id: &'a str,
    provider: FactoryProvider,
    release_subject_sha256: &'a str,
    manufacturing_package_sha256: &'a str,
}

#[derive(Serialize)]
struct TreeHeadSignaturePayload<'a> {
    domain: &'static str,
    tree_head_scope: &'a str,
    log_id: &'a str,
    tree_size: u64,
    root_sha256: &'a str,
    observed_at_unix: u64,
}

#[derive(Serialize)]
struct ReportBinding<'a> {
    schema_version: u32,
    verification_scope: &'a str,
    status: &'a str,
    monotonic_state_chain_verified: bool,
    state_entry_identity_verified: bool,
    observation_identity_verified: bool,
    policy_pack_pin_matched: bool,
    transparency_policy_pin_matched: bool,
    transparency_log_policy_matched: bool,
    tree_head_signature_verified: bool,
    inclusion_proof_verified: bool,
    transparency_inclusion_verified: bool,
    checkpoint_fresh_at_evaluation: bool,
    selected_ledger_transparency_report_committed: bool,
    global_non_equivocation_verified: bool,
    selected_ledger_rollback_resistance_verified: bool,
    trusted_time_verified: bool,
    endpoint_transport_authenticity_verified: bool,
    factory_legal_identity_verified: bool,
    server_side_idempotency_enforced: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    exactly_once_execution_verified: bool,
    state_entry: &'a ExactArtifactIdentity,
    observation: &'a ExactArtifactIdentity,
    state_sequence: u64,
    state_sha256: &'a str,
    state_status: FactoryReleaseAdapterStatus,
    idempotency_key: &'a str,
    factory_id: &'a str,
    provider: FactoryProvider,
    release_subject_sha256: &'a str,
    manufacturing_package_sha256: &'a str,
    policy_pack_sha256: &'a str,
    transparency_policy_sha256: &'a str,
    receipt_artifact: &'a ExactArtifactIdentity,
    transparency_receipt: &'a FactoryReleaseStateTransparencyReceipt,
    tree_head_sha256: &'a str,
    evaluated_at_unix: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_receipt(
    state_entry_source: &[u8],
    state_entry: &FactoryReleaseAdapterMonotonicStateEntry,
    observation_source: &[u8],
    complete_monotonic_chain_verified: bool,
    receipt_source: &[u8],
    policy_pack: &OrganizationPolicyPack,
    expected_policy_sha256: &str,
    transparency_policy_source: &[u8],
    expected_transparency_policy_sha256: &str,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyVerificationReport, String> {
    if !complete_monotonic_chain_verified {
        return Err(
            "factory release transparency requires a completely verified local state chain".into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err("factory release transparency evaluation time is outside its bound".into());
    }
    let parsed_entry = parse_factory_release_adapter_monotonic_state_entry(state_entry_source)?;
    if &parsed_entry != state_entry {
        return Err(
            "factory release transparency state entry differs from its exact source".into(),
        );
    }
    let state_entry_identity = exact_identity(state_entry_source);
    let observation_identity = exact_identity(observation_source);
    if observation_identity != state_entry.observation {
        return Err(
            "factory release transparency state entry observation identity is invalid".into(),
        );
    }
    validate_policy_pack(policy_pack)?;
    validate_digest(
        expected_policy_sha256,
        "expected organization policy SHA-256",
    )?;
    let actual_policy_sha256 = policy_pack_sha256(policy_pack)?;
    if actual_policy_sha256 != expected_policy_sha256 {
        return Err("factory release transparency organization policy pin does not match".into());
    }
    let transparency_policy =
        parse_factory_release_state_transparency_policy(transparency_policy_source)?;
    validate_digest(
        expected_transparency_policy_sha256,
        "expected factory release transparency policy SHA-256",
    )?;
    let actual_transparency_policy_sha256 =
        factory_release_state_transparency_policy_sha256(&transparency_policy)?;
    if actual_transparency_policy_sha256 != expected_transparency_policy_sha256 {
        return Err("factory release transparency trust-policy pin does not match".into());
    }
    validate_transparency_policy_role_separation(&transparency_policy, policy_pack)?;
    let receipt = parse_factory_release_state_transparency_receipt(receipt_source)?;
    if receipt.state_entry_sha256 != state_entry_identity.sha256 {
        return Err("factory release transparency receipt binds a different state entry".into());
    }
    let leaf_sha256 = factory_release_state_transparency_leaf_sha256(
        &state_entry_identity.sha256,
        &state_entry.observation.sha256,
        state_entry,
    )?;
    if receipt.leaf_sha256 != leaf_sha256 {
        return Err(
            "factory release transparency receipt leaf does not match the selected state".into(),
        );
    }
    let trusted_log = transparency_policy
        .trusted_logs
        .iter()
        .find(|trusted| trusted.log_id == receipt.tree_head.log_id)
        .ok_or_else(|| "factory release transparency log is not trusted by policy".to_string())?;
    if receipt.tree_head.public_key != trusted_log.public_key {
        return Err("factory release transparency tree-head key does not match policy".into());
    }
    if receipt.tree_head.observed_at_unix > evaluated_at_unix {
        return Err("factory release transparency tree head is from the future".into());
    }
    if evaluated_at_unix - receipt.tree_head.observed_at_unix
        > transparency_policy.maximum_checkpoint_age_seconds
    {
        return Err("factory release transparency tree head is stale at evaluation".into());
    }
    verify_tree_head_signature(&receipt.tree_head)?;
    verify_inclusion(&receipt)?;

    let receipt_artifact = exact_identity(receipt_source);
    let mut report = FactoryReleaseStateTransparencyVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_VERIFICATION_SCOPE.into(),
        status: "verified".into(),
        monotonic_state_chain_verified: true,
        state_entry_identity_verified: true,
        observation_identity_verified: true,
        policy_pack_pin_matched: true,
        transparency_policy_pin_matched: true,
        transparency_log_policy_matched: true,
        tree_head_signature_verified: true,
        inclusion_proof_verified: true,
        transparency_inclusion_verified: true,
        checkpoint_fresh_at_evaluation: true,
        selected_ledger_transparency_report_committed: false,
        global_non_equivocation_verified: false,
        selected_ledger_rollback_resistance_verified: false,
        trusted_time_verified: false,
        endpoint_transport_authenticity_verified: false,
        factory_legal_identity_verified: false,
        server_side_idempotency_enforced: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        state_entry: state_entry_identity,
        observation: observation_identity,
        state_sequence: state_entry.state.sequence,
        state_sha256: state_entry.state.state_sha256.clone(),
        state_status: state_entry.state.status,
        idempotency_key: state_entry.state.idempotency_key.clone(),
        factory_id: state_entry.state.factory_id.clone(),
        provider: state_entry.state.provider,
        release_subject_sha256: state_entry.state.release_subject_sha256.clone(),
        manufacturing_package_sha256: state_entry.state.manufacturing_package_sha256.clone(),
        policy_pack_sha256: actual_policy_sha256,
        transparency_policy_sha256: actual_transparency_policy_sha256,
        receipt_artifact,
        tree_head_sha256: tree_head_sha256(&receipt.tree_head)?,
        transparency_receipt: receipt,
        evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_report_shape(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn render_factory_release_state_transparency_verification_report(
    report: &FactoryReleaseStateTransparencyVerificationReport,
    state_entry_source: &[u8],
    state_entry: &FactoryReleaseAdapterMonotonicStateEntry,
    observation_source: &[u8],
    policy_pack: &OrganizationPolicyPack,
    expected_policy_sha256: &str,
    transparency_policy_source: &[u8],
    expected_transparency_policy_sha256: &str,
) -> Result<Vec<u8>, String> {
    validate_report_against_sources(
        report,
        state_entry_source,
        state_entry,
        observation_source,
        policy_pack,
        expected_policy_sha256,
        transparency_policy_source,
        expected_transparency_policy_sha256,
    )?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_REPORT_BYTES,
        "factory release state transparency verification report",
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_factory_release_state_transparency_verification_report(
    source: &[u8],
    state_entry_source: &[u8],
    state_entry: &FactoryReleaseAdapterMonotonicStateEntry,
    observation_source: &[u8],
    policy_pack: &OrganizationPolicyPack,
    expected_policy_sha256: &str,
    transparency_policy_source: &[u8],
    expected_transparency_policy_sha256: &str,
) -> Result<FactoryReleaseStateTransparencyVerificationReport, String> {
    let report: FactoryReleaseStateTransparencyVerificationReport = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_REPORT_BYTES,
        "factory release state transparency verification report",
    )?;
    validate_report_against_sources(
        &report,
        state_entry_source,
        state_entry,
        observation_source,
        policy_pack,
        expected_policy_sha256,
        transparency_policy_source,
        expected_transparency_policy_sha256,
    )?;
    Ok(report)
}

#[cfg(test)]
fn render_factory_release_state_transparency_policy(
    policy: &FactoryReleaseStateTransparencyPolicy,
) -> Result<Vec<u8>, String> {
    validate_transparency_policy(policy)?;
    render_bounded(
        policy,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_BYTES,
        "factory release state transparency policy",
    )
}

pub(crate) fn parse_factory_release_state_transparency_policy(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyPolicy, String> {
    let policy: FactoryReleaseStateTransparencyPolicy = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_BYTES,
        "factory release state transparency policy",
    )?;
    validate_transparency_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn factory_release_state_transparency_policy_sha256(
    policy: &FactoryReleaseStateTransparencyPolicy,
) -> Result<String, String> {
    validate_transparency_policy(policy)?;
    let source = serde_json::to_vec(policy)
        .map_err(|error| format!("serializing factory release transparency policy: {error}"))?;
    Ok(sha256(&source))
}

pub(crate) fn render_factory_release_state_transparency_receipt(
    receipt: &FactoryReleaseStateTransparencyReceipt,
) -> Result<Vec<u8>, String> {
    validate_receipt_shape(receipt)?;
    render_bounded(
        receipt,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_BYTES,
        "factory release state transparency receipt",
    )
}

pub(crate) fn parse_factory_release_state_transparency_receipt(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyReceipt, String> {
    let receipt: FactoryReleaseStateTransparencyReceipt = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_BYTES,
        "factory release state transparency receipt",
    )?;
    validate_receipt_shape(&receipt)?;
    Ok(receipt)
}

pub(crate) fn factory_release_state_transparency_filename(
    idempotency_key: &str,
    sequence: u64,
    log_id: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    if sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE {
        return Err("factory release transparency state sequence is outside its bound".into());
    }
    validate_slug(log_id, "factory release transparency log id")?;
    Ok(format!(
        "factory-release-state-transparency-v1-{idempotency_key}-{sequence:04}-{log_id}.json"
    ))
}

pub(crate) fn factory_release_state_transparency_leaf_sha256(
    state_entry_sha256: &str,
    observation_sha256: &str,
    state_entry: &FactoryReleaseAdapterMonotonicStateEntry,
) -> Result<String, String> {
    validate_digest(state_entry_sha256, "factory release state entry SHA-256")?;
    validate_digest(
        observation_sha256,
        "factory release state observation SHA-256",
    )?;
    if state_entry.observation.sha256 != observation_sha256 {
        return Err("factory release transparency leaf observation identity is invalid".into());
    }
    domain_hash(
        LEAF_BINDING_DOMAIN,
        &LeafBinding {
            state_entry_sha256,
            observation_sha256,
            state_sequence: state_entry.state.sequence,
            state_sha256: &state_entry.state.state_sha256,
            state_status: state_entry.state.status,
            idempotency_key: &state_entry.state.idempotency_key,
            factory_id: &state_entry.state.factory_id,
            provider: state_entry.state.provider,
            release_subject_sha256: &state_entry.state.release_subject_sha256,
            manufacturing_package_sha256: &state_entry.state.manufacturing_package_sha256,
        },
    )
}

fn validate_transparency_policy(
    policy: &FactoryReleaseStateTransparencyPolicy,
) -> Result<(), String> {
    if policy.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION
        || policy.policy_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_SCOPE
        || !(1..=604_800).contains(&policy.maximum_checkpoint_age_seconds)
        || !(1..=100).contains(&policy.trusted_logs.len())
    {
        return Err("factory release state transparency policy invariants are invalid".into());
    }
    let mut log_ids = HashSet::new();
    let mut log_keys = HashSet::new();
    for trusted in &policy.trusted_logs {
        validate_slug(&trusted.log_id, "factory release transparency log id")?;
        let public_key = decode_hex::<32>(
            &trusted.public_key,
            "factory release transparency log public key",
        )?;
        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
            format!(
                "invalid factory release transparency log public key for {:?}: {error}",
                trusted.log_id
            )
        })?;
        if verifying_key.is_weak() {
            return Err(format!(
                "factory release transparency log public key for {:?} is weak",
                trusted.log_id
            ));
        }
        if !log_ids.insert(&trusted.log_id) {
            return Err(format!(
                "duplicate factory release transparency log id {:?}",
                trusted.log_id
            ));
        }
        if !log_keys.insert(&trusted.public_key) {
            return Err("duplicate factory release transparency log public key".into());
        }
    }
    Ok(())
}

fn validate_transparency_policy_role_separation(
    transparency_policy: &FactoryReleaseStateTransparencyPolicy,
    organization_policy: &OrganizationPolicyPack,
) -> Result<(), String> {
    validate_transparency_policy(transparency_policy)?;
    validate_policy_pack(organization_policy)?;
    let mut assigned_ids = HashSet::new();
    let mut assigned_keys = HashSet::new();
    for trusted in &organization_policy.trusted_approval_keys {
        assigned_ids.insert(trusted.signer_id.as_str());
        assigned_keys.insert(trusted.public_key.as_str());
    }
    for trusted in &organization_policy.trusted_human_escalation_keys {
        assigned_ids.insert(trusted.signer_id.as_str());
        assigned_keys.insert(trusted.public_key.as_str());
    }
    if let Some(policy) = &organization_policy.fabrication_authorization_policy {
        for trusted in &policy.trusted_keys {
            assigned_ids.insert(trusted.signer_id.as_str());
            assigned_keys.insert(trusted.public_key.as_str());
        }
    }
    if let Some(policy) = &organization_policy.procurement_authorization_policy {
        for trusted in &policy.trusted_keys {
            assigned_ids.insert(trusted.signer_id.as_str());
            assigned_keys.insert(trusted.public_key.as_str());
        }
    }
    if let Some(policy) = &organization_policy.factory_receipt_attestation_policy {
        for trusted in &policy.trusted_keys {
            assigned_ids.insert(trusted.factory_id.as_str());
            assigned_keys.insert(trusted.public_key.as_str());
        }
    }
    if let Some(policy) = &organization_policy.factory_adapter_response_authentication_policy {
        for trusted in &policy.trusted_keys {
            assigned_ids.insert(trusted.key_id.as_str());
            assigned_ids.insert(trusted.factory_id.as_str());
            assigned_keys.insert(trusted.public_key.as_str());
        }
    }
    for trusted in &transparency_policy.trusted_logs {
        if assigned_ids.contains(trusted.log_id.as_str()) {
            return Err(format!(
                "factory release transparency log id {:?} holds another organization trust role",
                trusted.log_id
            ));
        }
        if assigned_keys.contains(trusted.public_key.as_str()) {
            return Err(
                "factory release transparency log key holds another organization trust role".into(),
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_report_against_sources(
    report: &FactoryReleaseStateTransparencyVerificationReport,
    state_entry_source: &[u8],
    state_entry: &FactoryReleaseAdapterMonotonicStateEntry,
    observation_source: &[u8],
    policy_pack: &OrganizationPolicyPack,
    expected_policy_sha256: &str,
    transparency_policy_source: &[u8],
    expected_transparency_policy_sha256: &str,
) -> Result<(), String> {
    validate_report_shape(report)?;
    let receipt_source =
        render_factory_release_state_transparency_receipt(&report.transparency_receipt)?;
    let expected = verify_factory_release_state_transparency_receipt(
        state_entry_source,
        state_entry,
        observation_source,
        true,
        &receipt_source,
        policy_pack,
        expected_policy_sha256,
        transparency_policy_source,
        expected_transparency_policy_sha256,
        report.evaluated_at_unix,
    )?;
    if &expected != report {
        return Err(
            "factory release state transparency report does not match its verified sources".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_report_shape(
    report: &FactoryReleaseStateTransparencyVerificationReport,
) -> Result<(), String> {
    let positive = report.monotonic_state_chain_verified
        && report.state_entry_identity_verified
        && report.observation_identity_verified
        && report.policy_pack_pin_matched
        && report.transparency_policy_pin_matched
        && report.transparency_log_policy_matched
        && report.tree_head_signature_verified
        && report.inclusion_proof_verified
        && report.transparency_inclusion_verified
        && report.checkpoint_fresh_at_evaluation;
    let nonclaims_false = !report.selected_ledger_transparency_report_committed
        && !report.global_non_equivocation_verified
        && !report.selected_ledger_rollback_resistance_verified
        && !report.trusted_time_verified
        && !report.endpoint_transport_authenticity_verified
        && !report.factory_legal_identity_verified
        && !report.server_side_idempotency_enforced
        && !report.capacity_reserved
        && !report.order_placed
        && !report.payment_performed
        && !report.exactly_once_execution_verified;
    if report.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION
        || report.verification_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_VERIFICATION_SCOPE
        || report.status != "verified"
        || !positive
        || !nonclaims_false
        || report.state_sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        || report.state_status == FactoryReleaseAdapterStatus::OutcomeUnknown
        || report.evaluated_at_unix > MAX_TIMESTAMP
    {
        return Err("factory release state transparency report invariants are invalid".into());
    }
    validate_artifact_identity(
        &report.state_entry,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_ENTRY_BYTES,
        "factory release monotonic state entry",
    )?;
    validate_artifact_identity(
        &report.observation,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES,
        "factory release monotonic observation",
    )?;
    validate_artifact_identity(
        &report.receipt_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_BYTES,
        "factory release transparency receipt",
    )?;
    for (value, label) in [
        (&report.state_sha256, "factory release state SHA-256"),
        (&report.idempotency_key, "factory release idempotency key"),
        (
            &report.release_subject_sha256,
            "factory release subject SHA-256",
        ),
        (
            &report.manufacturing_package_sha256,
            "factory release manufacturing package SHA-256",
        ),
        (&report.policy_pack_sha256, "organization policy SHA-256"),
        (
            &report.transparency_policy_sha256,
            "factory release transparency policy SHA-256",
        ),
        (&report.tree_head_sha256, "transparency tree head SHA-256"),
        (
            &report.binding_sha256,
            "transparency report binding SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_slug(&report.factory_id, "factory id")?;
    validate_receipt_shape(&report.transparency_receipt)?;
    if report.state_entry.sha256 != report.transparency_receipt.state_entry_sha256
        || report.tree_head_sha256 != tree_head_sha256(&report.transparency_receipt.tree_head)?
        || report.binding_sha256 != report_binding(report)?
    {
        return Err("factory release state transparency report binding is invalid".into());
    }
    Ok(())
}

fn validate_receipt_shape(receipt: &FactoryReleaseStateTransparencyReceipt) -> Result<(), String> {
    if receipt.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION
        || receipt.receipt_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_SCOPE
        || receipt.audit_path.len() > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_AUDIT_PATH
    {
        return Err("factory release state transparency receipt invariants are invalid".into());
    }
    validate_digest(
        &receipt.state_entry_sha256,
        "factory release transparency state entry SHA-256",
    )?;
    validate_digest(
        &receipt.leaf_sha256,
        "factory release transparency leaf SHA-256",
    )?;
    validate_tree_head_shape(&receipt.tree_head)?;
    if receipt.leaf_index >= receipt.tree_head.tree_size {
        return Err("factory release transparency leaf index is outside the tree".into());
    }
    for node in &receipt.audit_path {
        validate_digest(node, "factory release transparency audit node")?;
    }
    Ok(())
}

pub(crate) fn validate_tree_head_shape(
    head: &SignedFactoryReleaseStateTransparencyTreeHead,
) -> Result<(), String> {
    if head.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION
        || head.tree_head_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_HEAD_SCOPE
        || head.tree_size == 0
        || head.tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || head.observed_at_unix > MAX_TIMESTAMP
        || head.algorithm != "ed25519"
    {
        return Err("factory release state transparency tree-head invariants are invalid".into());
    }
    validate_slug(&head.log_id, "factory release transparency log id")?;
    validate_digest(
        &head.root_sha256,
        "factory release transparency Merkle root",
    )?;
    decode_hex::<32>(
        &head.public_key,
        "factory release transparency log public key",
    )?;
    decode_hex::<64>(
        &head.signature,
        "factory release transparency tree-head signature",
    )?;
    Ok(())
}

pub(crate) fn verify_tree_head_signature(
    head: &SignedFactoryReleaseStateTransparencyTreeHead,
) -> Result<(), String> {
    validate_tree_head_shape(head)?;
    let public_key = decode_hex::<32>(
        &head.public_key,
        "factory release transparency log public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid factory release transparency log key: {error}"))?;
    if verifying_key.is_weak() {
        return Err("factory release transparency log key is weak".into());
    }
    let signature = Signature::from_bytes(&decode_hex::<64>(
        &head.signature,
        "factory release transparency tree-head signature",
    )?);
    verifying_key
        .verify_strict(&tree_head_signature_payload(head)?, &signature)
        .map_err(|error| {
            format!("invalid factory release transparency tree-head signature: {error}")
        })
}

fn verify_inclusion(receipt: &FactoryReleaseStateTransparencyReceipt) -> Result<(), String> {
    validate_receipt_shape(receipt)?;
    let path = receipt
        .audit_path
        .iter()
        .map(|node| decode_hex::<32>(node, "factory release transparency audit node"))
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = merkle_leaf_hash(&receipt.leaf_sha256)?;
    let mut cursor = 0;
    let root = root_from_audit_path(
        leaf,
        receipt.leaf_index,
        receipt.tree_head.tree_size,
        &path,
        &mut cursor,
    )?;
    if cursor != path.len() || hex::encode(root) != receipt.tree_head.root_sha256 {
        return Err(
            "factory release transparency audit path does not reconstruct the signed root".into(),
        );
    }
    Ok(())
}

fn tree_head_signature_payload(
    head: &SignedFactoryReleaseStateTransparencyTreeHead,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&TreeHeadSignaturePayload {
        domain: TREE_HEAD_SIGNATURE_DOMAIN,
        tree_head_scope: &head.tree_head_scope,
        log_id: &head.log_id,
        tree_size: head.tree_size,
        root_sha256: &head.root_sha256,
        observed_at_unix: head.observed_at_unix,
    })
    .map_err(|error| format!("serializing factory release transparency tree head: {error}"))
}

pub(crate) fn tree_head_sha256(
    head: &SignedFactoryReleaseStateTransparencyTreeHead,
) -> Result<String, String> {
    validate_tree_head_shape(head)?;
    let source = serde_json::to_vec(head)
        .map_err(|error| format!("serializing factory release transparency tree head: {error}"))?;
    Ok(sha256(&source))
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyVerificationReport,
) -> Result<String, String> {
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &ReportBinding {
            schema_version: report.schema_version,
            verification_scope: &report.verification_scope,
            status: &report.status,
            monotonic_state_chain_verified: report.monotonic_state_chain_verified,
            state_entry_identity_verified: report.state_entry_identity_verified,
            observation_identity_verified: report.observation_identity_verified,
            policy_pack_pin_matched: report.policy_pack_pin_matched,
            transparency_policy_pin_matched: report.transparency_policy_pin_matched,
            transparency_log_policy_matched: report.transparency_log_policy_matched,
            tree_head_signature_verified: report.tree_head_signature_verified,
            inclusion_proof_verified: report.inclusion_proof_verified,
            transparency_inclusion_verified: report.transparency_inclusion_verified,
            checkpoint_fresh_at_evaluation: report.checkpoint_fresh_at_evaluation,
            selected_ledger_transparency_report_committed: report
                .selected_ledger_transparency_report_committed,
            global_non_equivocation_verified: report.global_non_equivocation_verified,
            selected_ledger_rollback_resistance_verified: report
                .selected_ledger_rollback_resistance_verified,
            trusted_time_verified: report.trusted_time_verified,
            endpoint_transport_authenticity_verified: report
                .endpoint_transport_authenticity_verified,
            factory_legal_identity_verified: report.factory_legal_identity_verified,
            server_side_idempotency_enforced: report.server_side_idempotency_enforced,
            capacity_reserved: report.capacity_reserved,
            order_placed: report.order_placed,
            payment_performed: report.payment_performed,
            exactly_once_execution_verified: report.exactly_once_execution_verified,
            state_entry: &report.state_entry,
            observation: &report.observation,
            state_sequence: report.state_sequence,
            state_sha256: &report.state_sha256,
            state_status: report.state_status,
            idempotency_key: &report.idempotency_key,
            factory_id: &report.factory_id,
            provider: report.provider,
            release_subject_sha256: &report.release_subject_sha256,
            manufacturing_package_sha256: &report.manufacturing_package_sha256,
            policy_pack_sha256: &report.policy_pack_sha256,
            transparency_policy_sha256: &report.transparency_policy_sha256,
            receipt_artifact: &report.receipt_artifact,
            transparency_receipt: &report.transparency_receipt,
            tree_head_sha256: &report.tree_head_sha256,
            evaluated_at_unix: report.evaluated_at_unix,
        },
    )
}

fn merkle_leaf_hash(leaf_sha256: &str) -> Result<[u8; 32], String> {
    let digest = decode_hex::<32>(leaf_sha256, "factory release transparency leaf SHA-256")?;
    let mut source = Vec::with_capacity(1 + MERKLE_LEAF_DOMAIN.len() + digest.len());
    source.push(0);
    source.extend_from_slice(MERKLE_LEAF_DOMAIN);
    source.extend_from_slice(&digest);
    Ok(Sha256::digest(source).into())
}

fn merkle_node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut source = Vec::with_capacity(65);
    source.push(1);
    source.extend_from_slice(&left);
    source.extend_from_slice(&right);
    Sha256::digest(source).into()
}

fn root_from_audit_path(
    leaf: [u8; 32],
    index: u64,
    size: u64,
    path: &[[u8; 32]],
    cursor: &mut usize,
) -> Result<[u8; 32], String> {
    if size == 0 || index >= size {
        return Err("factory release transparency audit position is outside the tree".into());
    }
    if size == 1 {
        return Ok(leaf);
    }
    let split = largest_power_of_two_less_than(size);
    if index < split {
        let left = root_from_audit_path(leaf, index, split, path, cursor)?;
        let right = next_audit_node(path, cursor)?;
        Ok(merkle_node_hash(left, right))
    } else {
        let right = root_from_audit_path(leaf, index - split, size - split, path, cursor)?;
        let left = next_audit_node(path, cursor)?;
        Ok(merkle_node_hash(left, right))
    }
}

fn next_audit_node(path: &[[u8; 32]], cursor: &mut usize) -> Result<[u8; 32], String> {
    let node = path
        .get(*cursor)
        .copied()
        .ok_or_else(|| "factory release transparency audit path is incomplete".to_string())?;
    *cursor += 1;
    Ok(node)
}

fn largest_power_of_two_less_than(value: u64) -> u64 {
    1_u64 << (u64::BITS - (value - 1).leading_zeros() - 1)
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> Result<String, String> {
    let source = serde_json::to_vec(value)
        .map_err(|error| format!("serializing factory release transparency binding: {error}"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
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
        sha256: sha256(source),
    }
}

fn sha256(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
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
    if value.len() != N * 2 {
        return Err(format!("{label} must contain {} hexadecimal digits", N * 2));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
}

pub(crate) fn factory_release_state_transparency_policy_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-policy-v1.json",
        "title": "pcbex factory-release state transparency trust policy",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "policy_scope", "maximum_checkpoint_age_seconds",
            "trusted_logs"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION},
            "policy_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_SCOPE},
            "maximum_checkpoint_age_seconds": {
                "type": "integer", "minimum": 1, "maximum": 604800
            },
            "trusted_logs": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["log_id", "public_key"],
                    "properties": {
                        "log_id": {
                            "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
                        },
                        "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    }
                }
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_receipt_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-receipt-v1.json",
        "title": "pcbex factory-release state transparency receipt",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "receipt_scope", "state_entry_sha256", "leaf_sha256",
            "leaf_index", "audit_path", "tree_head"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION},
            "receipt_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_SCOPE},
            "state_entry_sha256": digest.clone(),
            "leaf_sha256": digest.clone(),
            "leaf_index": {"type": "integer", "minimum": 0},
            "audit_path": {
                "type": "array", "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_AUDIT_PATH,
                "items": digest.clone()
            },
            "tree_head": tree_head_json_schema(digest)
        }
    })
}

pub(crate) fn factory_release_state_transparency_verification_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let artifact = || {
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["bytes", "sha256"],
            "properties": {
                "bytes": {"type": "integer", "minimum": 1},
                "sha256": digest.clone()
            }
        })
    };
    let positive = [
        "monotonic_state_chain_verified",
        "state_entry_identity_verified",
        "observation_identity_verified",
        "policy_pack_pin_matched",
        "transparency_policy_pin_matched",
        "transparency_log_policy_matched",
        "tree_head_signature_verified",
        "inclusion_proof_verified",
        "transparency_inclusion_verified",
        "checkpoint_fresh_at_evaluation",
    ];
    let negative = [
        "selected_ledger_transparency_report_committed",
        "global_non_equivocation_verified",
        "selected_ledger_rollback_resistance_verified",
        "trusted_time_verified",
        "endpoint_transport_authenticity_verified",
        "factory_legal_identity_verified",
        "server_side_idempotency_enforced",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "exactly_once_execution_verified",
    ];
    let mut properties = serde_json::Map::new();
    properties.insert(
        "schema_version".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION}),
    );
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_VERIFICATION_SCOPE}),
    );
    properties.insert("status".into(), json!({"const": "verified"}));
    for name in positive {
        properties.insert(name.into(), json!({"const": true}));
    }
    for name in negative {
        properties.insert(name.into(), json!({"const": false}));
    }
    properties.insert("state_entry".into(), artifact());
    properties.insert("observation".into(), artifact());
    properties.insert(
        "state_sequence".into(),
        json!({
            "type": "integer", "minimum": 0,
            "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        }),
    );
    properties.insert("state_sha256".into(), digest.clone());
    properties.insert(
        "state_status".into(),
        json!({
            "enum": ["adapter_pending", "adapter_accepted", "adapter_rejected"]
        }),
    );
    properties.insert("idempotency_key".into(), digest.clone());
    properties.insert(
        "factory_id".into(),
        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}),
    );
    properties.insert(
        "provider".into(),
        json!({"enum": ["jlcpcb", "pcbway", "generic"]}),
    );
    properties.insert("release_subject_sha256".into(), digest.clone());
    properties.insert("manufacturing_package_sha256".into(), digest.clone());
    properties.insert("policy_pack_sha256".into(), digest.clone());
    properties.insert("transparency_policy_sha256".into(), digest.clone());
    properties.insert("receipt_artifact".into(), artifact());
    properties.insert(
        "transparency_receipt".into(),
        factory_release_state_transparency_receipt_json_schema(),
    );
    properties.insert("tree_head_sha256".into(), digest.clone());
    properties.insert(
        "evaluated_at_unix".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}),
    );
    properties.insert("binding_sha256".into(), digest);

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
                "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-verification-report-v1.json"
            ),
        ),
        (
            "title".into(),
            json!("pcbex factory-release state transparency verification report"),
        ),
        ("type".into(), json!("object")),
        ("additionalProperties".into(), json!(false)),
        ("required".into(), Value::Array(required)),
        ("properties".into(), Value::Object(properties)),
    ]))
}

fn tree_head_json_schema(digest: Value) -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "tree_head_scope", "log_id", "tree_size",
            "root_sha256", "observed_at_unix", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION},
            "tree_head_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_HEAD_SCOPE},
            "log_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "tree_size": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
            },
            "root_sha256": digest,
            "observed_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_release_adapter_monotonic_state::{
        build_factory_release_adapter_monotonic_state,
        build_factory_release_adapter_monotonic_state_entry,
        render_factory_release_adapter_monotonic_state_entry,
    };
    use crate::policy_pack::parse_policy_pack;
    use crate::signed_factory_receipt_release_submission::{
        FactoryReleaseAdapterStatus, test_signed_factory_release_submission_intent,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const LOG_SECRET: [u8; 32] = [85; 32];

    fn fixture() -> (
        Vec<u8>,
        FactoryReleaseAdapterMonotonicStateEntry,
        Vec<u8>,
        OrganizationPolicyPack,
        String,
        Vec<u8>,
        String,
    ) {
        let intent = test_signed_factory_release_submission_intent(
            "http://127.0.0.1:14850/release",
            b"manufacturing-package-1485",
        );
        let state = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1485",
        )
        .unwrap();
        let observation_source = b"{\n  \"authenticated\": true\n}\n".to_vec();
        let entry = build_factory_release_adapter_monotonic_state_entry(
            &state,
            &format!(
                "monotonic-factory-release-submission-v1-{}.json",
                state.idempotency_key
            ),
            &observation_source,
        )
        .unwrap();
        let entry_source = render_factory_release_adapter_monotonic_state_entry(&entry).unwrap();
        let policy =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        validate_policy_pack(&policy).unwrap();
        let policy_sha256 = policy_pack_sha256(&policy).unwrap();
        let transparency_policy = FactoryReleaseStateTransparencyPolicy {
            schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_POLICY_SCOPE.into(),
            maximum_checkpoint_age_seconds: 300,
            trusted_logs: vec![TrustedFactoryReleaseTransparencyLog {
                log_id: "factory-release-log".into(),
                public_key: hex::encode(
                    SigningKey::from_bytes(&LOG_SECRET)
                        .verifying_key()
                        .to_bytes(),
                ),
            }],
        };
        let transparency_policy_source =
            render_factory_release_state_transparency_policy(&transparency_policy).unwrap();
        let transparency_policy_sha256 =
            factory_release_state_transparency_policy_sha256(&transparency_policy).unwrap();
        (
            entry_source,
            entry,
            observation_source,
            policy,
            policy_sha256,
            transparency_policy_source,
            transparency_policy_sha256,
        )
    }

    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        merkle_node_hash(merkle_root(&leaves[..split]), merkle_root(&leaves[split..]))
    }

    fn audit_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
        if leaves.len() == 1 {
            return Vec::new();
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        if index < split {
            let mut path = audit_path(&leaves[..split], index);
            path.push(merkle_root(&leaves[split..]));
            path
        } else {
            let mut path = audit_path(&leaves[split..], index - split);
            path.push(merkle_root(&leaves[..split]));
            path
        }
    }

    fn receipt(
        entry_source: &[u8],
        entry: &FactoryReleaseAdapterMonotonicStateEntry,
        extra_leaf_sha256: &[String],
        observed_at_unix: u64,
    ) -> FactoryReleaseStateTransparencyReceipt {
        let state_entry_sha256 = sha256(entry_source);
        let leaf_sha256 = factory_release_state_transparency_leaf_sha256(
            &state_entry_sha256,
            &entry.observation.sha256,
            entry,
        )
        .unwrap();
        let mut leaf_digests = extra_leaf_sha256.to_vec();
        let leaf_index = leaf_digests.len() as u64;
        leaf_digests.push(leaf_sha256.clone());
        let leaves = leaf_digests
            .iter()
            .map(|digest| merkle_leaf_hash(digest).unwrap())
            .collect::<Vec<_>>();
        let root_sha256 = hex::encode(merkle_root(&leaves));
        let mut head = SignedFactoryReleaseStateTransparencyTreeHead {
            schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION,
            tree_head_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_HEAD_SCOPE.into(),
            log_id: "factory-release-log".into(),
            tree_size: leaves.len() as u64,
            root_sha256,
            observed_at_unix,
            algorithm: "ed25519".into(),
            public_key: hex::encode(
                SigningKey::from_bytes(&LOG_SECRET)
                    .verifying_key()
                    .to_bytes(),
            ),
            signature: String::new(),
        };
        head.signature = hex::encode(
            SigningKey::from_bytes(&LOG_SECRET)
                .sign(&tree_head_signature_payload(&head).unwrap())
                .to_bytes(),
        );
        FactoryReleaseStateTransparencyReceipt {
            schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_SCHEMA_VERSION,
            receipt_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_SCOPE.into(),
            state_entry_sha256,
            leaf_sha256,
            leaf_index,
            audit_path: audit_path(&leaves, leaf_index as usize)
                .into_iter()
                .map(hex::encode)
                .collect(),
            tree_head: head,
        }
    }

    #[test]
    fn verifies_odd_tree_receipt_and_round_trips_bound_report() {
        let (
            entry_source,
            entry,
            observation_source,
            policy,
            policy_sha256,
            transparency_policy_source,
            transparency_policy_sha256,
        ) = fixture();
        let extra = (1_u8..=4)
            .map(|value| hex::encode([value; 32]))
            .collect::<Vec<_>>();
        let receipt = receipt(&entry_source, &entry, &extra, 1_700_000_000);
        let receipt_source = render_factory_release_state_transparency_receipt(&receipt).unwrap();
        let report = verify_factory_release_state_transparency_receipt(
            &entry_source,
            &entry,
            &observation_source,
            true,
            &receipt_source,
            &policy,
            &policy_sha256,
            &transparency_policy_source,
            &transparency_policy_sha256,
            1_700_000_100,
        )
        .unwrap();
        assert!(report.transparency_inclusion_verified);
        assert_eq!(report.state_sequence, 0);
        assert_eq!(report.transparency_receipt.leaf_index, 4);
        assert!(!report.global_non_equivocation_verified);
        assert!(!report.trusted_time_verified);
        let rendered = render_factory_release_state_transparency_verification_report(
            &report,
            &entry_source,
            &entry,
            &observation_source,
            &policy,
            &policy_sha256,
            &transparency_policy_source,
            &transparency_policy_sha256,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_verification_report(
                &rendered,
                &entry_source,
                &entry,
                &observation_source,
                &policy,
                &policy_sha256,
                &transparency_policy_source,
                &transparency_policy_sha256,
            )
            .unwrap(),
            report
        );
    }

    #[test]
    fn rejects_state_leaf_path_root_signature_key_policy_and_time_substitution() {
        let (
            entry_source,
            entry,
            observation_source,
            policy,
            policy_sha256,
            transparency_policy_source,
            transparency_policy_sha256,
        ) = fixture();
        let valid = receipt(&entry_source, &entry, &["11".repeat(32)], 1_700_000_000);
        let verify = |candidate: &FactoryReleaseStateTransparencyReceipt, evaluated_at_unix| {
            let source = render_factory_release_state_transparency_receipt(candidate).unwrap();
            verify_factory_release_state_transparency_receipt(
                &entry_source,
                &entry,
                &observation_source,
                true,
                &source,
                &policy,
                &policy_sha256,
                &transparency_policy_source,
                &transparency_policy_sha256,
                evaluated_at_unix,
            )
        };

        let mut changed = valid.clone();
        changed.state_entry_sha256 = "22".repeat(32);
        assert!(verify(&changed, 1_700_000_100).is_err());
        let mut changed = valid.clone();
        changed.leaf_sha256 = "33".repeat(32);
        assert!(verify(&changed, 1_700_000_100).is_err());
        let mut changed = valid.clone();
        changed.audit_path[0] = "44".repeat(32);
        assert!(verify(&changed, 1_700_000_100).is_err());
        let mut changed = valid.clone();
        changed.tree_head.root_sha256 = "55".repeat(32);
        assert!(verify(&changed, 1_700_000_100).is_err());
        let mut changed = valid.clone();
        changed.tree_head.signature = "66".repeat(64);
        assert!(verify(&changed, 1_700_000_100).is_err());
        let mut changed = valid.clone();
        changed.tree_head.public_key =
            hex::encode(SigningKey::from_bytes(&[86; 32]).verifying_key().to_bytes());
        assert!(verify(&changed, 1_700_000_100).is_err());
        assert!(verify(&valid, 1_699_999_999).is_err());
        assert!(verify(&valid, 1_700_000_301).is_err());
        assert!(
            verify_factory_release_state_transparency_receipt(
                &entry_source,
                &entry,
                &observation_source,
                false,
                &render_factory_release_state_transparency_receipt(&valid).unwrap(),
                &policy,
                &policy_sha256,
                &transparency_policy_source,
                &transparency_policy_sha256,
                1_700_000_100,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_noncanonical_duplicate_and_oversized_receipts() {
        let (entry_source, entry, _, _, _, _, _) = fixture();
        let receipt = receipt(&entry_source, &entry, &[], 1_700_000_000);
        let canonical = render_factory_release_state_transparency_receipt(&receipt).unwrap();
        assert!(parse_factory_release_state_transparency_receipt(&canonical).is_ok());
        let compact = serde_json::to_vec(&receipt).unwrap();
        assert!(parse_factory_release_state_transparency_receipt(&compact).is_err());
        let duplicate = canonical
            .iter()
            .position(|byte| *byte == b'{')
            .map(|offset| {
                let mut value = canonical.clone();
                value.splice(
                    offset + 1..offset + 1,
                    b"\n  \"schema_version\": 1,".iter().copied(),
                );
                value
            })
            .unwrap();
        assert!(parse_factory_release_state_transparency_receipt(&duplicate).is_err());
        assert!(
            parse_factory_release_state_transparency_receipt(&vec![
                b' ';
                MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_RECEIPT_BYTES
                    as usize
                    + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_unpinned_noncanonical_and_role_overlapping_transparency_policies() {
        let (
            entry_source,
            entry,
            observation_source,
            organization_policy,
            organization_policy_sha256,
            transparency_policy_source,
            transparency_policy_sha256,
        ) = fixture();
        let receipt = receipt(&entry_source, &entry, &[], 1_700_000_000);
        let receipt_source = render_factory_release_state_transparency_receipt(&receipt).unwrap();

        assert!(
            verify_factory_release_state_transparency_receipt(
                &entry_source,
                &entry,
                &observation_source,
                true,
                &receipt_source,
                &organization_policy,
                &organization_policy_sha256,
                &transparency_policy_source,
                &"00".repeat(32),
                1_700_000_100,
            )
            .is_err()
        );
        let compact: FactoryReleaseStateTransparencyPolicy =
            serde_json::from_slice(&transparency_policy_source).unwrap();
        assert!(
            parse_factory_release_state_transparency_policy(&serde_json::to_vec(&compact).unwrap())
                .is_err()
        );

        let mut overlapping = compact;
        overlapping.trusted_logs[0].public_key = organization_policy.trusted_approval_keys[0]
            .public_key
            .clone();
        let overlapping_source =
            render_factory_release_state_transparency_policy(&overlapping).unwrap();
        let overlapping_sha256 =
            factory_release_state_transparency_policy_sha256(&overlapping).unwrap();
        assert!(
            verify_factory_release_state_transparency_receipt(
                &entry_source,
                &entry,
                &observation_source,
                true,
                &receipt_source,
                &organization_policy,
                &organization_policy_sha256,
                &overlapping_source,
                &overlapping_sha256,
                1_700_000_100,
            )
            .is_err()
        );
        assert_eq!(
            factory_release_state_transparency_policy_sha256(
                &parse_factory_release_state_transparency_policy(&transparency_policy_source)
                    .unwrap()
            )
            .unwrap(),
            transparency_policy_sha256
        );
    }

    #[test]
    fn schemas_are_recursively_closed_and_filename_is_bounded() {
        let policy = factory_release_state_transparency_policy_json_schema();
        assert_eq!(policy["additionalProperties"], false);
        assert_eq!(
            policy["properties"]["trusted_logs"]["items"]["additionalProperties"],
            false
        );
        let receipt = factory_release_state_transparency_receipt_json_schema();
        assert_eq!(receipt["additionalProperties"], false);
        assert_eq!(
            receipt["properties"]["tree_head"]["additionalProperties"],
            false
        );
        let report = factory_release_state_transparency_verification_report_json_schema();
        assert_eq!(report["additionalProperties"], false);
        assert_eq!(
            report["properties"]["transparency_receipt"]["additionalProperties"],
            false
        );
        assert_eq!(
            factory_release_state_transparency_filename(&"ab".repeat(32), 12, "factory-log")
                .unwrap(),
            format!(
                "factory-release-state-transparency-v1-{}-0012-factory-log.json",
                "ab".repeat(32)
            )
        );
        assert!(
            factory_release_state_transparency_filename(
                &"ab".repeat(32),
                MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE + 1,
                "factory-log"
            )
            .is_err()
        );
    }
}
