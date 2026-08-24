//! External signed-log anchoring for factory-release transparency witness quorums.
//!
//! The v1.488 boundary binds one exact, fully verified v1.487 witness-quorum
//! report into a separately policy-pinned Ed25519 Merkle view. It proves
//! inclusion in that selected external view. It does not prove append-only
//! consistency for the external log, global non-equivocation, rollback
//! resistance for the selected local ledger, trusted time, independent legal
//! operation, transport identity, ordering, or payment.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_adapter_monotonic_state::MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE;
use crate::factory_release_state_transparency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE;
use crate::factory_release_state_transparency_consistency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION;
use crate::factory_release_state_transparency_witness_quorum::{
    FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_REPORT_BYTES,
    factory_release_state_transparency_witness_quorum_report_json_schema,
    parse_factory_release_state_transparency_witness_quorum_report,
    render_factory_release_state_transparency_witness_quorum_report,
};
use ed25519_dalek::{Signature, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_SCOPE: &str =
    "factory-release-state-transparency-external-anchor-policy-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_SCOPE: &str =
    "factory-release-state-transparency-witness-quorum-external-anchor-proof-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE: &str =
    "signed-factory-release-state-transparency-external-anchor-tree-head-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_VERIFICATION_SCOPE: &str =
    "verified-factory-release-state-transparency-witness-quorum-external-anchor-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_REPORT_BYTES: u64 =
    4 * 1024 * 1024;

const MAX_EXTERNAL_ANCHOR_LOGS: usize = 100;
const MAX_EXTERNAL_ANCHOR_AUDIT_PATH: usize = 64;
const MAX_EXTERNAL_ANCHOR_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const LEAF_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-anchor-leaf:v1\0";
const MERKLE_LEAF_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-anchor-merkle-leaf:v1\0";
const TREE_HEAD_SIGNATURE_DOMAIN: &str =
    "pcbex-factory-release-state-transparency-external-anchor-tree-head-v1";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-anchor-report:v1\0";
const FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-anchor-filename:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedFactoryReleaseTransparencyExternalLog {
    pub(crate) log_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalAnchorPolicy {
    pub(crate) schema_version: u32,
    pub(crate) policy_scope: String,
    pub(crate) policy_id: String,
    pub(crate) maximum_checkpoint_age_seconds: u64,
    pub(crate) trusted_logs: Vec<TrustedFactoryReleaseTransparencyExternalLog>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseTransparencyExternalTreeHead {
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
pub(crate) struct FactoryReleaseStateTransparencyExternalAnchorProof {
    pub(crate) schema_version: u32,
    pub(crate) proof_scope: String,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) witness_quorum_report_sha256: String,
    pub(crate) leaf_sha256: String,
    pub(crate) leaf_index: u64,
    pub(crate) audit_path: Vec<String>,
    pub(crate) tree_head: SignedFactoryReleaseTransparencyExternalTreeHead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalAnchorVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) monotonic_state_chain_verified: bool,
    pub(crate) current_checkpoint_inclusion_verified: bool,
    pub(crate) complete_consistency_chain_verified: bool,
    pub(crate) selected_log_append_only_consistency_verified: bool,
    pub(crate) witness_quorum_verified: bool,
    pub(crate) witness_quorum_report_identity_verified: bool,
    pub(crate) external_anchor_policy_pin_matched: bool,
    pub(crate) external_anchor_log_policy_matched: bool,
    pub(crate) external_anchor_log_role_separation_verified: bool,
    pub(crate) external_tree_head_signature_verified: bool,
    pub(crate) external_inclusion_proof_verified: bool,
    pub(crate) external_anchor_verified: bool,
    pub(crate) external_checkpoint_fresh_at_evaluation: bool,
    pub(crate) selected_ledger_external_anchor_report_committed: bool,
    pub(crate) external_log_append_only_consistency_verified: bool,
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
    pub(crate) checkpoint_generation: u64,
    pub(crate) current_state_sequence: u64,
    pub(crate) current_tree_head_sha256: String,
    pub(crate) witness_policy_sha256: String,
    pub(crate) witness_quorum_report_artifact: ExactArtifactIdentity,
    pub(crate) witness_quorum_report:
        FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
    pub(crate) external_anchor_policy_artifact: ExactArtifactIdentity,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) external_anchor_policy: FactoryReleaseStateTransparencyExternalAnchorPolicy,
    pub(crate) anchor_proof_artifact: ExactArtifactIdentity,
    pub(crate) anchor_proof: FactoryReleaseStateTransparencyExternalAnchorProof,
    pub(crate) external_log_id: String,
    pub(crate) external_leaf_sha256: String,
    pub(crate) external_tree_head_sha256: String,
    pub(crate) external_tree_size: u64,
    pub(crate) external_root_sha256: String,
    pub(crate) external_tree_head_observed_at_unix: u64,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct ExternalAnchorLeafBinding<'a> {
    schema_version: u32,
    witness_quorum_report_sha256: &'a str,
    witness_quorum_binding_sha256: &'a str,
    idempotency_key: &'a str,
    source_log_id: &'a str,
    checkpoint_generation: u64,
    current_state_sequence: u64,
    current_tree_head_sha256: &'a str,
    witness_policy_sha256: &'a str,
    external_anchor_policy_sha256: &'a str,
    external_log_id: &'a str,
}

#[derive(Serialize)]
struct ExternalTreeHeadSignaturePayload<'a> {
    domain: &'static str,
    schema_version: u32,
    tree_head_scope: &'a str,
    log_id: &'a str,
    tree_size: u64,
    root_sha256: &'a str,
    observed_at_unix: u64,
    algorithm: &'a str,
    public_key: &'a str,
}

#[derive(Serialize)]
struct FilenameContext<'a> {
    source_log_id: &'a str,
    witness_policy_sha256: &'a str,
    external_log_id: &'a str,
    external_anchor_policy_sha256: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_external_anchor(
    witness_quorum_report_source: &[u8],
    external_anchor_policy_source: &[u8],
    expected_external_anchor_policy_sha256: &str,
    expected_external_log_id: &str,
    anchor_proof_source: &[u8],
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyExternalAnchorVerificationReport, String> {
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external-anchor evaluation time is outside its bound"
                .into(),
        );
    }
    validate_slug(
        expected_external_log_id,
        "expected factory release transparency external log id",
    )?;
    validate_digest(
        expected_external_anchor_policy_sha256,
        "expected factory release transparency external-anchor policy SHA-256",
    )?;

    let witness_quorum_report = parse_factory_release_state_transparency_witness_quorum_report(
        witness_quorum_report_source,
    )?;
    let witness_quorum_report_artifact = exact_identity(witness_quorum_report_source);
    let external_anchor_policy = parse_factory_release_state_transparency_external_anchor_policy(
        external_anchor_policy_source,
    )?;
    let actual_external_anchor_policy_sha256 =
        factory_release_state_transparency_external_anchor_policy_sha256(&external_anchor_policy)?;
    if actual_external_anchor_policy_sha256 != expected_external_anchor_policy_sha256 {
        return Err(
            "factory release transparency external-anchor policy pin does not match".into(),
        );
    }
    let trusted_log = external_anchor_policy
        .trusted_logs
        .iter()
        .find(|trusted| trusted.log_id == expected_external_log_id)
        .ok_or_else(|| {
            "factory release transparency external log is not trusted by policy".to_string()
        })?;
    validate_external_anchor_policy_role_separation(
        &external_anchor_policy,
        &witness_quorum_report,
    )?;

    let anchor_proof =
        parse_factory_release_state_transparency_external_anchor_proof(anchor_proof_source)?;
    let anchor_proof_artifact = exact_identity(anchor_proof_source);
    let head = &anchor_proof.tree_head;
    if head.log_id != expected_external_log_id
        || head.algorithm != trusted_log.algorithm
        || head.public_key != trusted_log.public_key
    {
        return Err(
            "factory release transparency external tree head does not match the selected policy log"
                .into(),
        );
    }

    // Authenticate the selected external view before interpreting any claimed
    // inclusion relationship within that view.
    verify_external_tree_head_signature(head)?;

    if anchor_proof.external_anchor_policy_sha256 != actual_external_anchor_policy_sha256 {
        return Err(
            "factory release transparency external-anchor proof binds a different policy".into(),
        );
    }
    if anchor_proof.witness_quorum_report_sha256 != witness_quorum_report_artifact.sha256 {
        return Err(
            "factory release transparency external-anchor proof binds a different witness report"
                .into(),
        );
    }
    let leaf_sha256 = factory_release_state_transparency_external_anchor_leaf_sha256(
        &witness_quorum_report,
        &witness_quorum_report_artifact.sha256,
        &actual_external_anchor_policy_sha256,
        expected_external_log_id,
    )?;
    if anchor_proof.leaf_sha256 != leaf_sha256 {
        return Err(
            "factory release transparency external-anchor proof binds a different leaf".into(),
        );
    }
    verify_external_inclusion(&anchor_proof)?;

    if head.observed_at_unix < witness_quorum_report.evaluated_at_unix {
        return Err(
            "factory release transparency external tree head predates its witness report".into(),
        );
    }
    if head.observed_at_unix > evaluated_at_unix {
        return Err(
            "factory release transparency external tree head is not valid yet at evaluation".into(),
        );
    }
    if evaluated_at_unix - head.observed_at_unix
        > external_anchor_policy.maximum_checkpoint_age_seconds
    {
        return Err(
            "factory release transparency external tree head is stale at evaluation".into(),
        );
    }

    let external_anchor_policy_artifact = exact_identity(external_anchor_policy_source);
    let external_log_id = head.log_id.clone();
    let external_tree_head_sha256 = external_tree_head_sha256(head)?;
    let external_tree_size = head.tree_size;
    let external_root_sha256 = head.root_sha256.clone();
    let external_tree_head_observed_at_unix = head.observed_at_unix;
    let mut report = FactoryReleaseStateTransparencyExternalAnchorVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_VERIFICATION_SCOPE
            .into(),
        status: "verified".into(),
        monotonic_state_chain_verified: true,
        current_checkpoint_inclusion_verified: true,
        complete_consistency_chain_verified: true,
        selected_log_append_only_consistency_verified: true,
        witness_quorum_verified: true,
        witness_quorum_report_identity_verified: true,
        external_anchor_policy_pin_matched: true,
        external_anchor_log_policy_matched: true,
        external_anchor_log_role_separation_verified: true,
        external_tree_head_signature_verified: true,
        external_inclusion_proof_verified: true,
        external_anchor_verified: true,
        external_checkpoint_fresh_at_evaluation: true,
        selected_ledger_external_anchor_report_committed: false,
        external_log_append_only_consistency_verified: false,
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
        idempotency_key: witness_quorum_report.idempotency_key.clone(),
        source_log_id: witness_quorum_report.log_id.clone(),
        checkpoint_generation: witness_quorum_report.checkpoint_generation,
        current_state_sequence: witness_quorum_report.current_state_sequence,
        current_tree_head_sha256: witness_quorum_report.current_tree_head_sha256.clone(),
        witness_policy_sha256: witness_quorum_report.witness_policy_sha256.clone(),
        witness_quorum_report_artifact,
        witness_quorum_report,
        external_anchor_policy_artifact,
        external_anchor_policy_sha256: actual_external_anchor_policy_sha256,
        external_anchor_policy,
        anchor_proof_artifact,
        anchor_proof,
        external_log_id,
        external_leaf_sha256: leaf_sha256,
        external_tree_head_sha256,
        external_tree_size,
        external_root_sha256,
        external_tree_head_observed_at_unix,
        evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_external_anchor_report_shape(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_anchor_policy(
    policy: &FactoryReleaseStateTransparencyExternalAnchorPolicy,
) -> Result<Vec<u8>, String> {
    validate_external_anchor_policy(policy)?;
    render_bounded(
        policy,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
        "factory release state transparency external-anchor policy",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_anchor_policy(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalAnchorPolicy, String> {
    let policy = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
        "factory release state transparency external-anchor policy",
    )?;
    validate_external_anchor_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn factory_release_state_transparency_external_anchor_policy_sha256(
    policy: &FactoryReleaseStateTransparencyExternalAnchorPolicy,
) -> Result<String, String> {
    validate_external_anchor_policy(policy)?;
    let source = serde_json::to_vec(policy).map_err(|error| {
        format!("serializing factory release transparency external-anchor policy: {error}")
    })?;
    Ok(hex::encode(Sha256::digest(source)))
}

pub(crate) fn render_factory_release_state_transparency_external_anchor_proof(
    proof: &FactoryReleaseStateTransparencyExternalAnchorProof,
) -> Result<Vec<u8>, String> {
    validate_external_anchor_proof_shape(proof)?;
    render_bounded(
        proof,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_BYTES,
        "factory release state transparency external-anchor proof",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_anchor_proof(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalAnchorProof, String> {
    let proof = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_BYTES,
        "factory release state transparency external-anchor proof",
    )?;
    validate_external_anchor_proof_shape(&proof)?;
    Ok(proof)
}

pub(crate) fn render_factory_release_state_transparency_external_anchor_report(
    report: &FactoryReleaseStateTransparencyExternalAnchorVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_external_anchor_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_REPORT_BYTES,
        "factory release state transparency external-anchor report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_anchor_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalAnchorVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_REPORT_BYTES,
        "factory release state transparency external-anchor report",
    )?;
    validate_external_anchor_report_self_contained(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn factory_release_state_transparency_external_anchor_filename(
    idempotency_key: &str,
    source_log_id: &str,
    checkpoint_generation: u64,
    witness_policy_sha256: &str,
    external_log_id: &str,
    external_anchor_policy_sha256: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_slug(source_log_id, "factory release transparency source log id")?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION)
        .contains(&checkpoint_generation)
    {
        return Err(
            "factory release transparency external-anchor checkpoint generation is outside its bound"
                .into(),
        );
    }
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
    let context_sha256 = domain_hash(
        FILENAME_CONTEXT_DOMAIN,
        &FilenameContext {
            source_log_id,
            witness_policy_sha256,
            external_log_id,
            external_anchor_policy_sha256,
        },
        "factory release transparency external-anchor filename",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-anchor-v1-{idempotency_key}-{checkpoint_generation:04}-{context_sha256}.json"
    ))
}

pub(crate) fn factory_release_state_transparency_external_anchor_leaf_sha256(
    witness_report: &FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
    witness_quorum_report_sha256: &str,
    external_anchor_policy_sha256: &str,
    external_log_id: &str,
) -> Result<String, String> {
    validate_digest(
        witness_quorum_report_sha256,
        "factory release transparency witness quorum report SHA-256",
    )?;
    validate_digest(
        external_anchor_policy_sha256,
        "factory release transparency external-anchor policy SHA-256",
    )?;
    validate_slug(
        external_log_id,
        "factory release transparency external log id",
    )?;
    validate_digest(
        &witness_report.binding_sha256,
        "factory release transparency witness quorum binding SHA-256",
    )?;
    domain_hash(
        LEAF_BINDING_DOMAIN,
        &ExternalAnchorLeafBinding {
            schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION,
            witness_quorum_report_sha256,
            witness_quorum_binding_sha256: &witness_report.binding_sha256,
            idempotency_key: &witness_report.idempotency_key,
            source_log_id: &witness_report.log_id,
            checkpoint_generation: witness_report.checkpoint_generation,
            current_state_sequence: witness_report.current_state_sequence,
            current_tree_head_sha256: &witness_report.current_tree_head_sha256,
            witness_policy_sha256: &witness_report.witness_policy_sha256,
            external_anchor_policy_sha256,
            external_log_id,
        },
        "factory release transparency external-anchor leaf",
    )
}

pub(crate) fn external_tree_head_sha256(
    head: &SignedFactoryReleaseTransparencyExternalTreeHead,
) -> Result<String, String> {
    validate_external_tree_head_shape(head)?;
    let source = serde_json::to_vec(head).map_err(|error| {
        format!("serializing factory release transparency external tree head: {error}")
    })?;
    Ok(hex::encode(Sha256::digest(source)))
}

fn validate_external_anchor_policy(
    policy: &FactoryReleaseStateTransparencyExternalAnchorPolicy,
) -> Result<(), String> {
    if policy.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION
        || policy.policy_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_SCOPE
        || !(1..=MAX_EXTERNAL_ANCHOR_AGE_SECONDS).contains(&policy.maximum_checkpoint_age_seconds)
        || !(1..=MAX_EXTERNAL_ANCHOR_LOGS).contains(&policy.trusted_logs.len())
    {
        return Err(
            "factory release state transparency external-anchor policy invariants are invalid"
                .into(),
        );
    }
    validate_slug(
        &policy.policy_id,
        "factory release transparency external-anchor policy id",
    )?;
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    let mut previous: Option<&str> = None;
    for trusted in &policy.trusted_logs {
        validate_slug(
            &trusted.log_id,
            "factory release transparency external log id",
        )?;
        if trusted.algorithm != "ed25519" {
            return Err(
                "factory release transparency external log algorithm is unsupported".into(),
            );
        }
        let public_key = decode_hex::<32>(
            &trusted.public_key,
            "factory release transparency external log public key",
        )?;
        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|error| {
            format!("invalid factory release transparency external log public key: {error}")
        })?;
        if verifying_key.is_weak() {
            return Err("factory release transparency external log public key is weak".into());
        }
        if previous.is_some_and(|previous| previous >= trusted.log_id.as_str()) {
            return Err(
                "factory release transparency external logs are not canonically ordered".into(),
            );
        }
        previous = Some(&trusted.log_id);
        if !ids.insert(&trusted.log_id) {
            return Err(
                "factory release transparency external-anchor policy requires distinct log identities"
                    .into(),
            );
        }
        if !keys.insert(&trusted.public_key) {
            return Err(
                "factory release transparency external-anchor policy requires distinct log keys"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_external_anchor_policy_role_separation(
    policy: &FactoryReleaseStateTransparencyExternalAnchorPolicy,
    witness_report: &FactoryReleaseStateTransparencyWitnessQuorumVerificationReport,
) -> Result<(), String> {
    validate_external_anchor_policy(policy)?;
    let inner_head = &witness_report
        .consistency_report
        .current_transparency_report
        .transparency_receipt
        .tree_head;
    let mut assigned_ids = HashSet::new();
    let mut assigned_keys = HashSet::new();
    assigned_ids.insert(witness_report.log_id.as_str());
    assigned_keys.insert(inner_head.public_key.as_str());
    for member in &witness_report.members {
        assigned_ids.insert(member.organization_id.as_str());
        assigned_ids.insert(member.witness_id.as_str());
        assigned_keys.insert(member.witness_public_key.as_str());
    }
    for trusted in &policy.trusted_logs {
        if assigned_ids.contains(trusted.log_id.as_str()) {
            return Err(
                "factory release transparency external log identity is assigned to an inner log or witness role"
                    .into(),
            );
        }
        if assigned_keys.contains(trusted.public_key.as_str()) {
            return Err(
                "factory release transparency external log key is assigned to an inner log or witness role"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_external_tree_head_shape(
    head: &SignedFactoryReleaseTransparencyExternalTreeHead,
) -> Result<(), String> {
    if head.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION
        || head.tree_head_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE
        || head.tree_size == 0
        || head.tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || head.observed_at_unix > MAX_TIMESTAMP
        || head.algorithm != "ed25519"
    {
        return Err(
            "factory release state transparency external tree-head invariants are invalid".into(),
        );
    }
    validate_slug(&head.log_id, "factory release transparency external log id")?;
    validate_digest(
        &head.root_sha256,
        "factory release transparency external Merkle root",
    )?;
    decode_hex::<32>(
        &head.public_key,
        "factory release transparency external log public key",
    )?;
    decode_hex::<64>(
        &head.signature,
        "factory release transparency external tree-head signature",
    )?;
    Ok(())
}

fn validate_external_anchor_proof_shape(
    proof: &FactoryReleaseStateTransparencyExternalAnchorProof,
) -> Result<(), String> {
    if proof.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION
        || proof.proof_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_SCOPE
        || proof.audit_path.len() > MAX_EXTERNAL_ANCHOR_AUDIT_PATH
    {
        return Err(
            "factory release state transparency external-anchor proof invariants are invalid"
                .into(),
        );
    }
    for (value, label) in [
        (
            &proof.external_anchor_policy_sha256,
            "factory release transparency external-anchor policy SHA-256",
        ),
        (
            &proof.witness_quorum_report_sha256,
            "factory release transparency witness quorum report SHA-256",
        ),
        (
            &proof.leaf_sha256,
            "factory release transparency external-anchor leaf SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_external_tree_head_shape(&proof.tree_head)?;
    if proof.leaf_index >= proof.tree_head.tree_size {
        return Err(
            "factory release transparency external-anchor leaf index is outside the tree".into(),
        );
    }
    for node in &proof.audit_path {
        validate_digest(
            node,
            "factory release transparency external-anchor audit node",
        )?;
    }
    Ok(())
}

fn verify_external_tree_head_signature(
    head: &SignedFactoryReleaseTransparencyExternalTreeHead,
) -> Result<(), String> {
    validate_external_tree_head_shape(head)?;
    let key = decode_hex::<32>(
        &head.public_key,
        "factory release transparency external log public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&key).map_err(|error| {
        format!("invalid factory release transparency external log key: {error}")
    })?;
    if verifying_key.is_weak() {
        return Err("factory release transparency external log key is weak".into());
    }
    let signature = Signature::from_bytes(&decode_hex::<64>(
        &head.signature,
        "factory release transparency external tree-head signature",
    )?);
    verifying_key
        .verify_strict(&external_tree_head_signature_payload(head)?, &signature)
        .map_err(|error| {
            format!("invalid factory release transparency external tree-head signature: {error}")
        })
}

fn external_tree_head_signature_payload(
    head: &SignedFactoryReleaseTransparencyExternalTreeHead,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ExternalTreeHeadSignaturePayload {
        domain: TREE_HEAD_SIGNATURE_DOMAIN,
        schema_version: head.schema_version,
        tree_head_scope: &head.tree_head_scope,
        log_id: &head.log_id,
        tree_size: head.tree_size,
        root_sha256: &head.root_sha256,
        observed_at_unix: head.observed_at_unix,
        algorithm: &head.algorithm,
        public_key: &head.public_key,
    })
    .map_err(|error| {
        format!("serializing factory release transparency external tree head: {error}")
    })
}

fn verify_external_inclusion(
    proof: &FactoryReleaseStateTransparencyExternalAnchorProof,
) -> Result<(), String> {
    validate_external_anchor_proof_shape(proof)?;
    let path = proof
        .audit_path
        .iter()
        .map(|node| {
            decode_hex::<32>(
                node,
                "factory release transparency external-anchor audit node",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = external_merkle_leaf_hash(&proof.leaf_sha256)?;
    let mut cursor = 0;
    let root = root_from_audit_path(
        leaf,
        proof.leaf_index,
        proof.tree_head.tree_size,
        &path,
        &mut cursor,
    )?;
    if cursor != path.len() || hex::encode(root) != proof.tree_head.root_sha256 {
        return Err(
            "factory release transparency external-anchor audit path does not reconstruct the signed root"
                .into(),
        );
    }
    Ok(())
}

fn external_merkle_leaf_hash(leaf_sha256: &str) -> Result<[u8; 32], String> {
    let digest = decode_hex::<32>(
        leaf_sha256,
        "factory release transparency external-anchor leaf SHA-256",
    )?;
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
        return Err(
            "factory release transparency external-anchor audit position is outside the tree"
                .into(),
        );
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
    let node = path.get(*cursor).copied().ok_or_else(|| {
        "factory release transparency external-anchor audit path is incomplete".to_string()
    })?;
    *cursor += 1;
    Ok(node)
}

fn largest_power_of_two_less_than(value: u64) -> u64 {
    1_u64 << (u64::BITS - (value - 1).leading_zeros() - 1)
}

fn validate_external_anchor_report_shape(
    report: &FactoryReleaseStateTransparencyExternalAnchorVerificationReport,
) -> Result<(), String> {
    let positives = [
        report.monotonic_state_chain_verified,
        report.current_checkpoint_inclusion_verified,
        report.complete_consistency_chain_verified,
        report.selected_log_append_only_consistency_verified,
        report.witness_quorum_verified,
        report.witness_quorum_report_identity_verified,
        report.external_anchor_policy_pin_matched,
        report.external_anchor_log_policy_matched,
        report.external_anchor_log_role_separation_verified,
        report.external_tree_head_signature_verified,
        report.external_inclusion_proof_verified,
        report.external_anchor_verified,
        report.external_checkpoint_fresh_at_evaluation,
    ];
    let negatives = [
        report.selected_ledger_external_anchor_report_committed,
        report.external_log_append_only_consistency_verified,
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
    if report.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_VERIFICATION_SCOPE
        || report.status != "verified"
        || positives.contains(&false)
        || negatives.contains(&true)
        || report.binding_sha256 != report_binding(report)?
    {
        return Err(
            "factory release transparency external-anchor report invariants are invalid".into(),
        );
    }
    validate_digest(&report.idempotency_key, "factory release idempotency key")?;
    validate_slug(
        &report.source_log_id,
        "factory release transparency source log id",
    )?;
    validate_slug(
        &report.external_log_id,
        "factory release transparency external log id",
    )?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION)
        .contains(&report.checkpoint_generation)
        || report.current_state_sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        || report.external_tree_size == 0
        || report.external_tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || report.external_tree_head_observed_at_unix > report.evaluated_at_unix
        || report.external_tree_head_observed_at_unix
            < report.witness_quorum_report.evaluated_at_unix
        || report.evaluated_at_unix - report.external_tree_head_observed_at_unix
            > report.external_anchor_policy.maximum_checkpoint_age_seconds
    {
        return Err(
            "factory release transparency external-anchor report bounds are invalid".into(),
        );
    }
    for (value, label) in [
        (
            &report.current_tree_head_sha256,
            "factory release transparency current tree-head SHA-256",
        ),
        (
            &report.witness_policy_sha256,
            "factory release transparency witness policy SHA-256",
        ),
        (
            &report.external_anchor_policy_sha256,
            "factory release transparency external-anchor policy SHA-256",
        ),
        (
            &report.external_leaf_sha256,
            "factory release transparency external-anchor leaf SHA-256",
        ),
        (
            &report.external_tree_head_sha256,
            "factory release transparency external tree-head SHA-256",
        ),
        (
            &report.external_root_sha256,
            "factory release transparency external Merkle root",
        ),
        (
            &report.binding_sha256,
            "factory release transparency external-anchor report binding",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_artifact_identity(
        &report.witness_quorum_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_WITNESS_REPORT_BYTES,
        "factory release transparency witness quorum report",
    )?;
    validate_artifact_identity(
        &report.external_anchor_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
        "factory release transparency external-anchor policy",
    )?;
    validate_artifact_identity(
        &report.anchor_proof_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_BYTES,
        "factory release transparency external-anchor proof",
    )?;
    validate_external_anchor_policy(&report.external_anchor_policy)?;
    validate_external_anchor_proof_shape(&report.anchor_proof)?;
    let witness = &report.witness_quorum_report;
    let head = &report.anchor_proof.tree_head;
    if report.idempotency_key != witness.idempotency_key
        || report.source_log_id != witness.log_id
        || report.checkpoint_generation != witness.checkpoint_generation
        || report.current_state_sequence != witness.current_state_sequence
        || report.current_tree_head_sha256 != witness.current_tree_head_sha256
        || report.witness_policy_sha256 != witness.witness_policy_sha256
        || report.external_anchor_policy_sha256
            != factory_release_state_transparency_external_anchor_policy_sha256(
                &report.external_anchor_policy,
            )?
        || report.anchor_proof.external_anchor_policy_sha256 != report.external_anchor_policy_sha256
        || report.anchor_proof.witness_quorum_report_sha256
            != report.witness_quorum_report_artifact.sha256
        || report.external_log_id != head.log_id
        || report.external_leaf_sha256 != report.anchor_proof.leaf_sha256
        || report.external_tree_head_sha256 != external_tree_head_sha256(head)?
        || report.external_tree_size != head.tree_size
        || report.external_root_sha256 != head.root_sha256
        || report.external_tree_head_observed_at_unix != head.observed_at_unix
        || report.external_leaf_sha256
            != factory_release_state_transparency_external_anchor_leaf_sha256(
                witness,
                &report.witness_quorum_report_artifact.sha256,
                &report.external_anchor_policy_sha256,
                &report.external_log_id,
            )?
    {
        return Err(
            "factory release transparency external-anchor report context is inconsistent".into(),
        );
    }
    let trusted_log = report
        .external_anchor_policy
        .trusted_logs
        .iter()
        .find(|trusted| trusted.log_id == report.external_log_id)
        .ok_or_else(|| {
            "factory release transparency external log is not trusted by embedded policy"
                .to_string()
        })?;
    if trusted_log.algorithm != head.algorithm || trusted_log.public_key != head.public_key {
        return Err(
            "factory release transparency external tree head is not selected by embedded policy"
                .into(),
        );
    }
    validate_external_anchor_policy_role_separation(&report.external_anchor_policy, witness)?;
    verify_external_tree_head_signature(head)?;
    verify_external_inclusion(&report.anchor_proof)?;
    Ok(())
}

fn validate_external_anchor_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalAnchorVerificationReport,
) -> Result<(), String> {
    validate_external_anchor_report_shape(report)?;
    let witness_source = render_factory_release_state_transparency_witness_quorum_report(
        &report.witness_quorum_report,
    )?;
    let policy_source = render_factory_release_state_transparency_external_anchor_policy(
        &report.external_anchor_policy,
    )?;
    let proof_source =
        render_factory_release_state_transparency_external_anchor_proof(&report.anchor_proof)?;
    if exact_identity(&witness_source) != report.witness_quorum_report_artifact
        || exact_identity(&policy_source) != report.external_anchor_policy_artifact
        || exact_identity(&proof_source) != report.anchor_proof_artifact
    {
        return Err(
            "factory release transparency external-anchor embedded artifact identity is invalid"
                .into(),
        );
    }
    let expected = verify_factory_release_state_transparency_external_anchor(
        &witness_source,
        &policy_source,
        &report.external_anchor_policy_sha256,
        &report.external_log_id,
        &proof_source,
        report.evaluated_at_unix,
    )?;
    if &expected != report {
        return Err(
            "factory release transparency external-anchor report binding is invalid".into(),
        );
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyExternalAnchorVerificationReport,
) -> Result<String, String> {
    let mut unbound = report.clone();
    unbound.binding_sha256.clear();
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &unbound,
        "factory release transparency external-anchor report binding",
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

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    decode_hex::<32>(value, label).map(|_| ())
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

pub(crate) fn factory_release_state_transparency_external_anchor_policy_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-anchor-policy-v1.json",
        "title": "pcbex factory-release state transparency external-anchor policy",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "policy_scope", "policy_id",
            "maximum_checkpoint_age_seconds", "trusted_logs"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "policy_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_SCOPE},
            "policy_id": slug_schema(),
            "maximum_checkpoint_age_seconds": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_EXTERNAL_ANCHOR_AGE_SECONDS
            },
            "trusted_logs": {
                "type": "array", "minItems": 1,
                "maxItems": MAX_EXTERNAL_ANCHOR_LOGS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["log_id", "algorithm", "public_key"],
                    "properties": {
                        "log_id": slug_schema(),
                        "algorithm": {"const": "ed25519"},
                        "public_key": digest_schema()
                    }
                }
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_anchor_proof_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-anchor-proof-v1.json",
        "title": "pcbex factory-release state transparency external-anchor inclusion proof",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "proof_scope", "external_anchor_policy_sha256",
            "witness_quorum_report_sha256", "leaf_sha256", "leaf_index",
            "audit_path", "tree_head"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "proof_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_SCOPE},
            "external_anchor_policy_sha256": digest_schema(),
            "witness_quorum_report_sha256": digest_schema(),
            "leaf_sha256": digest_schema(),
            "leaf_index": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE - 1
            },
            "audit_path": {
                "type": "array", "maxItems": MAX_EXTERNAL_ANCHOR_AUDIT_PATH,
                "items": digest_schema()
            },
            "tree_head": external_tree_head_schema()
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_anchor_report_json_schema() -> Value {
    let mut witness = factory_release_state_transparency_witness_quorum_report_json_schema();
    remove_schema_metadata(&mut witness);
    let mut policy = factory_release_state_transparency_external_anchor_policy_json_schema();
    remove_schema_metadata(&mut policy);
    let mut proof = factory_release_state_transparency_external_anchor_proof_json_schema();
    remove_schema_metadata(&mut proof);
    let digest = digest_schema();
    let mut properties = serde_json::Map::new();
    properties.insert("schema_version".into(), json!({"const": 1}));
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_VERIFICATION_SCOPE}),
    );
    properties.insert("status".into(), json!({"const": "verified"}));
    for name in [
        "monotonic_state_chain_verified",
        "current_checkpoint_inclusion_verified",
        "complete_consistency_chain_verified",
        "selected_log_append_only_consistency_verified",
        "witness_quorum_verified",
        "witness_quorum_report_identity_verified",
        "external_anchor_policy_pin_matched",
        "external_anchor_log_policy_matched",
        "external_anchor_log_role_separation_verified",
        "external_tree_head_signature_verified",
        "external_inclusion_proof_verified",
        "external_anchor_verified",
        "external_checkpoint_fresh_at_evaluation",
    ] {
        properties.insert(name.into(), json!({"const": true}));
    }
    for name in [
        "selected_ledger_external_anchor_report_committed",
        "external_log_append_only_consistency_verified",
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
    ] {
        properties.insert(name.into(), json!({"const": false}));
    }
    properties.insert("idempotency_key".into(), digest.clone());
    properties.insert("source_log_id".into(), slug_schema());
    properties.insert(
        "checkpoint_generation".into(),
        json!({
            "type": "integer", "minimum": 1,
            "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION
        }),
    );
    properties.insert(
        "current_state_sequence".into(),
        json!({
            "type": "integer", "minimum": 0,
            "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        }),
    );
    properties.insert("current_tree_head_sha256".into(), digest.clone());
    properties.insert("witness_policy_sha256".into(), digest.clone());
    properties.insert("witness_quorum_report_artifact".into(), artifact_schema());
    properties.insert("witness_quorum_report".into(), witness);
    properties.insert("external_anchor_policy_artifact".into(), artifact_schema());
    properties.insert("external_anchor_policy_sha256".into(), digest.clone());
    properties.insert("external_anchor_policy".into(), policy);
    properties.insert("anchor_proof_artifact".into(), artifact_schema());
    properties.insert("anchor_proof".into(), proof);
    properties.insert("external_log_id".into(), slug_schema());
    properties.insert("external_leaf_sha256".into(), digest.clone());
    properties.insert("external_tree_head_sha256".into(), digest.clone());
    properties.insert(
        "external_tree_size".into(),
        json!({
            "type": "integer", "minimum": 1,
            "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        }),
    );
    properties.insert("external_root_sha256".into(), digest.clone());
    properties.insert(
        "external_tree_head_observed_at_unix".into(),
        timestamp_schema(),
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
                "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-anchor-verification-report-v1.json"
            ),
        ),
        (
            "title".into(),
            json!("pcbex factory-release state transparency external-anchor verification report"),
        ),
        ("type".into(), json!("object")),
        ("additionalProperties".into(), json!(false)),
        ("required".into(), Value::Array(required)),
        ("properties".into(), Value::Object(properties)),
    ]))
}

fn external_tree_head_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "tree_head_scope", "log_id", "tree_size",
            "root_sha256", "observed_at_unix", "algorithm", "public_key",
            "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "tree_head_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE},
            "log_id": slug_schema(),
            "tree_size": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
            },
            "root_sha256": digest_schema(),
            "observed_at_unix": timestamp_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": digest_schema(),
            "signature": {
                "type": "string", "pattern": "^[0-9a-f]{128}$"
            }
        }
    })
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn artifact_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1},
            "sha256": digest_schema()
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
    use ed25519_dalek::{Signer, SigningKey};

    fn policy(key: &SigningKey) -> FactoryReleaseStateTransparencyExternalAnchorPolicy {
        FactoryReleaseStateTransparencyExternalAnchorPolicy {
            schema_version: 1,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_SCOPE.into(),
            policy_id: "release-external-anchor".into(),
            maximum_checkpoint_age_seconds: 300,
            trusted_logs: vec![TrustedFactoryReleaseTransparencyExternalLog {
                log_id: "public-log".into(),
                algorithm: "ed25519".into(),
                public_key: hex::encode(key.verifying_key().to_bytes()),
            }],
        }
    }

    fn signed_single_leaf_proof(
        key: &SigningKey,
    ) -> FactoryReleaseStateTransparencyExternalAnchorProof {
        let leaf_sha256 = "12".repeat(32);
        let root_sha256 = hex::encode(external_merkle_leaf_hash(&leaf_sha256).unwrap());
        let mut head = SignedFactoryReleaseTransparencyExternalTreeHead {
            schema_version: 1,
            tree_head_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE
                .into(),
            log_id: "public-log".into(),
            tree_size: 1,
            root_sha256,
            observed_at_unix: 200,
            algorithm: "ed25519".into(),
            public_key: hex::encode(key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        head.signature = hex::encode(
            key.sign(&external_tree_head_signature_payload(&head).unwrap())
                .to_bytes(),
        );
        FactoryReleaseStateTransparencyExternalAnchorProof {
            schema_version: 1,
            proof_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_PROOF_SCOPE.into(),
            external_anchor_policy_sha256: "34".repeat(32),
            witness_quorum_report_sha256: "56".repeat(32),
            leaf_sha256,
            leaf_index: 0,
            audit_path: vec![],
            tree_head: head,
        }
    }

    #[test]
    fn policy_is_canonical_pinned_ordered_and_nonweak() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let policy = policy(&key);
        let source =
            render_factory_release_state_transparency_external_anchor_policy(&policy).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_anchor_policy(&source).unwrap(),
            policy
        );
        assert_eq!(
            factory_release_state_transparency_external_anchor_policy_sha256(&policy)
                .unwrap()
                .len(),
            64
        );
        let mut duplicate = policy.clone();
        duplicate
            .trusted_logs
            .push(duplicate.trusted_logs[0].clone());
        assert!(validate_external_anchor_policy(&duplicate).is_err());
        let mut weak = policy.clone();
        weak.trusted_logs[0].public_key = format!("01{}", "00".repeat(31));
        assert!(validate_external_anchor_policy(&weak).is_err());
        let mut uppercase = policy;
        uppercase.trusted_logs[0].public_key = uppercase.trusted_logs[0].public_key.to_uppercase();
        assert!(validate_external_anchor_policy(&uppercase).is_err());
    }

    #[test]
    fn signed_external_view_authenticates_before_inclusion() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let proof = signed_single_leaf_proof(&key);
        verify_external_tree_head_signature(&proof.tree_head).unwrap();
        verify_external_inclusion(&proof).unwrap();

        let mut unauthenticated = proof.clone();
        unauthenticated.tree_head.root_sha256 = "89".repeat(32);
        assert!(verify_external_tree_head_signature(&unauthenticated.tree_head).is_err());

        let mut extra_path = proof;
        extra_path.audit_path.push("ab".repeat(32));
        assert!(verify_external_tree_head_signature(&extra_path.tree_head).is_ok());
        assert!(verify_external_inclusion(&extra_path).is_err());
    }

    #[test]
    fn proof_parser_rejects_noncanonical_duplicate_and_uppercase_json() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let proof = signed_single_leaf_proof(&key);
        let canonical =
            render_factory_release_state_transparency_external_anchor_proof(&proof).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_anchor_proof(&canonical).unwrap(),
            proof
        );
        assert!(
            parse_factory_release_state_transparency_external_anchor_proof(
                &serde_json::to_vec(&proof).unwrap()
            )
            .is_err()
        );
        let duplicate = String::from_utf8(canonical).unwrap().replacen(
            "{\n",
            "{\n  \"schema_version\": 1,\n",
            1,
        );
        assert!(
            parse_factory_release_state_transparency_external_anchor_proof(duplicate.as_bytes())
                .is_err()
        );
        let mut uppercase = proof;
        uppercase.tree_head.signature = uppercase.tree_head.signature.to_uppercase();
        assert!(validate_external_anchor_proof_shape(&uppercase).is_err());
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
                Value::Array(values) => {
                    for value in values {
                        walk(value);
                    }
                }
                _ => {}
            }
        }
        for schema in [
            factory_release_state_transparency_external_anchor_policy_json_schema(),
            factory_release_state_transparency_external_anchor_proof_json_schema(),
            factory_release_state_transparency_external_anchor_report_json_schema(),
        ] {
            walk(&schema);
        }
    }

    #[test]
    fn filename_is_bounded_and_binds_every_selected_context() {
        let key = "ab".repeat(32);
        let witness_policy = "cd".repeat(32);
        let anchor_policy = "ef".repeat(32);
        let name = factory_release_state_transparency_external_anchor_filename(
            &key,
            "source-log",
            2,
            &witness_policy,
            "public-log",
            &anchor_policy,
        )
        .unwrap();
        assert!(name.len() < 255);
        assert!(name.contains(&format!("-{key}-0002-")));
        let changed = factory_release_state_transparency_external_anchor_filename(
            &key,
            "source-log",
            2,
            &witness_policy,
            "other-public-log",
            &anchor_policy,
        )
        .unwrap();
        assert_ne!(name, changed);
    }
}
