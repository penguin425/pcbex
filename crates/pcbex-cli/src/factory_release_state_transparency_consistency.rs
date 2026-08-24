//! Append-only consistency for retained factory-release transparency checkpoints.
//!
//! The v1.486 boundary compares two individually verified v1.485 inclusion
//! reports for one policy-pinned log. A bounded RFC 6962-shaped consistency
//! path must reconstruct both signed roots, the later view must strictly extend
//! the earlier view, and deterministic predecessor identities allow a selected
//! ledger to retain a complete no-replace checkpoint chain. This does not prove
//! global non-equivocation, protect the selected ledger from rollback, or
//! establish trusted time, transport identity, ordering, or payment.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_adapter_monotonic_state::MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE;
use crate::factory_release_state_transparency::{
    FactoryReleaseStateTransparencyVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_AUDIT_PATH,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_REPORT_BYTES,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE,
    SignedFactoryReleaseStateTransparencyTreeHead,
    factory_release_state_transparency_verification_report_json_schema, tree_head_sha256,
    validate_report_shape, validate_tree_head_shape, verify_tree_head_signature,
};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_SCOPE: &str =
    "factory-release-state-transparency-consistency-proof-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_VERIFICATION_SCOPE: &str =
    "verified-factory-release-state-transparency-consistency-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_BYTES: u64 = 32 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_REPORT_BYTES: u64 = 256 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION: u64 = 10_000;

const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-consistency-report:v1\0";
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyConsistencyProof {
    pub(crate) schema_version: u32,
    pub(crate) proof_scope: String,
    pub(crate) previous_tree_head_sha256: String,
    pub(crate) current_tree_head_sha256: String,
    pub(crate) consistency_path: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyConsistencyVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) monotonic_state_chain_verified: bool,
    pub(crate) previous_checkpoint_inclusion_verified: bool,
    pub(crate) current_checkpoint_inclusion_verified: bool,
    pub(crate) same_log_and_key_verified: bool,
    pub(crate) tree_head_signatures_verified: bool,
    pub(crate) strict_tree_extension_verified: bool,
    pub(crate) consistency_proof_verified: bool,
    pub(crate) complete_consistency_chain_verified: bool,
    pub(crate) selected_log_append_only_consistency_verified: bool,
    pub(crate) selected_ledger_consistency_report_committed: bool,
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
    pub(crate) checkpoint_generation: u64,
    pub(crate) idempotency_key: String,
    pub(crate) log_id: String,
    pub(crate) policy_pack_sha256: String,
    pub(crate) transparency_policy_sha256: String,
    pub(crate) previous_state_sequence: u64,
    pub(crate) current_state_sequence: u64,
    pub(crate) previous_tree_head_sha256: String,
    pub(crate) current_tree_head_sha256: String,
    pub(crate) previous_tree_size: u64,
    pub(crate) current_tree_size: u64,
    pub(crate) previous_root_sha256: String,
    pub(crate) current_root_sha256: String,
    pub(crate) previous_tree_head_observed_at_unix: u64,
    pub(crate) current_tree_head_observed_at_unix: u64,
    pub(crate) anchor_transparency_report_artifact: Option<ExactArtifactIdentity>,
    pub(crate) previous_consistency_report_artifact: Option<ExactArtifactIdentity>,
    pub(crate) consistency_proof_artifact: ExactArtifactIdentity,
    pub(crate) previous_transparency_report: FactoryReleaseStateTransparencyVerificationReport,
    pub(crate) current_transparency_report: FactoryReleaseStateTransparencyVerificationReport,
    pub(crate) consistency_proof: FactoryReleaseStateTransparencyConsistencyProof,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct ReportBinding<'a> {
    schema_version: u32,
    verification_scope: &'a str,
    status: &'a str,
    monotonic_state_chain_verified: bool,
    previous_checkpoint_inclusion_verified: bool,
    current_checkpoint_inclusion_verified: bool,
    same_log_and_key_verified: bool,
    tree_head_signatures_verified: bool,
    strict_tree_extension_verified: bool,
    consistency_proof_verified: bool,
    complete_consistency_chain_verified: bool,
    selected_log_append_only_consistency_verified: bool,
    selected_ledger_consistency_report_committed: bool,
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
    checkpoint_generation: u64,
    idempotency_key: &'a str,
    log_id: &'a str,
    policy_pack_sha256: &'a str,
    transparency_policy_sha256: &'a str,
    previous_state_sequence: u64,
    current_state_sequence: u64,
    previous_tree_head_sha256: &'a str,
    current_tree_head_sha256: &'a str,
    previous_tree_size: u64,
    current_tree_size: u64,
    previous_root_sha256: &'a str,
    current_root_sha256: &'a str,
    previous_tree_head_observed_at_unix: u64,
    current_tree_head_observed_at_unix: u64,
    anchor_transparency_report_artifact: &'a Option<ExactArtifactIdentity>,
    previous_consistency_report_artifact: &'a Option<ExactArtifactIdentity>,
    consistency_proof_artifact: &'a ExactArtifactIdentity,
    previous_transparency_report: &'a FactoryReleaseStateTransparencyVerificationReport,
    current_transparency_report: &'a FactoryReleaseStateTransparencyVerificationReport,
    consistency_proof: &'a FactoryReleaseStateTransparencyConsistencyProof,
    evaluated_at_unix: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_consistency(
    previous_report: &FactoryReleaseStateTransparencyVerificationReport,
    current_report: &FactoryReleaseStateTransparencyVerificationReport,
    complete_monotonic_chain_verified: bool,
    complete_consistency_chain_verified: bool,
    checkpoint_generation: u64,
    anchor_transparency_report_artifact: Option<ExactArtifactIdentity>,
    previous_consistency_report_artifact: Option<ExactArtifactIdentity>,
    consistency_proof_source: &[u8],
) -> Result<FactoryReleaseStateTransparencyConsistencyVerificationReport, String> {
    if !complete_monotonic_chain_verified || !complete_consistency_chain_verified {
        return Err(
            "factory release transparency consistency requires complete verified local chains"
                .into(),
        );
    }
    validate_report_shape(previous_report)?;
    validate_report_shape(current_report)?;
    validate_predecessor(
        checkpoint_generation,
        &anchor_transparency_report_artifact,
        &previous_consistency_report_artifact,
    )?;
    if previous_report.idempotency_key != current_report.idempotency_key
        || previous_report.factory_id != current_report.factory_id
        || previous_report.provider != current_report.provider
        || previous_report.release_subject_sha256 != current_report.release_subject_sha256
        || previous_report.manufacturing_package_sha256
            != current_report.manufacturing_package_sha256
    {
        return Err("factory release transparency consistency subject changed".into());
    }
    if current_report.state_sequence < previous_report.state_sequence {
        return Err("factory release transparency consistency state sequence rolled back".into());
    }
    if previous_report.policy_pack_sha256 != current_report.policy_pack_sha256
        || previous_report.transparency_policy_sha256 != current_report.transparency_policy_sha256
    {
        return Err("factory release transparency consistency policy pin changed".into());
    }

    let previous_head = &previous_report.transparency_receipt.tree_head;
    let current_head = &current_report.transparency_receipt.tree_head;
    validate_head_pair(previous_head, current_head)?;
    verify_tree_head_signature(previous_head)?;
    verify_tree_head_signature(current_head)?;

    let proof =
        parse_factory_release_state_transparency_consistency_proof(consistency_proof_source)?;
    let previous_tree_head_sha256 = tree_head_sha256(previous_head)?;
    let current_tree_head_sha256 = tree_head_sha256(current_head)?;
    if proof.previous_tree_head_sha256 != previous_tree_head_sha256
        || proof.current_tree_head_sha256 != current_tree_head_sha256
    {
        return Err(
            "factory release transparency consistency proof binds different tree heads".into(),
        );
    }
    verify_consistency_path(previous_head, current_head, &proof.consistency_path)?;

    let mut report = FactoryReleaseStateTransparencyConsistencyVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_VERIFICATION_SCOPE
            .into(),
        status: "verified".into(),
        monotonic_state_chain_verified: true,
        previous_checkpoint_inclusion_verified: true,
        current_checkpoint_inclusion_verified: true,
        same_log_and_key_verified: true,
        tree_head_signatures_verified: true,
        strict_tree_extension_verified: true,
        consistency_proof_verified: true,
        complete_consistency_chain_verified: true,
        selected_log_append_only_consistency_verified: true,
        selected_ledger_consistency_report_committed: false,
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
        checkpoint_generation,
        idempotency_key: current_report.idempotency_key.clone(),
        log_id: current_head.log_id.clone(),
        policy_pack_sha256: current_report.policy_pack_sha256.clone(),
        transparency_policy_sha256: current_report.transparency_policy_sha256.clone(),
        previous_state_sequence: previous_report.state_sequence,
        current_state_sequence: current_report.state_sequence,
        previous_tree_head_sha256,
        current_tree_head_sha256,
        previous_tree_size: previous_head.tree_size,
        current_tree_size: current_head.tree_size,
        previous_root_sha256: previous_head.root_sha256.clone(),
        current_root_sha256: current_head.root_sha256.clone(),
        previous_tree_head_observed_at_unix: previous_head.observed_at_unix,
        current_tree_head_observed_at_unix: current_head.observed_at_unix,
        anchor_transparency_report_artifact,
        previous_consistency_report_artifact,
        consistency_proof_artifact: exact_identity(consistency_proof_source),
        previous_transparency_report: previous_report.clone(),
        current_transparency_report: current_report.clone(),
        consistency_proof: proof,
        evaluated_at_unix: current_report.evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_consistency_report_shape(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_consistency_proof(
    proof: &FactoryReleaseStateTransparencyConsistencyProof,
) -> Result<Vec<u8>, String> {
    validate_consistency_proof_shape(proof)?;
    render_bounded(
        proof,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_BYTES,
        "factory release state transparency consistency proof",
    )
}

pub(crate) fn parse_factory_release_state_transparency_consistency_proof(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyConsistencyProof, String> {
    let proof = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_BYTES,
        "factory release state transparency consistency proof",
    )?;
    validate_consistency_proof_shape(&proof)?;
    Ok(proof)
}

pub(crate) fn render_factory_release_state_transparency_consistency_report(
    report: &FactoryReleaseStateTransparencyConsistencyVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_consistency_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_REPORT_BYTES,
        "factory release state transparency consistency verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_consistency_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyConsistencyVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_REPORT_BYTES,
        "factory release state transparency consistency verification report",
    )?;
    validate_consistency_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn factory_release_state_transparency_consistency_filename(
    idempotency_key: &str,
    log_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_slug(log_id, "factory release transparency log id")?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION).contains(&generation) {
        return Err(
            "factory release transparency consistency generation is outside its bound".into(),
        );
    }
    Ok(format!(
        "factory-release-state-transparency-consistency-v1-{idempotency_key}-{log_id}-{generation:04}.json"
    ))
}

fn validate_head_pair(
    previous: &SignedFactoryReleaseStateTransparencyTreeHead,
    current: &SignedFactoryReleaseStateTransparencyTreeHead,
) -> Result<(), String> {
    validate_tree_head_shape(previous)?;
    validate_tree_head_shape(current)?;
    if previous.log_id != current.log_id {
        return Err("factory release transparency consistency log identity changed".into());
    }
    if previous.public_key != current.public_key {
        return Err("factory release transparency consistency log key changed".into());
    }
    if current.tree_size < previous.tree_size {
        return Err("factory release transparency tree size rolled back".into());
    }
    if current.tree_size == previous.tree_size {
        if current.root_sha256 != previous.root_sha256 {
            return Err("factory release transparency log equivocated at one tree size".into());
        }
        return Err(
            "factory release transparency consistency requires a strict tree extension".into(),
        );
    }
    if current.observed_at_unix < previous.observed_at_unix {
        return Err("factory release transparency tree-head observation time rolled back".into());
    }
    Ok(())
}

fn verify_consistency_path(
    previous: &SignedFactoryReleaseStateTransparencyTreeHead,
    current: &SignedFactoryReleaseStateTransparencyTreeHead,
    encoded_path: &[String],
) -> Result<(), String> {
    let path = encoded_path
        .iter()
        .map(|node| decode_hex::<32>(node, "factory release transparency consistency node"))
        .collect::<Result<Vec<_>, _>>()?;
    let trusted_previous_root = decode_hex::<32>(
        &previous.root_sha256,
        "factory release transparency previous root",
    )?;
    let mut cursor = 0;
    let (reconstructed_previous, reconstructed_current) = roots_from_consistency_path(
        previous.tree_size,
        current.tree_size,
        true,
        trusted_previous_root,
        &path,
        &mut cursor,
    )?;
    if cursor != path.len()
        || hex::encode(reconstructed_previous) != previous.root_sha256
        || hex::encode(reconstructed_current) != current.root_sha256
    {
        return Err(
            "factory release transparency consistency path does not reconstruct both signed roots"
                .into(),
        );
    }
    Ok(())
}

fn roots_from_consistency_path(
    previous_size: u64,
    current_size: u64,
    complete_subtree: bool,
    trusted_previous_root: [u8; 32],
    path: &[[u8; 32]],
    cursor: &mut usize,
) -> Result<([u8; 32], [u8; 32]), String> {
    if previous_size == current_size {
        let root = if complete_subtree {
            trusted_previous_root
        } else {
            next_consistency_node(path, cursor)?
        };
        return Ok((root, root));
    }
    let split = largest_power_of_two_less_than(current_size);
    if previous_size <= split {
        let (previous_root, current_left) = roots_from_consistency_path(
            previous_size,
            split,
            complete_subtree,
            trusted_previous_root,
            path,
            cursor,
        )?;
        let current_right = next_consistency_node(path, cursor)?;
        Ok((previous_root, merkle_node_hash(current_left, current_right)))
    } else {
        let (previous_right, current_right) = roots_from_consistency_path(
            previous_size - split,
            current_size - split,
            false,
            trusted_previous_root,
            path,
            cursor,
        )?;
        let left = next_consistency_node(path, cursor)?;
        Ok((
            merkle_node_hash(left, previous_right),
            merkle_node_hash(left, current_right),
        ))
    }
}

fn next_consistency_node(path: &[[u8; 32]], cursor: &mut usize) -> Result<[u8; 32], String> {
    let node = path
        .get(*cursor)
        .copied()
        .ok_or_else(|| "factory release transparency consistency path is incomplete".to_string())?;
    *cursor += 1;
    Ok(node)
}

fn largest_power_of_two_less_than(value: u64) -> u64 {
    1_u64 << (u64::BITS - (value - 1).leading_zeros() - 1)
}

fn merkle_node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut source = Vec::with_capacity(65);
    source.push(1);
    source.extend_from_slice(&left);
    source.extend_from_slice(&right);
    Sha256::digest(source).into()
}

fn validate_consistency_proof_shape(
    proof: &FactoryReleaseStateTransparencyConsistencyProof,
) -> Result<(), String> {
    if proof.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_SCHEMA_VERSION
        || proof.proof_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_SCOPE
        || proof.consistency_path.is_empty()
        || proof.consistency_path.len() > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_AUDIT_PATH
    {
        return Err("factory release transparency consistency proof invariants are invalid".into());
    }
    validate_digest(
        &proof.previous_tree_head_sha256,
        "factory release transparency previous tree-head SHA-256",
    )?;
    validate_digest(
        &proof.current_tree_head_sha256,
        "factory release transparency current tree-head SHA-256",
    )?;
    if proof.previous_tree_head_sha256 == proof.current_tree_head_sha256 {
        return Err(
            "factory release transparency consistency proof tree heads are identical".into(),
        );
    }
    for node in &proof.consistency_path {
        validate_digest(node, "factory release transparency consistency node")?;
    }
    Ok(())
}

fn validate_predecessor(
    generation: u64,
    anchor: &Option<ExactArtifactIdentity>,
    previous: &Option<ExactArtifactIdentity>,
) -> Result<(), String> {
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION).contains(&generation) {
        return Err(
            "factory release transparency consistency generation is outside its bound".into(),
        );
    }
    match (generation, anchor, previous) {
        (1, Some(anchor), None) => validate_artifact_identity(
            anchor,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_REPORT_BYTES,
            "factory release transparency anchor report",
        ),
        (2.., None, Some(previous)) => validate_artifact_identity(
            previous,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_REPORT_BYTES,
            "previous factory release transparency consistency report",
        ),
        _ => Err("factory release transparency consistency predecessor is invalid".into()),
    }
}

fn validate_consistency_report_shape(
    report: &FactoryReleaseStateTransparencyConsistencyVerificationReport,
) -> Result<(), String> {
    let positives = [
        report.monotonic_state_chain_verified,
        report.previous_checkpoint_inclusion_verified,
        report.current_checkpoint_inclusion_verified,
        report.same_log_and_key_verified,
        report.tree_head_signatures_verified,
        report.strict_tree_extension_verified,
        report.consistency_proof_verified,
        report.complete_consistency_chain_verified,
        report.selected_log_append_only_consistency_verified,
    ];
    let negatives = [
        report.selected_ledger_consistency_report_committed,
        report.global_non_equivocation_verified,
        report.selected_ledger_rollback_resistance_verified,
        report.trusted_time_verified,
        report.endpoint_transport_authenticity_verified,
        report.factory_legal_identity_verified,
        report.server_side_idempotency_enforced,
        report.capacity_reserved,
        report.order_placed,
        report.payment_performed,
        report.exactly_once_execution_verified,
    ];
    if report.schema_version != FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_VERIFICATION_SCOPE
        || report.status != "verified"
        || positives.contains(&false)
        || negatives.contains(&true)
    {
        return Err("factory release transparency consistency report claims are invalid".into());
    }
    validate_predecessor(
        report.checkpoint_generation,
        &report.anchor_transparency_report_artifact,
        &report.previous_consistency_report_artifact,
    )?;
    validate_artifact_identity(
        &report.consistency_proof_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_BYTES,
        "factory release transparency consistency proof",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency consistency binding",
    )?;
    Ok(())
}

fn validate_consistency_report_self_contained(
    report: &FactoryReleaseStateTransparencyConsistencyVerificationReport,
) -> Result<(), String> {
    validate_consistency_report_shape(report)?;
    let proof_source =
        render_factory_release_state_transparency_consistency_proof(&report.consistency_proof)?;
    let expected = verify_factory_release_state_transparency_consistency(
        &report.previous_transparency_report,
        &report.current_transparency_report,
        true,
        true,
        report.checkpoint_generation,
        report.anchor_transparency_report_artifact.clone(),
        report.previous_consistency_report_artifact.clone(),
        &proof_source,
    )?;
    if &expected != report {
        return Err("factory release transparency consistency report binding is invalid".into());
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyConsistencyVerificationReport,
) -> Result<String, String> {
    let binding = ReportBinding {
        schema_version: report.schema_version,
        verification_scope: &report.verification_scope,
        status: &report.status,
        monotonic_state_chain_verified: report.monotonic_state_chain_verified,
        previous_checkpoint_inclusion_verified: report.previous_checkpoint_inclusion_verified,
        current_checkpoint_inclusion_verified: report.current_checkpoint_inclusion_verified,
        same_log_and_key_verified: report.same_log_and_key_verified,
        tree_head_signatures_verified: report.tree_head_signatures_verified,
        strict_tree_extension_verified: report.strict_tree_extension_verified,
        consistency_proof_verified: report.consistency_proof_verified,
        complete_consistency_chain_verified: report.complete_consistency_chain_verified,
        selected_log_append_only_consistency_verified: report
            .selected_log_append_only_consistency_verified,
        selected_ledger_consistency_report_committed: report
            .selected_ledger_consistency_report_committed,
        global_non_equivocation_verified: report.global_non_equivocation_verified,
        selected_ledger_rollback_resistance_verified: report
            .selected_ledger_rollback_resistance_verified,
        trusted_time_verified: report.trusted_time_verified,
        endpoint_transport_authenticity_verified: report.endpoint_transport_authenticity_verified,
        factory_legal_identity_verified: report.factory_legal_identity_verified,
        server_side_idempotency_enforced: report.server_side_idempotency_enforced,
        capacity_reserved: report.capacity_reserved,
        order_placed: report.order_placed,
        payment_performed: report.payment_performed,
        exactly_once_execution_verified: report.exactly_once_execution_verified,
        checkpoint_generation: report.checkpoint_generation,
        idempotency_key: &report.idempotency_key,
        log_id: &report.log_id,
        policy_pack_sha256: &report.policy_pack_sha256,
        transparency_policy_sha256: &report.transparency_policy_sha256,
        previous_state_sequence: report.previous_state_sequence,
        current_state_sequence: report.current_state_sequence,
        previous_tree_head_sha256: &report.previous_tree_head_sha256,
        current_tree_head_sha256: &report.current_tree_head_sha256,
        previous_tree_size: report.previous_tree_size,
        current_tree_size: report.current_tree_size,
        previous_root_sha256: &report.previous_root_sha256,
        current_root_sha256: &report.current_root_sha256,
        previous_tree_head_observed_at_unix: report.previous_tree_head_observed_at_unix,
        current_tree_head_observed_at_unix: report.current_tree_head_observed_at_unix,
        anchor_transparency_report_artifact: &report.anchor_transparency_report_artifact,
        previous_consistency_report_artifact: &report.previous_consistency_report_artifact,
        consistency_proof_artifact: &report.consistency_proof_artifact,
        previous_transparency_report: &report.previous_transparency_report,
        current_transparency_report: &report.current_transparency_report,
        consistency_proof: &report.consistency_proof,
        evaluated_at_unix: report.evaluated_at_unix,
    };
    let source = serde_json::to_vec(&binding).map_err(|error| {
        format!("serializing factory release transparency consistency binding: {error}")
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

pub(crate) fn factory_release_state_transparency_consistency_proof_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-consistency-proof-v1.json",
        "title": "pcbex factory-release state transparency consistency proof",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "proof_scope", "previous_tree_head_sha256",
            "current_tree_head_sha256", "consistency_path"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_SCHEMA_VERSION},
            "proof_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_SCOPE},
            "previous_tree_head_sha256": digest.clone(),
            "current_tree_head_sha256": digest.clone(),
            "consistency_path": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_AUDIT_PATH,
                "items": digest
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_consistency_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let artifact = json!({
        "type": "object", "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1},
            "sha256": digest.clone()
        }
    });
    let nullable_artifact = json!({"oneOf": [artifact.clone(), {"type": "null"}]});
    let mut embedded_report = factory_release_state_transparency_verification_report_json_schema();
    if let Some(object) = embedded_report.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
        object.remove("title");
    }
    let positive = [
        "monotonic_state_chain_verified",
        "previous_checkpoint_inclusion_verified",
        "current_checkpoint_inclusion_verified",
        "same_log_and_key_verified",
        "tree_head_signatures_verified",
        "strict_tree_extension_verified",
        "consistency_proof_verified",
        "complete_consistency_chain_verified",
        "selected_log_append_only_consistency_verified",
    ];
    let negative = [
        "selected_ledger_consistency_report_committed",
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
    properties.insert("schema_version".into(), json!({"const": 1}));
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_VERIFICATION_SCOPE}),
    );
    properties.insert("status".into(), json!({"const": "verified"}));
    for name in positive {
        properties.insert(name.into(), json!({"const": true}));
    }
    for name in negative {
        properties.insert(name.into(), json!({"const": false}));
    }
    properties.insert(
        "checkpoint_generation".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION}),
    );
    properties.insert("idempotency_key".into(), digest.clone());
    properties.insert(
        "log_id".into(),
        json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}),
    );
    properties.insert("policy_pack_sha256".into(), digest.clone());
    properties.insert("transparency_policy_sha256".into(), digest.clone());
    properties.insert(
        "previous_state_sequence".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE}),
    );
    properties.insert(
        "current_state_sequence".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE}),
    );
    for name in [
        "previous_tree_head_sha256",
        "current_tree_head_sha256",
        "previous_root_sha256",
        "current_root_sha256",
        "binding_sha256",
    ] {
        properties.insert(name.into(), digest.clone());
    }
    properties.insert(
        "previous_tree_size".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE}),
    );
    properties.insert(
        "current_tree_size".into(),
        json!({"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE}),
    );
    properties.insert(
        "previous_tree_head_observed_at_unix".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}),
    );
    properties.insert(
        "current_tree_head_observed_at_unix".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}),
    );
    properties.insert(
        "anchor_transparency_report_artifact".into(),
        nullable_artifact.clone(),
    );
    properties.insert(
        "previous_consistency_report_artifact".into(),
        nullable_artifact,
    );
    properties.insert("consistency_proof_artifact".into(), artifact);
    properties.insert(
        "previous_transparency_report".into(),
        embedded_report.clone(),
    );
    properties.insert("current_transparency_report".into(), embedded_report);
    let mut proof_schema = factory_release_state_transparency_consistency_proof_json_schema();
    if let Some(object) = proof_schema.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
        object.remove("title");
    }
    properties.insert("consistency_proof".into(), proof_schema);
    properties.insert(
        "evaluated_at_unix".into(),
        json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}),
    );
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
                "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-consistency-verification-report-v1.json"
            ),
        ),
        (
            "title".into(),
            json!("pcbex factory-release state transparency consistency verification report"),
        ),
        ("type".into(), json!("object")),
        ("additionalProperties".into(), json!(false)),
        ("required".into(), Value::Array(required)),
        ("properties".into(), Value::Object(properties)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[derive(Serialize)]
    struct TreeHeadPayload<'a> {
        domain: &'static str,
        tree_head_scope: &'a str,
        log_id: &'a str,
        tree_size: u64,
        root_sha256: &'a str,
        observed_at_unix: u64,
    }

    fn leaf(value: u8) -> [u8; 32] {
        Sha256::digest([value]).into()
    }

    fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
        merkle_node_hash(root(&leaves[..split]), root(&leaves[split..]))
    }

    fn subproof(old_size: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
        if old_size == leaves.len() {
            return if complete {
                Vec::new()
            } else {
                vec![root(leaves)]
            };
        }
        let split = largest_power_of_two_less_than(leaves.len() as u64) as usize;
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

    fn signed_head(
        leaves: &[[u8; 32]],
        observed_at_unix: u64,
    ) -> SignedFactoryReleaseStateTransparencyTreeHead {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let mut head = SignedFactoryReleaseStateTransparencyTreeHead {
            schema_version: 1,
            tree_head_scope: "signed-factory-release-state-transparency-tree-head-v1".into(),
            log_id: "factory-log".into(),
            tree_size: leaves.len() as u64,
            root_sha256: hex::encode(root(leaves)),
            observed_at_unix,
            algorithm: "ed25519".into(),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        let payload = serde_json::to_vec(&TreeHeadPayload {
            domain: "pcbex-factory-release-state-transparency-tree-head-v1",
            tree_head_scope: &head.tree_head_scope,
            log_id: &head.log_id,
            tree_size: head.tree_size,
            root_sha256: &head.root_sha256,
            observed_at_unix,
        })
        .unwrap();
        head.signature = hex::encode(signing_key.sign(&payload).to_bytes());
        head
    }

    #[test]
    fn verifies_balanced_and_unbalanced_strict_extensions() {
        let leaves = (0..32).map(leaf).collect::<Vec<_>>();
        for current_size in 2..=leaves.len() {
            for previous_size in 1..current_size {
                let previous = signed_head(&leaves[..previous_size], previous_size as u64);
                let current = signed_head(&leaves[..current_size], current_size as u64);
                let path = subproof(previous_size, &leaves[..current_size], true)
                    .into_iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>();
                verify_consistency_path(&previous, &current, &path).unwrap();
                validate_head_pair(&previous, &current).unwrap();
            }
        }
    }

    #[test]
    fn rejects_tampering_rollback_equivocation_time_and_substitution() {
        let leaves = (0..7).map(leaf).collect::<Vec<_>>();
        let previous = signed_head(&leaves[..3], 10);
        let current = signed_head(&leaves, 20);
        let mut path = subproof(3, &leaves, true)
            .into_iter()
            .map(hex::encode)
            .collect::<Vec<_>>();
        path[0] = "0".repeat(64);
        assert!(verify_consistency_path(&previous, &current, &path).is_err());
        let mut oversized_path = subproof(3, &leaves, true)
            .into_iter()
            .map(hex::encode)
            .collect::<Vec<_>>();
        oversized_path.push("0".repeat(64));
        assert!(verify_consistency_path(&previous, &current, &oversized_path).is_err());
        assert!(validate_head_pair(&current, &previous).is_err());
        assert!(validate_head_pair(&previous, &previous).is_err());

        let mut equivocation = previous.clone();
        equivocation.root_sha256 = "0".repeat(64);
        assert!(validate_head_pair(&previous, &equivocation).is_err());

        let mut backwards_time = current.clone();
        backwards_time.observed_at_unix = 9;
        assert!(validate_head_pair(&previous, &backwards_time).is_err());

        let mut other_log = current.clone();
        other_log.log_id = "other-log".into();
        assert!(validate_head_pair(&previous, &other_log).is_err());

        let mut other_key = current;
        other_key.public_key = "0".repeat(64);
        assert!(validate_head_pair(&previous, &other_key).is_err());
    }

    #[test]
    fn proof_parser_is_canonical_bounded_and_duplicate_safe() {
        let proof = FactoryReleaseStateTransparencyConsistencyProof {
            schema_version: 1,
            proof_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_SCOPE.into(),
            previous_tree_head_sha256: "1".repeat(64),
            current_tree_head_sha256: "2".repeat(64),
            consistency_path: vec!["3".repeat(64)],
        };
        let canonical =
            render_factory_release_state_transparency_consistency_proof(&proof).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_consistency_proof(&canonical).unwrap(),
            proof
        );
        assert!(
            parse_factory_release_state_transparency_consistency_proof(
                &serde_json::to_vec(&proof).unwrap()
            )
            .is_err()
        );
        let duplicate = String::from_utf8(canonical.clone()).unwrap().replacen(
            "  \"schema_version\": 1,",
            "  \"schema_version\": 1,\n  \"schema_version\": 1,",
            1,
        );
        assert!(
            parse_factory_release_state_transparency_consistency_proof(duplicate.as_bytes())
                .is_err()
        );
        assert!(
            parse_factory_release_state_transparency_consistency_proof(&vec![
                b' ';
                (MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_PROOF_BYTES + 1)
                    as usize
            ])
            .is_err()
        );
    }

    #[test]
    fn schemas_are_recursively_closed_and_filenames_are_bounded() {
        let proof = factory_release_state_transparency_consistency_proof_json_schema();
        assert_eq!(proof["additionalProperties"], false);
        let report = factory_release_state_transparency_consistency_report_json_schema();
        assert_eq!(report["additionalProperties"], false);
        assert_eq!(
            report["properties"]["previous_transparency_report"]["additionalProperties"],
            false
        );
        assert_eq!(
            report["properties"]["current_transparency_report"]["properties"]["transparency_receipt"]
                ["additionalProperties"],
            false
        );
        assert_eq!(
            report["properties"]["consistency_proof"]["additionalProperties"],
            false
        );
        assert_eq!(
            factory_release_state_transparency_consistency_filename(
                &"ab".repeat(32),
                "factory-log",
                12
            )
            .unwrap(),
            format!(
                "factory-release-state-transparency-consistency-v1-{}-factory-log-0012.json",
                "ab".repeat(32)
            ),
        );
        assert!(
            factory_release_state_transparency_consistency_filename(
                &"ab".repeat(32),
                "factory-log",
                0
            )
            .is_err()
        );
        assert!(
            factory_release_state_transparency_consistency_filename(&"ab".repeat(32), "../log", 1)
                .is_err()
        );
    }
}
