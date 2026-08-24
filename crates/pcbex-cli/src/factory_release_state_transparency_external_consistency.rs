//! Append-only consistency for externally anchored factory-release transparency.
//!
//! The v1.489 boundary starts from one exact, fully verified v1.488 external
//! anchor and verifies strict RFC 6962-shaped extensions of the same signed
//! external log. It proves append-only consistency only for the retained views
//! in one selected local ledger. It does not prove global non-equivocation,
//! ledger rollback resistance, trusted time, independent legal operation,
//! transport identity, ordering, payment, or exactly-once execution.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_adapter_monotonic_state::MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE;
use crate::factory_release_state_transparency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE;
use crate::factory_release_state_transparency_consistency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION;
use crate::factory_release_state_transparency_external_anchor::{
    FactoryReleaseStateTransparencyExternalAnchorVerificationReport,
    MAX_EXTERNAL_ANCHOR_AUDIT_PATH,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_REPORT_BYTES,
    SignedFactoryReleaseTransparencyExternalTreeHead, external_tree_head_schema,
    external_tree_head_sha256, factory_release_state_transparency_external_anchor_policy_sha256,
    factory_release_state_transparency_external_anchor_report_json_schema,
    parse_factory_release_state_transparency_external_anchor_policy,
    parse_factory_release_state_transparency_external_anchor_report,
    render_factory_release_state_transparency_external_anchor_policy,
    render_factory_release_state_transparency_external_anchor_report,
    validate_external_tree_head_shape, verify_external_tree_head_signature,
};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_SCOPE: &str =
    "factory-release-state-transparency-external-log-consistency-proof-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_VERIFICATION_SCOPE: &str =
    "verified-factory-release-state-transparency-external-log-consistency-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES: u64 =
    8 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION: u64 =
    10_000;

const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-consistency-report:v1\0";
const FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-consistency-filename:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalConsistencyProof {
    pub(crate) schema_version: u32,
    pub(crate) proof_scope: String,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) external_log_id: String,
    pub(crate) previous_tree_head_sha256: String,
    pub(crate) current_tree_head_sha256: String,
    pub(crate) previous_tree_head: SignedFactoryReleaseTransparencyExternalTreeHead,
    pub(crate) current_tree_head: SignedFactoryReleaseTransparencyExternalTreeHead,
    pub(crate) consistency_path: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalConsistencyVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) monotonic_state_chain_verified: bool,
    pub(crate) source_checkpoint_inclusion_verified: bool,
    pub(crate) complete_source_consistency_chain_verified: bool,
    pub(crate) source_log_append_only_consistency_verified: bool,
    pub(crate) witness_quorum_verified: bool,
    pub(crate) external_anchor_verified: bool,
    pub(crate) external_anchor_report_identity_verified: bool,
    pub(crate) external_anchor_policy_pin_matched: bool,
    pub(crate) external_log_policy_matched: bool,
    pub(crate) previous_external_tree_head_signature_verified: bool,
    pub(crate) current_external_tree_head_signature_verified: bool,
    pub(crate) same_external_log_and_key_verified: bool,
    pub(crate) strict_external_tree_extension_verified: bool,
    pub(crate) external_consistency_proof_verified: bool,
    pub(crate) complete_external_consistency_chain_verified: bool,
    pub(crate) external_log_append_only_consistency_verified: bool,
    pub(crate) current_external_checkpoint_fresh_at_evaluation: bool,
    pub(crate) selected_ledger_external_consistency_report_committed: bool,
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
    pub(crate) external_consistency_generation: u64,
    pub(crate) anchor_external_tree_head_sha256: String,
    pub(crate) previous_external_tree_head_sha256: String,
    pub(crate) current_external_tree_head_sha256: String,
    pub(crate) previous_external_tree_size: u64,
    pub(crate) current_external_tree_size: u64,
    pub(crate) previous_external_root_sha256: String,
    pub(crate) current_external_root_sha256: String,
    pub(crate) previous_external_tree_head_observed_at_unix: u64,
    pub(crate) current_external_tree_head_observed_at_unix: u64,
    pub(crate) chain_anchor_external_anchor_report_artifact: ExactArtifactIdentity,
    pub(crate) previous_external_consistency_report_artifact: Option<ExactArtifactIdentity>,
    pub(crate) external_anchor_policy_artifact: ExactArtifactIdentity,
    pub(crate) consistency_proof_artifact: ExactArtifactIdentity,
    pub(crate) external_anchor_report:
        FactoryReleaseStateTransparencyExternalAnchorVerificationReport,
    pub(crate) consistency_proof: FactoryReleaseStateTransparencyExternalConsistencyProof,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct FilenameContext<'a> {
    source_log_id: &'a str,
    witness_policy_sha256: &'a str,
    external_log_id: &'a str,
    external_anchor_policy_sha256: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_external_consistency(
    external_anchor_report_source: &[u8],
    external_anchor_policy_source: &[u8],
    expected_external_anchor_policy_sha256: &str,
    expected_external_log_id: &str,
    complete_factory_release_chain_verified: bool,
    complete_external_consistency_chain_verified: bool,
    external_consistency_generation: u64,
    previous_external_consistency_report_artifact: Option<ExactArtifactIdentity>,
    expected_previous_tree_head: &SignedFactoryReleaseTransparencyExternalTreeHead,
    consistency_proof_source: &[u8],
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyExternalConsistencyVerificationReport, String> {
    if !complete_factory_release_chain_verified || !complete_external_consistency_chain_verified {
        return Err(
            "factory release transparency external consistency requires complete verified local chains"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external consistency evaluation time is outside its bound"
                .into(),
        );
    }
    validate_predecessor(
        external_consistency_generation,
        &previous_external_consistency_report_artifact,
    )?;
    validate_slug(
        expected_external_log_id,
        "expected factory release transparency external log id",
    )?;
    validate_digest(
        expected_external_anchor_policy_sha256,
        "expected factory release transparency external-anchor policy SHA-256",
    )?;

    let external_anchor_report = parse_factory_release_state_transparency_external_anchor_report(
        external_anchor_report_source,
    )?;
    let chain_anchor_external_anchor_report_artifact =
        exact_identity(external_anchor_report_source);
    let external_anchor_policy = parse_factory_release_state_transparency_external_anchor_policy(
        external_anchor_policy_source,
    )?;
    let external_anchor_policy_artifact = exact_identity(external_anchor_policy_source);
    let actual_external_anchor_policy_sha256 =
        factory_release_state_transparency_external_anchor_policy_sha256(&external_anchor_policy)?;
    if actual_external_anchor_policy_sha256 != expected_external_anchor_policy_sha256 {
        return Err(
            "factory release transparency external consistency policy pin does not match".into(),
        );
    }
    if external_anchor_report.external_anchor_policy_sha256 != actual_external_anchor_policy_sha256
        || external_anchor_report.external_anchor_policy_artifact != external_anchor_policy_artifact
        || external_anchor_report.external_anchor_policy != external_anchor_policy
    {
        return Err(
            "factory release transparency external consistency anchor uses a different policy"
                .into(),
        );
    }
    if external_anchor_report.external_log_id != expected_external_log_id {
        return Err(
            "factory release transparency external consistency anchor uses a different log".into(),
        );
    }
    let trusted_log = external_anchor_policy
        .trusted_logs
        .iter()
        .find(|trusted| trusted.log_id == expected_external_log_id)
        .ok_or_else(|| {
            "factory release transparency external consistency log is not trusted by policy"
                .to_string()
        })?;

    let consistency_proof = parse_factory_release_state_transparency_external_consistency_proof(
        consistency_proof_source,
    )?;
    let consistency_proof_artifact = exact_identity(consistency_proof_source);
    if consistency_proof.external_anchor_policy_sha256 != actual_external_anchor_policy_sha256
        || consistency_proof.external_log_id != expected_external_log_id
    {
        return Err(
            "factory release transparency external consistency proof binds a different context"
                .into(),
        );
    }
    if consistency_proof.previous_tree_head != *expected_previous_tree_head {
        return Err(
            "factory release transparency external consistency proof does not extend the selected retained head"
                .into(),
        );
    }
    if external_consistency_generation == 1
        && consistency_proof.previous_tree_head != external_anchor_report.anchor_proof.tree_head
    {
        return Err(
            "factory release transparency external consistency generation 1 does not extend its external anchor"
                .into(),
        );
    }
    for head in [
        &consistency_proof.previous_tree_head,
        &consistency_proof.current_tree_head,
    ] {
        if head.log_id != trusted_log.log_id
            || head.algorithm != trusted_log.algorithm
            || head.public_key != trusted_log.public_key
        {
            return Err(
                "factory release transparency external consistency tree head does not match the selected policy log"
                    .into(),
            );
        }
    }

    // Authenticate both selected views before interpreting their ordering or
    // any claimed Merkle consistency relationship.
    verify_external_tree_head_signature(&consistency_proof.previous_tree_head)?;
    verify_external_tree_head_signature(&consistency_proof.current_tree_head)?;

    let previous_tree_head_sha256 =
        external_tree_head_sha256(&consistency_proof.previous_tree_head)?;
    let current_tree_head_sha256 = external_tree_head_sha256(&consistency_proof.current_tree_head)?;
    if consistency_proof.previous_tree_head_sha256 != previous_tree_head_sha256
        || consistency_proof.current_tree_head_sha256 != current_tree_head_sha256
    {
        return Err(
            "factory release transparency external consistency proof binds different tree heads"
                .into(),
        );
    }
    validate_head_pair(
        &consistency_proof.previous_tree_head,
        &consistency_proof.current_tree_head,
    )?;
    verify_consistency_path(
        &consistency_proof.previous_tree_head,
        &consistency_proof.current_tree_head,
        &consistency_proof.consistency_path,
    )?;
    let current_head = &consistency_proof.current_tree_head;
    if current_head.observed_at_unix > evaluated_at_unix
        || evaluated_at_unix - current_head.observed_at_unix
            > external_anchor_policy.maximum_checkpoint_age_seconds
    {
        return Err(
            "factory release transparency external consistency current checkpoint is stale or future-dated"
                .into(),
        );
    }

    let anchor_head = &external_anchor_report.anchor_proof.tree_head;
    let mut report = FactoryReleaseStateTransparencyExternalConsistencyVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_SCHEMA_VERSION,
        verification_scope:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_VERIFICATION_SCOPE.into(),
        status: "verified".into(),
        monotonic_state_chain_verified: true,
        source_checkpoint_inclusion_verified: true,
        complete_source_consistency_chain_verified: true,
        source_log_append_only_consistency_verified: true,
        witness_quorum_verified: true,
        external_anchor_verified: true,
        external_anchor_report_identity_verified: true,
        external_anchor_policy_pin_matched: true,
        external_log_policy_matched: true,
        previous_external_tree_head_signature_verified: true,
        current_external_tree_head_signature_verified: true,
        same_external_log_and_key_verified: true,
        strict_external_tree_extension_verified: true,
        external_consistency_proof_verified: true,
        complete_external_consistency_chain_verified: true,
        external_log_append_only_consistency_verified: true,
        current_external_checkpoint_fresh_at_evaluation: true,
        selected_ledger_external_consistency_report_committed: false,
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
        idempotency_key: external_anchor_report.idempotency_key.clone(),
        source_log_id: external_anchor_report.source_log_id.clone(),
        anchor_checkpoint_generation: external_anchor_report.checkpoint_generation,
        anchor_state_sequence: external_anchor_report.current_state_sequence,
        witness_policy_sha256: external_anchor_report.witness_policy_sha256.clone(),
        external_anchor_policy_sha256: actual_external_anchor_policy_sha256,
        external_log_id: expected_external_log_id.into(),
        external_consistency_generation,
        anchor_external_tree_head_sha256: external_tree_head_sha256(anchor_head)?,
        previous_external_tree_head_sha256: previous_tree_head_sha256,
        current_external_tree_head_sha256: current_tree_head_sha256,
        previous_external_tree_size: consistency_proof.previous_tree_head.tree_size,
        current_external_tree_size: current_head.tree_size,
        previous_external_root_sha256: consistency_proof.previous_tree_head.root_sha256.clone(),
        current_external_root_sha256: current_head.root_sha256.clone(),
        previous_external_tree_head_observed_at_unix: consistency_proof
            .previous_tree_head
            .observed_at_unix,
        current_external_tree_head_observed_at_unix: current_head.observed_at_unix,
        chain_anchor_external_anchor_report_artifact,
        previous_external_consistency_report_artifact,
        external_anchor_policy_artifact,
        consistency_proof_artifact,
        external_anchor_report,
        consistency_proof,
        evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_report_shape(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_consistency_proof(
    proof: &FactoryReleaseStateTransparencyExternalConsistencyProof,
) -> Result<Vec<u8>, String> {
    validate_proof_shape(proof)?;
    render_bounded(
        proof,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
        "factory release state transparency external consistency proof",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_consistency_proof(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalConsistencyProof, String> {
    let proof = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
        "factory release state transparency external consistency proof",
    )?;
    validate_proof_shape(&proof)?;
    Ok(proof)
}

pub(crate) fn render_factory_release_state_transparency_external_consistency_report(
    report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES,
        "factory release state transparency external consistency verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_consistency_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalConsistencyVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES,
        "factory release state transparency external consistency verification report",
    )?;
    validate_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn factory_release_state_transparency_external_consistency_filename(
    idempotency_key: &str,
    source_log_id: &str,
    witness_policy_sha256: &str,
    external_log_id: &str,
    external_anchor_policy_sha256: &str,
    generation: u64,
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
        .contains(&generation)
    {
        return Err(
            "factory release transparency external consistency generation is outside its bound"
                .into(),
        );
    }
    let context = FilenameContext {
        source_log_id,
        witness_policy_sha256,
        external_log_id,
        external_anchor_policy_sha256,
    };
    let digest = domain_hash(
        FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external consistency filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-consistency-v1-{idempotency_key}-{generation:04}-{}.json",
        &digest[..32]
    ))
}

pub(crate) fn validate_head_pair(
    previous: &SignedFactoryReleaseTransparencyExternalTreeHead,
    current: &SignedFactoryReleaseTransparencyExternalTreeHead,
) -> Result<(), String> {
    validate_external_tree_head_shape(previous)?;
    validate_external_tree_head_shape(current)?;
    if previous.log_id != current.log_id {
        return Err(
            "factory release transparency external consistency log identity changed".into(),
        );
    }
    if previous.algorithm != current.algorithm || previous.public_key != current.public_key {
        return Err("factory release transparency external consistency log key changed".into());
    }
    if current.tree_size < previous.tree_size {
        return Err("factory release transparency external tree size rolled back".into());
    }
    if current.tree_size == previous.tree_size {
        if current.root_sha256 != previous.root_sha256 {
            return Err(
                "factory release transparency external log equivocated at one tree size".into(),
            );
        }
        return Err(
            "factory release transparency external consistency requires a strict tree extension"
                .into(),
        );
    }
    if current.observed_at_unix < previous.observed_at_unix {
        return Err(
            "factory release transparency external tree-head observation time rolled back".into(),
        );
    }
    Ok(())
}

pub(crate) fn verify_consistency_path(
    previous: &SignedFactoryReleaseTransparencyExternalTreeHead,
    current: &SignedFactoryReleaseTransparencyExternalTreeHead,
    encoded_path: &[String],
) -> Result<(), String> {
    let path = encoded_path
        .iter()
        .map(|node| {
            decode_hex::<32>(
                node,
                "factory release transparency external consistency node",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trusted_previous_root = decode_hex::<32>(
        &previous.root_sha256,
        "factory release transparency previous external root",
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
            "factory release transparency external consistency path does not reconstruct both signed roots"
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
    let node = path.get(*cursor).copied().ok_or_else(|| {
        "factory release transparency external consistency path is incomplete".to_string()
    })?;
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

fn validate_proof_shape(
    proof: &FactoryReleaseStateTransparencyExternalConsistencyProof,
) -> Result<(), String> {
    if proof.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_SCHEMA_VERSION
        || proof.proof_scope != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_SCOPE
        || proof.consistency_path.is_empty()
        || proof.consistency_path.len() > MAX_EXTERNAL_ANCHOR_AUDIT_PATH
    {
        return Err(
            "factory release transparency external consistency proof invariants are invalid".into(),
        );
    }
    validate_digest(
        &proof.external_anchor_policy_sha256,
        "factory release transparency external-anchor policy SHA-256",
    )?;
    validate_slug(
        &proof.external_log_id,
        "factory release transparency external log id",
    )?;
    validate_digest(
        &proof.previous_tree_head_sha256,
        "factory release transparency previous external tree-head SHA-256",
    )?;
    validate_digest(
        &proof.current_tree_head_sha256,
        "factory release transparency current external tree-head SHA-256",
    )?;
    if proof.previous_tree_head_sha256 == proof.current_tree_head_sha256 {
        return Err(
            "factory release transparency external consistency proof tree heads are identical"
                .into(),
        );
    }
    validate_external_tree_head_shape(&proof.previous_tree_head)?;
    validate_external_tree_head_shape(&proof.current_tree_head)?;
    for node in &proof.consistency_path {
        validate_digest(
            node,
            "factory release transparency external consistency node",
        )?;
    }
    Ok(())
}

fn validate_predecessor(
    generation: u64,
    previous: &Option<ExactArtifactIdentity>,
) -> Result<(), String> {
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION)
        .contains(&generation)
    {
        return Err(
            "factory release transparency external consistency generation is outside its bound"
                .into(),
        );
    }
    match (generation, previous) {
        (1, None) => Ok(()),
        (2.., Some(identity)) => validate_artifact_identity(
            identity,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES,
            "previous factory release transparency external consistency report",
        ),
        _ => Err("factory release transparency external consistency predecessor is invalid".into()),
    }
}

fn validate_report_shape(
    report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
) -> Result<(), String> {
    let positives = [
        report.monotonic_state_chain_verified,
        report.source_checkpoint_inclusion_verified,
        report.complete_source_consistency_chain_verified,
        report.source_log_append_only_consistency_verified,
        report.witness_quorum_verified,
        report.external_anchor_verified,
        report.external_anchor_report_identity_verified,
        report.external_anchor_policy_pin_matched,
        report.external_log_policy_matched,
        report.previous_external_tree_head_signature_verified,
        report.current_external_tree_head_signature_verified,
        report.same_external_log_and_key_verified,
        report.strict_external_tree_extension_verified,
        report.external_consistency_proof_verified,
        report.complete_external_consistency_chain_verified,
        report.external_log_append_only_consistency_verified,
        report.current_external_checkpoint_fresh_at_evaluation,
    ];
    let negatives = [
        report.selected_ledger_external_consistency_report_committed,
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
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_VERIFICATION_SCOPE
        || report.status != "verified"
        || positives.contains(&false)
        || negatives.contains(&true)
        || report.binding_sha256 != report_binding(report)?
    {
        return Err(
            "factory release transparency external consistency report claims are invalid".into(),
        );
    }
    validate_predecessor(
        report.external_consistency_generation,
        &report.previous_external_consistency_report_artifact,
    )?;
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
        .contains(&report.anchor_checkpoint_generation)
        || report.anchor_state_sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        || report.previous_external_tree_size == 0
        || report.current_external_tree_size <= report.previous_external_tree_size
        || report.current_external_tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || report.previous_external_tree_head_observed_at_unix
            > report.current_external_tree_head_observed_at_unix
        || report.current_external_tree_head_observed_at_unix > report.evaluated_at_unix
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || report.evaluated_at_unix - report.current_external_tree_head_observed_at_unix
            > report
                .external_anchor_report
                .external_anchor_policy
                .maximum_checkpoint_age_seconds
    {
        return Err(
            "factory release transparency external consistency report bounds are invalid".into(),
        );
    }
    for (value, label) in [
        (
            &report.witness_policy_sha256,
            "factory release transparency witness policy SHA-256",
        ),
        (
            &report.external_anchor_policy_sha256,
            "factory release transparency external-anchor policy SHA-256",
        ),
        (
            &report.anchor_external_tree_head_sha256,
            "factory release transparency anchor external tree-head SHA-256",
        ),
        (
            &report.previous_external_tree_head_sha256,
            "factory release transparency previous external tree-head SHA-256",
        ),
        (
            &report.current_external_tree_head_sha256,
            "factory release transparency current external tree-head SHA-256",
        ),
        (
            &report.previous_external_root_sha256,
            "factory release transparency previous external root SHA-256",
        ),
        (
            &report.current_external_root_sha256,
            "factory release transparency current external root SHA-256",
        ),
        (
            &report.binding_sha256,
            "factory release transparency external consistency report binding",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_artifact_identity(
        &report.chain_anchor_external_anchor_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_REPORT_BYTES,
        "factory release transparency external anchor report",
    )?;
    validate_artifact_identity(
        &report.external_anchor_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
        "factory release transparency external-anchor policy",
    )?;
    validate_artifact_identity(
        &report.consistency_proof_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
        "factory release transparency external consistency proof",
    )?;
    Ok(())
}

fn validate_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
) -> Result<(), String> {
    validate_report_shape(report)?;
    let anchor_source = render_factory_release_state_transparency_external_anchor_report(
        &report.external_anchor_report,
    )?;
    let policy_source = render_factory_release_state_transparency_external_anchor_policy(
        &report.external_anchor_report.external_anchor_policy,
    )?;
    let proof_source = render_factory_release_state_transparency_external_consistency_proof(
        &report.consistency_proof,
    )?;
    if exact_identity(&anchor_source) != report.chain_anchor_external_anchor_report_artifact
        || exact_identity(&policy_source) != report.external_anchor_policy_artifact
        || exact_identity(&proof_source) != report.consistency_proof_artifact
    {
        return Err(
            "factory release transparency external consistency embedded artifact identity is invalid"
                .into(),
        );
    }
    let expected = verify_factory_release_state_transparency_external_consistency(
        &anchor_source,
        &policy_source,
        &report.external_anchor_policy_sha256,
        &report.external_log_id,
        true,
        true,
        report.external_consistency_generation,
        report.previous_external_consistency_report_artifact.clone(),
        &report.consistency_proof.previous_tree_head,
        &proof_source,
        report.evaluated_at_unix,
    )?;
    if &expected != report {
        return Err(
            "factory release transparency external consistency report binding is invalid".into(),
        );
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
) -> Result<String, String> {
    let mut unbound = report.clone();
    unbound.binding_sha256.clear();
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &unbound,
        "factory release transparency external consistency report binding",
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

pub(crate) fn factory_release_state_transparency_external_consistency_proof_json_schema() -> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-consistency-proof-v1.json",
        "title": "pcbex factory-release state transparency external-log consistency proof",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "proof_scope", "external_anchor_policy_sha256",
            "external_log_id", "previous_tree_head_sha256", "current_tree_head_sha256",
            "previous_tree_head", "current_tree_head", "consistency_path"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_SCHEMA_VERSION},
            "proof_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_SCOPE},
            "external_anchor_policy_sha256": digest.clone(),
            "external_log_id": slug_schema(),
            "previous_tree_head_sha256": digest.clone(),
            "current_tree_head_sha256": digest.clone(),
            "previous_tree_head": external_tree_head_schema(),
            "current_tree_head": external_tree_head_schema(),
            "consistency_path": {
                "type": "array", "minItems": 1,
                "maxItems": MAX_EXTERNAL_ANCHOR_AUDIT_PATH,
                "items": digest
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_consistency_report_json_schema() -> Value
{
    let digest = digest_schema();
    let artifact = artifact_schema();
    let nullable_artifact = json!({"oneOf": [artifact.clone(), {"type": "null"}]});
    let mut anchor_report = factory_release_state_transparency_external_anchor_report_json_schema();
    remove_schema_metadata(&mut anchor_report);
    let mut proof = factory_release_state_transparency_external_consistency_proof_json_schema();
    remove_schema_metadata(&mut proof);
    let positive = [
        "monotonic_state_chain_verified",
        "source_checkpoint_inclusion_verified",
        "complete_source_consistency_chain_verified",
        "source_log_append_only_consistency_verified",
        "witness_quorum_verified",
        "external_anchor_verified",
        "external_anchor_report_identity_verified",
        "external_anchor_policy_pin_matched",
        "external_log_policy_matched",
        "previous_external_tree_head_signature_verified",
        "current_external_tree_head_signature_verified",
        "same_external_log_and_key_verified",
        "strict_external_tree_extension_verified",
        "external_consistency_proof_verified",
        "complete_external_consistency_chain_verified",
        "external_log_append_only_consistency_verified",
        "current_external_checkpoint_fresh_at_evaluation",
    ];
    let negative = [
        "selected_ledger_external_consistency_report_committed",
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
        json!({"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_VERIFICATION_SCOPE}),
    );
    properties.insert("status".into(), json!({"const": "verified"}));
    for name in positive {
        properties.insert(name.into(), json!({"const": true}));
    }
    for name in negative {
        properties.insert(name.into(), json!({"const": false}));
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
        "external_consistency_generation".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION}),
    );
    for name in [
        "anchor_external_tree_head_sha256",
        "previous_external_tree_head_sha256",
        "current_external_tree_head_sha256",
        "previous_external_root_sha256",
        "current_external_root_sha256",
        "binding_sha256",
    ] {
        properties.insert(name.into(), digest.clone());
    }
    properties.insert(
        "previous_external_tree_size".into(),
        json!({"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE}),
    );
    properties.insert(
        "current_external_tree_size".into(),
        json!({"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE}),
    );
    for name in [
        "previous_external_tree_head_observed_at_unix",
        "current_external_tree_head_observed_at_unix",
        "evaluated_at_unix",
    ] {
        properties.insert(
            name.into(),
            json!({"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}),
        );
    }
    properties.insert(
        "chain_anchor_external_anchor_report_artifact".into(),
        artifact.clone(),
    );
    properties.insert(
        "previous_external_consistency_report_artifact".into(),
        nullable_artifact,
    );
    properties.insert("external_anchor_policy_artifact".into(), artifact.clone());
    properties.insert("consistency_proof_artifact".into(), artifact);
    properties.insert("external_anchor_report".into(), anchor_report);
    properties.insert("consistency_proof".into(), proof);
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
                "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-consistency-verification-report-v1.json"
            ),
        ),
        (
            "title".into(),
            json!(
                "pcbex factory-release state transparency external-log consistency verification report"
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

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn artifact_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES
            },
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
    use ed25519_dalek::{Signer, SigningKey};

    fn leaf(value: u8) -> [u8; 32] {
        Sha256::digest([value]).into()
    }

    fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let split = 1_usize << (usize::BITS - (leaves.len() - 1).leading_zeros() - 1);
        merkle_node_hash(root(&leaves[..split]), root(&leaves[split..]))
    }

    fn consistency_path(leaves: &[[u8; 32]], old_size: usize) -> Vec<[u8; 32]> {
        fn subproof(old_size: usize, leaves: &[[u8; 32]], complete_subtree: bool) -> Vec<[u8; 32]> {
            if old_size == leaves.len() {
                return if complete_subtree {
                    Vec::new()
                } else {
                    vec![root(leaves)]
                };
            }
            let split = 1_usize << (usize::BITS - (leaves.len() - 1).leading_zeros() - 1);
            if old_size <= split {
                let mut proof = subproof(old_size, &leaves[..split], complete_subtree);
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
        tree_size: usize,
        root_sha256: String,
        observed_at_unix: u64,
    ) -> SignedFactoryReleaseTransparencyExternalTreeHead {
        let mut head = SignedFactoryReleaseTransparencyExternalTreeHead {
            schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_SCHEMA_VERSION,
            tree_head_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_TREE_HEAD_SCOPE
                .into(),
            log_id: "public-log".into(),
            tree_size: tree_size as u64,
            root_sha256,
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
        key: &SigningKey,
        leaves: &[[u8; 32]],
        old_size: usize,
    ) -> FactoryReleaseStateTransparencyExternalConsistencyProof {
        let previous = signed_head(key, old_size, hex::encode(root(&leaves[..old_size])), 100);
        let current = signed_head(key, leaves.len(), hex::encode(root(leaves)), 101);
        FactoryReleaseStateTransparencyExternalConsistencyProof {
            schema_version: 1,
            proof_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_SCOPE.into(),
            external_anchor_policy_sha256: "ab".repeat(32),
            external_log_id: "public-log".into(),
            previous_tree_head_sha256: external_tree_head_sha256(&previous).unwrap(),
            current_tree_head_sha256: external_tree_head_sha256(&current).unwrap(),
            previous_tree_head: previous,
            current_tree_head: current,
            consistency_path: consistency_path(leaves, old_size)
                .into_iter()
                .map(hex::encode)
                .collect(),
        }
    }

    #[test]
    fn verifies_balanced_and_unbalanced_external_tree_extensions() {
        let key = SigningKey::from_bytes(&[19; 32]);
        for new_size in [2_usize, 3, 4, 5, 7, 8, 13] {
            let leaves = (0..new_size)
                .map(|index| leaf(index as u8))
                .collect::<Vec<_>>();
            for old_size in 1..new_size {
                let proof = proof(&key, &leaves, old_size);
                verify_external_tree_head_signature(&proof.previous_tree_head).unwrap();
                verify_external_tree_head_signature(&proof.current_tree_head).unwrap();
                validate_head_pair(&proof.previous_tree_head, &proof.current_tree_head).unwrap();
                verify_consistency_path(
                    &proof.previous_tree_head,
                    &proof.current_tree_head,
                    &proof.consistency_path,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn rejects_tampering_rollback_equivocation_and_key_substitution() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let other = SigningKey::from_bytes(&[20; 32]);
        let leaves = (0..5).map(leaf).collect::<Vec<_>>();
        let valid = proof(&key, &leaves, 3);

        let mut tampered = valid.clone();
        tampered.consistency_path[0] = "00".repeat(32);
        assert!(
            verify_consistency_path(
                &tampered.previous_tree_head,
                &tampered.current_tree_head,
                &tampered.consistency_path,
            )
            .is_err()
        );

        assert!(validate_head_pair(&valid.current_tree_head, &valid.previous_tree_head).is_err());
        let mut equivocation = valid.previous_tree_head.clone();
        equivocation.root_sha256 = "11".repeat(32);
        assert!(validate_head_pair(&valid.previous_tree_head, &equivocation).is_err());

        let substituted = signed_head(
            &other,
            valid.current_tree_head.tree_size as usize,
            valid.current_tree_head.root_sha256.clone(),
            valid.current_tree_head.observed_at_unix,
        );
        assert!(validate_head_pair(&valid.previous_tree_head, &substituted).is_err());

        let mut unauthenticated = valid.current_tree_head;
        unauthenticated.root_sha256 = "22".repeat(32);
        assert!(verify_external_tree_head_signature(&unauthenticated).is_err());
    }

    #[test]
    fn proof_parser_rejects_noncanonical_duplicate_and_uppercase_json() {
        let key = SigningKey::from_bytes(&[19; 32]);
        let leaves = (0..4).map(leaf).collect::<Vec<_>>();
        let proof = proof(&key, &leaves, 3);
        let canonical =
            render_factory_release_state_transparency_external_consistency_proof(&proof).unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_consistency_proof(&canonical)
                .unwrap(),
            proof
        );
        assert!(
            parse_factory_release_state_transparency_external_consistency_proof(
                &serde_json::to_vec(&proof).unwrap(),
            )
            .is_err()
        );
        let duplicate = String::from_utf8(canonical).unwrap().replacen(
            "{\n",
            "{\n  \"schema_version\": 1,\n",
            1,
        );
        assert!(
            parse_factory_release_state_transparency_external_consistency_proof(
                duplicate.as_bytes(),
            )
            .is_err()
        );
        let mut uppercase = proof;
        uppercase.current_tree_head_sha256 = uppercase.current_tree_head_sha256.to_uppercase();
        assert!(validate_proof_shape(&uppercase).is_err());
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
            factory_release_state_transparency_external_consistency_proof_json_schema(),
            factory_release_state_transparency_external_consistency_report_json_schema(),
        ] {
            walk(&schema);
        }
    }

    #[test]
    fn filename_is_bounded_and_binds_every_selected_context() {
        let key = "ab".repeat(32);
        let witness = "cd".repeat(32);
        let policy = "ef".repeat(32);
        let name = factory_release_state_transparency_external_consistency_filename(
            &key,
            "source-log",
            &witness,
            "public-log",
            &policy,
            1,
        )
        .unwrap();
        assert!(name.len() < 255);
        assert!(name.contains(&format!("-{key}-0001-")));
        let changed = factory_release_state_transparency_external_consistency_filename(
            &key,
            "source-log",
            &witness,
            "other-public-log",
            &policy,
            1,
        )
        .unwrap();
        assert_ne!(name, changed);
    }
}
