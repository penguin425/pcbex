//! Bounded remote acquisition and exact-head observer quorum for external gossip.
//!
//! The v1.491 boundary acquires canonical v1.490 observation envelopes over a
//! bounded HTTPS adapter and requires policy-pinned observers from distinct
//! configured organizations to agree on one exact signed external-log head.
//! Every selected observation is independently replayed against the exact
//! latest v1.489 local head. Consistent but different heads do not form one
//! quorum. This remains selected-view evidence: it does not establish global
//! non-equivocation, real organization independence, trusted time, ledger
//! rollback resistance, legal identity, ordering, payment, or exactly-once
//! execution.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_adapter_monotonic_state::MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE;
use crate::factory_release_state_transparency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE;
use crate::factory_release_state_transparency_consistency::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION;
use crate::factory_release_state_transparency_external_anchor::{
    FactoryReleaseStateTransparencyExternalAnchorPolicy,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES,
    SignedFactoryReleaseTransparencyExternalTreeHead,
    factory_release_state_transparency_external_anchor_policy_sha256,
    parse_factory_release_state_transparency_external_anchor_policy,
    render_factory_release_state_transparency_external_anchor_policy,
};
use crate::factory_release_state_transparency_external_consistency::{
    FactoryReleaseStateTransparencyExternalConsistencyProof,
    FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES,
    factory_release_state_transparency_external_consistency_proof_json_schema,
    factory_release_state_transparency_external_consistency_report_json_schema,
    parse_factory_release_state_transparency_external_consistency_report,
    render_factory_release_state_transparency_external_consistency_proof,
    render_factory_release_state_transparency_external_consistency_report,
};
use crate::factory_release_state_transparency_external_gossip::{
    FactoryReleaseStateTransparencyExternalGossipVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
    SignedFactoryReleaseTransparencyExternalGossipReceipt,
    factory_release_state_transparency_external_gossip_receipt_json_schema,
    render_factory_release_state_transparency_external_gossip_receipt,
    verify_factory_release_state_transparency_external_gossip,
};
use ed25519_dalek::VerifyingKey;
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::{env, time::Duration};

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE: &str =
    "factory-release-state-transparency-external-gossip-quorum-policy-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_SCOPE: &str =
    "factory-release-state-transparency-external-gossip-observation-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_VERIFICATION_SCOPE:
    &str = "verified-factory-release-state-transparency-external-gossip-quorum-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_BYTES: u64 =
    256 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES: u64 =
    64 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_REPORT_BYTES: u64 =
    32 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS: usize = 100;

const MAX_REMOTE_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_QUORUM_RECEIPT_AGE_SECONDS: u64 = 24 * 60 * 60;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const REMOTE_PROTOCOL: &str =
    "pcbex-factory-release-state-transparency-external-gossip-observation-v1";
const REMOTE_ADAPTER: &str = "remote-factory-release-state-transparency-external-gossip-https-v1";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-quorum-report:v1\0";
const FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-quorum-filename:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustedFactoryReleaseTransparencyExternalGossipObserver {
    pub(crate) organization_id: String,
    pub(crate) observer_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
    pub(crate) schema_version: u32,
    pub(crate) policy_scope: String,
    pub(crate) policy_id: String,
    pub(crate) minimum_organizations: u32,
    pub(crate) maximum_receipt_age_seconds: u64,
    pub(crate) trusted_observers: Vec<TrustedFactoryReleaseTransparencyExternalGossipObserver>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipObservation {
    pub(crate) schema_version: u32,
    pub(crate) observation_scope: String,
    pub(crate) gossip_receipt: SignedFactoryReleaseTransparencyExternalGossipReceipt,
    pub(crate) consistency_proof: Option<FactoryReleaseStateTransparencyExternalConsistencyProof>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseStateTransparencyExternalGossipReceipt {
    pub(crate) schema_version: u32,
    pub(crate) adapter: String,
    pub(crate) endpoint: String,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) external_log_id: String,
    pub(crate) local_external_consistency_generation: u64,
    pub(crate) local_external_consistency_report_sha256: String,
    pub(crate) local_external_tree_head_sha256: String,
    pub(crate) observer_quorum_policy_sha256: String,
    pub(crate) organization_id: String,
    pub(crate) observer_id: String,
    pub(crate) observer_public_key: String,
    pub(crate) request_sha256: String,
    pub(crate) response_sha256: String,
    pub(crate) response_bytes: u64,
    pub(crate) gossip_receipt_sha256: String,
    pub(crate) consistency_proof_sha256: Option<String>,
    pub(crate) observed_external_tree_head_sha256: String,
    pub(crate) received_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipQuorumMember {
    pub(crate) organization_id: String,
    pub(crate) observer_id: String,
    pub(crate) observer_public_key: String,
    pub(crate) relationship: String,
    pub(crate) received_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) observation_artifact: ExactArtifactIdentity,
    pub(crate) transport_receipt_artifact: ExactArtifactIdentity,
    pub(crate) gossip_receipt_artifact: ExactArtifactIdentity,
    pub(crate) consistency_proof_artifact: Option<ExactArtifactIdentity>,
    pub(crate) observation: FactoryReleaseStateTransparencyExternalGossipObservation,
    pub(crate) transport_receipt: RemoteFactoryReleaseStateTransparencyExternalGossipReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport {
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
    pub(crate) external_anchor_policy_pin_matched: bool,
    pub(crate) observer_quorum_policy_pin_matched: bool,
    pub(crate) observer_policy_role_separation_verified: bool,
    pub(crate) bounded_remote_acquisition_receipts_verified: bool,
    pub(crate) observer_pins_matched: bool,
    pub(crate) observer_receipt_signatures_verified: bool,
    pub(crate) external_tree_relationships_verified: bool,
    pub(crate) exact_observed_head_agreement_verified: bool,
    pub(crate) observed_external_checkpoints_fresh_at_evaluation: bool,
    pub(crate) distinct_organization_quorum_verified: bool,
    pub(crate) selected_observer_quorum_verified: bool,
    pub(crate) selected_observer_split_view_detected: bool,
    pub(crate) selected_ledger_external_gossip_quorum_report_committed: bool,
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
    pub(crate) quorum_met: bool,
    pub(crate) idempotency_key: String,
    pub(crate) source_log_id: String,
    pub(crate) anchor_checkpoint_generation: u64,
    pub(crate) anchor_state_sequence: u64,
    pub(crate) witness_policy_sha256: String,
    pub(crate) external_anchor_policy_sha256: String,
    pub(crate) external_log_id: String,
    pub(crate) local_external_consistency_generation: u64,
    pub(crate) local_external_tree_head_sha256: String,
    pub(crate) local_external_tree_size: u64,
    pub(crate) local_external_root_sha256: String,
    pub(crate) agreed_observed_external_tree_head_sha256: String,
    pub(crate) agreed_observed_external_tree_size: u64,
    pub(crate) agreed_observed_external_root_sha256: String,
    pub(crate) agreed_observed_external_tree_head_observed_at_unix: u64,
    pub(crate) relationship: String,
    pub(crate) local_external_consistency_report_artifact: ExactArtifactIdentity,
    pub(crate) local_external_consistency_report:
        FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    pub(crate) external_anchor_policy_artifact: ExactArtifactIdentity,
    pub(crate) external_anchor_policy: FactoryReleaseStateTransparencyExternalAnchorPolicy,
    pub(crate) observer_quorum_policy_artifact: ExactArtifactIdentity,
    pub(crate) observer_quorum_policy_sha256: String,
    pub(crate) observer_quorum_policy: FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    pub(crate) minimum_organizations: u32,
    pub(crate) valid_observations: u32,
    pub(crate) distinct_organizations: u32,
    pub(crate) freshest_received_at_unix: u64,
    pub(crate) earliest_expires_at_unix: u64,
    pub(crate) members: Vec<FactoryReleaseStateTransparencyExternalGossipQuorumMember>,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct RemoteGossipRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    external_anchor_policy_sha256: &'a str,
    external_log_id: &'a str,
    local_external_consistency_generation: u64,
    local_external_tree_head_sha256: &'a str,
    local_external_tree_head: &'a SignedFactoryReleaseTransparencyExternalTreeHead,
    observer_quorum_policy_sha256: &'a str,
    organization_id: &'a str,
    observer_id: &'a str,
}

#[derive(Serialize)]
struct FilenameContext<'a> {
    source_log_id: &'a str,
    witness_policy_sha256: &'a str,
    external_log_id: &'a str,
    external_anchor_policy_sha256: &'a str,
    local_external_consistency_generation: u64,
    observer_quorum_policy_sha256: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExactObservedHead {
    sha256: String,
    tree_size: u64,
    root_sha256: String,
    observed_at_unix: u64,
    relationship: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_state_transparency_external_gossip_observation(
    local_external_consistency_report_source: &[u8],
    external_anchor_policy_source: &[u8],
    expected_external_anchor_policy_sha256: &str,
    expected_external_log_id: &str,
    observer_quorum_policy_source: &[u8],
    expected_observer_quorum_policy_sha256: &str,
    organization_id: &str,
    observer_id: &str,
    endpoint: &str,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        FactoryReleaseStateTransparencyExternalGossipObservation,
        RemoteFactoryReleaseStateTransparencyExternalGossipReceipt,
    ),
    String,
> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err(
            "remote factory release transparency external gossip timeout must be between 1 and 600 seconds"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release transparency external gossip evaluation time is outside its bound"
                .into(),
        );
    }
    validate_endpoint(endpoint, allow_http_loopback)?;
    let local_report = parse_factory_release_state_transparency_external_consistency_report(
        local_external_consistency_report_source,
    )?;
    let external_policy = parse_factory_release_state_transparency_external_anchor_policy(
        external_anchor_policy_source,
    )?;
    let actual_external_policy_sha256 =
        factory_release_state_transparency_external_anchor_policy_sha256(&external_policy)?;
    validate_digest(
        expected_external_anchor_policy_sha256,
        "expected external-anchor policy SHA-256",
    )?;
    if actual_external_policy_sha256 != expected_external_anchor_policy_sha256
        || local_report.external_anchor_policy_sha256 != actual_external_policy_sha256
        || local_report.external_log_id != expected_external_log_id
    {
        return Err(
            "remote factory release transparency external gossip local context does not match the pinned external policy"
                .into(),
        );
    }
    let quorum_policy = parse_factory_release_state_transparency_external_gossip_quorum_policy(
        observer_quorum_policy_source,
    )?;
    let actual_quorum_policy_sha256 =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(&quorum_policy)?;
    validate_digest(
        expected_observer_quorum_policy_sha256,
        "expected external gossip observer-quorum policy SHA-256",
    )?;
    if actual_quorum_policy_sha256 != expected_observer_quorum_policy_sha256 {
        return Err(
            "factory release transparency external gossip observer-quorum policy pin does not match"
                .into(),
        );
    }
    validate_observer_policy_role_separation(&local_report, &quorum_policy)?;
    let trusted = trusted_observer(&quorum_policy, organization_id, observer_id)?;
    let request_bytes = remote_request_bytes(
        &local_report,
        &actual_quorum_policy_sha256,
        organization_id,
        observer_id,
    )?;
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
                "remote factory release transparency external gossip bearer-token environment {variable} is unset"
            )
        })?;
        if token.trim().is_empty() {
            return Err(format!(
                "remote factory release transparency external gossip bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call.send(request_bytes).map_err(|error| {
        format!("remote factory release transparency external gossip HTTPS request failed: {error}")
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote factory release transparency external gossip returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err(
            "remote factory release transparency external gossip response Content-Type must be application/json"
                .into(),
        );
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_REMOTE_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| {
            format!(
                "reading bounded remote factory release transparency external gossip response: {error}"
            )
        })?;
    if response_bytes.len() as u64 > MAX_REMOTE_RESPONSE_BYTES {
        return Err(format!(
            "remote factory release transparency external gossip response exceeds {MAX_REMOTE_RESPONSE_BYTES} bytes"
        ));
    }
    let observation =
        parse_factory_release_state_transparency_external_gossip_observation(&response_bytes)?;
    let single = verify_observation(
        local_external_consistency_report_source,
        external_anchor_policy_source,
        expected_external_anchor_policy_sha256,
        expected_external_log_id,
        trusted,
        &observation,
        evaluated_at_unix,
    )?;
    if evaluated_at_unix - single.observer_received_at_unix
        > quorum_policy.maximum_receipt_age_seconds
    {
        return Err(
            "remote factory release transparency external gossip receipt is older than the observer-quorum window"
                .into(),
        );
    }
    let receipt_source = render_factory_release_state_transparency_external_gossip_receipt(
        &observation.gossip_receipt,
    )?;
    let proof_source = observation
        .consistency_proof
        .as_ref()
        .map(render_factory_release_state_transparency_external_consistency_proof)
        .transpose()?;
    let transport = RemoteFactoryReleaseStateTransparencyExternalGossipReceipt {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION,
        adapter: REMOTE_ADAPTER.into(),
        endpoint: endpoint.into(),
        external_anchor_policy_sha256: actual_external_policy_sha256,
        external_log_id: expected_external_log_id.into(),
        local_external_consistency_generation: local_report.external_consistency_generation,
        local_external_consistency_report_sha256: sha256(local_external_consistency_report_source),
        local_external_tree_head_sha256: single.local_external_tree_head_sha256,
        observer_quorum_policy_sha256: actual_quorum_policy_sha256,
        organization_id: organization_id.into(),
        observer_id: observer_id.into(),
        observer_public_key: trusted.public_key.clone(),
        request_sha256,
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        gossip_receipt_sha256: sha256(&receipt_source),
        consistency_proof_sha256: proof_source.as_deref().map(sha256),
        observed_external_tree_head_sha256: single.observed_external_tree_head_sha256,
        received_at_unix: single.observer_received_at_unix,
        expires_at_unix: single.observer_expires_at_unix,
        evaluated_at_unix,
        verified: true,
    };
    validate_remote_transport_receipt_shape(&transport)?;
    Ok((observation, transport))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum(
    local_external_consistency_report_source: &[u8],
    external_anchor_policy_source: &[u8],
    expected_external_anchor_policy_sha256: &str,
    expected_external_log_id: &str,
    observer_quorum_policy_source: &[u8],
    expected_observer_quorum_policy_sha256: &str,
    observation_sources: &[Vec<u8>],
    transport_receipt_sources: &[Vec<u8>],
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport, String> {
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip quorum evaluation time is outside its bound"
                .into(),
        );
    }
    if observation_sources.is_empty()
        || observation_sources.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS
        || observation_sources.len() != transport_receipt_sources.len()
    {
        return Err(
            "factory release transparency external gossip observations and transport receipts must be non-empty, paired, and bounded"
                .into(),
        );
    }
    let local_report = parse_factory_release_state_transparency_external_consistency_report(
        local_external_consistency_report_source,
    )?;
    let local_report_artifact = exact_identity(local_external_consistency_report_source);
    let external_policy = parse_factory_release_state_transparency_external_anchor_policy(
        external_anchor_policy_source,
    )?;
    let external_policy_artifact = exact_identity(external_anchor_policy_source);
    let actual_external_policy_sha256 =
        factory_release_state_transparency_external_anchor_policy_sha256(&external_policy)?;
    if actual_external_policy_sha256 != expected_external_anchor_policy_sha256
        || local_report.external_anchor_policy_sha256 != actual_external_policy_sha256
        || local_report.external_log_id != expected_external_log_id
    {
        return Err(
            "factory release transparency external gossip quorum local context does not match the pinned external policy"
                .into(),
        );
    }
    let quorum_policy = parse_factory_release_state_transparency_external_gossip_quorum_policy(
        observer_quorum_policy_source,
    )?;
    let quorum_policy_artifact = exact_identity(observer_quorum_policy_source);
    let actual_quorum_policy_sha256 =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(&quorum_policy)?;
    if actual_quorum_policy_sha256 != expected_observer_quorum_policy_sha256 {
        return Err(
            "factory release transparency external gossip observer-quorum policy pin does not match"
                .into(),
        );
    }
    validate_observer_policy_role_separation(&local_report, &quorum_policy)?;
    let local_head = selected_local_head(&local_report)?;

    let mut organizations = HashSet::new();
    let mut observers = HashSet::new();
    let mut keys = HashSet::new();
    let mut observations = HashSet::new();
    let mut transports = HashSet::new();
    let mut gossip_receipts = HashSet::new();
    let mut agreed_head: Option<ExactObservedHead> = None;
    let mut members = Vec::with_capacity(observation_sources.len());
    for (observation_source, transport_source) in
        observation_sources.iter().zip(transport_receipt_sources)
    {
        let observation = parse_factory_release_state_transparency_external_gossip_observation(
            observation_source,
        )?;
        let transport = parse_remote_factory_release_state_transparency_external_gossip_receipt(
            transport_source,
        )?;
        let trusted = trusted_observer(
            &quorum_policy,
            &transport.organization_id,
            &transport.observer_id,
        )?;
        validate_transport_binding(
            &transport,
            observation_source,
            &observation,
            local_external_consistency_report_source,
            &local_report,
            &actual_external_policy_sha256,
            expected_external_log_id,
            &actual_quorum_policy_sha256,
            trusted,
        )?;
        if transport.evaluated_at_unix > evaluated_at_unix {
            return Err(
                "remote factory release transparency external gossip transport receipt is future-dated at quorum evaluation"
                    .into(),
            );
        }
        let single = verify_observation(
            local_external_consistency_report_source,
            external_anchor_policy_source,
            expected_external_anchor_policy_sha256,
            expected_external_log_id,
            trusted,
            &observation,
            evaluated_at_unix,
        )?;
        if evaluated_at_unix - single.observer_received_at_unix
            > quorum_policy.maximum_receipt_age_seconds
        {
            return Err(
                "factory release transparency external gossip quorum receipt is older than the configured quorum window"
                    .into(),
            );
        }
        let candidate = ExactObservedHead {
            sha256: single.observed_external_tree_head_sha256.clone(),
            tree_size: single.observed_external_tree_size,
            root_sha256: single.observed_external_root_sha256.clone(),
            observed_at_unix: single.observed_external_tree_head_observed_at_unix,
            relationship: single.relationship.clone(),
        };
        enforce_exact_head_agreement(agreed_head.as_ref(), &candidate)?;
        agreed_head.get_or_insert(candidate);

        let observation_artifact = exact_identity(observation_source);
        let transport_receipt_artifact = exact_identity(transport_source);
        let gossip_receipt_source =
            render_factory_release_state_transparency_external_gossip_receipt(
                &observation.gossip_receipt,
            )?;
        let gossip_receipt_artifact = exact_identity(&gossip_receipt_source);
        let consistency_proof_artifact = observation
            .consistency_proof
            .as_ref()
            .map(render_factory_release_state_transparency_external_consistency_proof)
            .transpose()?
            .as_deref()
            .map(exact_identity);
        if !organizations.insert(trusted.organization_id.clone()) {
            return Err(
                "factory release transparency external gossip quorum requires distinct organizations"
                    .into(),
            );
        }
        if !observers.insert(trusted.observer_id.clone()) {
            return Err(
                "factory release transparency external gossip quorum requires distinct observer identities"
                    .into(),
            );
        }
        if !keys.insert(trusted.public_key.clone()) {
            return Err(
                "factory release transparency external gossip quorum requires distinct observer keys"
                    .into(),
            );
        }
        if !observations.insert(observation_artifact.sha256.clone()) {
            return Err(
                "factory release transparency external gossip quorum rejects duplicate observations"
                    .into(),
            );
        }
        if !transports.insert(transport_receipt_artifact.sha256.clone()) {
            return Err(
                "factory release transparency external gossip quorum rejects duplicate transport receipts"
                    .into(),
            );
        }
        if !gossip_receipts.insert(gossip_receipt_artifact.sha256.clone()) {
            return Err(
                "factory release transparency external gossip quorum rejects duplicate signed receipts"
                    .into(),
            );
        }
        members.push(FactoryReleaseStateTransparencyExternalGossipQuorumMember {
            organization_id: trusted.organization_id.clone(),
            observer_id: trusted.observer_id.clone(),
            observer_public_key: trusted.public_key.clone(),
            relationship: single.relationship,
            received_at_unix: single.observer_received_at_unix,
            expires_at_unix: single.observer_expires_at_unix,
            observation_artifact,
            transport_receipt_artifact,
            gossip_receipt_artifact,
            consistency_proof_artifact,
            observation,
            transport_receipt: transport,
        });
    }
    members.sort_by(|left, right| {
        (&left.organization_id, &left.observer_id)
            .cmp(&(&right.organization_id, &right.observer_id))
    });
    let agreed_head = agreed_head.ok_or_else(|| {
        "factory release transparency external gossip quorum has no observed head".to_string()
    })?;
    let count = u32::try_from(members.len()).map_err(|_| {
        "factory release transparency external gossip observation count overflow".to_string()
    })?;
    let distinct_organizations = u32::try_from(organizations.len()).map_err(|_| {
        "factory release transparency external gossip organization count overflow".to_string()
    })?;
    let quorum_met = distinct_organizations >= quorum_policy.minimum_organizations;
    let mut report = FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION,
        verification_scope:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_VERIFICATION_SCOPE.into(),
        status: if quorum_met {
            "verified"
        } else {
            "insufficient_organizations"
        }
        .into(),
        monotonic_state_chain_verified: true,
        source_checkpoint_inclusion_verified: true,
        complete_source_consistency_chain_verified: true,
        source_log_append_only_consistency_verified: true,
        witness_quorum_verified: true,
        external_anchor_verified: true,
        complete_external_consistency_chain_verified: true,
        external_log_append_only_consistency_verified: true,
        local_external_consistency_report_identity_verified: true,
        external_anchor_policy_pin_matched: true,
        observer_quorum_policy_pin_matched: true,
        observer_policy_role_separation_verified: true,
        bounded_remote_acquisition_receipts_verified: true,
        observer_pins_matched: true,
        observer_receipt_signatures_verified: true,
        external_tree_relationships_verified: true,
        exact_observed_head_agreement_verified: true,
        observed_external_checkpoints_fresh_at_evaluation: true,
        distinct_organization_quorum_verified: quorum_met,
        selected_observer_quorum_verified: quorum_met,
        selected_observer_split_view_detected: false,
        selected_ledger_external_gossip_quorum_report_committed: false,
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
        quorum_met,
        idempotency_key: local_report.idempotency_key.clone(),
        source_log_id: local_report.source_log_id.clone(),
        anchor_checkpoint_generation: local_report.anchor_checkpoint_generation,
        anchor_state_sequence: local_report.anchor_state_sequence,
        witness_policy_sha256: local_report.witness_policy_sha256.clone(),
        external_anchor_policy_sha256: actual_external_policy_sha256,
        external_log_id: expected_external_log_id.into(),
        local_external_consistency_generation: local_report.external_consistency_generation,
        local_external_tree_head_sha256: local_report.current_external_tree_head_sha256.clone(),
        local_external_tree_size: local_head.tree_size,
        local_external_root_sha256: local_head.root_sha256.clone(),
        agreed_observed_external_tree_head_sha256: agreed_head.sha256,
        agreed_observed_external_tree_size: agreed_head.tree_size,
        agreed_observed_external_root_sha256: agreed_head.root_sha256,
        agreed_observed_external_tree_head_observed_at_unix: agreed_head.observed_at_unix,
        relationship: agreed_head.relationship,
        local_external_consistency_report_artifact: local_report_artifact,
        local_external_consistency_report: local_report,
        external_anchor_policy_artifact: external_policy_artifact,
        external_anchor_policy: external_policy,
        observer_quorum_policy_artifact: quorum_policy_artifact,
        observer_quorum_policy_sha256: actual_quorum_policy_sha256,
        observer_quorum_policy: quorum_policy.clone(),
        minimum_organizations: quorum_policy.minimum_organizations,
        valid_observations: count,
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
        evaluated_at_unix,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_quorum_report_shape(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn verify_observation(
    local_report_source: &[u8],
    external_policy_source: &[u8],
    expected_external_policy_sha256: &str,
    expected_external_log_id: &str,
    trusted: &TrustedFactoryReleaseTransparencyExternalGossipObserver,
    observation: &FactoryReleaseStateTransparencyExternalGossipObservation,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseStateTransparencyExternalGossipVerificationReport, String> {
    let receipt_source = render_factory_release_state_transparency_external_gossip_receipt(
        &observation.gossip_receipt,
    )?;
    let proof_source = observation
        .consistency_proof
        .as_ref()
        .map(render_factory_release_state_transparency_external_consistency_proof)
        .transpose()?;
    verify_factory_release_state_transparency_external_gossip(
        local_report_source,
        external_policy_source,
        expected_external_policy_sha256,
        expected_external_log_id,
        true,
        true,
        &trusted.observer_id,
        &trusted.public_key,
        &receipt_source,
        proof_source.as_deref(),
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_transport_binding(
    transport: &RemoteFactoryReleaseStateTransparencyExternalGossipReceipt,
    observation_source: &[u8],
    observation: &FactoryReleaseStateTransparencyExternalGossipObservation,
    local_report_source: &[u8],
    local_report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    expected_external_policy_sha256: &str,
    expected_external_log_id: &str,
    expected_quorum_policy_sha256: &str,
    trusted: &TrustedFactoryReleaseTransparencyExternalGossipObserver,
) -> Result<(), String> {
    let local_head = selected_local_head(local_report)?;
    let receipt_source = render_factory_release_state_transparency_external_gossip_receipt(
        &observation.gossip_receipt,
    )?;
    let proof_source = observation
        .consistency_proof
        .as_ref()
        .map(render_factory_release_state_transparency_external_consistency_proof)
        .transpose()?;
    let request_source = remote_request_bytes(
        local_report,
        expected_quorum_policy_sha256,
        &trusted.organization_id,
        &trusted.observer_id,
    )?;
    if transport.external_anchor_policy_sha256 != expected_external_policy_sha256
        || transport.external_log_id != expected_external_log_id
        || transport.local_external_consistency_generation
            != local_report.external_consistency_generation
        || transport.local_external_consistency_report_sha256 != sha256(local_report_source)
        || transport.local_external_tree_head_sha256
            != local_report.current_external_tree_head_sha256
        || transport.local_external_tree_head_sha256
            != crate::factory_release_state_transparency_external_anchor::external_tree_head_sha256(
                local_head,
            )?
        || transport.observer_quorum_policy_sha256 != expected_quorum_policy_sha256
        || transport.organization_id != trusted.organization_id
        || transport.observer_id != trusted.observer_id
        || transport.observer_public_key != trusted.public_key
        || transport.request_sha256 != sha256(&request_source)
        || transport.response_sha256 != sha256(observation_source)
        || transport.response_bytes != observation_source.len() as u64
        || transport.gossip_receipt_sha256 != sha256(&receipt_source)
        || transport.consistency_proof_sha256 != proof_source.as_deref().map(sha256)
        || transport.observed_external_tree_head_sha256
            != observation.gossip_receipt.observed_tree_head_sha256
        || transport.received_at_unix != observation.gossip_receipt.received_at_unix
        || transport.expires_at_unix != observation.gossip_receipt.expires_at_unix
    {
        return Err(
            "remote factory release transparency external gossip transport receipt does not bind the selected request and response"
                .into(),
        );
    }
    Ok(())
}

fn remote_request_bytes(
    local_report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    observer_quorum_policy_sha256: &str,
    organization_id: &str,
    observer_id: &str,
) -> Result<Vec<u8>, String> {
    let local_head = selected_local_head(local_report)?;
    serde_json::to_vec(&RemoteGossipRequest {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION,
        protocol: REMOTE_PROTOCOL,
        external_anchor_policy_sha256: &local_report.external_anchor_policy_sha256,
        external_log_id: &local_report.external_log_id,
        local_external_consistency_generation: local_report.external_consistency_generation,
        local_external_tree_head_sha256: &local_report.current_external_tree_head_sha256,
        local_external_tree_head: local_head,
        observer_quorum_policy_sha256,
        organization_id,
        observer_id,
    })
    .map_err(|error| {
        format!("serializing remote factory release transparency gossip request: {error}")
    })
}

fn selected_local_head(
    report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
) -> Result<&SignedFactoryReleaseTransparencyExternalTreeHead, String> {
    let head = &report.consistency_proof.current_tree_head;
    let digest =
        crate::factory_release_state_transparency_external_anchor::external_tree_head_sha256(head)?;
    if report.current_external_tree_head_sha256 != digest
        || report.current_external_tree_size != head.tree_size
        || report.current_external_root_sha256 != head.root_sha256
        || report.external_log_id != head.log_id
    {
        return Err(
            "factory release transparency external gossip quorum local report head is inconsistent"
                .into(),
        );
    }
    Ok(head)
}

fn trusted_observer<'a>(
    policy: &'a FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    organization_id: &str,
    observer_id: &str,
) -> Result<&'a TrustedFactoryReleaseTransparencyExternalGossipObserver, String> {
    policy
        .trusted_observers
        .iter()
        .find(|trusted| {
            trusted.organization_id == organization_id && trusted.observer_id == observer_id
        })
        .ok_or_else(|| {
            "factory release transparency external gossip observer is not trusted by quorum policy"
                .to_string()
        })
}

fn enforce_exact_head_agreement(
    expected: Option<&ExactObservedHead>,
    candidate: &ExactObservedHead,
) -> Result<(), String> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.sha256 == candidate.sha256
        && expected.tree_size == candidate.tree_size
        && expected.root_sha256 == candidate.root_sha256
        && expected.observed_at_unix == candidate.observed_at_unix
        && expected.relationship == candidate.relationship
    {
        return Ok(());
    }
    if expected.tree_size == candidate.tree_size && expected.root_sha256 != candidate.root_sha256 {
        return Err(
            "factory release transparency external gossip quorum detected split-view roots at one observer tree size"
                .into(),
        );
    }
    Err(
        "factory release transparency external gossip quorum requires every selected observer to agree on one exact signed head"
            .into(),
    )
}

fn validate_observer_policy_role_separation(
    local_report: &FactoryReleaseStateTransparencyExternalConsistencyVerificationReport,
    policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
) -> Result<(), String> {
    validate_quorum_policy(policy)?;
    let anchor = &local_report.external_anchor_report;
    let witness_report = &anchor.witness_quorum_report;
    let current_transparency = &witness_report
        .consistency_report
        .current_transparency_report;
    let mut assigned_ids = HashSet::new();
    assigned_ids.insert(local_report.source_log_id.as_str());
    assigned_ids.insert(local_report.external_log_id.as_str());
    assigned_ids.insert(current_transparency.factory_id.as_str());
    for trusted in &anchor.external_anchor_policy.trusted_logs {
        assigned_ids.insert(trusted.log_id.as_str());
    }
    for trusted in &witness_report.witness_policy.trusted_witnesses {
        assigned_ids.insert(trusted.organization_id.as_str());
        assigned_ids.insert(trusted.witness_id.as_str());
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
    for trusted in &witness_report.witness_policy.trusted_witnesses {
        assigned_keys.insert(trusted.public_key.as_str());
    }
    for observer in &policy.trusted_observers {
        if assigned_ids.contains(observer.organization_id.as_str())
            || assigned_ids.contains(observer.observer_id.as_str())
        {
            return Err(
                "factory release transparency external gossip quorum policy assigns an observer organization or identity to a log, witness, or factory role"
                    .into(),
            );
        }
        if assigned_keys.contains(observer.public_key.as_str()) {
            return Err(
                "factory release transparency external gossip quorum policy reuses a log or witness key"
                    .into(),
            );
        }
    }
    Ok(())
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_quorum_policy(
    policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
) -> Result<Vec<u8>, String> {
    validate_quorum_policy(policy)?;
    render_bounded(
        policy,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES,
        "factory release state transparency external gossip observer-quorum policy",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_quorum_policy(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipQuorumPolicy, String> {
    let policy = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES,
        "factory release state transparency external gossip observer-quorum policy",
    )?;
    validate_quorum_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn factory_release_state_transparency_external_gossip_quorum_policy_sha256(
    policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
) -> Result<String, String> {
    validate_quorum_policy(policy)?;
    let source = serde_json::to_vec(policy).map_err(|error| {
        format!(
            "serializing factory release transparency external gossip observer-quorum policy: {error}"
        )
    })?;
    Ok(sha256(&source))
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_observation(
    observation: &FactoryReleaseStateTransparencyExternalGossipObservation,
) -> Result<Vec<u8>, String> {
    validate_observation_shape(observation)?;
    render_bounded(
        observation,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_BYTES,
        "factory release state transparency external gossip observation",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_observation(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipObservation, String> {
    let observation = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_BYTES,
        "factory release state transparency external gossip observation",
    )?;
    validate_observation_shape(&observation)?;
    Ok(observation)
}

pub(crate) fn render_remote_factory_release_state_transparency_external_gossip_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipReceipt,
) -> Result<Vec<u8>, String> {
    validate_remote_transport_receipt_shape(receipt)?;
    render_bounded(
        receipt,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
        "remote factory release state transparency external gossip transport receipt",
    )
}

pub(crate) fn parse_remote_factory_release_state_transparency_external_gossip_receipt(
    source: &[u8],
) -> Result<RemoteFactoryReleaseStateTransparencyExternalGossipReceipt, String> {
    let receipt = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
        "remote factory release state transparency external gossip transport receipt",
    )?;
    validate_remote_transport_receipt_shape(&receipt)?;
    Ok(receipt)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_quorum_report(
    report: &FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_quorum_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_REPORT_BYTES,
        "factory release state transparency external gossip quorum verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_quorum_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_REPORT_BYTES,
        "factory release state transparency external gossip quorum verification report",
    )?;
    validate_quorum_report_self_contained(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn factory_release_state_transparency_external_gossip_quorum_filename(
    idempotency_key: &str,
    source_log_id: &str,
    witness_policy_sha256: &str,
    external_log_id: &str,
    external_anchor_policy_sha256: &str,
    local_external_consistency_generation: u64,
    observer_quorum_policy_sha256: &str,
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
    validate_digest(
        observer_quorum_policy_sha256,
        "factory release transparency external gossip observer-quorum policy SHA-256",
    )?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION)
        .contains(&local_external_consistency_generation)
    {
        return Err(
            "factory release transparency external gossip quorum local generation is outside its bound"
                .into(),
        );
    }
    let context = FilenameContext {
        source_log_id,
        witness_policy_sha256,
        external_log_id,
        external_anchor_policy_sha256,
        local_external_consistency_generation,
        observer_quorum_policy_sha256,
    };
    let context_sha256 = domain_hash(
        FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip quorum filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-quorum-v1-{idempotency_key}-{local_external_consistency_generation:04}-{}.json",
        &context_sha256[..32]
    ))
}

fn validate_quorum_policy(
    policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
) -> Result<(), String> {
    let count = policy.trusted_observers.len();
    if policy.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION
        || policy.policy_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE
        || !(2..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS as u32)
            .contains(&policy.minimum_organizations)
        || !(1..=MAX_QUORUM_RECEIPT_AGE_SECONDS).contains(&policy.maximum_receipt_age_seconds)
        || count < policy.minimum_organizations as usize
        || count > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS
    {
        return Err(
            "factory release state transparency external gossip observer-quorum policy invariants are invalid"
                .into(),
        );
    }
    validate_slug(
        &policy.policy_id,
        "factory release transparency external gossip observer-quorum policy id",
    )?;
    let mut organizations = HashSet::new();
    let mut observers = HashSet::new();
    let mut keys = HashSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for trusted in &policy.trusted_observers {
        validate_slug(
            &trusted.organization_id,
            "factory release transparency external gossip organization id",
        )?;
        validate_observer_slug(
            &trusted.observer_id,
            "factory release transparency external gossip observer id",
        )?;
        if trusted.algorithm != "ed25519" {
            return Err(
                "factory release transparency external gossip observer algorithm is unsupported"
                    .into(),
            );
        }
        validate_nonweak_public_key(
            &trusted.public_key,
            "factory release transparency external gossip observer public key",
        )?;
        let order = (
            trusted.organization_id.as_str(),
            trusted.observer_id.as_str(),
        );
        if previous.is_some_and(|previous| previous >= order) {
            return Err(
                "factory release transparency external gossip trusted observers are not canonically ordered"
                    .into(),
            );
        }
        previous = Some(order);
        if !organizations.insert(&trusted.organization_id) {
            return Err(
                "factory release transparency external gossip quorum policy requires distinct organizations"
                    .into(),
            );
        }
        if !observers.insert(&trusted.observer_id) {
            return Err(
                "factory release transparency external gossip quorum policy requires distinct observer identities"
                    .into(),
            );
        }
        if !keys.insert(&trusted.public_key) {
            return Err(
                "factory release transparency external gossip quorum policy requires distinct observer keys"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_observation_shape(
    observation: &FactoryReleaseStateTransparencyExternalGossipObservation,
) -> Result<(), String> {
    if observation.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION
        || observation.observation_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_SCOPE
    {
        return Err(
            "factory release state transparency external gossip observation invariants are invalid"
                .into(),
        );
    }
    render_factory_release_state_transparency_external_gossip_receipt(&observation.gossip_receipt)?;
    if let Some(proof) = &observation.consistency_proof {
        render_factory_release_state_transparency_external_consistency_proof(proof)?;
    }
    Ok(())
}

fn validate_remote_transport_receipt_shape(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipReceipt,
) -> Result<(), String> {
    if receipt.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION
        || receipt.adapter != REMOTE_ADAPTER
        || !receipt.verified
        || !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION)
            .contains(&receipt.local_external_consistency_generation)
        || receipt.response_bytes == 0
        || receipt.response_bytes > MAX_REMOTE_RESPONSE_BYTES
        || receipt.received_at_unix > receipt.evaluated_at_unix
        || receipt.evaluated_at_unix > receipt.expires_at_unix
        || receipt.evaluated_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "remote factory release state transparency external gossip transport receipt invariants are invalid"
                .into(),
        );
    }
    validate_endpoint(&receipt.endpoint, true)?;
    validate_slug(
        &receipt.external_log_id,
        "remote factory release transparency external gossip log id",
    )?;
    validate_slug(
        &receipt.organization_id,
        "remote factory release transparency external gossip organization id",
    )?;
    validate_observer_slug(
        &receipt.observer_id,
        "remote factory release transparency external gossip observer id",
    )?;
    validate_nonweak_public_key(
        &receipt.observer_public_key,
        "remote factory release transparency external gossip observer public key",
    )?;
    for (digest, label) in [
        (
            &receipt.external_anchor_policy_sha256,
            "remote external-anchor policy SHA-256",
        ),
        (
            &receipt.local_external_consistency_report_sha256,
            "remote local external consistency report SHA-256",
        ),
        (
            &receipt.local_external_tree_head_sha256,
            "remote local external tree-head SHA-256",
        ),
        (
            &receipt.observer_quorum_policy_sha256,
            "remote observer-quorum policy SHA-256",
        ),
        (&receipt.request_sha256, "remote gossip request SHA-256"),
        (&receipt.response_sha256, "remote gossip response SHA-256"),
        (
            &receipt.gossip_receipt_sha256,
            "remote signed gossip receipt SHA-256",
        ),
        (
            &receipt.observed_external_tree_head_sha256,
            "remote observed external tree-head SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    if let Some(digest) = &receipt.consistency_proof_sha256 {
        validate_digest(digest, "remote external consistency proof SHA-256")?;
    }
    Ok(())
}

fn validate_quorum_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport,
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
        report.external_anchor_policy_pin_matched,
        report.observer_quorum_policy_pin_matched,
        report.observer_policy_role_separation_verified,
        report.bounded_remote_acquisition_receipts_verified,
        report.observer_pins_matched,
        report.observer_receipt_signatures_verified,
        report.external_tree_relationships_verified,
        report.exact_observed_head_agreement_verified,
        report.observed_external_checkpoints_fresh_at_evaluation,
    ];
    let negatives = [
        report.selected_observer_split_view_detected,
        report.selected_ledger_external_gossip_quorum_report_committed,
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
    let count = usize::try_from(report.valid_observations).map_err(|_| {
        "factory release transparency external gossip observation count overflow".to_string()
    })?;
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_VERIFICATION_SCOPE
        || positives.contains(&false)
        || negatives.contains(&true)
        || count == 0
        || count > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS
        || count != report.members.len()
        || report.distinct_organizations != report.valid_observations
        || report.quorum_met != (report.distinct_organizations >= report.minimum_organizations)
        || report.distinct_organization_quorum_verified != report.quorum_met
        || report.selected_observer_quorum_verified != report.quorum_met
        || report.status
            != if report.quorum_met {
                "verified"
            } else {
                "insufficient_organizations"
            }
        || report.minimum_organizations != report.observer_quorum_policy.minimum_organizations
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
        || report.binding_sha256 != report_binding(report)?
    {
        return Err(
            "factory release transparency external gossip quorum report claims are invalid".into(),
        );
    }
    validate_quorum_policy(&report.observer_quorum_policy)?;
    validate_digest(&report.idempotency_key, "factory release idempotency key")?;
    validate_slug(
        &report.source_log_id,
        "factory release transparency source log id",
    )?;
    validate_slug(
        &report.external_log_id,
        "factory release transparency external log id",
    )?;
    for (digest, label) in [
        (&report.witness_policy_sha256, "witness policy SHA-256"),
        (
            &report.external_anchor_policy_sha256,
            "external-anchor policy SHA-256",
        ),
        (
            &report.local_external_tree_head_sha256,
            "local external tree-head SHA-256",
        ),
        (
            &report.local_external_root_sha256,
            "local external Merkle root SHA-256",
        ),
        (
            &report.agreed_observed_external_tree_head_sha256,
            "agreed observed external tree-head SHA-256",
        ),
        (
            &report.agreed_observed_external_root_sha256,
            "agreed observed external Merkle root SHA-256",
        ),
        (
            &report.observer_quorum_policy_sha256,
            "observer-quorum policy SHA-256",
        ),
        (
            &report.binding_sha256,
            "external gossip quorum report binding",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION)
        .contains(&report.anchor_checkpoint_generation)
        || report.anchor_state_sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
        || !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION)
            .contains(&report.local_external_consistency_generation)
        || report.local_external_tree_size == 0
        || report.agreed_observed_external_tree_size == 0
        || report.local_external_tree_size > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || report.agreed_observed_external_tree_size
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE
        || report.agreed_observed_external_tree_head_observed_at_unix > MAX_TIMESTAMP
        || report.evaluated_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "factory release transparency external gossip quorum report bounds are invalid".into(),
        );
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
        &report.observer_quorum_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES,
        "factory release transparency external gossip observer-quorum policy",
    )?;
    let local_head = selected_local_head(&report.local_external_consistency_report)?;
    if report.idempotency_key != report.local_external_consistency_report.idempotency_key
        || report.source_log_id != report.local_external_consistency_report.source_log_id
        || report.anchor_checkpoint_generation
            != report
                .local_external_consistency_report
                .anchor_checkpoint_generation
        || report.anchor_state_sequence
            != report
                .local_external_consistency_report
                .anchor_state_sequence
        || report.witness_policy_sha256
            != report
                .local_external_consistency_report
                .witness_policy_sha256
        || report.external_anchor_policy_sha256
            != report
                .local_external_consistency_report
                .external_anchor_policy_sha256
        || report.external_log_id != report.local_external_consistency_report.external_log_id
        || report.local_external_consistency_generation
            != report
                .local_external_consistency_report
                .external_consistency_generation
        || report.local_external_tree_head_sha256
            != report
                .local_external_consistency_report
                .current_external_tree_head_sha256
        || report.local_external_tree_size != local_head.tree_size
        || report.local_external_root_sha256 != local_head.root_sha256
        || report.external_anchor_policy
            != report
                .local_external_consistency_report
                .external_anchor_report
                .external_anchor_policy
        || report.observer_quorum_policy_sha256
            != factory_release_state_transparency_external_gossip_quorum_policy_sha256(
                &report.observer_quorum_policy,
            )?
    {
        return Err(
            "factory release transparency external gossip quorum report binds a different local context"
                .into(),
        );
    }
    let mut organizations = HashSet::new();
    let mut observers = HashSet::new();
    let mut keys = HashSet::new();
    let mut observation_digests = HashSet::new();
    let mut transport_digests = HashSet::new();
    let mut gossip_digests = HashSet::new();
    let mut previous: Option<(&str, &str)> = None;
    for member in &report.members {
        validate_slug(
            &member.organization_id,
            "factory release transparency external gossip organization id",
        )?;
        validate_observer_slug(
            &member.observer_id,
            "factory release transparency external gossip observer id",
        )?;
        validate_nonweak_public_key(
            &member.observer_public_key,
            "factory release transparency external gossip observer public key",
        )?;
        if member.relationship != report.relationship
            || member.received_at_unix > report.evaluated_at_unix
            || member.expires_at_unix < report.evaluated_at_unix
            || report.evaluated_at_unix - member.received_at_unix
                > report.observer_quorum_policy.maximum_receipt_age_seconds
        {
            return Err(
                "factory release transparency external gossip quorum member is invalid".into(),
            );
        }
        validate_artifact_identity(
            &member.observation_artifact,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_BYTES,
            "factory release transparency external gossip observation",
        )?;
        validate_artifact_identity(
            &member.transport_receipt_artifact,
            MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
            "remote factory release transparency external gossip transport receipt",
        )?;
        validate_artifact_identity(
            &member.gossip_receipt_artifact,
            MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES,
            "factory release transparency external gossip signed receipt",
        )?;
        if let Some(identity) = &member.consistency_proof_artifact {
            validate_artifact_identity(
                identity,
                MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES,
                "factory release transparency external gossip consistency proof",
            )?;
        }
        let order = (member.organization_id.as_str(), member.observer_id.as_str());
        if previous.is_some_and(|previous| previous >= order) {
            return Err(
                "factory release transparency external gossip quorum members are not canonically ordered"
                    .into(),
            );
        }
        previous = Some(order);
        if !organizations.insert(&member.organization_id)
            || !observers.insert(&member.observer_id)
            || !keys.insert(&member.observer_public_key)
            || !observation_digests.insert(&member.observation_artifact.sha256)
            || !transport_digests.insert(&member.transport_receipt_artifact.sha256)
            || !gossip_digests.insert(&member.gossip_receipt_artifact.sha256)
        {
            return Err(
                "factory release transparency external gossip quorum members are not distinct"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_quorum_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport,
) -> Result<(), String> {
    validate_quorum_report_shape(report)?;
    let local_source = render_factory_release_state_transparency_external_consistency_report(
        &report.local_external_consistency_report,
    )?;
    let external_policy_source = render_factory_release_state_transparency_external_anchor_policy(
        &report.external_anchor_policy,
    )?;
    let quorum_policy_source =
        render_factory_release_state_transparency_external_gossip_quorum_policy(
            &report.observer_quorum_policy,
        )?;
    let mut observation_sources = Vec::with_capacity(report.members.len());
    let mut transport_sources = Vec::with_capacity(report.members.len());
    for member in &report.members {
        let observation_source =
            render_factory_release_state_transparency_external_gossip_observation(
                &member.observation,
            )?;
        let transport_source =
            render_remote_factory_release_state_transparency_external_gossip_receipt(
                &member.transport_receipt,
            )?;
        let gossip_source = render_factory_release_state_transparency_external_gossip_receipt(
            &member.observation.gossip_receipt,
        )?;
        let proof_source = member
            .observation
            .consistency_proof
            .as_ref()
            .map(render_factory_release_state_transparency_external_consistency_proof)
            .transpose()?;
        if exact_identity(&observation_source) != member.observation_artifact
            || exact_identity(&transport_source) != member.transport_receipt_artifact
            || exact_identity(&gossip_source) != member.gossip_receipt_artifact
            || proof_source.as_deref().map(exact_identity) != member.consistency_proof_artifact
        {
            return Err(
                "factory release transparency external gossip quorum embedded member identity is invalid"
                    .into(),
            );
        }
        observation_sources.push(observation_source);
        transport_sources.push(transport_source);
    }
    if exact_identity(&local_source) != report.local_external_consistency_report_artifact
        || exact_identity(&external_policy_source) != report.external_anchor_policy_artifact
        || exact_identity(&quorum_policy_source) != report.observer_quorum_policy_artifact
    {
        return Err(
            "factory release transparency external gossip quorum embedded artifact identity is invalid"
                .into(),
        );
    }
    let expected = verify_factory_release_state_transparency_external_gossip_quorum(
        &local_source,
        &external_policy_source,
        &report.external_anchor_policy_sha256,
        &report.external_log_id,
        &quorum_policy_source,
        &report.observer_quorum_policy_sha256,
        &observation_sources,
        &transport_sources,
        report.evaluated_at_unix,
    )?;
    if &expected != report {
        return Err(
            "factory release transparency external gossip quorum report binding is invalid".into(),
        );
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport,
) -> Result<String, String> {
    let mut unbound = report.clone();
    unbound.binding_sha256.clear();
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &unbound,
        "factory release transparency external gossip quorum report binding",
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
        sha256: sha256(source),
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

fn sha256(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint.parse().map_err(|error| {
        format!("invalid remote factory release transparency external gossip endpoint: {error}")
    })?;
    let scheme = uri.scheme_str().ok_or_else(|| {
        "remote factory release transparency external gossip endpoint must have a scheme"
            .to_string()
    })?;
    if uri.authority().is_none() {
        return Err(
            "remote factory release transparency external gossip endpoint must have an authority"
                .into(),
        );
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(
            "remote factory release transparency external gossip endpoint must not contain userinfo"
                .into(),
        );
    }
    if uri.query().is_some() {
        return Err(
            "remote factory release transparency external gossip endpoint must not contain a query"
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
        Err("remote factory release transparency external gossip endpoint must use HTTPS".into())
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
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} must be lowercase hexadecimal"));
    }
    Ok(())
}

fn validate_nonweak_public_key(value: &str, label: &str) -> Result<(), String> {
    validate_digest(value, label)?;
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|error| format!("invalid {label}: {error}"))?
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid {label}: {error}"))?;
    if key.is_weak() {
        return Err(format!("{label} is weak"));
    }
    Ok(())
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

fn observer_slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
    })
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

pub(crate) fn factory_release_state_transparency_external_gossip_quorum_policy_json_schema() -> Value
{
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-quorum-policy-v1.json",
        "title": "pcbex factory-release transparency external gossip observer-quorum policy",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "policy_scope", "policy_id", "minimum_organizations",
            "maximum_receipt_age_seconds", "trusted_observers"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION},
            "policy_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE},
            "policy_id": slug_schema(),
            "minimum_organizations": {"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS},
            "maximum_receipt_age_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_QUORUM_RECEIPT_AGE_SECONDS},
            "trusted_observers": {
                "type": "array", "minItems": 2,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["organization_id", "observer_id", "algorithm", "public_key"],
                    "properties": {
                        "organization_id": slug_schema(),
                        "observer_id": observer_slug_schema(),
                        "algorithm": {"const": "ed25519"},
                        "public_key": digest_schema()
                    }
                }
            }
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_observation_json_schema() -> Value
{
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-observation-v1.json",
        "title": "pcbex factory-release transparency external gossip observation",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "observation_scope", "gossip_receipt", "consistency_proof"],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION},
            "observation_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_SCOPE},
            "gossip_receipt": factory_release_state_transparency_external_gossip_receipt_json_schema(),
            "consistency_proof": {
                "oneOf": [
                    {"type": "null"},
                    factory_release_state_transparency_external_consistency_proof_json_schema()
                ]
            }
        }
    })
}

pub(crate) fn remote_factory_release_state_transparency_external_gossip_receipt_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-state-transparency-external-gossip-receipt-v1.json",
        "title": "pcbex remote factory-release transparency external gossip transport receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "external_anchor_policy_sha256",
            "external_log_id", "local_external_consistency_generation",
            "local_external_consistency_report_sha256", "local_external_tree_head_sha256",
            "observer_quorum_policy_sha256", "organization_id", "observer_id",
            "observer_public_key", "request_sha256", "response_sha256", "response_bytes",
            "gossip_receipt_sha256", "consistency_proof_sha256",
            "observed_external_tree_head_sha256", "received_at_unix", "expires_at_unix",
            "evaluated_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION},
            "adapter": {"const": REMOTE_ADAPTER},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "external_anchor_policy_sha256": digest.clone(),
            "external_log_id": slug_schema(),
            "local_external_consistency_generation": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION},
            "local_external_consistency_report_sha256": digest.clone(),
            "local_external_tree_head_sha256": digest.clone(),
            "observer_quorum_policy_sha256": digest.clone(),
            "organization_id": slug_schema(),
            "observer_id": observer_slug_schema(),
            "observer_public_key": digest.clone(),
            "request_sha256": digest.clone(),
            "response_sha256": digest.clone(),
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_REMOTE_RESPONSE_BYTES},
            "gossip_receipt_sha256": digest.clone(),
            "consistency_proof_sha256": {"oneOf": [{"type": "null"}, digest.clone()]},
            "observed_external_tree_head_sha256": digest,
            "received_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "expires_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "verified": {"const": true}
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_quorum_report_json_schema() -> Value
{
    let digest = digest_schema();
    let artifact = |maximum| artifact_schema(maximum);
    let observation = factory_release_state_transparency_external_gossip_observation_json_schema();
    let transport = remote_factory_release_state_transparency_external_gossip_receipt_json_schema();
    let member = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "organization_id", "observer_id", "observer_public_key", "relationship",
            "received_at_unix", "expires_at_unix", "observation_artifact",
            "transport_receipt_artifact", "gossip_receipt_artifact",
            "consistency_proof_artifact", "observation", "transport_receipt"
        ],
        "properties": {
            "organization_id": slug_schema(),
            "observer_id": observer_slug_schema(),
            "observer_public_key": digest.clone(),
            "relationship": {"enum": ["same_tree", "local_precedes_observed", "observed_precedes_local"]},
            "received_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "expires_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "observation_artifact": artifact(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATION_BYTES),
            "transport_receipt_artifact": artifact(MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES),
            "gossip_receipt_artifact": artifact(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_RECEIPT_BYTES),
            "consistency_proof_artifact": {
                "oneOf": [
                    {"type": "null"},
                    artifact(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_PROOF_BYTES)
                ]
            },
            "observation": observation,
            "transport_receipt": transport
        }
    });
    let bool_value = json!({"type": "boolean"});
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-quorum-verification-report-v1.json",
        "title": "pcbex factory-release transparency exact-head external gossip quorum verification report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "status",
            "monotonic_state_chain_verified", "source_checkpoint_inclusion_verified",
            "complete_source_consistency_chain_verified", "source_log_append_only_consistency_verified",
            "witness_quorum_verified", "external_anchor_verified",
            "complete_external_consistency_chain_verified", "external_log_append_only_consistency_verified",
            "local_external_consistency_report_identity_verified", "external_anchor_policy_pin_matched",
            "observer_quorum_policy_pin_matched", "observer_policy_role_separation_verified",
            "bounded_remote_acquisition_receipts_verified", "observer_pins_matched",
            "observer_receipt_signatures_verified", "external_tree_relationships_verified",
            "exact_observed_head_agreement_verified", "observed_external_checkpoints_fresh_at_evaluation",
            "distinct_organization_quorum_verified", "selected_observer_quorum_verified",
            "selected_observer_split_view_detected", "selected_ledger_external_gossip_quorum_report_committed",
            "global_non_equivocation_verified", "selected_ledger_rollback_resistance_verified",
            "trusted_time_verified", "independent_organization_operation_verified",
            "endpoint_transport_authenticity_verified", "factory_legal_identity_verified",
            "server_side_idempotency_enforced", "capacity_reserved", "order_placed",
            "payment_performed", "exactly_once_execution_verified", "quorum_met",
            "idempotency_key", "source_log_id", "anchor_checkpoint_generation",
            "anchor_state_sequence", "witness_policy_sha256", "external_anchor_policy_sha256",
            "external_log_id", "local_external_consistency_generation",
            "local_external_tree_head_sha256", "local_external_tree_size",
            "local_external_root_sha256", "agreed_observed_external_tree_head_sha256",
            "agreed_observed_external_tree_size", "agreed_observed_external_root_sha256",
            "agreed_observed_external_tree_head_observed_at_unix", "relationship",
            "local_external_consistency_report_artifact", "local_external_consistency_report",
            "external_anchor_policy_artifact", "external_anchor_policy",
            "observer_quorum_policy_artifact", "observer_quorum_policy_sha256",
            "observer_quorum_policy", "minimum_organizations", "valid_observations",
            "distinct_organizations", "freshest_received_at_unix", "earliest_expires_at_unix",
            "members", "evaluated_at_unix", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_SCHEMA_VERSION},
            "verification_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_VERIFICATION_SCOPE},
            "status": {"enum": ["verified", "insufficient_organizations"]},
            "monotonic_state_chain_verified": {"const": true},
            "source_checkpoint_inclusion_verified": {"const": true},
            "complete_source_consistency_chain_verified": {"const": true},
            "source_log_append_only_consistency_verified": {"const": true},
            "witness_quorum_verified": {"const": true},
            "external_anchor_verified": {"const": true},
            "complete_external_consistency_chain_verified": {"const": true},
            "external_log_append_only_consistency_verified": {"const": true},
            "local_external_consistency_report_identity_verified": {"const": true},
            "external_anchor_policy_pin_matched": {"const": true},
            "observer_quorum_policy_pin_matched": {"const": true},
            "observer_policy_role_separation_verified": {"const": true},
            "bounded_remote_acquisition_receipts_verified": {"const": true},
            "observer_pins_matched": {"const": true},
            "observer_receipt_signatures_verified": {"const": true},
            "external_tree_relationships_verified": {"const": true},
            "exact_observed_head_agreement_verified": {"const": true},
            "observed_external_checkpoints_fresh_at_evaluation": {"const": true},
            "distinct_organization_quorum_verified": bool_value.clone(),
            "selected_observer_quorum_verified": bool_value.clone(),
            "selected_observer_split_view_detected": false_value.clone(),
            "selected_ledger_external_gossip_quorum_report_committed": false_value.clone(),
            "global_non_equivocation_verified": false_value.clone(),
            "selected_ledger_rollback_resistance_verified": false_value.clone(),
            "trusted_time_verified": false_value.clone(),
            "independent_organization_operation_verified": false_value.clone(),
            "endpoint_transport_authenticity_verified": false_value.clone(),
            "factory_legal_identity_verified": false_value.clone(),
            "server_side_idempotency_enforced": false_value.clone(),
            "capacity_reserved": false_value.clone(),
            "order_placed": false_value.clone(),
            "payment_performed": false_value.clone(),
            "exactly_once_execution_verified": false_value,
            "quorum_met": bool_value,
            "idempotency_key": digest.clone(),
            "source_log_id": slug_schema(),
            "anchor_checkpoint_generation": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_CONSISTENCY_GENERATION},
            "anchor_state_sequence": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE},
            "witness_policy_sha256": digest.clone(),
            "external_anchor_policy_sha256": digest.clone(),
            "external_log_id": slug_schema(),
            "local_external_consistency_generation": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_GENERATION},
            "local_external_tree_head_sha256": digest.clone(),
            "local_external_tree_size": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE},
            "local_external_root_sha256": digest.clone(),
            "agreed_observed_external_tree_head_sha256": digest.clone(),
            "agreed_observed_external_tree_size": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_TREE_SIZE},
            "agreed_observed_external_root_sha256": digest.clone(),
            "agreed_observed_external_tree_head_observed_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "relationship": {"enum": ["same_tree", "local_precedes_observed", "observed_precedes_local"]},
            "local_external_consistency_report_artifact": artifact(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_CONSISTENCY_REPORT_BYTES),
            "local_external_consistency_report": factory_release_state_transparency_external_consistency_report_json_schema(),
            "external_anchor_policy_artifact": artifact(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_ANCHOR_POLICY_BYTES),
            "external_anchor_policy": crate::factory_release_state_transparency_external_anchor::factory_release_state_transparency_external_anchor_policy_json_schema(),
            "observer_quorum_policy_artifact": artifact(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES),
            "observer_quorum_policy_sha256": digest.clone(),
            "observer_quorum_policy": factory_release_state_transparency_external_gossip_quorum_policy_json_schema(),
            "minimum_organizations": {"type": "integer", "minimum": 2, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS},
            "valid_observations": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS},
            "distinct_organizations": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS},
            "freshest_received_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "earliest_expires_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "members": {"type": "array", "minItems": 1, "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS, "items": member},
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "binding_sha256": digest
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn key(marker: u8) -> String {
        hex::encode(
            SigningKey::from_bytes(&[marker; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn policy() -> FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
            schema_version: 1,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE
                .into(),
            policy_id: "external-observers".into(),
            minimum_organizations: 2,
            maximum_receipt_age_seconds: 3600,
            trusted_observers: vec![
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "observer-org-a".into(),
                    observer_id: "observer-a".into(),
                    algorithm: "ed25519".into(),
                    public_key: key(41),
                },
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "observer-org-b".into(),
                    observer_id: "observer-b".into(),
                    algorithm: "ed25519".into(),
                    public_key: key(42),
                },
            ],
        }
    }

    #[test]
    fn policy_is_canonical_bounded_and_digest_pinned() {
        let policy = policy();
        let source =
            render_factory_release_state_transparency_external_gossip_quorum_policy(&policy)
                .unwrap();
        assert_eq!(
            parse_factory_release_state_transparency_external_gossip_quorum_policy(&source)
                .unwrap(),
            policy
        );
        assert_eq!(
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&policy)
                .unwrap()
                .len(),
            64
        );
        let mut reversed = policy.clone();
        reversed.trusted_observers.reverse();
        assert!(validate_quorum_policy(&reversed).is_err());
        let mut duplicate = policy.clone();
        duplicate.trusted_observers[1].organization_id = "observer-org-a".into();
        assert!(validate_quorum_policy(&duplicate).is_err());
    }

    #[test]
    fn exact_head_agreement_rejects_later_forks_and_same_size_splits() {
        let first = ExactObservedHead {
            sha256: "11".repeat(32),
            tree_size: 10,
            root_sha256: "22".repeat(32),
            observed_at_unix: 100,
            relationship: "local_precedes_observed".into(),
        };
        assert!(enforce_exact_head_agreement(None, &first).is_ok());
        assert!(enforce_exact_head_agreement(Some(&first), &first).is_ok());
        let mut later_fork = first.clone();
        later_fork.sha256 = "33".repeat(32);
        later_fork.tree_size = 11;
        later_fork.root_sha256 = "44".repeat(32);
        assert!(enforce_exact_head_agreement(Some(&first), &later_fork).is_err());
        let mut split = first.clone();
        split.sha256 = "55".repeat(32);
        split.root_sha256 = "66".repeat(32);
        assert!(
            enforce_exact_head_agreement(Some(&first), &split)
                .unwrap_err()
                .contains("split-view")
        );
    }

    #[test]
    fn schemas_are_closed_and_transport_is_safe_by_default() {
        for schema in [
            factory_release_state_transparency_external_gossip_quorum_policy_json_schema(),
            factory_release_state_transparency_external_gossip_observation_json_schema(),
            remote_factory_release_state_transparency_external_gossip_receipt_json_schema(),
            factory_release_state_transparency_external_gossip_quorum_report_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
        }
        assert!(validate_endpoint("https://observer.example/v1/gossip", false).is_ok());
        assert!(
            validate_endpoint("https://observer.example/v1/gossip?token=secret", false).is_err()
        );
        assert!(validate_endpoint("https://secret@observer.example/v1/gossip", false).is_err());
        assert!(validate_endpoint("http://example.com/v1/gossip", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/gossip", false).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/gossip", true).is_ok());
        assert!(validate_env_name("PCBEX_EXTERNAL_GOSSIP_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
        let weak = hex::encode(VerifyingKey::default().to_bytes());
        assert!(validate_nonweak_public_key(&weak, "test key").is_err());
    }
}
