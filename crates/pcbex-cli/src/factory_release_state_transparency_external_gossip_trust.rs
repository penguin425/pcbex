//! Generation-chained observer trust for factory-release external gossip.
//!
//! The v1.492 boundary anchors every observer to the exact semantic v1.491
//! policy that introduced it. A successor key becomes current only after the
//! retained key and the successor key dual-sign one exact, monotonic,
//! generation- and digest-chained transition. The resulting effective policy
//! remains a canonical v1.491 policy, so acquisition and exact-head quorum
//! verification reuse the unchanged v1.491 wire contract.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_state_transparency_external_gossip_quorum::{
    FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES,
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_REPORT_BYTES,
    factory_release_state_transparency_external_gossip_quorum_policy_json_schema,
    factory_release_state_transparency_external_gossip_quorum_policy_sha256,
    factory_release_state_transparency_external_gossip_quorum_report_json_schema,
    parse_factory_release_state_transparency_external_gossip_quorum_policy,
    parse_factory_release_state_transparency_external_gossip_quorum_report,
    render_factory_release_state_transparency_external_gossip_quorum_policy,
    render_factory_release_state_transparency_external_gossip_quorum_report,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_SCOPE: &str =
    "factory-release-state-transparency-external-gossip-observer-trust-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION_SCOPE: &str =
    "signed-factory-release-state-transparency-external-gossip-observer-key-rotation-v1";
pub(crate) const FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_VERIFICATION_SCOPE: &str =
    "verified-factory-release-state-transparency-external-gossip-observer-trust-v1";
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_STATE_BYTES:
    u64 = 16 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_KEY_ROTATION_BYTES:
    u64 = 16 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES: u64 =
    64 * 1024 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATIONS: usize =
    4_096;
pub(crate) const MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION: u64 =
    4_096;

const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
const ROTATION_DOMAIN: &str =
    "pcbex-factory-release-state-transparency-external-gossip-observer-key-rotation-v1";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-observer-trust-report:v1\0";
const ROTATION_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-observer-rotation-filename:v1\0";
const REPORT_FILENAME_CONTEXT_DOMAIN: &[u8] =
    b"pcbex:factory-release-state-transparency-external-gossip-observer-trust-filename:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipObserverTrustState {
    pub(crate) schema_version: u32,
    pub(crate) trust_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) organization_id: String,
    pub(crate) observer_id: String,
    pub(crate) generation: u64,
    pub(crate) initial_public_key: String,
    pub(crate) current_public_key: String,
    pub(crate) last_rotation_sha256: Option<String>,
    pub(crate) last_rotated_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation {
    pub(crate) schema_version: u32,
    pub(crate) rotation_scope: String,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) policy_id: String,
    pub(crate) organization_id: String,
    pub(crate) observer_id: String,
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
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipObserverRotationEvidence {
    pub(crate) artifact: ExactArtifactIdentity,
    pub(crate) rotation: SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipObserverTrustEvidence {
    pub(crate) organization_id: String,
    pub(crate) observer_id: String,
    pub(crate) initial_public_key: String,
    pub(crate) current_trust_state: FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
    pub(crate) current_trust_state_sha256: String,
    pub(crate) rotations:
        Vec<FactoryReleaseStateTransparencyExternalGossipObserverRotationEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) base_observer_quorum_policy_pin_matched: bool,
    pub(crate) complete_observer_rotation_histories_verified: bool,
    pub(crate) observer_rotation_dual_signatures_verified: bool,
    pub(crate) observer_rotation_generation_chains_verified: bool,
    pub(crate) observer_rotation_digest_chains_verified: bool,
    pub(crate) observer_rotation_timestamps_monotonic: bool,
    pub(crate) effective_observer_quorum_policy_derived: bool,
    pub(crate) effective_observer_quorum_policy_pin_matched: bool,
    pub(crate) current_observer_trust_bound_to_quorum: bool,
    pub(crate) selected_ledger_latest_observer_rotations_verified: bool,
    pub(crate) selected_ledger_rollback_resistance_verified: bool,
    pub(crate) global_non_equivocation_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) independent_organization_operation_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) quorum_met: bool,
    pub(crate) base_observer_quorum_policy_artifact: ExactArtifactIdentity,
    pub(crate) base_observer_quorum_policy_sha256: String,
    pub(crate) base_observer_quorum_policy:
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    pub(crate) effective_observer_quorum_policy_artifact: ExactArtifactIdentity,
    pub(crate) effective_observer_quorum_policy_sha256: String,
    pub(crate) effective_observer_quorum_policy:
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    pub(crate) observer_rotation_count: u32,
    pub(crate) observer_trust:
        Vec<FactoryReleaseStateTransparencyExternalGossipObserverTrustEvidence>,
    pub(crate) quorum_report_artifact: ExactArtifactIdentity,
    pub(crate) quorum_report: FactoryReleaseStateTransparencyExternalGossipQuorumVerificationReport,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct RotationPayload<'a> {
    domain: &'static str,
    schema_version: u32,
    rotation_scope: &'static str,
    base_observer_quorum_policy_sha256: &'a str,
    policy_id: &'a str,
    organization_id: &'a str,
    observer_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_rotation_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    rotated_at_unix: u64,
    algorithm: &'static str,
}

#[derive(Serialize)]
struct RotationFilenameContext<'a> {
    base_observer_quorum_policy_sha256: &'a str,
    organization_id: &'a str,
    observer_id: &'a str,
}

#[derive(Serialize)]
struct ReportFilenameContext<'a> {
    idempotency_key: &'a str,
    local_external_consistency_generation: u64,
    base_observer_quorum_policy_sha256: &'a str,
    effective_observer_quorum_policy_sha256: &'a str,
    observer_trust_sha256: &'a str,
}

pub(crate) fn new_factory_release_state_transparency_external_gossip_observer_trust_state(
    base_policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    expected_base_policy_sha256: &str,
    organization_id: &str,
    observer_id: &str,
) -> Result<FactoryReleaseStateTransparencyExternalGossipObserverTrustState, String> {
    let actual =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(base_policy)?;
    if actual != expected_base_policy_sha256 {
        return Err(
            "factory release transparency external gossip base observer policy pin does not match"
                .into(),
        );
    }
    let observer = base_policy
        .trusted_observers
        .iter()
        .find(|candidate| {
            candidate.organization_id == organization_id && candidate.observer_id == observer_id
        })
        .ok_or_else(|| {
            "factory release transparency external gossip observer is absent from the base policy"
                .to_string()
        })?;
    let state = FactoryReleaseStateTransparencyExternalGossipObserverTrustState {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION,
        trust_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_SCOPE.into(),
        base_observer_quorum_policy_sha256: actual,
        policy_id: base_policy.policy_id.clone(),
        organization_id: observer.organization_id.clone(),
        observer_id: observer.observer_id.clone(),
        generation: 0,
        initial_public_key: observer.public_key.clone(),
        current_public_key: observer.public_key.clone(),
        last_rotation_sha256: None,
        last_rotated_at_unix: None,
    };
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(&state)?;
    Ok(state)
}

pub(crate) fn sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
    state: &FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation, String> {
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(state)?;
    if rotated_at_unix > MAX_TIMESTAMP {
        return Err(
            "factory release transparency external gossip observer rotation time is outside its bound"
                .into(),
        );
    }
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex::encode(old_key.verifying_key().to_bytes());
    let new_public_key = hex::encode(new_key.verifying_key().to_bytes());
    validate_nonweak_public_key(
        &old_public_key,
        "old factory release transparency external gossip observer public key",
    )?;
    validate_nonweak_public_key(
        &new_public_key,
        "new factory release transparency external gossip observer public key",
    )?;
    if old_public_key != state.current_public_key {
        return Err(
            "old factory release transparency external gossip observer key does not match the current trust state"
                .into(),
        );
    }
    if new_public_key == old_public_key {
        return Err(
            "new factory release transparency external gossip observer key must differ from the current key"
                .into(),
        );
    }
    if new_public_key == state.initial_public_key {
        return Err(
            "new factory release transparency external gossip observer key must not reuse the initial key"
                .into(),
        );
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err(
            "factory release transparency external gossip observer rotation timestamps must be monotonic"
                .into(),
        );
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .filter(|generation| {
            *generation
                <= MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION
        })
        .ok_or_else(|| {
            "factory release transparency external gossip observer generation is exhausted"
                .to_string()
        })?;
    let payload = rotation_payload(
        &state.base_observer_quorum_policy_sha256,
        &state.policy_id,
        &state.organization_id,
        &state.observer_id,
        state.generation,
        to_generation,
        state.last_rotation_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    let rotation = SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION,
        rotation_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION_SCOPE
            .into(),
        base_observer_quorum_policy_sha256: state.base_observer_quorum_policy_sha256.clone(),
        policy_id: state.policy_id.clone(),
        organization_id: state.organization_id.clone(),
        observer_id: state.observer_id.clone(),
        from_generation: state.generation,
        to_generation,
        previous_rotation_sha256: state.last_rotation_sha256.clone(),
        old_public_key,
        new_public_key,
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_signature: hex::encode(old_key.sign(&payload).to_bytes()),
        new_signature: hex::encode(new_key.sign(&payload).to_bytes()),
    };
    validate_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn apply_factory_release_state_transparency_external_gossip_observer_key_rotation(
    state: &FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation,
) -> Result<FactoryReleaseStateTransparencyExternalGossipObserverTrustState, String> {
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(state)?;
    validate_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
        rotation,
    )?;
    let expected_generation = state.generation.checked_add(1).ok_or_else(|| {
        "factory release transparency external gossip observer generation overflow".to_string()
    })?;
    if rotation.base_observer_quorum_policy_sha256 != state.base_observer_quorum_policy_sha256
        || rotation.policy_id != state.policy_id
        || rotation.organization_id != state.organization_id
        || rotation.observer_id != state.observer_id
        || rotation.from_generation != state.generation
        || rotation.to_generation != expected_generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
        || rotation.new_public_key == state.initial_public_key
    {
        return Err(
            "factory release transparency external gossip observer rotation does not extend the selected trust state"
                .into(),
        );
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err(
            "factory release transparency external gossip observer rotation timestamps must be monotonic"
                .into(),
        );
    }
    let next = FactoryReleaseStateTransparencyExternalGossipObserverTrustState {
        schema_version: state.schema_version,
        trust_scope: state.trust_scope.clone(),
        base_observer_quorum_policy_sha256: state.base_observer_quorum_policy_sha256.clone(),
        policy_id: state.policy_id.clone(),
        organization_id: state.organization_id.clone(),
        observer_id: state.observer_id.clone(),
        generation: rotation.to_generation,
        initial_public_key: state.initial_public_key.clone(),
        current_public_key: rotation.new_public_key.clone(),
        last_rotation_sha256: Some(
            signed_factory_release_state_transparency_external_gossip_observer_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_rotated_at_unix: Some(rotation.rotated_at_unix),
    };
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(&next)?;
    Ok(next)
}

pub(crate) fn derive_factory_release_state_transparency_external_gossip_effective_quorum_policy(
    base_policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    observer_trust_states: &[FactoryReleaseStateTransparencyExternalGossipObserverTrustState],
) -> Result<FactoryReleaseStateTransparencyExternalGossipQuorumPolicy, String> {
    let base_sha256 =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(base_policy)?;
    if observer_trust_states.len() != base_policy.trusted_observers.len() {
        return Err(
            "factory release transparency external gossip observer trust must cover every base-policy observer"
                .into(),
        );
    }
    let mut states = HashMap::with_capacity(observer_trust_states.len());
    for state in observer_trust_states {
        validate_factory_release_state_transparency_external_gossip_observer_trust_state(state)?;
        if state.base_observer_quorum_policy_sha256 != base_sha256
            || state.policy_id != base_policy.policy_id
            || states
                .insert(
                    (state.organization_id.as_str(), state.observer_id.as_str()),
                    state,
                )
                .is_some()
        {
            return Err(
                "factory release transparency external gossip observer trust does not uniquely bind the base policy"
                    .into(),
            );
        }
    }
    let mut effective = base_policy.clone();
    for observer in &mut effective.trusted_observers {
        let state = states
            .get(&(
                observer.organization_id.as_str(),
                observer.observer_id.as_str(),
            ))
            .ok_or_else(|| {
                "factory release transparency external gossip observer trust omits a base-policy observer"
                    .to_string()
            })?;
        if state.initial_public_key != observer.public_key {
            return Err(
                "factory release transparency external gossip observer trust initial key does not match the base policy"
                    .into(),
            );
        }
        observer.public_key.clone_from(&state.current_public_key);
    }
    render_factory_release_state_transparency_external_gossip_quorum_policy(&effective)?;
    Ok(effective)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_factory_release_state_transparency_external_gossip_quorum_with_observer_trust(
    base_policy_source: &[u8],
    expected_base_policy_sha256: &str,
    effective_policy_source: &[u8],
    expected_effective_policy_sha256: &str,
    rotation_sources: &[Vec<u8>],
    quorum_report_source: &[u8],
    selected_ledger_latest_observer_rotations_verified: bool,
) -> Result<FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport, String> {
    if !selected_ledger_latest_observer_rotations_verified {
        return Err(
            "factory release transparency external gossip observer trust requires the latest selected-ledger rotations"
                .into(),
        );
    }
    let base_policy =
        parse_factory_release_state_transparency_external_gossip_quorum_policy(base_policy_source)?;
    let actual_base_sha256 =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(&base_policy)?;
    if actual_base_sha256 != expected_base_policy_sha256 {
        return Err(
            "factory release transparency external gossip base observer policy pin does not match"
                .into(),
        );
    }
    let effective_policy = parse_factory_release_state_transparency_external_gossip_quorum_policy(
        effective_policy_source,
    )?;
    let actual_effective_sha256 =
        factory_release_state_transparency_external_gossip_quorum_policy_sha256(&effective_policy)?;
    if actual_effective_sha256 != expected_effective_policy_sha256 {
        return Err(
            "factory release transparency external gossip effective observer policy pin does not match"
                .into(),
        );
    }
    let (observer_trust, trust_states) =
        build_observer_trust_evidence(&base_policy, &actual_base_sha256, rotation_sources)?;
    let derived =
        derive_factory_release_state_transparency_external_gossip_effective_quorum_policy(
            &base_policy,
            &trust_states,
        )?;
    if derived != effective_policy {
        return Err(
            "factory release transparency external gossip effective policy does not match the complete observer rotation histories"
                .into(),
        );
    }
    let quorum_report = parse_factory_release_state_transparency_external_gossip_quorum_report(
        quorum_report_source,
    )?;
    let effective_artifact = exact_identity(effective_policy_source);
    if quorum_report.observer_quorum_policy != effective_policy
        || quorum_report.observer_quorum_policy_sha256 != actual_effective_sha256
        || quorum_report.observer_quorum_policy_artifact != effective_artifact
    {
        return Err(
            "factory release transparency external gossip quorum report is not bound to the derived current observer policy"
                .into(),
        );
    }
    let observer_rotation_count = u32::try_from(rotation_sources.len()).map_err(|_| {
        "factory release transparency external gossip observer rotation count overflow".to_string()
    })?;
    let mut report = FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport {
        schema_version: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION,
        verification_scope:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_VERIFICATION_SCOPE.into(),
        status: if quorum_report.quorum_met {
            "verified"
        } else {
            "insufficient_organizations"
        }
        .into(),
        base_observer_quorum_policy_pin_matched: true,
        complete_observer_rotation_histories_verified: true,
        observer_rotation_dual_signatures_verified: true,
        observer_rotation_generation_chains_verified: true,
        observer_rotation_digest_chains_verified: true,
        observer_rotation_timestamps_monotonic: true,
        effective_observer_quorum_policy_derived: true,
        effective_observer_quorum_policy_pin_matched: true,
        current_observer_trust_bound_to_quorum: true,
        selected_ledger_latest_observer_rotations_verified: true,
        selected_ledger_rollback_resistance_verified: false,
        global_non_equivocation_verified: false,
        trusted_time_verified: false,
        independent_organization_operation_verified: false,
        factory_legal_identity_verified: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        quorum_met: quorum_report.quorum_met,
        base_observer_quorum_policy_artifact: exact_identity(base_policy_source),
        base_observer_quorum_policy_sha256: actual_base_sha256,
        base_observer_quorum_policy: base_policy,
        effective_observer_quorum_policy_artifact: effective_artifact,
        effective_observer_quorum_policy_sha256: actual_effective_sha256,
        effective_observer_quorum_policy: effective_policy,
        observer_rotation_count,
        observer_trust,
        quorum_report_artifact: exact_identity(quorum_report_source),
        evaluated_at_unix: quorum_report.evaluated_at_unix,
        quorum_report,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_trust_report_shape(&report)?;
    Ok(report)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_observer_trust_state(
    state: &FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
) -> Result<Vec<u8>, String> {
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(state)?;
    render_bounded(
        state,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_STATE_BYTES,
        "factory release transparency external gossip observer trust state",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_observer_trust_state(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipObserverTrustState, String> {
    let state = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_STATE_BYTES,
        "factory release transparency external gossip observer trust state",
    )?;
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(&state)?;
    Ok(state)
}

pub(crate) fn render_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
        rotation,
    )?;
    render_bounded(
        rotation,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_KEY_ROTATION_BYTES,
        "signed factory release transparency external gossip observer key rotation",
    )
}

pub(crate) fn parse_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
    source: &[u8],
) -> Result<SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation, String> {
    let rotation = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_KEY_ROTATION_BYTES,
        "signed factory release transparency external gossip observer key rotation",
    )?;
    validate_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub(crate) fn render_factory_release_state_transparency_external_gossip_trust_report(
    report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<Vec<u8>, String> {
    validate_trust_report_self_contained(report)?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust verification report",
    )
}

pub(crate) fn parse_factory_release_state_transparency_external_gossip_trust_report(
    source: &[u8],
) -> Result<FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_REPORT_BYTES,
        "factory release transparency external gossip observer trust verification report",
    )?;
    validate_trust_report_self_contained(&report)?;
    Ok(report)
}

pub(crate) fn factory_release_state_transparency_external_gossip_observer_trust_state_sha256(
    state: &FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
) -> Result<String, String> {
    validate_factory_release_state_transparency_external_gossip_observer_trust_state(state)?;
    normalized_sha256(
        state,
        "factory release transparency external gossip observer trust state",
    )
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_observer_key_rotation_sha256(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation,
) -> Result<String, String> {
    validate_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
        rotation,
    )?;
    normalized_sha256(
        rotation,
        "signed factory release transparency external gossip observer key rotation",
    )
}

pub(crate) fn factory_release_state_transparency_external_gossip_observer_rotation_filename(
    base_policy_sha256: &str,
    organization_id: &str,
    observer_id: &str,
    generation: u64,
) -> Result<String, String> {
    validate_digest(
        base_policy_sha256,
        "factory release transparency external gossip base observer policy SHA-256",
    )?;
    validate_slug(
        organization_id,
        "factory release transparency external gossip observer organization id",
    )?;
    validate_observer_slug(
        observer_id,
        "factory release transparency external gossip observer id",
    )?;
    if !(1..=MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION)
        .contains(&generation)
    {
        return Err(
            "factory release transparency external gossip observer rotation generation is outside its bound"
                .into(),
        );
    }
    let context = RotationFilenameContext {
        base_observer_quorum_policy_sha256: base_policy_sha256,
        organization_id,
        observer_id,
    };
    let digest = domain_hash(
        ROTATION_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip observer rotation filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-observer-rotation-v1-{}-{generation:04}.json",
        &digest[..32]
    ))
}

pub(crate) fn factory_release_state_transparency_external_gossip_trust_report_filename(
    report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<String, String> {
    validate_trust_report_shape(report)?;
    let observer_trust_sha256 = domain_hash(
        REPORT_FILENAME_CONTEXT_DOMAIN,
        &report.observer_trust,
        "factory release transparency external gossip observer trust filename evidence",
    )?;
    let context = ReportFilenameContext {
        idempotency_key: &report.quorum_report.idempotency_key,
        local_external_consistency_generation: report
            .quorum_report
            .local_external_consistency_generation,
        base_observer_quorum_policy_sha256: &report.base_observer_quorum_policy_sha256,
        effective_observer_quorum_policy_sha256: &report.effective_observer_quorum_policy_sha256,
        observer_trust_sha256: &observer_trust_sha256,
    };
    let digest = domain_hash(
        REPORT_FILENAME_CONTEXT_DOMAIN,
        &context,
        "factory release transparency external gossip observer trust report filename context",
    )?;
    Ok(format!(
        "factory-release-state-transparency-external-gossip-observer-trust-v1-{}-{:04}-{}.json",
        report.quorum_report.idempotency_key,
        report.quorum_report.local_external_consistency_generation,
        &digest[..32]
    ))
}

fn build_observer_trust_evidence(
    base_policy: &FactoryReleaseStateTransparencyExternalGossipQuorumPolicy,
    base_policy_sha256: &str,
    rotation_sources: &[Vec<u8>],
) -> Result<
    (
        Vec<FactoryReleaseStateTransparencyExternalGossipObserverTrustEvidence>,
        Vec<FactoryReleaseStateTransparencyExternalGossipObserverTrustState>,
    ),
    String,
> {
    if rotation_sources.len()
        > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATIONS
    {
        return Err(
            "factory release transparency external gossip observer rotation history exceeds its bound"
                .into(),
        );
    }
    let known = base_policy
        .trusted_observers
        .iter()
        .map(|observer| {
            (
                (
                    observer.organization_id.clone(),
                    observer.observer_id.clone(),
                ),
                (),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut grouped = HashMap::<
        (String, String),
        Vec<FactoryReleaseStateTransparencyExternalGossipObserverRotationEvidence>,
    >::new();
    let mut exact_digests = HashSet::new();
    for source in rotation_sources {
        let rotation =
            parse_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                source,
            )?;
        let identity = exact_identity(source);
        if !exact_digests.insert(identity.sha256.clone()) {
            return Err(
                "factory release transparency external gossip observer rotation evidence is duplicated"
                    .into(),
            );
        }
        if rotation.base_observer_quorum_policy_sha256 != base_policy_sha256
            || rotation.policy_id != base_policy.policy_id
            || !known.contains_key(&(
                rotation.organization_id.clone(),
                rotation.observer_id.clone(),
            ))
        {
            return Err(
                "factory release transparency external gossip observer rotation is not bound to a base-policy observer"
                    .into(),
            );
        }
        grouped
            .entry((
                rotation.organization_id.clone(),
                rotation.observer_id.clone(),
            ))
            .or_default()
            .push(
                FactoryReleaseStateTransparencyExternalGossipObserverRotationEvidence {
                    artifact: identity,
                    rotation,
                },
            );
    }

    let mut evidence = Vec::with_capacity(base_policy.trusted_observers.len());
    let mut states = Vec::with_capacity(base_policy.trusted_observers.len());
    for observer in &base_policy.trusted_observers {
        let mut state =
            new_factory_release_state_transparency_external_gossip_observer_trust_state(
                base_policy,
                base_policy_sha256,
                &observer.organization_id,
                &observer.observer_id,
            )?;
        let mut rotations = grouped
            .remove(&(
                observer.organization_id.clone(),
                observer.observer_id.clone(),
            ))
            .unwrap_or_default();
        rotations.sort_by(|left, right| {
            left.rotation
                .to_generation
                .cmp(&right.rotation.to_generation)
                .then_with(|| left.artifact.sha256.cmp(&right.artifact.sha256))
        });
        let mut historical_keys = HashSet::from([observer.public_key.clone()]);
        for rotation in &rotations {
            if !historical_keys.insert(rotation.rotation.new_public_key.clone()) {
                return Err(
                    "factory release transparency external gossip observer rotation reuses a historical key"
                        .into(),
                );
            }
            state = apply_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &state,
                &rotation.rotation,
            )?;
        }
        evidence.push(
            FactoryReleaseStateTransparencyExternalGossipObserverTrustEvidence {
                organization_id: observer.organization_id.clone(),
                observer_id: observer.observer_id.clone(),
                initial_public_key: observer.public_key.clone(),
                current_trust_state_sha256:
                    factory_release_state_transparency_external_gossip_observer_trust_state_sha256(
                        &state,
                    )?,
                current_trust_state: state.clone(),
                rotations,
            },
        );
        states.push(state);
    }
    if !grouped.is_empty() {
        return Err(
            "factory release transparency external gossip observer rotation history contains an unknown observer"
                .into(),
        );
    }
    Ok((evidence, states))
}

fn validate_factory_release_state_transparency_external_gossip_observer_trust_state(
    state: &FactoryReleaseStateTransparencyExternalGossipObserverTrustState,
) -> Result<(), String> {
    if state.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION
        || state.trust_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_SCOPE
        || state.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION
    {
        return Err(
            "factory release transparency external gossip observer trust-state invariants are invalid"
                .into(),
        );
    }
    validate_digest(
        &state.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip base observer policy SHA-256",
    )?;
    validate_slug(
        &state.policy_id,
        "factory release transparency external gossip observer policy id",
    )?;
    validate_slug(
        &state.organization_id,
        "factory release transparency external gossip observer organization id",
    )?;
    validate_observer_slug(
        &state.observer_id,
        "factory release transparency external gossip observer id",
    )?;
    validate_nonweak_public_key(
        &state.initial_public_key,
        "initial factory release transparency external gossip observer public key",
    )?;
    validate_nonweak_public_key(
        &state.current_public_key,
        "current factory release transparency external gossip observer public key",
    )?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) if state.initial_public_key == state.current_public_key => Ok(()),
        (0, _, _) => Err(
            "initial factory release transparency external gossip observer trust cannot reference a rotation"
                .into(),
        ),
        (_, Some(digest), Some(rotated_at_unix)) if rotated_at_unix <= MAX_TIMESTAMP => {
            validate_digest(
                digest,
                "factory release transparency external gossip observer last rotation SHA-256",
            )
        }
        _ => Err(
            "rotated factory release transparency external gossip observer trust requires complete bounded rotation evidence"
                .into(),
        ),
    }
}

fn validate_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
    rotation: &SignedFactoryReleaseStateTransparencyExternalGossipObserverKeyRotation,
) -> Result<(), String> {
    let expected_generation = rotation.from_generation.checked_add(1);
    if rotation.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION
        || rotation.rotation_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION_SCOPE
        || rotation.algorithm != "ed25519"
        || expected_generation != Some(rotation.to_generation)
        || rotation.to_generation == 0
        || rotation.to_generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION
        || rotation.old_public_key == rotation.new_public_key
        || rotation.rotated_at_unix > MAX_TIMESTAMP
        || (rotation.from_generation == 0) != rotation.previous_rotation_sha256.is_none()
    {
        return Err(
            "signed factory release transparency external gossip observer rotation invariants are invalid"
                .into(),
        );
    }
    validate_digest(
        &rotation.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip base observer policy SHA-256",
    )?;
    validate_slug(
        &rotation.policy_id,
        "factory release transparency external gossip observer policy id",
    )?;
    validate_slug(
        &rotation.organization_id,
        "factory release transparency external gossip observer organization id",
    )?;
    validate_observer_slug(
        &rotation.observer_id,
        "factory release transparency external gossip observer id",
    )?;
    if let Some(digest) = &rotation.previous_rotation_sha256 {
        validate_digest(
            digest,
            "previous factory release transparency external gossip observer rotation SHA-256",
        )?;
    }
    validate_nonweak_public_key(
        &rotation.old_public_key,
        "old factory release transparency external gossip observer public key",
    )?;
    validate_nonweak_public_key(
        &rotation.new_public_key,
        "new factory release transparency external gossip observer public key",
    )?;
    let old_signature = decode_hex::<64>(
        &rotation.old_signature,
        "old factory release transparency external gossip observer rotation signature",
    )?;
    let new_signature = decode_hex::<64>(
        &rotation.new_signature,
        "new factory release transparency external gossip observer rotation signature",
    )?;
    let payload = rotation_payload(
        &rotation.base_observer_quorum_policy_sha256,
        &rotation.policy_id,
        &rotation.organization_id,
        &rotation.observer_id,
        rotation.from_generation,
        rotation.to_generation,
        rotation.previous_rotation_sha256.as_deref(),
        &rotation.old_public_key,
        &rotation.new_public_key,
        rotation.rotated_at_unix,
    )?;
    for (key, signature, label) in [
        (
            &rotation.old_public_key,
            old_signature,
            "old factory release transparency external gossip observer rotation",
        ),
        (
            &rotation.new_public_key,
            new_signature,
            "new factory release transparency external gossip observer rotation",
        ),
    ] {
        let key = decode_hex::<32>(key, label)?;
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &Signature::from_bytes(&signature))
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    Ok(())
}

fn validate_trust_report_shape(
    report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    let positives = [
        report.base_observer_quorum_policy_pin_matched,
        report.complete_observer_rotation_histories_verified,
        report.observer_rotation_dual_signatures_verified,
        report.observer_rotation_generation_chains_verified,
        report.observer_rotation_digest_chains_verified,
        report.observer_rotation_timestamps_monotonic,
        report.effective_observer_quorum_policy_derived,
        report.effective_observer_quorum_policy_pin_matched,
        report.current_observer_trust_bound_to_quorum,
        report.selected_ledger_latest_observer_rotations_verified,
    ];
    let negatives = [
        report.selected_ledger_rollback_resistance_verified,
        report.global_non_equivocation_verified,
        report.trusted_time_verified,
        report.independent_organization_operation_verified,
        report.factory_legal_identity_verified,
        report.capacity_reserved,
        report.order_placed,
        report.payment_performed,
        report.exactly_once_execution_verified,
    ];
    let rotation_count = usize::try_from(report.observer_rotation_count).map_err(|_| {
        "factory release transparency external gossip observer rotation count overflow".to_string()
    })?;
    if report.schema_version
        != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION
        || report.verification_scope
            != FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_VERIFICATION_SCOPE
        || positives.contains(&false)
        || negatives.contains(&true)
        || report.quorum_met != report.quorum_report.quorum_met
        || report.status
            != if report.quorum_met {
                "verified"
            } else {
                "insufficient_organizations"
            }
        || report.evaluated_at_unix != report.quorum_report.evaluated_at_unix
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || report.observer_trust.len() != report.base_observer_quorum_policy.trusted_observers.len()
        || report.observer_trust.len()
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS
        || rotation_count
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATIONS
        || rotation_count
            != report
                .observer_trust
                .iter()
                .map(|evidence| evidence.rotations.len())
                .sum::<usize>()
        || report.binding_sha256 != report_binding(report)?
    {
        return Err(
            "factory release transparency external gossip observer trust report claims are invalid"
                .into(),
        );
    }
    validate_digest(
        &report.base_observer_quorum_policy_sha256,
        "factory release transparency external gossip base observer policy SHA-256",
    )?;
    validate_digest(
        &report.effective_observer_quorum_policy_sha256,
        "factory release transparency external gossip effective observer policy SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory release transparency external gossip observer trust report binding",
    )?;
    validate_artifact_identity(
        &report.base_observer_quorum_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES,
        "factory release transparency external gossip base observer policy",
    )?;
    validate_artifact_identity(
        &report.effective_observer_quorum_policy_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES,
        "factory release transparency external gossip effective observer policy",
    )?;
    validate_artifact_identity(
        &report.quorum_report_artifact,
        MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_REPORT_BYTES,
        "factory release transparency external gossip quorum report",
    )?;
    Ok(())
}

fn validate_trust_report_self_contained(
    report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<(), String> {
    validate_trust_report_shape(report)?;
    let base_source = render_factory_release_state_transparency_external_gossip_quorum_policy(
        &report.base_observer_quorum_policy,
    )?;
    let effective_source = render_factory_release_state_transparency_external_gossip_quorum_policy(
        &report.effective_observer_quorum_policy,
    )?;
    let quorum_source = render_factory_release_state_transparency_external_gossip_quorum_report(
        &report.quorum_report,
    )?;
    if exact_identity(&base_source) != report.base_observer_quorum_policy_artifact
        || exact_identity(&effective_source) != report.effective_observer_quorum_policy_artifact
        || exact_identity(&quorum_source) != report.quorum_report_artifact
    {
        return Err(
            "factory release transparency external gossip observer trust embedded artifact identity is invalid"
                .into(),
        );
    }
    let mut rotation_sources = Vec::with_capacity(report.observer_rotation_count as usize);
    for (observer, evidence) in report
        .base_observer_quorum_policy
        .trusted_observers
        .iter()
        .zip(&report.observer_trust)
    {
        if evidence.organization_id != observer.organization_id
            || evidence.observer_id != observer.observer_id
            || evidence.initial_public_key != observer.public_key
            || evidence.current_trust_state.organization_id != observer.organization_id
            || evidence.current_trust_state.observer_id != observer.observer_id
            || evidence.current_trust_state.initial_public_key != observer.public_key
            || evidence.current_trust_state_sha256
                != factory_release_state_transparency_external_gossip_observer_trust_state_sha256(
                    &evidence.current_trust_state,
                )?
        {
            return Err(
                "factory release transparency external gossip observer trust evidence does not match the base policy"
                    .into(),
            );
        }
        for rotation in &evidence.rotations {
            let source = render_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotation.rotation,
            )?;
            if exact_identity(&source) != rotation.artifact {
                return Err(
                    "factory release transparency external gossip observer rotation artifact identity is invalid"
                        .into(),
                );
            }
            rotation_sources.push(source);
        }
    }
    let expected =
        verify_factory_release_state_transparency_external_gossip_quorum_with_observer_trust(
            &base_source,
            &report.base_observer_quorum_policy_sha256,
            &effective_source,
            &report.effective_observer_quorum_policy_sha256,
            &rotation_sources,
            &quorum_source,
            report.selected_ledger_latest_observer_rotations_verified,
        )?;
    if &expected != report {
        return Err(
            "factory release transparency external gossip observer trust report binding is invalid"
                .into(),
        );
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseStateTransparencyExternalGossipTrustVerificationReport,
) -> Result<String, String> {
    let mut unbound = report.clone();
    unbound.binding_sha256.clear();
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &unbound,
        "factory release transparency external gossip observer trust report binding",
    )
}

#[allow(clippy::too_many_arguments)]
fn rotation_payload(
    base_policy_sha256: &str,
    policy_id: &str,
    organization_id: &str,
    observer_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_rotation_sha256: Option<&str>,
    old_public_key: &str,
    new_public_key: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&RotationPayload {
        domain: ROTATION_DOMAIN,
        schema_version:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_SCHEMA_VERSION,
        rotation_scope:
            FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION_SCOPE,
        base_observer_quorum_policy_sha256: base_policy_sha256,
        policy_id,
        organization_id,
        observer_id,
        from_generation,
        to_generation,
        previous_rotation_sha256,
        old_public_key,
        new_public_key,
        rotated_at_unix,
        algorithm: "ed25519",
    })
    .map_err(|error| {
        format!(
            "serializing factory release transparency external gossip observer rotation payload: {error}"
        )
    })
}

fn normalized_sha256(value: &impl Serialize, label: &str) -> Result<String, String> {
    let source =
        serde_json::to_vec(value).map_err(|error| format!("serializing {label}: {error}"))?;
    Ok(sha256(&source))
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
    let bytes = decode_hex::<32>(value, label)?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid {label}: {error}"))?;
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
            "{label} must contain exactly {N} lowercase hexadecimal bytes"
        ));
    }
    hex::decode(value)
        .map_err(|error| format!("invalid {label}: {error}"))?
        .try_into()
        .map_err(|_| format!("{label} has the wrong length"))
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
        "type": "object", "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
            "sha256": digest_schema()
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_observer_trust_state_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-observer-trust-state-v1.json",
        "title": "pcbex factory-release transparency external-gossip observer trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "trust_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "organization_id", "observer_id", "generation",
            "initial_public_key", "current_public_key", "last_rotation_sha256",
            "last_rotated_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "trust_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_TRUST_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "organization_id": slug_schema(),
            "observer_id": observer_slug_schema(),
            "generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION
            },
            "initial_public_key": digest_schema(),
            "current_public_key": digest_schema(),
            "last_rotation_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "last_rotated_at_unix": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP}
                ]
            }
        }
    })
}

pub(crate) fn signed_factory_release_state_transparency_external_gossip_observer_key_rotation_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-state-transparency-external-gossip-observer-key-rotation-v1.json",
        "title": "Signed pcbex factory-release transparency external-gossip observer key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "rotation_scope", "base_observer_quorum_policy_sha256",
            "policy_id", "organization_id", "observer_id", "from_generation",
            "to_generation", "previous_rotation_sha256", "old_public_key",
            "new_public_key", "rotated_at_unix", "algorithm", "old_signature",
            "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "rotation_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATION_SCOPE},
            "base_observer_quorum_policy_sha256": digest_schema(),
            "policy_id": slug_schema(),
            "organization_id": slug_schema(),
            "observer_id": observer_slug_schema(),
            "from_generation": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION - 1
            },
            "to_generation": {
                "type": "integer", "minimum": 1,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_GENERATION
            },
            "previous_rotation_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_public_key": digest_schema(),
            "new_public_key": digest_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn factory_release_state_transparency_external_gossip_trust_report_json_schema() -> Value
{
    let trust_state =
        factory_release_state_transparency_external_gossip_observer_trust_state_json_schema();
    let rotation =
        signed_factory_release_state_transparency_external_gossip_observer_key_rotation_json_schema(
        );
    let rotation_evidence = json!({
        "type": "object", "additionalProperties": false,
        "required": ["artifact", "rotation"],
        "properties": {
            "artifact": artifact_schema(MAX_SIGNED_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_KEY_ROTATION_BYTES),
            "rotation": rotation
        }
    });
    let observer_trust = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "organization_id", "observer_id", "initial_public_key",
            "current_trust_state", "current_trust_state_sha256", "rotations"
        ],
        "properties": {
            "organization_id": slug_schema(),
            "observer_id": observer_slug_schema(),
            "initial_public_key": digest_schema(),
            "current_trust_state": trust_state,
            "current_trust_state_sha256": digest_schema(),
            "rotations": {
                "type": "array", "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATIONS,
                "items": rotation_evidence
            }
        }
    });
    let true_value = json!({"const": true});
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-state-transparency-external-gossip-observer-trust-verification-report-v1.json",
        "title": "pcbex factory-release transparency external-gossip observer trust verification report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "status",
            "base_observer_quorum_policy_pin_matched",
            "complete_observer_rotation_histories_verified",
            "observer_rotation_dual_signatures_verified",
            "observer_rotation_generation_chains_verified",
            "observer_rotation_digest_chains_verified",
            "observer_rotation_timestamps_monotonic",
            "effective_observer_quorum_policy_derived",
            "effective_observer_quorum_policy_pin_matched",
            "current_observer_trust_bound_to_quorum",
            "selected_ledger_latest_observer_rotations_verified",
            "selected_ledger_rollback_resistance_verified",
            "global_non_equivocation_verified", "trusted_time_verified",
            "independent_organization_operation_verified", "factory_legal_identity_verified",
            "capacity_reserved", "order_placed", "payment_performed",
            "exactly_once_execution_verified", "quorum_met",
            "base_observer_quorum_policy_artifact", "base_observer_quorum_policy_sha256",
            "base_observer_quorum_policy", "effective_observer_quorum_policy_artifact",
            "effective_observer_quorum_policy_sha256", "effective_observer_quorum_policy",
            "observer_rotation_count", "observer_trust", "quorum_report_artifact",
            "quorum_report", "evaluated_at_unix", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "verification_scope": {"const": FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_TRUST_VERIFICATION_SCOPE},
            "status": {"enum": ["verified", "insufficient_organizations"]},
            "base_observer_quorum_policy_pin_matched": true_value.clone(),
            "complete_observer_rotation_histories_verified": true_value.clone(),
            "observer_rotation_dual_signatures_verified": true_value.clone(),
            "observer_rotation_generation_chains_verified": true_value.clone(),
            "observer_rotation_digest_chains_verified": true_value.clone(),
            "observer_rotation_timestamps_monotonic": true_value.clone(),
            "effective_observer_quorum_policy_derived": true_value.clone(),
            "effective_observer_quorum_policy_pin_matched": true_value.clone(),
            "current_observer_trust_bound_to_quorum": true_value.clone(),
            "selected_ledger_latest_observer_rotations_verified": true_value,
            "selected_ledger_rollback_resistance_verified": false_value.clone(),
            "global_non_equivocation_verified": false_value.clone(),
            "trusted_time_verified": false_value.clone(),
            "independent_organization_operation_verified": false_value.clone(),
            "factory_legal_identity_verified": false_value.clone(),
            "capacity_reserved": false_value.clone(),
            "order_placed": false_value.clone(),
            "payment_performed": false_value.clone(),
            "exactly_once_execution_verified": false_value,
            "quorum_met": {"type": "boolean"},
            "base_observer_quorum_policy_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES),
            "base_observer_quorum_policy_sha256": digest_schema(),
            "base_observer_quorum_policy": factory_release_state_transparency_external_gossip_quorum_policy_json_schema(),
            "effective_observer_quorum_policy_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_BYTES),
            "effective_observer_quorum_policy_sha256": digest_schema(),
            "effective_observer_quorum_policy": factory_release_state_transparency_external_gossip_quorum_policy_json_schema(),
            "observer_rotation_count": {
                "type": "integer", "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVER_ROTATIONS
            },
            "observer_trust": {
                "type": "array", "minItems": 2,
                "maxItems": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_OBSERVATIONS,
                "items": observer_trust
            },
            "quorum_report_artifact": artifact_schema(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_REPORT_BYTES),
            "quorum_report": factory_release_state_transparency_external_gossip_quorum_report_json_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "binding_sha256": digest_schema()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_release_state_transparency_external_gossip_quorum::{
        FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE,
        TrustedFactoryReleaseTransparencyExternalGossipObserver,
    };

    fn public(secret: [u8; 32]) -> String {
        hex::encode(SigningKey::from_bytes(&secret).verifying_key().to_bytes())
    }

    fn policy() -> FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
        FactoryReleaseStateTransparencyExternalGossipQuorumPolicy {
            schema_version: 1,
            policy_scope: FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_QUORUM_POLICY_SCOPE
                .into(),
            policy_id: "external-observers".into(),
            minimum_organizations: 2,
            maximum_receipt_age_seconds: 300,
            trusted_observers: vec![
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "lab-a".into(),
                    observer_id: "observer-a".into(),
                    algorithm: "ed25519".into(),
                    public_key: public([11; 32]),
                },
                TrustedFactoryReleaseTransparencyExternalGossipObserver {
                    organization_id: "lab-b".into(),
                    observer_id: "observer-b".into(),
                    algorithm: "ed25519".into(),
                    public_key: public([21; 32]),
                },
            ],
        }
    }

    #[test]
    fn dual_signed_rotation_derives_an_effective_v1491_policy() {
        let base = policy();
        let base_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&base).unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &base,
            &base_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let first = sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
            &initial, &[11; 32], &[12; 32], 1_000,
        )
        .unwrap();
        let rotated =
            apply_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &initial, &first,
            )
            .unwrap();
        assert_eq!(rotated.generation, 1);
        assert_eq!(rotated.current_public_key, public([12; 32]));
        assert!(
            apply_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotated, &first,
            )
            .is_err()
        );
        let untouched =
            new_factory_release_state_transparency_external_gossip_observer_trust_state(
                &base,
                &base_sha,
                "lab-b",
                "observer-b",
            )
            .unwrap();
        let effective =
            derive_factory_release_state_transparency_external_gossip_effective_quorum_policy(
                &base,
                &[rotated.clone(), untouched],
            )
            .unwrap();
        assert_eq!(effective.trusted_observers[0].public_key, public([12; 32]));
        assert_eq!(effective.trusted_observers[1].public_key, public([21; 32]));

        let second = sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
            &rotated, &[12; 32], &[13; 32], 2_000,
        )
        .unwrap();
        let twice = apply_factory_release_state_transparency_external_gossip_observer_key_rotation(
            &rotated, &second,
        )
        .unwrap();
        assert_eq!(twice.generation, 2);
        assert_eq!(twice.current_public_key, public([13; 32]));

        let mut fork = second.clone();
        fork.previous_rotation_sha256 = Some("0".repeat(64));
        assert!(
            apply_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotated, &fork,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotated, &[11; 32], &[13; 32], 2_000,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotated, &[12; 32], &[12; 32], 2_000,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotated, &[12; 32], &[11; 32], 2_000,
            )
            .is_err()
        );
        assert!(
            sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotated, &[12; 32], &[13; 32], 999,
            )
            .is_err()
        );
        let reused = sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
            &twice, &[13; 32], &[12; 32], 3_000,
        )
        .unwrap();
        let first_source =
            render_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &first,
            )
            .unwrap();
        let second_source =
            render_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &second,
            )
            .unwrap();
        let reused_source =
            render_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &reused,
            )
            .unwrap();
        assert!(
            build_observer_trust_evidence(
                &base,
                &base_sha,
                &[first_source, second_source, reused_source],
            )
            .is_err()
        );
    }

    #[test]
    fn rotation_is_policy_bound_canonical_and_filename_safe() {
        let base = policy();
        let base_sha =
            factory_release_state_transparency_external_gossip_quorum_policy_sha256(&base).unwrap();
        let initial = new_factory_release_state_transparency_external_gossip_observer_trust_state(
            &base,
            &base_sha,
            "lab-a",
            "observer-a",
        )
        .unwrap();
        let rotation =
            sign_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &initial, &[11; 32], &[12; 32], 1_000,
            )
            .unwrap();
        let source =
            render_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &rotation,
            )
            .unwrap();
        assert_eq!(
            parse_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &source
            )
            .unwrap(),
            rotation
        );
        let mut noncanonical = source.clone();
        noncanonical.pop();
        assert!(
            parse_signed_factory_release_state_transparency_external_gossip_observer_key_rotation(
                &noncanonical
            )
            .is_err()
        );
        let filename =
            factory_release_state_transparency_external_gossip_observer_rotation_filename(
                &base_sha,
                &"a".repeat(128),
                &"b".repeat(128),
                1,
            )
            .unwrap();
        assert!(filename.len() < 160);
        assert!(!filename.contains(&base_sha));
    }

    #[test]
    fn schemas_are_closed_and_bounded() {
        let state =
            factory_release_state_transparency_external_gossip_observer_trust_state_json_schema();
        let rotation = signed_factory_release_state_transparency_external_gossip_observer_key_rotation_json_schema();
        let report = factory_release_state_transparency_external_gossip_trust_report_json_schema();
        assert_eq!(state["additionalProperties"], false);
        assert_eq!(rotation["additionalProperties"], false);
        assert_eq!(report["additionalProperties"], false);
        assert_eq!(
            report["properties"]["observer_trust"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            report["properties"]["selected_ledger_rollback_resistance_verified"],
            json!({"const": false})
        );
    }
}
