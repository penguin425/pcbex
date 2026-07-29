use crate::policy_lifecycle_anchor::PolicyLifecycleLogAnchorProof;
use crate::policy_lifecycle_gossip_quorum::PolicyLifecycleLogGossipObservation;
use crate::policy_lifecycle_gossip_trust::{
    PolicyLifecycleLogGossipObserverTrustState, PolicyLifecycleLogGossipTrustBoundQuorumReport,
    policy_lifecycle_log_gossip_observer_trust_state_sha256,
    policy_lifecycle_log_gossip_trust_bound_quorum_report_json_schema,
    validate_policy_lifecycle_log_gossip_observer_trust_state,
    validate_policy_lifecycle_log_gossip_trust_bound_quorum_report,
    verify_policy_lifecycle_log_gossip_quorum_with_observer_trust_states,
};
use clap::ValueEnum;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const TRANSITION_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-transition-v1";
const AUTHORITY_ROTATION_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-authority-key-rotation-v1";
const GOVERNANCE_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-governance-v1";
const THRESHOLD_TRANSITION_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-threshold-transition-v1";
const GOVERNANCE_ROTATION_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-governance-rotation-v1";
const GOVERNED_AUTHORITY_ROTATION_DOMAIN: &str = "pcbex-policy-lifecycle-public-log-gossip-organization-registry-governed-authority-key-rotation-v1";
const MAXIMUM_GOVERNANCE_AUTHORITIES: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLifecycleLogGossipOrganizationStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipObserverAdmission {
    pub observer_id: String,
    pub observer_trust_state_sha256: String,
    pub admitted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipOrganizationRegistryEntry {
    pub organization_id: String,
    pub status: PolicyLifecycleLogGossipOrganizationStatus,
    pub status_since_unix: u64,
    pub status_reason_sha256: String,
    pub observers: Vec<PolicyLifecycleLogGossipObserverAdmission>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipOrganizationRegistry {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub authority_public_key: String,
    #[serde(default)]
    pub active_governance_sha256: Option<String>,
    pub last_transition_sha256: Option<String>,
    pub last_updated_at_unix: Option<u64>,
    pub organizations: Vec<PolicyLifecycleLogGossipOrganizationRegistryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLifecycleLogGossipOrganizationRegistryAction {
    AdmitObserver,
    SuspendOrganization,
    RevokeOrganization,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryTransition {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub action: PolicyLifecycleLogGossipOrganizationRegistryAction,
    pub organization_id: String,
    pub observer_id: Option<String>,
    pub observer_trust_state_sha256: Option<String>,
    pub reason_sha256: String,
    pub effective_at_unix: u64,
    pub authority_public_key: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub old_public_key: String,
    pub new_public_key: String,
    pub rotated_at_unix: u64,
    pub algorithm: String,
    pub old_signature: String,
    pub new_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipRegistryGovernanceAuthority {
    pub authority_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance {
    pub schema_version: u32,
    pub registry_id: String,
    pub registry_authority_public_key: String,
    pub minimum_approvals: u32,
    pub authorities: Vec<PolicyLifecycleLogGossipRegistryGovernanceAuthority>,
    pub issued_at_unix: u64,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipRegistryThresholdApproval {
    pub authority_id: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub governance_sha256: String,
    pub action: PolicyLifecycleLogGossipOrganizationRegistryAction,
    pub organization_id: String,
    pub observer_id: Option<String>,
    pub observer_trust_state_sha256: Option<String>,
    pub reason_sha256: String,
    pub effective_at_unix: u64,
    pub algorithm: String,
    pub approvals: Vec<PolicyLifecycleLogGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub old_governance_sha256: String,
    pub new_governance_sha256: String,
    pub rotated_at_unix: u64,
    pub algorithm: String,
    pub old_approvals: Vec<PolicyLifecycleLogGossipRegistryThresholdApproval>,
    pub new_approvals: Vec<PolicyLifecycleLogGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub old_public_key: String,
    pub new_public_key: String,
    pub old_governance_sha256: String,
    pub new_governance_sha256: String,
    pub rotated_at_unix: u64,
    pub algorithm: String,
    pub old_approvals: Vec<PolicyLifecycleLogGossipRegistryThresholdApproval>,
    pub new_approvals: Vec<PolicyLifecycleLogGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipRegistryBoundQuorumReport {
    pub schema_version: u32,
    pub trust_quorum: PolicyLifecycleLogGossipTrustBoundQuorumReport,
    pub registry_id: String,
    pub registry_generation: u64,
    pub registry_sha256: String,
    pub registry_bound: bool,
}

#[derive(Serialize)]
struct TransitionPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    action: &'a PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &'a str,
    observer_id: Option<&'a str>,
    observer_trust_state_sha256: Option<&'a str>,
    reason_sha256: &'a str,
    effective_at_unix: u64,
    authority_public_key: &'a str,
}

#[derive(Serialize)]
struct AuthorityRotationPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    rotated_at_unix: u64,
}

#[derive(Serialize)]
struct GovernancePayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    registry_authority_public_key: &'a str,
    minimum_approvals: u32,
    authorities: &'a [PolicyLifecycleLogGossipRegistryGovernanceAuthority],
    issued_at_unix: u64,
}

#[derive(Serialize)]
struct ThresholdTransitionPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    governance_sha256: &'a str,
    action: &'a PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &'a str,
    observer_id: Option<&'a str>,
    observer_trust_state_sha256: Option<&'a str>,
    reason_sha256: &'a str,
    effective_at_unix: u64,
}

#[derive(Serialize)]
struct GovernanceRotationPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    old_governance_sha256: &'a str,
    new_governance_sha256: &'a str,
    rotated_at_unix: u64,
}

#[derive(Serialize)]
struct GovernedAuthorityRotationPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    old_governance_sha256: &'a str,
    new_governance_sha256: &'a str,
    rotated_at_unix: u64,
}

pub fn new_policy_lifecycle_log_gossip_organization_registry(
    registry_id: &str,
    authority_public_key: &[u8; 32],
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    validate_slug(registry_id, "gossip organization registry id")?;
    VerifyingKey::from_bytes(authority_public_key)
        .map_err(|error| format!("invalid gossip registry authority public key: {error}"))?;
    Ok(PolicyLifecycleLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry_id.into(),
        generation: 0,
        authority_public_key: hex_encode(authority_public_key),
        active_governance_sha256: None,
        last_transition_sha256: None,
        last_updated_at_unix: None,
        organizations: Vec::new(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy_lifecycle_log_gossip_organization_registry_transition(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    authority_secret_key: &[u8; 32],
    action: PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&PolicyLifecycleLogGossipObserverTrustState>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryTransition, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "gossip registry with active governance requires a threshold transition".into(),
        );
    }
    validate_slug(organization_id, "gossip registry organization id")?;
    validate_sha256(reason_sha256, "gossip registry transition reason SHA-256")?;
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| effective_at_unix < previous)
    {
        return Err("gossip registry transition timestamps must be monotonic".into());
    }
    let authority = SigningKey::from_bytes(authority_secret_key);
    let authority_public_key = hex_encode(&authority.verifying_key().to_bytes());
    if authority_public_key != registry.authority_public_key {
        return Err("gossip registry authority key does not match retained trust".into());
    }
    let (observer_id, observer_trust_state_sha256) =
        transition_observer_binding(&action, organization_id, observer_trust_state)?;
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "gossip organization registry generation overflow".to_string())?;
    let payload = transition_payload(
        registry,
        to_generation,
        &action,
        organization_id,
        observer_id.as_deref(),
        observer_trust_state_sha256.as_deref(),
        reason_sha256,
        effective_at_unix,
    )?;
    let transition = SignedPolicyLifecycleLogGossipOrganizationRegistryTransition {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        action,
        organization_id: organization_id.into(),
        observer_id,
        observer_trust_state_sha256,
        reason_sha256: reason_sha256.into(),
        effective_at_unix,
        authority_public_key,
        algorithm: "ed25519".into(),
        signature: hex_encode(&authority.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_transition(&transition)?;
    Ok(transition)
}

pub fn apply_policy_lifecycle_log_gossip_organization_registry_transition(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryTransition,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err("gossip registry with active governance rejects root-only transitions".into());
    }
    validate_signed_policy_lifecycle_log_gossip_organization_registry_transition(transition)?;
    if transition.registry_id != registry.registry_id
        || transition.from_generation != registry.generation
        || transition.previous_transition_sha256 != registry.last_transition_sha256
        || transition.authority_public_key != registry.authority_public_key
    {
        return Err("gossip registry transition does not extend retained state".into());
    }
    if transition.to_generation
        != registry
            .generation
            .checked_add(1)
            .ok_or_else(|| "gossip organization registry generation overflow".to_string())?
    {
        return Err("gossip registry transition must advance exactly one generation".into());
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| transition.effective_at_unix < previous)
    {
        return Err("gossip registry transition timestamps must be monotonic".into());
    }
    let payload = transition_payload(
        registry,
        transition.to_generation,
        &transition.action,
        &transition.organization_id,
        transition.observer_id.as_deref(),
        transition.observer_trust_state_sha256.as_deref(),
        &transition.reason_sha256,
        transition.effective_at_unix,
    )?;
    let public_key = hex_decode::<32>(
        &transition.authority_public_key,
        "gossip registry authority public key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &transition.signature,
        "gossip registry authority signature",
    )?);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid gossip registry authority public key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "gossip registry transition signature verification failed".to_string())?;

    let mut organizations = registry.organizations.clone();
    apply_action(&mut organizations, transition)?;
    organizations.sort_by(|left, right| left.organization_id.cmp(&right.organization_id));
    let next = PolicyLifecycleLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: transition.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: None,
        last_transition_sha256: Some(
            signed_policy_lifecycle_log_gossip_organization_registry_transition_sha256(transition)?,
        ),
        last_updated_at_unix: Some(transition.effective_at_unix),
        organizations,
    };
    validate_policy_lifecycle_log_gossip_organization_registry(&next)?;
    Ok(next)
}

pub fn sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "gossip registry with active governance rejects root-only authority rotation".into(),
        );
    }
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != registry.authority_public_key {
        return Err("old gossip registry authority key does not match retained trust".into());
    }
    if new_public_key == old_public_key {
        return Err("new gossip registry authority key must differ from the current key".into());
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err("gossip registry authority rotation timestamps must be monotonic".into());
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "gossip organization registry generation overflow".to_string())?;
    let payload = authority_rotation_payload(
        &registry.registry_id,
        registry.generation,
        to_generation,
        registry.last_transition_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    let rotation = SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        old_public_key,
        new_public_key,
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_signature: hex_encode(&old_key.sign(&payload).to_bytes()),
        new_signature: hex_encode(&new_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "gossip registry with active governance rejects root-only authority rotation".into(),
        );
    }
    validate_signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
        rotation,
    )?;
    if rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_public_key != registry.authority_public_key
    {
        return Err("gossip registry authority rotation does not extend retained state".into());
    }
    let expected_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "gossip organization registry generation overflow".to_string())?;
    if rotation.to_generation != expected_generation {
        return Err(
            "gossip registry authority rotation must advance exactly one generation".into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err("gossip registry authority rotation timestamps must be monotonic".into());
    }
    let payload = authority_rotation_payload(
        &rotation.registry_id,
        rotation.from_generation,
        rotation.to_generation,
        rotation.previous_transition_sha256.as_deref(),
        &rotation.old_public_key,
        &rotation.new_public_key,
        rotation.rotated_at_unix,
    )?;
    for (key, signature, label) in [
        (
            &rotation.old_public_key,
            &rotation.old_signature,
            "old gossip registry authority rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new gossip registry authority rotation",
        ),
    ] {
        let key = hex_decode::<32>(key, label)?;
        let signature = Signature::from_bytes(&hex_decode::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let next = PolicyLifecycleLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: rotation.new_public_key.clone(),
        active_governance_sha256: None,
        last_transition_sha256: Some(
            signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_policy_lifecycle_log_gossip_organization_registry(&next)?;
    Ok(next)
}

pub fn sign_policy_lifecycle_log_gossip_organization_registry_governance(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    registry_authority_secret_key: &[u8; 32],
    minimum_approvals: u32,
    mut authorities: Vec<PolicyLifecycleLogGossipRegistryGovernanceAuthority>,
    issued_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    if !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&minimum_approvals) {
        return Err(
            "gossip registry governance minimum approvals must be between 2 and 100".into(),
        );
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_authorities(&authorities)?;
    if authorities.len() < minimum_approvals as usize {
        return Err("gossip registry governance has fewer authorities than its threshold".into());
    }
    let signing_key = SigningKey::from_bytes(registry_authority_secret_key);
    let registry_authority_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if registry_authority_public_key != registry.authority_public_key {
        return Err("gossip registry governance signer does not match retained authority".into());
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err("gossip registry governance predates retained registry state".into());
    }
    let payload = governance_payload(
        &registry.registry_id,
        &registry_authority_public_key,
        minimum_approvals,
        &authorities,
        issued_at_unix,
    )?;
    let governance = SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        registry_authority_public_key,
        minimum_approvals,
        authorities,
        issued_at_unix,
        algorithm: "ed25519".into(),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(&governance)?;
    Ok(governance)
}

pub fn sign_policy_lifecycle_log_gossip_organization_registry_successor_governance(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    successor_registry_authority_secret_key: &[u8; 32],
    minimum_approvals: u32,
    mut authorities: Vec<PolicyLifecycleLogGossipRegistryGovernanceAuthority>,
    issued_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_none() {
        return Err("successor governance requires retained active governance".into());
    }
    if !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&minimum_approvals) {
        return Err(
            "gossip registry governance minimum approvals must be between 2 and 100".into(),
        );
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_authorities(&authorities)?;
    if authorities.len() < minimum_approvals as usize {
        return Err("gossip registry governance has fewer authorities than its threshold".into());
    }
    let signing_key = SigningKey::from_bytes(successor_registry_authority_secret_key);
    let successor_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if successor_public_key == registry.authority_public_key {
        return Err("successor governance root must differ from retained registry root".into());
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err("successor gossip registry governance predates retained state".into());
    }
    let payload = governance_payload(
        &registry.registry_id,
        &successor_public_key,
        minimum_approvals,
        &authorities,
        issued_at_unix,
    )?;
    let governance = SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        registry_authority_public_key: successor_public_key,
        minimum_approvals,
        authorities,
        issued_at_unix,
        algorithm: "ed25519".into(),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(&governance)?;
    verify_governance_root_signature(&governance)?;
    Ok(governance)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    signers: &[(String, [u8; 32])],
    action: PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&PolicyLifecycleLogGossipObserverTrustState>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition, String> {
    validate_governance_for_registry(registry, governance)?;
    validate_slug(organization_id, "gossip registry organization id")?;
    validate_sha256(reason_sha256, "gossip registry transition reason SHA-256")?;
    if effective_at_unix < governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| effective_at_unix < last)
    {
        return Err("governed gossip registry transition timestamps must be monotonic".into());
    }
    if signers.len() < governance.minimum_approvals as usize
        || signers.len() > governance.authorities.len()
    {
        return Err("governed gossip registry transition does not satisfy its threshold".into());
    }
    let (observer_id, observer_trust_state_sha256) =
        transition_observer_binding(&action, organization_id, observer_trust_state)?;
    let governance_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(governance)?;
    if registry
        .active_governance_sha256
        .as_deref()
        .is_some_and(|retained| retained != governance_sha256)
    {
        return Err("gossip registry governance does not match retained active governance".into());
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "gossip organization registry generation overflow".to_string())?;
    let payload = threshold_transition_payload(
        &registry.registry_id,
        registry.generation,
        to_generation,
        registry.last_transition_sha256.as_deref(),
        &governance_sha256,
        &action,
        organization_id,
        observer_id.as_deref(),
        observer_trust_state_sha256.as_deref(),
        reason_sha256,
        effective_at_unix,
    )?;
    let mut seen_ids = HashSet::new();
    let mut seen_keys = HashSet::new();
    let mut approvals = Vec::with_capacity(signers.len());
    for (authority_id, secret_key) in signers {
        if !seen_ids.insert(authority_id.as_str()) {
            return Err("duplicate gossip registry governance authority identity".into());
        }
        let key = SigningKey::from_bytes(secret_key);
        let public_key = hex_encode(&key.verifying_key().to_bytes());
        if !seen_keys.insert(public_key.clone()) {
            return Err("duplicate gossip registry governance authority public key".into());
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.as_str().cmp(authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| {
                format!("untrusted gossip registry governance authority {authority_id:?}")
            })?;
        if trusted.public_key != public_key {
            return Err(format!(
                "gossip registry governance authority {authority_id:?} key does not match policy"
            ));
        }
        approvals.push(PolicyLifecycleLogGossipRegistryThresholdApproval {
            authority_id: authority_id.clone(),
            public_key,
            signature: hex_encode(&key.sign(&payload).to_bytes()),
        });
    }
    approvals.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    let transition = SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        governance_sha256,
        action,
        organization_id: organization_id.into(),
        observer_id,
        observer_trust_state_sha256,
        reason_sha256: reason_sha256.into(),
        effective_at_unix,
        algorithm: "ed25519".into(),
        approvals,
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
        &transition,
    )?;
    Ok(transition)
}

pub fn apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    validate_governance_for_registry(registry, governance)?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
        transition,
    )?;
    let governance_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(governance)?;
    if registry
        .active_governance_sha256
        .as_deref()
        .is_some_and(|retained| retained != governance_sha256)
    {
        return Err("gossip registry governance does not match retained active governance".into());
    }
    if transition.registry_id != registry.registry_id
        || transition.from_generation != registry.generation
        || transition.to_generation
            != registry
                .generation
                .checked_add(1)
                .ok_or_else(|| "gossip organization registry generation overflow".to_string())?
        || transition.previous_transition_sha256 != registry.last_transition_sha256
        || transition.governance_sha256 != governance_sha256
    {
        return Err("governed gossip registry transition does not extend retained state".into());
    }
    if transition.effective_at_unix < governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| transition.effective_at_unix < last)
    {
        return Err("governed gossip registry transition timestamps must be monotonic".into());
    }
    if transition.approvals.len() < governance.minimum_approvals as usize {
        return Err("governed gossip registry transition has insufficient approvals".into());
    }
    let payload = threshold_transition_payload(
        &transition.registry_id,
        transition.from_generation,
        transition.to_generation,
        transition.previous_transition_sha256.as_deref(),
        &transition.governance_sha256,
        &transition.action,
        &transition.organization_id,
        transition.observer_id.as_deref(),
        transition.observer_trust_state_sha256.as_deref(),
        &transition.reason_sha256,
        transition.effective_at_unix,
    )?;
    let mut previous_id = None;
    let mut seen_keys = HashSet::new();
    for approval in &transition.approvals {
        if previous_id.is_some_and(|id: &String| id >= &approval.authority_id) {
            return Err("governed gossip registry approvals must be unique and ordered".into());
        }
        previous_id = Some(&approval.authority_id);
        if !seen_keys.insert(approval.public_key.as_str()) {
            return Err("governed gossip registry approvals require distinct keys".into());
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.cmp(&approval.authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| "untrusted governed gossip registry approval".to_string())?;
        if trusted.public_key != approval.public_key {
            return Err("governed gossip registry approval key substitution".into());
        }
        let key = hex_decode::<32>(&approval.public_key, "governance approval public key")?;
        let signature = Signature::from_bytes(&hex_decode::<64>(
            &approval.signature,
            "governance approval signature",
        )?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid governance approval public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| "governed gossip registry approval verification failed".to_string())?;
    }
    let compatibility_transition = SignedPolicyLifecycleLogGossipOrganizationRegistryTransition {
        schema_version: 1,
        registry_id: transition.registry_id.clone(),
        from_generation: transition.from_generation,
        to_generation: transition.to_generation,
        previous_transition_sha256: transition.previous_transition_sha256.clone(),
        action: transition.action.clone(),
        organization_id: transition.organization_id.clone(),
        observer_id: transition.observer_id.clone(),
        observer_trust_state_sha256: transition.observer_trust_state_sha256.clone(),
        reason_sha256: transition.reason_sha256.clone(),
        effective_at_unix: transition.effective_at_unix,
        authority_public_key: registry.authority_public_key.clone(),
        algorithm: "ed25519".into(),
        signature: "00".repeat(64),
    };
    let mut organizations = registry.organizations.clone();
    apply_action(&mut organizations, &compatibility_transition)?;
    organizations.sort_by(|left, right| left.organization_id.cmp(&right.organization_id));
    let next = PolicyLifecycleLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: transition.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: Some(governance_sha256),
        last_transition_sha256: Some(
            signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition_sha256(
                transition,
            )?,
        ),
        last_updated_at_unix: Some(transition.effective_at_unix),
        organizations,
    };
    validate_policy_lifecycle_log_gossip_organization_registry(&next)?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    old_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    new_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    old_signers: &[(String, [u8; 32])],
    new_signers: &[(String, [u8; 32])],
    rotated_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation, String> {
    validate_governance_for_registry(registry, old_governance)?;
    validate_governance_for_registry(registry, new_governance)?;
    let old_governance_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(old_governance)?;
    let new_governance_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(new_governance)?;
    if registry.active_governance_sha256.as_deref() != Some(old_governance_sha256.as_str()) {
        return Err("old governance does not match retained active governance".into());
    }
    if old_governance_sha256 == new_governance_sha256 {
        return Err("successor gossip registry governance must differ".into());
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotated_at_unix < new_governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| new_governance.issued_at_unix < last || rotated_at_unix < last)
    {
        return Err("gossip registry governance rotation timestamps must be monotonic".into());
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "gossip organization registry generation overflow".to_string())?;
    let payload = governance_rotation_payload(
        &registry.registry_id,
        registry.generation,
        to_generation,
        registry.last_transition_sha256.as_deref(),
        &old_governance_sha256,
        &new_governance_sha256,
        rotated_at_unix,
    )?;
    let rotation = SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        old_governance_sha256,
        new_governance_sha256,
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_approvals: sign_governance_approvals(old_governance, old_signers, &payload, "old")?,
        new_approvals: sign_governance_approvals(new_governance, new_signers, &payload, "new")?,
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn apply_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    old_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    new_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    validate_governance_for_registry(registry, old_governance)?;
    validate_governance_for_registry(registry, new_governance)?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
        rotation,
    )?;
    let old_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(old_governance)?;
    let new_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(new_governance)?;
    if registry.active_governance_sha256.as_deref() != Some(old_sha256.as_str()) {
        return Err("old governance does not match retained active governance".into());
    }
    if rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.to_generation
            != registry
                .generation
                .checked_add(1)
                .ok_or_else(|| "gossip organization registry generation overflow".to_string())?
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_governance_sha256 != old_sha256
        || rotation.new_governance_sha256 != new_sha256
    {
        return Err("gossip registry governance rotation does not extend retained state".into());
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotation.rotated_at_unix < new_governance.issued_at_unix
        || registry.last_updated_at_unix.is_some_and(|last| {
            new_governance.issued_at_unix < last || rotation.rotated_at_unix < last
        })
    {
        return Err("gossip registry governance rotation timestamps must be monotonic".into());
    }
    let payload = governance_rotation_payload(
        &rotation.registry_id,
        rotation.from_generation,
        rotation.to_generation,
        rotation.previous_transition_sha256.as_deref(),
        &rotation.old_governance_sha256,
        &rotation.new_governance_sha256,
        rotation.rotated_at_unix,
    )?;
    verify_governance_approvals(old_governance, &rotation.old_approvals, &payload, "old")?;
    verify_governance_approvals(new_governance, &rotation.new_approvals, &payload, "new")?;
    let next = PolicyLifecycleLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: Some(new_sha256),
        last_transition_sha256: Some(
            signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_policy_lifecycle_log_gossip_organization_registry(&next)?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    old_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    new_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    old_signers: &[(String, [u8; 32])],
    new_signers: &[(String, [u8; 32])],
    rotated_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation, String>
{
    validate_governance_for_registry(registry, old_governance)?;
    validate_successor_governance_for_registry(registry, new_governance)?;
    let old_governance_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(old_governance)?;
    let new_governance_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(new_governance)?;
    if registry.active_governance_sha256.as_deref() != Some(old_governance_sha256.as_str()) {
        return Err("old governance does not match retained active governance".into());
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotated_at_unix < new_governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| new_governance.issued_at_unix < last || rotated_at_unix < last)
    {
        return Err("governed registry authority rotation timestamps must be monotonic".into());
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "gossip organization registry generation overflow".to_string())?;
    let payload = governed_authority_rotation_payload(
        &registry.registry_id,
        registry.generation,
        to_generation,
        registry.last_transition_sha256.as_deref(),
        &registry.authority_public_key,
        &new_governance.registry_authority_public_key,
        &old_governance_sha256,
        &new_governance_sha256,
        rotated_at_unix,
    )?;
    let rotation = SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.clone(),
        old_public_key: registry.authority_public_key.clone(),
        new_public_key: new_governance.registry_authority_public_key.clone(),
        old_governance_sha256,
        new_governance_sha256,
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_approvals: sign_governance_approvals(old_governance, old_signers, &payload, "old")?,
        new_approvals: sign_governance_approvals(new_governance, new_signers, &payload, "new")?,
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn apply_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    old_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    new_governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    validate_governance_for_registry(registry, old_governance)?;
    validate_successor_governance_for_registry(registry, new_governance)?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
        rotation,
    )?;
    let old_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(old_governance)?;
    let new_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(new_governance)?;
    if registry.active_governance_sha256.as_deref() != Some(old_sha256.as_str())
        || rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.to_generation
            != registry
                .generation
                .checked_add(1)
                .ok_or_else(|| "gossip organization registry generation overflow".to_string())?
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_public_key != registry.authority_public_key
        || rotation.new_public_key != new_governance.registry_authority_public_key
        || rotation.old_governance_sha256 != old_sha256
        || rotation.new_governance_sha256 != new_sha256
    {
        return Err("governed registry authority rotation does not extend retained state".into());
    }
    if new_governance.issued_at_unix < old_governance.issued_at_unix
        || rotation.rotated_at_unix < new_governance.issued_at_unix
        || registry.last_updated_at_unix.is_some_and(|last| {
            new_governance.issued_at_unix < last || rotation.rotated_at_unix < last
        })
    {
        return Err("governed registry authority rotation timestamps must be monotonic".into());
    }
    let payload = governed_authority_rotation_payload(
        &rotation.registry_id,
        rotation.from_generation,
        rotation.to_generation,
        rotation.previous_transition_sha256.as_deref(),
        &rotation.old_public_key,
        &rotation.new_public_key,
        &rotation.old_governance_sha256,
        &rotation.new_governance_sha256,
        rotation.rotated_at_unix,
    )?;
    verify_governance_approvals(old_governance, &rotation.old_approvals, &payload, "old")?;
    verify_governance_approvals(new_governance, &rotation.new_approvals, &payload, "new")?;
    let next = PolicyLifecycleLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: rotation.new_public_key.clone(),
        active_governance_sha256: Some(new_sha256),
        last_transition_sha256: Some(
            signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_policy_lifecycle_log_gossip_organization_registry(&next)?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_policy_lifecycle_log_gossip_quorum_with_organization_registry(
    local_anchor: &PolicyLifecycleLogAnchorProof,
    observations: &[PolicyLifecycleLogGossipObservation],
    observer_trust_states: &[PolicyLifecycleLogGossipObserverTrustState],
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    minimum_organizations: u32,
    trusted_log_id: &str,
    trusted_log_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipRegistryBoundQuorumReport, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    for state in observer_trust_states {
        validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
        let organization = registry
            .organizations
            .binary_search_by(|entry| entry.organization_id.cmp(&state.organization_id))
            .ok()
            .map(|index| &registry.organizations[index])
            .ok_or_else(|| {
                format!(
                    "gossip observer organization {} is not admitted",
                    state.organization_id
                )
            })?;
        if organization.status != PolicyLifecycleLogGossipOrganizationStatus::Active {
            return Err(format!(
                "gossip observer organization {} is not active",
                state.organization_id
            ));
        }
        let trust_sha256 = policy_lifecycle_log_gossip_observer_trust_state_sha256(state)?;
        let admitted = organization.observers.iter().any(|observer| {
            observer.observer_id == state.observer_id
                && observer.observer_trust_state_sha256 == trust_sha256
        });
        if !admitted {
            return Err(format!(
                "gossip observer {}/{} does not match an admitted trust state",
                state.organization_id, state.observer_id
            ));
        }
    }
    let trust_quorum = verify_policy_lifecycle_log_gossip_quorum_with_observer_trust_states(
        local_anchor,
        observations,
        observer_trust_states,
        minimum_organizations,
        trusted_log_id,
        trusted_log_public_key,
        evaluated_at_unix,
    )?;
    let report = PolicyLifecycleLogGossipRegistryBoundQuorumReport {
        schema_version: 1,
        trust_quorum,
        registry_id: registry.registry_id.clone(),
        registry_generation: registry.generation,
        registry_sha256: policy_lifecycle_log_gossip_organization_registry_sha256(registry)?,
        registry_bound: true,
    };
    validate_policy_lifecycle_log_gossip_registry_bound_quorum_report(&report)?;
    Ok(report)
}

pub fn parse_policy_lifecycle_log_gossip_organization_registry(
    source: &str,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistry, String> {
    let registry = serde_json::from_str(source)
        .map_err(|error| format!("invalid gossip organization registry JSON: {error}"))?;
    validate_policy_lifecycle_log_gossip_organization_registry(&registry)?;
    Ok(registry)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_transition(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryTransition, String> {
    let transition = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed gossip registry transition JSON: {error}"))?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_transition(&transition)?;
    Ok(transition)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation, String> {
    let rotation = serde_json::from_str(source).map_err(|error| {
        format!("invalid signed gossip registry authority rotation JSON: {error}")
    })?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_governance(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance, String> {
    let governance = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed gossip registry governance JSON: {error}"))?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(&governance)?;
    Ok(governance)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition, String> {
    let transition = serde_json::from_str(source).map_err(|error| {
        format!("invalid signed gossip registry threshold transition JSON: {error}")
    })?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
        &transition,
    )?;
    Ok(transition)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation, String> {
    let rotation = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed gossip registry governance rotation: {error}"))?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation, String>
{
    let rotation = serde_json::from_str(source)
        .map_err(|error| format!("invalid governed gossip registry authority rotation: {error}"))?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn parse_policy_lifecycle_log_gossip_registry_bound_quorum_report(
    source: &str,
) -> Result<PolicyLifecycleLogGossipRegistryBoundQuorumReport, String> {
    let report = serde_json::from_str(source)
        .map_err(|error| format!("invalid registry-bound gossip quorum JSON: {error}"))?;
    validate_policy_lifecycle_log_gossip_registry_bound_quorum_report(&report)?;
    Ok(report)
}

pub fn policy_lifecycle_log_gossip_organization_registry_sha256(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
) -> Result<String, String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    normalized_sha256(registry, "gossip organization registry")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_transition_sha256(
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryTransition,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_transition(transition)?;
    normalized_sha256(transition, "signed gossip organization registry transition")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation_sha256(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
        rotation,
    )?;
    normalized_sha256(rotation, "signed gossip registry authority key rotation")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(governance)?;
    normalized_sha256(governance, "signed gossip registry governance")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition_sha256(
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
        transition,
    )?;
    normalized_sha256(transition, "signed gossip registry threshold transition")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation_sha256(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
        rotation,
    )?;
    normalized_sha256(rotation, "signed gossip registry governance rotation")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation_sha256(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
        rotation,
    )?;
    normalized_sha256(
        rotation,
        "signed governed gossip registry authority rotation",
    )
}

pub fn validate_policy_lifecycle_log_gossip_organization_registry(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
) -> Result<(), String> {
    if registry.schema_version != 1 {
        return Err("unsupported gossip organization registry".into());
    }
    validate_slug(&registry.registry_id, "gossip organization registry id")?;
    validate_public_key(
        &registry.authority_public_key,
        "gossip registry authority public key",
    )?;
    if let Some(digest) = &registry.active_governance_sha256 {
        validate_sha256(digest, "active gossip registry governance SHA-256")?;
    }
    match (
        registry.generation,
        &registry.last_transition_sha256,
        registry.last_updated_at_unix,
    ) {
        (0, None, None)
            if registry.organizations.is_empty() && registry.active_governance_sha256.is_none() => {
        }
        (0, _, _) => return Err("initial gossip registry must be empty and unadvanced".into()),
        (_, Some(digest), Some(_)) => {
            validate_sha256(digest, "last gossip registry transition SHA-256")?
        }
        _ => return Err("advanced gossip registry requires complete transition evidence".into()),
    }
    let mut previous = None;
    for organization in &registry.organizations {
        validate_slug(
            &organization.organization_id,
            "gossip registry organization id",
        )?;
        validate_sha256(
            &organization.status_reason_sha256,
            "gossip organization status reason SHA-256",
        )?;
        if registry
            .last_updated_at_unix
            .is_some_and(|last| organization.status_since_unix > last)
        {
            return Err("gossip organization status time exceeds registry update time".into());
        }
        if previous.is_some_and(|value: &String| value >= &organization.organization_id) {
            return Err("gossip registry organizations must be unique and ordered".into());
        }
        previous = Some(&organization.organization_id);
        let mut observer_previous = None;
        for observer in &organization.observers {
            validate_slug(&observer.observer_id, "admitted gossip observer id")?;
            validate_sha256(
                &observer.observer_trust_state_sha256,
                "admitted gossip observer trust-state SHA-256",
            )?;
            if registry
                .last_updated_at_unix
                .is_some_and(|last| observer.admitted_at_unix > last)
            {
                return Err("gossip observer admission time exceeds registry update time".into());
            }
            if observer_previous.is_some_and(|value: &String| value >= &observer.observer_id) {
                return Err("admitted gossip observers must be unique and ordered".into());
            }
            observer_previous = Some(&observer.observer_id);
        }
        if organization.observers.is_empty() {
            return Err("gossip registry organizations require an admitted observer".into());
        }
    }
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_transition(
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryTransition,
) -> Result<(), String> {
    if transition.schema_version != 1
        || transition.algorithm != "ed25519"
        || transition.from_generation.checked_add(1) != Some(transition.to_generation)
    {
        return Err("invalid gossip organization registry transition invariants".into());
    }
    validate_slug(&transition.registry_id, "gossip organization registry id")?;
    validate_slug(
        &transition.organization_id,
        "gossip registry organization id",
    )?;
    validate_sha256(
        &transition.reason_sha256,
        "gossip registry transition reason SHA-256",
    )?;
    if let Some(digest) = &transition.previous_transition_sha256 {
        validate_sha256(digest, "previous gossip registry transition SHA-256")?;
    }
    if (transition.from_generation == 0) != transition.previous_transition_sha256.is_none() {
        return Err("gossip registry transition chain reference is inconsistent".into());
    }
    match transition.action {
        PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver => {
            validate_slug(
                transition
                    .observer_id
                    .as_deref()
                    .ok_or_else(|| "observer admission requires observer id".to_string())?,
                "admitted gossip observer id",
            )?;
            validate_sha256(
                transition
                    .observer_trust_state_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "observer admission requires observer trust-state SHA-256".to_string()
                    })?,
                "admitted gossip observer trust-state SHA-256",
            )?;
        }
        PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization
        | PolicyLifecycleLogGossipOrganizationRegistryAction::RevokeOrganization => {
            if transition.observer_id.is_some() || transition.observer_trust_state_sha256.is_some()
            {
                return Err("organization status transition cannot bind an observer".into());
            }
        }
    }
    validate_public_key(
        &transition.authority_public_key,
        "gossip registry authority public key",
    )?;
    hex_decode::<64>(&transition.signature, "gossip registry authority signature")?;
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid gossip registry authority rotation invariants".into());
    }
    validate_slug(&rotation.registry_id, "gossip organization registry id")?;
    match (
        rotation.from_generation,
        &rotation.previous_transition_sha256,
    ) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err("initial gossip registry rotation cannot reference a transition".into());
        }
        (_, Some(digest)) => {
            validate_sha256(digest, "previous gossip registry transition SHA-256")?
        }
        (_, None) => {
            return Err("advanced gossip registry rotation requires chain evidence".into());
        }
    }
    validate_public_key(
        &rotation.old_public_key,
        "old gossip registry authority public key",
    )?;
    validate_public_key(
        &rotation.new_public_key,
        "new gossip registry authority public key",
    )?;
    hex_decode::<64>(
        &rotation.old_signature,
        "old gossip registry authority signature",
    )?;
    hex_decode::<64>(
        &rotation.new_signature,
        "new gossip registry authority signature",
    )?;
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    if governance.schema_version != 1
        || governance.algorithm != "ed25519"
        || !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&governance.minimum_approvals)
        || governance.authorities.len() < governance.minimum_approvals as usize
    {
        return Err("invalid gossip registry governance invariants".into());
    }
    validate_slug(&governance.registry_id, "gossip organization registry id")?;
    validate_public_key(
        &governance.registry_authority_public_key,
        "gossip registry governance root public key",
    )?;
    validate_governance_authorities(&governance.authorities)?;
    hex_decode::<64>(
        &governance.signature,
        "gossip registry governance signature",
    )?;
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryThresholdTransition,
) -> Result<(), String> {
    if transition.schema_version != 1
        || transition.algorithm != "ed25519"
        || transition.from_generation.checked_add(1) != Some(transition.to_generation)
        || transition.approvals.len() < 2
        || transition.approvals.len() > MAXIMUM_GOVERNANCE_AUTHORITIES
    {
        return Err("invalid governed gossip registry transition invariants".into());
    }
    validate_slug(&transition.registry_id, "gossip organization registry id")?;
    validate_slug(
        &transition.organization_id,
        "gossip registry organization id",
    )?;
    validate_sha256(
        &transition.governance_sha256,
        "gossip registry governance SHA-256",
    )?;
    validate_sha256(
        &transition.reason_sha256,
        "gossip registry transition reason SHA-256",
    )?;
    match (
        transition.from_generation,
        &transition.previous_transition_sha256,
    ) {
        (0, None) => {}
        (0, Some(_)) => return Err("initial governed transition cannot reference history".into()),
        (_, Some(digest)) => validate_sha256(
            digest,
            "previous governed gossip registry transition SHA-256",
        )?,
        (_, None) => return Err("advanced governed transition requires chain evidence".into()),
    }
    match transition.action {
        PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver => {
            validate_slug(
                transition
                    .observer_id
                    .as_deref()
                    .ok_or_else(|| "observer admission requires observer id".to_string())?,
                "admitted gossip observer id",
            )?;
            validate_sha256(
                transition
                    .observer_trust_state_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "observer admission requires observer trust-state SHA-256".to_string()
                    })?,
                "admitted gossip observer trust-state SHA-256",
            )?;
        }
        PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization
        | PolicyLifecycleLogGossipOrganizationRegistryAction::RevokeOrganization => {
            if transition.observer_id.is_some() || transition.observer_trust_state_sha256.is_some()
            {
                return Err("organization status transition cannot bind an observer".into());
            }
        }
    }
    let mut previous = None;
    let mut keys = HashSet::new();
    for approval in &transition.approvals {
        validate_slug(
            &approval.authority_id,
            "gossip registry governance authority id",
        )?;
        validate_public_key(&approval.public_key, "governance approval public key")?;
        hex_decode::<64>(&approval.signature, "governance approval signature")?;
        if previous.is_some_and(|id: &String| id >= &approval.authority_id)
            || !keys.insert(approval.public_key.as_str())
        {
            return Err(
                "governance approvals must have ordered distinct identities and keys".into(),
            );
        }
        previous = Some(&approval.authority_id);
    }
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernanceRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.old_governance_sha256 == rotation.new_governance_sha256
    {
        return Err("invalid gossip registry governance rotation invariants".into());
    }
    validate_slug(&rotation.registry_id, "gossip organization registry id")?;
    match (
        rotation.from_generation,
        &rotation.previous_transition_sha256,
    ) {
        (0, None) => {}
        (0, Some(_)) => return Err("initial governance rotation cannot reference history".into()),
        (_, Some(digest)) => validate_sha256(
            digest,
            "previous gossip registry governance rotation SHA-256",
        )?,
        (_, None) => return Err("advanced governance rotation requires chain evidence".into()),
    }
    validate_sha256(
        &rotation.old_governance_sha256,
        "old gossip registry governance SHA-256",
    )?;
    validate_sha256(
        &rotation.new_governance_sha256,
        "new gossip registry governance SHA-256",
    )?;
    validate_approval_shape(&rotation.old_approvals, "old")?;
    validate_approval_shape(&rotation.new_approvals, "new")?;
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernedAuthorityKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.old_public_key == rotation.new_public_key
        || rotation.old_governance_sha256 == rotation.new_governance_sha256
    {
        return Err("invalid governed gossip registry authority rotation invariants".into());
    }
    validate_slug(&rotation.registry_id, "gossip organization registry id")?;
    match (
        rotation.from_generation,
        &rotation.previous_transition_sha256,
    ) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err("initial governed authority rotation cannot reference history".into());
        }
        (_, Some(digest)) => validate_sha256(
            digest,
            "previous governed registry authority rotation SHA-256",
        )?,
        (_, None) => {
            return Err("advanced governed authority rotation requires chain evidence".into());
        }
    }
    validate_public_key(
        &rotation.old_public_key,
        "old governed registry authority public key",
    )?;
    validate_public_key(
        &rotation.new_public_key,
        "new governed registry authority public key",
    )?;
    validate_sha256(
        &rotation.old_governance_sha256,
        "old governed registry governance SHA-256",
    )?;
    validate_sha256(
        &rotation.new_governance_sha256,
        "new governed registry governance SHA-256",
    )?;
    validate_approval_shape(&rotation.old_approvals, "old")?;
    validate_approval_shape(&rotation.new_approvals, "new")?;
    Ok(())
}

pub fn validate_policy_lifecycle_log_gossip_registry_bound_quorum_report(
    report: &PolicyLifecycleLogGossipRegistryBoundQuorumReport,
) -> Result<(), String> {
    validate_policy_lifecycle_log_gossip_trust_bound_quorum_report(&report.trust_quorum)?;
    if report.schema_version != 1 || !report.registry_bound {
        return Err("invalid registry-bound gossip quorum invariants".into());
    }
    validate_slug(&report.registry_id, "gossip organization registry id")?;
    validate_sha256(
        &report.registry_sha256,
        "gossip organization registry SHA-256",
    )
}

pub fn policy_lifecycle_log_gossip_organization_registry_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-organization-registry-v1.json",
        "title": "pcbex policy lifecycle public-log gossip organization registry",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "authority_public_key",
            "last_transition_sha256", "last_updated_at_unix", "organizations"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "authority_public_key": key_schema(),
            "active_governance_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "last_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "last_updated_at_unix": {"oneOf": [
                {"type": "null"}, {"type": "integer", "minimum": 0}
            ]},
            "organizations": {
                "type": "array", "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "organization_id", "status", "status_since_unix",
                        "status_reason_sha256", "observers"
                    ],
                    "properties": {
                        "organization_id": slug_schema(),
                        "status": {"enum": ["active", "suspended", "revoked"]},
                        "status_since_unix": {"type": "integer", "minimum": 0},
                        "status_reason_sha256": digest_schema(),
                        "observers": {
                            "type": "array", "minItems": 1, "maxItems": 100,
                            "items": {
                                "type": "object", "additionalProperties": false,
                                "required": [
                                    "observer_id", "observer_trust_state_sha256",
                                    "admitted_at_unix"
                                ],
                                "properties": {
                                    "observer_id": slug_schema(),
                                    "observer_trust_state_sha256": digest_schema(),
                                    "admitted_at_unix": {"type": "integer", "minimum": 0}
                                }
                            }
                        }
                    }
                }
            }
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_transition_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-transition-v1.json",
        "title": "Signed pcbex gossip organization registry transition",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "action", "organization_id", "observer_id",
            "observer_trust_state_sha256", "reason_sha256", "effective_at_unix",
            "authority_public_key", "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "from_generation": {"type": "integer", "minimum": 0},
            "to_generation": {"type": "integer", "minimum": 1},
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "action": {"enum": [
                "admit_observer", "suspend_organization", "revoke_organization"
            ]},
            "organization_id": slug_schema(),
            "observer_id": {"oneOf": [{"type": "null"}, slug_schema()]},
            "observer_trust_state_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "reason_sha256": digest_schema(),
            "effective_at_unix": {"type": "integer", "minimum": 0},
            "authority_public_key": key_schema(),
            "algorithm": {"const": "ed25519"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-authority-key-rotation-v1.json",
        "title": "Dual-signed pcbex gossip organization registry authority key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "old_public_key", "new_public_key",
            "rotated_at_unix", "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "from_generation": {"type": "integer", "minimum": 0},
            "to_generation": {"type": "integer", "minimum": 1},
            "previous_transition_sha256": {"oneOf": [
                {"type": "null"}, digest_schema()
            ]},
            "old_public_key": key_schema(),
            "new_public_key": key_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_governance_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-governance-v1.json",
        "title": "Root-signed pcbex gossip organization registry threshold governance",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "registry_authority_public_key",
            "minimum_approvals", "authorities", "issued_at_unix", "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "registry_authority_public_key": key_schema(),
            "minimum_approvals": {
                "type": "integer", "minimum": 2, "maximum": MAXIMUM_GOVERNANCE_AUTHORITIES
            },
            "authorities": {
                "type": "array", "minItems": 2, "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["authority_id", "public_key"],
                    "properties": {
                        "authority_id": slug_schema(),
                        "public_key": key_schema()
                    }
                }
            },
            "issued_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-threshold-transition-v1.json",
        "title": "Threshold-approved pcbex gossip organization registry transition",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "governance_sha256", "action",
            "organization_id", "observer_id", "observer_trust_state_sha256",
            "reason_sha256", "effective_at_unix", "algorithm", "approvals"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "from_generation": {"type": "integer", "minimum": 0},
            "to_generation": {"type": "integer", "minimum": 1},
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "governance_sha256": digest_schema(),
            "action": {"enum": [
                "admit_observer", "suspend_organization", "revoke_organization"
            ]},
            "organization_id": slug_schema(),
            "observer_id": {"oneOf": [{"type": "null"}, slug_schema()]},
            "observer_trust_state_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "reason_sha256": digest_schema(),
            "effective_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "approvals": {
                "type": "array", "minItems": 2, "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["authority_id", "public_key", "signature"],
                    "properties": {
                        "authority_id": slug_schema(),
                        "public_key": key_schema(),
                        "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
                    }
                }
            }
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation_json_schema()
-> Value {
    let approval = json!({
        "type": "object", "additionalProperties": false,
        "required": ["authority_id", "public_key", "signature"],
        "properties": {
            "authority_id": slug_schema(),
            "public_key": key_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-governance-rotation-v1.json",
        "title": "Old-and-new quorum approved gossip registry governance rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "old_governance_sha256",
            "new_governance_sha256", "rotated_at_unix", "algorithm",
            "old_approvals", "new_approvals"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "from_generation": {"type": "integer", "minimum": 0},
            "to_generation": {"type": "integer", "minimum": 1},
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_governance_sha256": digest_schema(),
            "new_governance_sha256": digest_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES, "items": approval.clone()
            },
            "new_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES, "items": approval
            }
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation_json_schema()
-> Value {
    let approval = json!({
        "type": "object", "additionalProperties": false,
        "required": ["authority_id", "public_key", "signature"],
        "properties": {
            "authority_id": slug_schema(),
            "public_key": key_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-governed-authority-key-rotation-v1.json",
        "title": "Dual-quorum governed gossip registry authority key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "from_generation", "to_generation",
            "previous_transition_sha256", "old_public_key", "new_public_key",
            "old_governance_sha256", "new_governance_sha256",
            "rotated_at_unix", "algorithm", "old_approvals", "new_approvals"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "from_generation": {"type": "integer", "minimum": 0},
            "to_generation": {"type": "integer", "minimum": 1},
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_public_key": key_schema(),
            "new_public_key": key_schema(),
            "old_governance_sha256": digest_schema(),
            "new_governance_sha256": digest_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES, "items": approval.clone()
            },
            "new_approvals": {
                "type": "array", "minItems": 2,
                "maxItems": MAXIMUM_GOVERNANCE_AUTHORITIES, "items": approval
            }
        }
    })
}

pub fn policy_lifecycle_log_gossip_registry_bound_quorum_report_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-registry-bound-quorum-v1.json",
        "title": "pcbex registry-bound policy lifecycle public-log gossip quorum",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "trust_quorum", "registry_id", "registry_generation",
            "registry_sha256", "registry_bound"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "trust_quorum": policy_lifecycle_log_gossip_trust_bound_quorum_report_json_schema(),
            "registry_id": slug_schema(),
            "registry_generation": {"type": "integer", "minimum": 0},
            "registry_sha256": digest_schema(),
            "registry_bound": {"const": true}
        }
    })
}

fn transition_observer_binding(
    action: &PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&PolicyLifecycleLogGossipObserverTrustState>,
) -> Result<(Option<String>, Option<String>), String> {
    match action {
        PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver => {
            let state = observer_trust_state
                .ok_or_else(|| "observer admission requires an observer trust state".to_string())?;
            validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
            if state.organization_id != organization_id {
                return Err("observer trust organization does not match admission target".into());
            }
            Ok((
                Some(state.observer_id.clone()),
                Some(policy_lifecycle_log_gossip_observer_trust_state_sha256(
                    state,
                )?),
            ))
        }
        PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization
        | PolicyLifecycleLogGossipOrganizationRegistryAction::RevokeOrganization => {
            if observer_trust_state.is_some() {
                return Err("organization status transition cannot include observer trust".into());
            }
            Ok((None, None))
        }
    }
}

fn apply_action(
    organizations: &mut Vec<PolicyLifecycleLogGossipOrganizationRegistryEntry>,
    transition: &SignedPolicyLifecycleLogGossipOrganizationRegistryTransition,
) -> Result<(), String> {
    let index = organizations
        .binary_search_by(|entry| entry.organization_id.cmp(&transition.organization_id));
    match transition.action {
        PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver => {
            let observer = PolicyLifecycleLogGossipObserverAdmission {
                observer_id: transition
                    .observer_id
                    .clone()
                    .ok_or_else(|| "observer admission is incomplete".to_string())?,
                observer_trust_state_sha256: transition
                    .observer_trust_state_sha256
                    .clone()
                    .ok_or_else(|| "observer admission is incomplete".to_string())?,
                admitted_at_unix: transition.effective_at_unix,
            };
            match index {
                Ok(index) => {
                    let organization = &mut organizations[index];
                    if organization.status != PolicyLifecycleLogGossipOrganizationStatus::Active {
                        return Err("cannot admit an observer to a non-active organization".into());
                    }
                    match organization
                        .observers
                        .binary_search_by(|entry| entry.observer_id.cmp(&observer.observer_id))
                    {
                        Ok(index) => {
                            if organization.observers[index].observer_trust_state_sha256
                                == observer.observer_trust_state_sha256
                            {
                                return Err(
                                    "exact gossip observer trust state is already admitted".into(),
                                );
                            }
                            organization.observers[index] = observer;
                        }
                        Err(index) => organization.observers.insert(index, observer),
                    }
                }
                Err(index) => organizations.insert(
                    index,
                    PolicyLifecycleLogGossipOrganizationRegistryEntry {
                        organization_id: transition.organization_id.clone(),
                        status: PolicyLifecycleLogGossipOrganizationStatus::Active,
                        status_since_unix: transition.effective_at_unix,
                        status_reason_sha256: transition.reason_sha256.clone(),
                        observers: vec![observer],
                    },
                ),
            }
        }
        PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization => {
            let organization = index
                .ok()
                .map(|index| &mut organizations[index])
                .ok_or_else(|| "cannot suspend an organization that is not admitted".to_string())?;
            if organization.status != PolicyLifecycleLogGossipOrganizationStatus::Active {
                return Err("only an active gossip organization can be suspended".into());
            }
            organization.status = PolicyLifecycleLogGossipOrganizationStatus::Suspended;
            organization.status_since_unix = transition.effective_at_unix;
            organization.status_reason_sha256 = transition.reason_sha256.clone();
        }
        PolicyLifecycleLogGossipOrganizationRegistryAction::RevokeOrganization => {
            let organization = index
                .ok()
                .map(|index| &mut organizations[index])
                .ok_or_else(|| "cannot revoke an organization that is not admitted".to_string())?;
            if organization.status == PolicyLifecycleLogGossipOrganizationStatus::Revoked {
                return Err("gossip organization is already permanently revoked".into());
            }
            organization.status = PolicyLifecycleLogGossipOrganizationStatus::Revoked;
            organization.status_since_unix = transition.effective_at_unix;
            organization.status_reason_sha256 = transition.reason_sha256.clone();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transition_payload(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    to_generation: u64,
    action: &PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_id: Option<&str>,
    observer_trust_state_sha256: Option<&str>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&TransitionPayload {
        domain: TRANSITION_DOMAIN,
        registry_id: &registry.registry_id,
        from_generation: registry.generation,
        to_generation,
        previous_transition_sha256: registry.last_transition_sha256.as_deref(),
        action,
        organization_id,
        observer_id,
        observer_trust_state_sha256,
        reason_sha256,
        effective_at_unix,
        authority_public_key: &registry.authority_public_key,
    })
    .map_err(|error| format!("serializing gossip registry transition: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn authority_rotation_payload(
    registry_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&str>,
    old_public_key: &str,
    new_public_key: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AuthorityRotationPayload {
        domain: AUTHORITY_ROTATION_DOMAIN,
        registry_id,
        from_generation,
        to_generation,
        previous_transition_sha256,
        old_public_key,
        new_public_key,
        rotated_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry authority rotation: {error}"))
}

fn governance_payload(
    registry_id: &str,
    registry_authority_public_key: &str,
    minimum_approvals: u32,
    authorities: &[PolicyLifecycleLogGossipRegistryGovernanceAuthority],
    issued_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GovernancePayload {
        domain: GOVERNANCE_DOMAIN,
        registry_id,
        registry_authority_public_key,
        minimum_approvals,
        authorities,
        issued_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry governance: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn threshold_transition_payload(
    registry_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&str>,
    governance_sha256: &str,
    action: &PolicyLifecycleLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_id: Option<&str>,
    observer_trust_state_sha256: Option<&str>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ThresholdTransitionPayload {
        domain: THRESHOLD_TRANSITION_DOMAIN,
        registry_id,
        from_generation,
        to_generation,
        previous_transition_sha256,
        governance_sha256,
        action,
        organization_id,
        observer_id,
        observer_trust_state_sha256,
        reason_sha256,
        effective_at_unix,
    })
    .map_err(|error| format!("serializing governed gossip registry transition: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn governance_rotation_payload(
    registry_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&str>,
    old_governance_sha256: &str,
    new_governance_sha256: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GovernanceRotationPayload {
        domain: GOVERNANCE_ROTATION_DOMAIN,
        registry_id,
        from_generation,
        to_generation,
        previous_transition_sha256,
        old_governance_sha256,
        new_governance_sha256,
        rotated_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry governance rotation: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn governed_authority_rotation_payload(
    registry_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&str>,
    old_public_key: &str,
    new_public_key: &str,
    old_governance_sha256: &str,
    new_governance_sha256: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&GovernedAuthorityRotationPayload {
        domain: GOVERNED_AUTHORITY_ROTATION_DOMAIN,
        registry_id,
        from_generation,
        to_generation,
        previous_transition_sha256,
        old_public_key,
        new_public_key,
        old_governance_sha256,
        new_governance_sha256,
        rotated_at_unix,
    })
    .map_err(|error| format!("serializing governed registry authority rotation: {error}"))
}

fn sign_governance_approvals(
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    signers: &[(String, [u8; 32])],
    payload: &[u8],
    label: &str,
) -> Result<Vec<PolicyLifecycleLogGossipRegistryThresholdApproval>, String> {
    if signers.len() < governance.minimum_approvals as usize
        || signers.len() > governance.authorities.len()
    {
        return Err(format!(
            "{label} governance rotation quorum is insufficient"
        ));
    }
    let mut ids = HashSet::new();
    let mut keys = HashSet::new();
    let mut approvals = Vec::with_capacity(signers.len());
    for (authority_id, secret) in signers {
        if !ids.insert(authority_id.as_str()) {
            return Err(format!("duplicate {label} governance authority identity"));
        }
        let key = SigningKey::from_bytes(secret);
        let public_key = hex_encode(&key.verifying_key().to_bytes());
        if !keys.insert(public_key.clone()) {
            return Err(format!("duplicate {label} governance authority key"));
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.as_str().cmp(authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| format!("untrusted {label} governance authority {authority_id:?}"))?;
        if trusted.public_key != public_key {
            return Err(format!("{label} governance authority key substitution"));
        }
        approvals.push(PolicyLifecycleLogGossipRegistryThresholdApproval {
            authority_id: authority_id.clone(),
            public_key,
            signature: hex_encode(&key.sign(payload).to_bytes()),
        });
    }
    approvals.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    Ok(approvals)
}

fn verify_governance_approvals(
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
    approvals: &[PolicyLifecycleLogGossipRegistryThresholdApproval],
    payload: &[u8],
    label: &str,
) -> Result<(), String> {
    if approvals.len() < governance.minimum_approvals as usize {
        return Err(format!(
            "{label} governance rotation quorum is insufficient"
        ));
    }
    validate_approval_shape(approvals, label)?;
    for approval in approvals {
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.cmp(&approval.authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| format!("untrusted {label} governance rotation approval"))?;
        if trusted.public_key != approval.public_key {
            return Err(format!(
                "{label} governance rotation approval key substitution"
            ));
        }
        let key = hex_decode::<32>(&approval.public_key, "governance rotation public key")?;
        let signature = Signature::from_bytes(&hex_decode::<64>(
            &approval.signature,
            "governance rotation signature",
        )?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid governance rotation public key: {error}"))?
            .verify_strict(payload, &signature)
            .map_err(|_| format!("{label} governance rotation approval verification failed"))?;
    }
    Ok(())
}

fn validate_approval_shape(
    approvals: &[PolicyLifecycleLogGossipRegistryThresholdApproval],
    label: &str,
) -> Result<(), String> {
    if approvals.len() < 2 || approvals.len() > MAXIMUM_GOVERNANCE_AUTHORITIES {
        return Err(format!(
            "{label} governance approval set must contain 2 to 100 members"
        ));
    }
    let mut previous = None;
    let mut keys = HashSet::new();
    for approval in approvals {
        validate_slug(&approval.authority_id, "governance rotation authority id")?;
        validate_public_key(&approval.public_key, "governance rotation public key")?;
        hex_decode::<64>(&approval.signature, "governance rotation signature")?;
        if previous.is_some_and(|id: &String| id >= &approval.authority_id)
            || !keys.insert(approval.public_key.as_str())
        {
            return Err(format!(
                "{label} governance approvals require ordered distinct identities and keys"
            ));
        }
        previous = Some(&approval.authority_id);
    }
    Ok(())
}

fn validate_governance_authorities(
    authorities: &[PolicyLifecycleLogGossipRegistryGovernanceAuthority],
) -> Result<(), String> {
    if authorities.len() < 2 || authorities.len() > MAXIMUM_GOVERNANCE_AUTHORITIES {
        return Err("gossip registry governance requires 2 to 100 authorities".into());
    }
    let mut previous = None;
    let mut keys = HashSet::new();
    for authority in authorities {
        validate_slug(
            &authority.authority_id,
            "gossip registry governance authority id",
        )?;
        validate_public_key(
            &authority.public_key,
            "gossip registry governance authority public key",
        )?;
        if previous.is_some_and(|id: &String| id >= &authority.authority_id)
            || !keys.insert(authority.public_key.as_str())
        {
            return Err(
                "governance authorities must have ordered distinct identities and keys".into(),
            );
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_governance_for_registry(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(governance)?;
    if governance.registry_id != registry.registry_id
        || governance.registry_authority_public_key != registry.authority_public_key
    {
        return Err("gossip registry governance does not match retained root trust".into());
    }
    verify_governance_root_signature(governance)
}

fn validate_successor_governance_for_registry(
    registry: &PolicyLifecycleLogGossipOrganizationRegistry,
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    validate_policy_lifecycle_log_gossip_organization_registry(registry)?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_governance(governance)?;
    if governance.registry_id != registry.registry_id
        || governance.registry_authority_public_key == registry.authority_public_key
    {
        return Err("successor governance does not bind a distinct registry root".into());
    }
    verify_governance_root_signature(governance)
}

fn verify_governance_root_signature(
    governance: &SignedPolicyLifecycleLogGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    let payload = governance_payload(
        &governance.registry_id,
        &governance.registry_authority_public_key,
        governance.minimum_approvals,
        &governance.authorities,
        governance.issued_at_unix,
    )?;
    let key = hex_decode::<32>(
        &governance.registry_authority_public_key,
        "gossip registry governance root public key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &governance.signature,
        "gossip registry governance root signature",
    )?);
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid gossip registry governance root key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "gossip registry governance root signature verification failed".to_string())
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_public_key(value: &str, label: &str) -> Result<(), String> {
    let bytes = hex_decode::<32>(value, label)?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| format!("invalid {label}: {error}"))?;
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} must contain exactly {} hex bytes", N));
    }
    let mut output = [0_u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(chunk[0], label)? << 4) | hex_nibble(chunk[1], label)?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8, label: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(format!("{label} contains invalid hex")),
    }
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn key_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_lifecycle_gossip_trust::new_policy_lifecycle_log_gossip_observer_trust_state;

    #[test]
    fn signed_registry_rejects_replay_forks_and_terminal_organization_states() {
        let authority_secret = [41; 32];
        let authority_public = SigningKey::from_bytes(&authority_secret)
            .verifying_key()
            .to_bytes();
        let observer_public = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
        let trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &observer_public,
        )
        .unwrap();
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &authority_public,
        )
        .unwrap();
        let admission = sign_policy_lifecycle_log_gossip_organization_registry_transition(
            &initial,
            &authority_secret,
            PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
            "independent-lab",
            Some(&trust),
            &"1".repeat(64),
            1_000,
        )
        .unwrap();
        let admitted = apply_policy_lifecycle_log_gossip_organization_registry_transition(
            &initial, &admission,
        )
        .unwrap();
        assert_eq!(admitted.generation, 1);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_transition(
                &admitted, &admission
            )
            .is_err()
        );

        let suspension = sign_policy_lifecycle_log_gossip_organization_registry_transition(
            &admitted,
            &authority_secret,
            PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization,
            "independent-lab",
            None,
            &"2".repeat(64),
            2_000,
        )
        .unwrap();
        let suspended = apply_policy_lifecycle_log_gossip_organization_registry_transition(
            &admitted,
            &suspension,
        )
        .unwrap();
        assert_eq!(
            suspended.organizations[0].status,
            PolicyLifecycleLogGossipOrganizationStatus::Suspended
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_transition(
                &suspended,
                &authority_secret,
                PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
                "independent-lab",
                Some(&trust),
                &"3".repeat(64),
                3_000,
            )
            .and_then(|transition| {
                apply_policy_lifecycle_log_gossip_organization_registry_transition(
                    &suspended,
                    &transition,
                )
            })
            .is_err()
        );

        let revocation = sign_policy_lifecycle_log_gossip_organization_registry_transition(
            &suspended,
            &authority_secret,
            PolicyLifecycleLogGossipOrganizationRegistryAction::RevokeOrganization,
            "independent-lab",
            None,
            &"4".repeat(64),
            4_000,
        )
        .unwrap();
        let revoked = apply_policy_lifecycle_log_gossip_organization_registry_transition(
            &suspended,
            &revocation,
        )
        .unwrap();
        assert_eq!(
            revoked.organizations[0].status,
            PolicyLifecycleLogGossipOrganizationStatus::Revoked
        );

        let mut fork = revocation.clone();
        fork.previous_transition_sha256 = Some("0".repeat(64));
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_transition(&suspended, &fork)
                .is_err()
        );
        let mut tampered = revocation;
        tampered.reason_sha256 = "5".repeat(64);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_transition(
                &suspended, &tampered
            )
            .is_err()
        );
    }

    #[test]
    fn registry_schemas_are_closed() {
        assert_eq!(
            policy_lifecycle_log_gossip_organization_registry_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            signed_policy_lifecycle_log_gossip_organization_registry_transition_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation_json_schema()
                ["additionalProperties"],
            false
        );
        assert_eq!(
            signed_policy_lifecycle_log_gossip_organization_registry_governance_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            signed_policy_lifecycle_log_gossip_organization_registry_threshold_transition_json_schema()
                ["additionalProperties"],
            false
        );
        assert_eq!(
            signed_policy_lifecycle_log_gossip_organization_registry_governance_rotation_json_schema()
                ["additionalProperties"],
            false
        );
        assert_eq!(
            signed_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation_json_schema()
                ["additionalProperties"],
            false
        );
        assert_eq!(
            policy_lifecycle_log_gossip_registry_bound_quorum_report_json_schema()["additionalProperties"],
            false
        );
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &SigningKey::from_bytes(&[70; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let mut legacy_value = serde_json::to_value(initial).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("active_governance_sha256");
        let legacy: PolicyLifecycleLogGossipOrganizationRegistry =
            serde_json::from_value(legacy_value).unwrap();
        assert!(legacy.active_governance_sha256.is_none());
        validate_policy_lifecycle_log_gossip_organization_registry(&legacy).unwrap();
    }

    #[test]
    fn threshold_governance_requires_distinct_trusted_authorities() {
        let root_secret = [71; 32];
        let authority_a = [72; 32];
        let authority_b = [73; 32];
        let authority_c = [74; 32];
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &SigningKey::from_bytes(&root_secret)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let authorities = [
            ("authority-a", authority_a),
            ("authority-b", authority_b),
            ("authority-c", authority_c),
        ]
        .into_iter()
        .map(
            |(authority_id, secret)| PolicyLifecycleLogGossipRegistryGovernanceAuthority {
                authority_id: authority_id.into(),
                public_key: hex_encode(&SigningKey::from_bytes(&secret).verifying_key().to_bytes()),
            },
        )
        .collect();
        let governance = sign_policy_lifecycle_log_gossip_organization_registry_governance(
            &initial,
            &root_secret,
            2,
            authorities,
            1_000,
        )
        .unwrap();
        let trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&[75; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let admission =
            sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &[
                    ("authority-a".into(), authority_a),
                    ("authority-c".into(), authority_c),
                ],
                PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
                "independent-lab",
                Some(&trust),
                &"a".repeat(64),
                2_000,
            )
            .unwrap();
        let admitted =
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &admission,
            )
            .unwrap();
        assert_eq!(admitted.generation, 1);
        assert_eq!(admitted.organizations.len(), 1);
        let retained_governance_sha256 =
            signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(&governance)
                .unwrap();
        assert_eq!(
            admitted.active_governance_sha256.as_deref(),
            Some(retained_governance_sha256.as_str())
        );
        let alternate_governance =
            sign_policy_lifecycle_log_gossip_organization_registry_governance(
                &admitted,
                &root_secret,
                3,
                [
                    ("authority-a", authority_a),
                    ("authority-b", authority_b),
                    ("authority-c", authority_c),
                ]
                .into_iter()
                .map(
                    |(authority_id, secret)| PolicyLifecycleLogGossipRegistryGovernanceAuthority {
                        authority_id: authority_id.into(),
                        public_key: hex_encode(
                            &SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
                        ),
                    },
                )
                .collect(),
                2_500,
            )
            .unwrap();
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &admitted,
                &alternate_governance,
                &[
                    ("authority-a".into(), authority_a),
                    ("authority-b".into(), authority_b),
                    ("authority-c".into(), authority_c),
                ],
                PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization,
                "independent-lab",
                None,
                &"b".repeat(64),
                3_000,
            )
            .is_err()
        );
        let mut unbound_copy = admitted.clone();
        unbound_copy.active_governance_sha256 = None;
        let stale_policy_transition =
            sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &unbound_copy,
                &alternate_governance,
                &[
                    ("authority-a".into(), authority_a),
                    ("authority-b".into(), authority_b),
                    ("authority-c".into(), authority_c),
                ],
                PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization,
                "independent-lab",
                None,
                &"b".repeat(64),
                3_000,
            )
            .unwrap();
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &admitted,
                &alternate_governance,
                &stale_policy_transition,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_transition(
                &admitted,
                &root_secret,
                PolicyLifecycleLogGossipOrganizationRegistryAction::SuspendOrganization,
                "independent-lab",
                None,
                &"b".repeat(64),
                3_000,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &admitted,
                &root_secret,
                &[76; 32],
                3_000,
            )
            .is_err()
        );
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &admitted,
                &governance,
                &admission,
            )
            .is_err()
        );

        let mut insufficient = admission.clone();
        insufficient.approvals.pop();
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &insufficient,
            )
            .is_err()
        );
        let mut substitution = admission.clone();
        substitution.governance_sha256 = "0".repeat(64);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &substitution,
            )
            .is_err()
        );
        let mut signature_tampered = admission;
        signature_tampered.approvals[0].signature = "0".repeat(128);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &signature_tampered,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &[("authority-a".into(), authority_a)],
                PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
                "independent-lab",
                Some(&trust),
                &"a".repeat(64),
                2_000,
            )
            .is_err()
        );
    }

    #[test]
    fn governance_rotation_requires_old_and_successor_quorums() {
        let root = [81; 32];
        let old_a = [82; 32];
        let old_b = [83; 32];
        let new_a = [84; 32];
        let new_b = [85; 32];
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &SigningKey::from_bytes(&root).verifying_key().to_bytes(),
        )
        .unwrap();
        let authorities = |pairs: &[(&str, [u8; 32])]| {
            pairs
                .iter()
                .map(
                    |(id, secret)| PolicyLifecycleLogGossipRegistryGovernanceAuthority {
                        authority_id: (*id).into(),
                        public_key: hex_encode(
                            &SigningKey::from_bytes(secret).verifying_key().to_bytes(),
                        ),
                    },
                )
                .collect()
        };
        let old = sign_policy_lifecycle_log_gossip_organization_registry_governance(
            &initial,
            &root,
            2,
            authorities(&[("old-a", old_a), ("old-b", old_b)]),
            1_000,
        )
        .unwrap();
        let trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&[86; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let admission =
            sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &old,
                &[("old-a".into(), old_a), ("old-b".into(), old_b)],
                PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
                "independent-lab",
                Some(&trust),
                &"a".repeat(64),
                2_000,
            )
            .unwrap();
        let governed =
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial, &old, &admission,
            )
            .unwrap();
        let old_sha256 =
            signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(&old)
                .unwrap();
        assert_eq!(
            governed.active_governance_sha256.as_deref(),
            Some(old_sha256.as_str())
        );
        let new = sign_policy_lifecycle_log_gossip_organization_registry_governance(
            &governed,
            &root,
            2,
            authorities(&[("new-a", new_a), ("new-b", new_b)]),
            3_000,
        )
        .unwrap();
        let rotation = sign_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
            &governed,
            &old,
            &new,
            &[("old-a".into(), old_a), ("old-b".into(), old_b)],
            &[("new-a".into(), new_a), ("new-b".into(), new_b)],
            4_000,
        )
        .unwrap();
        let rotated = apply_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
            &governed, &old, &new, &rotation,
        )
        .unwrap();
        assert_eq!(rotated.generation, 2);
        let new_sha256 =
            signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(&new)
                .unwrap();
        assert_eq!(
            rotated.active_governance_sha256.as_deref(),
            Some(new_sha256.as_str())
        );
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
                &rotated, &old, &new, &rotation,
            )
            .is_err()
        );
        let mut old_tampered = rotation.clone();
        old_tampered.old_approvals[0].signature = "0".repeat(128);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
                &governed,
                &old,
                &new,
                &old_tampered,
            )
            .is_err()
        );
        let mut new_tampered = rotation;
        new_tampered.new_approvals.pop();
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
                &governed,
                &old,
                &new,
                &new_tampered,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_governance_rotation(
                &governed,
                &old,
                &new,
                &[("old-a".into(), old_a)],
                &[("new-a".into(), new_a), ("new-b".into(), new_b)],
                4_000,
            )
            .is_err()
        );
    }

    #[test]
    fn governed_authority_rotation_requires_both_quorums_and_successor_root_possession() {
        let old_root = [91; 32];
        let new_root = [92; 32];
        let old_a = [93; 32];
        let old_b = [94; 32];
        let new_a = [95; 32];
        let new_b = [96; 32];
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &SigningKey::from_bytes(&old_root).verifying_key().to_bytes(),
        )
        .unwrap();
        let authorities = |pairs: &[(&str, [u8; 32])]| {
            pairs
                .iter()
                .map(
                    |(id, secret)| PolicyLifecycleLogGossipRegistryGovernanceAuthority {
                        authority_id: (*id).into(),
                        public_key: hex_encode(
                            &SigningKey::from_bytes(secret).verifying_key().to_bytes(),
                        ),
                    },
                )
                .collect()
        };
        let old = sign_policy_lifecycle_log_gossip_organization_registry_governance(
            &initial,
            &old_root,
            2,
            authorities(&[("old-a", old_a), ("old-b", old_b)]),
            1_000,
        )
        .unwrap();
        let trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&[97; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let admission =
            sign_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial,
                &old,
                &[("old-a".into(), old_a), ("old-b".into(), old_b)],
                PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
                "independent-lab",
                Some(&trust),
                &"a".repeat(64),
                2_000,
            )
            .unwrap();
        let governed =
            apply_policy_lifecycle_log_gossip_organization_registry_threshold_transition(
                &initial, &old, &admission,
            )
            .unwrap();
        let successor =
            sign_policy_lifecycle_log_gossip_organization_registry_successor_governance(
                &governed,
                &new_root,
                2,
                authorities(&[("new-a", new_a), ("new-b", new_b)]),
                3_000,
            )
            .unwrap();
        let rotation =
            sign_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old,
                &successor,
                &[("old-a".into(), old_a), ("old-b".into(), old_b)],
                &[("new-a".into(), new_a), ("new-b".into(), new_b)],
                4_000,
            )
            .unwrap();
        let rotated =
            apply_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old,
                &successor,
                &rotation,
            )
            .unwrap();
        assert_eq!(rotated.generation, governed.generation + 1);
        assert_eq!(
            rotated.authority_public_key,
            successor.registry_authority_public_key
        );
        assert_eq!(
            rotated.active_governance_sha256,
            Some(
                signed_policy_lifecycle_log_gossip_organization_registry_governance_sha256(
                    &successor,
                )
                .unwrap()
            )
        );
        assert_eq!(rotated.organizations, governed.organizations);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
                &rotated,
                &old,
                &successor,
                &rotation,
            )
            .is_err()
        );
        let mut old_tampered = rotation.clone();
        old_tampered.old_approvals.pop();
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old,
                &successor,
                &old_tampered,
            )
            .is_err()
        );
        let mut new_tampered = rotation;
        new_tampered.new_approvals[0].signature = "0".repeat(128);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old,
                &successor,
                &new_tampered,
            )
            .is_err()
        );
        let mut forged_successor = successor;
        forged_successor.signature = "0".repeat(128);
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_governed_authority_key_rotation(
                &governed,
                &old,
                &forged_successor,
                &[("old-a".into(), old_a), ("old-b".into(), old_b)],
                &[("new-a".into(), new_a), ("new-b".into(), new_b)],
                4_000,
            )
            .is_err()
        );
    }

    #[test]
    fn signed_readmission_replaces_only_the_exact_observer_trust_digest() {
        let authority_secret = [51; 32];
        let authority_public = SigningKey::from_bytes(&authority_secret)
            .verifying_key()
            .to_bytes();
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &authority_public,
        )
        .unwrap();
        let old_trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let admission = sign_policy_lifecycle_log_gossip_organization_registry_transition(
            &initial,
            &authority_secret,
            PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
            "independent-lab",
            Some(&old_trust),
            &"a".repeat(64),
            1_000,
        )
        .unwrap();
        let admitted = apply_policy_lifecycle_log_gossip_organization_registry_transition(
            &initial, &admission,
        )
        .unwrap();
        let new_trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&[53; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        let readmission = sign_policy_lifecycle_log_gossip_organization_registry_transition(
            &admitted,
            &authority_secret,
            PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
            "independent-lab",
            Some(&new_trust),
            &"b".repeat(64),
            2_000,
        )
        .unwrap();
        let updated = apply_policy_lifecycle_log_gossip_organization_registry_transition(
            &admitted,
            &readmission,
        )
        .unwrap();
        assert_eq!(updated.organizations[0].observers.len(), 1);
        assert_eq!(
            updated.organizations[0].observers[0].observer_trust_state_sha256,
            policy_lifecycle_log_gossip_observer_trust_state_sha256(&new_trust).unwrap()
        );
        assert_ne!(
            updated.organizations[0].observers[0].observer_trust_state_sha256,
            policy_lifecycle_log_gossip_observer_trust_state_sha256(&old_trust).unwrap()
        );
    }

    #[test]
    fn rotates_registry_authority_with_old_and_new_signatures_in_the_same_chain() {
        let old_secret = [61; 32];
        let next_secret = [62; 32];
        let final_secret = [63; 32];
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &SigningKey::from_bytes(&old_secret)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let first = sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
            &initial,
            &old_secret,
            &next_secret,
            1_000,
        )
        .unwrap();
        let rotated =
            apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &initial, &first,
            )
            .unwrap();
        assert_eq!(rotated.generation, 1);
        assert_eq!(
            rotated.authority_public_key,
            hex_encode(
                &SigningKey::from_bytes(&next_secret)
                    .verifying_key()
                    .to_bytes()
            )
        );
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated, &first,
            )
            .is_err()
        );

        let second = sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
            &rotated,
            &next_secret,
            &final_secret,
            2_000,
        )
        .unwrap();
        let twice = apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
            &rotated, &second,
        )
        .unwrap();
        assert_eq!(twice.generation, 2);
        assert_eq!(
            twice.last_transition_sha256,
            Some(
                signed_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation_sha256(
                    &second,
                )
                .unwrap()
            )
        );

        let mut fork = second.clone();
        fork.previous_transition_sha256 = Some("0".repeat(64));
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated, &fork,
            )
            .is_err()
        );
        let mut identity_tampered = second.clone();
        identity_tampered.registry_id = "other-registry".into();
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &identity_tampered,
            )
            .is_err()
        );
        let mut signature_tampered = second;
        signature_tampered.new_signature = "0".repeat(128);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &signature_tampered,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &old_secret,
                &final_secret,
                2_000,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &next_secret,
                &next_secret,
                2_000,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &next_secret,
                &final_secret,
                999,
            )
            .is_err()
        );
    }
}
