use crate::{
    ApprovalLogAnchorProof, ApprovalLogGossipObservation, ApprovalLogGossipObserverTrustState,
    ApprovalLogGossipTrustBoundQuorumReport, approval_log_gossip_observer_trust_state_sha256,
    approval_log_gossip_trust_bound_quorum_report_json_schema,
    validate_approval_log_gossip_observer_trust_state,
    validate_approval_log_gossip_trust_bound_quorum_report,
    verify_approval_log_gossip_quorum_with_observer_trust_states,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const TRANSITION_DOMAIN: &str =
    "pcbex-approval-public-log-gossip-organization-registry-transition-v1";
const AUTHORITY_ROTATION_DOMAIN: &str =
    "pcbex-approval-public-log-gossip-organization-registry-authority-key-rotation-v1";
const GOVERNANCE_DOMAIN: &str =
    "pcbex-approval-public-log-gossip-organization-registry-governance-v1";
const THRESHOLD_TRANSITION_DOMAIN: &str =
    "pcbex-approval-public-log-gossip-organization-registry-threshold-transition-v1";
const MAXIMUM_GOVERNANCE_AUTHORITIES: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLogGossipOrganizationStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipObserverAdmission {
    pub observer_id: String,
    pub observer_trust_state_sha256: String,
    pub admitted_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipOrganizationRegistryEntry {
    pub organization_id: String,
    pub status: ApprovalLogGossipOrganizationStatus,
    pub status_since_unix: u64,
    pub status_reason_sha256: String,
    pub observers: Vec<ApprovalLogGossipObserverAdmission>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipOrganizationRegistry {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub authority_public_key: String,
    #[serde(default)]
    pub active_governance_sha256: Option<String>,
    pub last_transition_sha256: Option<String>,
    pub last_updated_at_unix: Option<u64>,
    pub organizations: Vec<ApprovalLogGossipOrganizationRegistryEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLogGossipOrganizationRegistryAction {
    AdmitObserver,
    SuspendOrganization,
    RevokeOrganization,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalLogGossipOrganizationRegistryTransition {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub action: ApprovalLogGossipOrganizationRegistryAction,
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
pub struct SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation {
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
pub struct ApprovalLogGossipRegistryGovernanceAuthority {
    pub authority_id: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalLogGossipOrganizationRegistryGovernance {
    pub schema_version: u32,
    pub registry_id: String,
    pub registry_authority_public_key: String,
    pub minimum_approvals: u32,
    pub authorities: Vec<ApprovalLogGossipRegistryGovernanceAuthority>,
    pub issued_at_unix: u64,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipRegistryThresholdApproval {
    pub authority_id: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalLogGossipOrganizationRegistryThresholdTransition {
    pub schema_version: u32,
    pub registry_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_transition_sha256: Option<String>,
    pub governance_sha256: String,
    pub action: ApprovalLogGossipOrganizationRegistryAction,
    pub organization_id: String,
    pub observer_id: Option<String>,
    pub observer_trust_state_sha256: Option<String>,
    pub reason_sha256: String,
    pub effective_at_unix: u64,
    pub algorithm: String,
    pub approvals: Vec<ApprovalLogGossipRegistryThresholdApproval>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipRegistryBoundQuorumReport {
    pub schema_version: u32,
    pub trust_quorum: ApprovalLogGossipTrustBoundQuorumReport,
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
    action: &'a ApprovalLogGossipOrganizationRegistryAction,
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
    authorities: &'a [ApprovalLogGossipRegistryGovernanceAuthority],
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
    action: &'a ApprovalLogGossipOrganizationRegistryAction,
    organization_id: &'a str,
    observer_id: Option<&'a str>,
    observer_trust_state_sha256: Option<&'a str>,
    reason_sha256: &'a str,
    effective_at_unix: u64,
}

pub fn new_approval_log_gossip_organization_registry(
    registry_id: &str,
    authority_public_key: &[u8; 32],
) -> Result<ApprovalLogGossipOrganizationRegistry, String> {
    validate_slug(registry_id, "approval gossip organization registry id")?;
    VerifyingKey::from_bytes(authority_public_key).map_err(|error| {
        format!("invalid approval gossip registry authority public key: {error}")
    })?;
    Ok(ApprovalLogGossipOrganizationRegistry {
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
pub fn sign_approval_log_gossip_organization_registry_transition(
    registry: &ApprovalLogGossipOrganizationRegistry,
    authority_secret_key: &[u8; 32],
    action: ApprovalLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&ApprovalLogGossipObserverTrustState>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryTransition, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "approval gossip registry with active governance rejects root-only transitions".into(),
        );
    }
    validate_slug(organization_id, "approval gossip registry organization id")?;
    validate_sha256(
        reason_sha256,
        "approval gossip registry transition reason SHA-256",
    )?;
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| effective_at_unix < previous)
    {
        return Err("approval gossip registry transition timestamps must be monotonic".into());
    }
    let authority = SigningKey::from_bytes(authority_secret_key);
    let authority_public_key = hex_encode(&authority.verifying_key().to_bytes());
    if authority_public_key != registry.authority_public_key {
        return Err("approval gossip registry authority key does not match retained trust".into());
    }
    let (observer_id, observer_trust_state_sha256) =
        transition_observer_binding(&action, organization_id, observer_trust_state)?;
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "approval gossip organization registry generation overflow".to_string())?;
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
    let transition = SignedApprovalLogGossipOrganizationRegistryTransition {
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
    validate_signed_approval_log_gossip_organization_registry_transition(&transition)?;
    Ok(transition)
}

pub fn apply_approval_log_gossip_organization_registry_transition(
    registry: &ApprovalLogGossipOrganizationRegistry,
    transition: &SignedApprovalLogGossipOrganizationRegistryTransition,
) -> Result<ApprovalLogGossipOrganizationRegistry, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    validate_signed_approval_log_gossip_organization_registry_transition(transition)?;
    if transition.registry_id != registry.registry_id
        || transition.from_generation != registry.generation
        || transition.previous_transition_sha256 != registry.last_transition_sha256
        || transition.authority_public_key != registry.authority_public_key
    {
        return Err("approval gossip registry transition does not extend retained state".into());
    }
    if transition.to_generation
        != registry.generation.checked_add(1).ok_or_else(|| {
            "approval gossip organization registry generation overflow".to_string()
        })?
    {
        return Err(
            "approval gossip registry transition must advance exactly one generation".into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| transition.effective_at_unix < previous)
    {
        return Err("approval gossip registry transition timestamps must be monotonic".into());
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
        "approval gossip registry authority public key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &transition.signature,
        "approval gossip registry authority signature",
    )?);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid approval gossip registry authority key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| {
            "approval gossip registry transition signature verification failed".to_string()
        })?;

    let mut organizations = registry.organizations.clone();
    apply_action(&mut organizations, transition)?;
    let next = ApprovalLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: transition.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: None,
        last_transition_sha256: Some(
            signed_approval_log_gossip_organization_registry_transition_sha256(transition)?,
        ),
        last_updated_at_unix: Some(transition.effective_at_unix),
        organizations,
    };
    validate_approval_log_gossip_organization_registry(&next)?;
    Ok(next)
}

pub fn sign_approval_log_gossip_organization_registry_authority_key_rotation(
    registry: &ApprovalLogGossipOrganizationRegistry,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "approval gossip registry with active governance rejects root-only authority rotation"
                .into(),
        );
    }
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != registry.authority_public_key {
        return Err(
            "old approval gossip registry authority key does not match retained trust".into(),
        );
    }
    if new_public_key == old_public_key {
        return Err(
            "new approval gossip registry authority key must differ from the current key".into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err(
            "approval gossip registry authority rotation timestamps must be monotonic".into(),
        );
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "approval gossip organization registry generation overflow".to_string())?;
    let payload = authority_rotation_payload(
        &registry.registry_id,
        registry.generation,
        to_generation,
        registry.last_transition_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    let rotation = SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation {
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
    validate_signed_approval_log_gossip_organization_registry_authority_key_rotation(&rotation)?;
    Ok(rotation)
}

pub fn apply_approval_log_gossip_organization_registry_authority_key_rotation(
    registry: &ApprovalLogGossipOrganizationRegistry,
    rotation: &SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<ApprovalLogGossipOrganizationRegistry, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    if registry.active_governance_sha256.is_some() {
        return Err(
            "approval gossip registry with active governance rejects root-only authority rotation"
                .into(),
        );
    }
    validate_signed_approval_log_gossip_organization_registry_authority_key_rotation(rotation)?;
    if rotation.registry_id != registry.registry_id
        || rotation.from_generation != registry.generation
        || rotation.previous_transition_sha256 != registry.last_transition_sha256
        || rotation.old_public_key != registry.authority_public_key
    {
        return Err(
            "approval gossip registry authority rotation does not extend retained state".into(),
        );
    }
    if rotation.to_generation
        != registry.generation.checked_add(1).ok_or_else(|| {
            "approval gossip organization registry generation overflow".to_string()
        })?
    {
        return Err(
            "approval gossip registry authority rotation must advance exactly one generation"
                .into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err(
            "approval gossip registry authority rotation timestamps must be monotonic".into(),
        );
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
            "old approval gossip registry authority rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new approval gossip registry authority rotation",
        ),
    ] {
        let key = hex_decode::<32>(key, label)?;
        let signature = Signature::from_bytes(&hex_decode::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let next = ApprovalLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: rotation.to_generation,
        authority_public_key: rotation.new_public_key.clone(),
        active_governance_sha256: None,
        last_transition_sha256: Some(
            signed_approval_log_gossip_organization_registry_authority_key_rotation_sha256(
                rotation,
            )?,
        ),
        last_updated_at_unix: Some(rotation.rotated_at_unix),
        organizations: registry.organizations.clone(),
    };
    validate_approval_log_gossip_organization_registry(&next)?;
    Ok(next)
}

pub fn sign_approval_log_gossip_organization_registry_governance(
    registry: &ApprovalLogGossipOrganizationRegistry,
    registry_authority_secret_key: &[u8; 32],
    minimum_approvals: u32,
    mut authorities: Vec<ApprovalLogGossipRegistryGovernanceAuthority>,
    issued_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryGovernance, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    if !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&minimum_approvals) {
        return Err(
            "approval gossip registry governance minimum approvals must be between 2 and 100"
                .into(),
        );
    }
    authorities.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    validate_governance_authorities(&authorities)?;
    if authorities.len() < minimum_approvals as usize {
        return Err(
            "approval gossip registry governance has fewer authorities than its threshold".into(),
        );
    }
    let signing_key = SigningKey::from_bytes(registry_authority_secret_key);
    let registry_authority_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if registry_authority_public_key != registry.authority_public_key {
        return Err(
            "approval gossip registry governance signer does not match retained authority".into(),
        );
    }
    if registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err("approval gossip registry governance predates retained registry state".into());
    }
    let payload = governance_payload(
        &registry.registry_id,
        &registry_authority_public_key,
        minimum_approvals,
        &authorities,
        issued_at_unix,
    )?;
    let governance = SignedApprovalLogGossipOrganizationRegistryGovernance {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        registry_authority_public_key,
        minimum_approvals,
        authorities,
        issued_at_unix,
        algorithm: "ed25519".into(),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_approval_log_gossip_organization_registry_governance(&governance)?;
    Ok(governance)
}

#[allow(clippy::too_many_arguments)]
pub fn sign_approval_log_gossip_organization_registry_threshold_transition(
    registry: &ApprovalLogGossipOrganizationRegistry,
    governance: &SignedApprovalLogGossipOrganizationRegistryGovernance,
    signers: &[(String, [u8; 32])],
    action: ApprovalLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&ApprovalLogGossipObserverTrustState>,
    reason_sha256: &str,
    effective_at_unix: u64,
) -> Result<SignedApprovalLogGossipOrganizationRegistryThresholdTransition, String> {
    validate_governance_for_registry(registry, governance)?;
    validate_slug(organization_id, "approval gossip registry organization id")?;
    validate_sha256(
        reason_sha256,
        "approval gossip registry transition reason SHA-256",
    )?;
    if effective_at_unix < governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| effective_at_unix < last)
    {
        return Err(
            "governed approval gossip registry transition timestamps must be monotonic".into(),
        );
    }
    if signers.len() < governance.minimum_approvals as usize
        || signers.len() > governance.authorities.len()
    {
        return Err(
            "governed approval gossip registry transition does not satisfy its threshold".into(),
        );
    }
    let (observer_id, observer_trust_state_sha256) =
        transition_observer_binding(&action, organization_id, observer_trust_state)?;
    let governance_sha256 =
        signed_approval_log_gossip_organization_registry_governance_sha256(governance)?;
    if registry
        .active_governance_sha256
        .as_deref()
        .is_some_and(|retained| retained != governance_sha256)
    {
        return Err(
            "approval gossip registry governance does not match retained active governance".into(),
        );
    }
    let to_generation = registry
        .generation
        .checked_add(1)
        .ok_or_else(|| "approval gossip organization registry generation overflow".to_string())?;
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
            return Err("duplicate approval gossip registry governance authority identity".into());
        }
        let key = SigningKey::from_bytes(secret_key);
        let public_key = hex_encode(&key.verifying_key().to_bytes());
        if !seen_keys.insert(public_key.clone()) {
            return Err("duplicate approval gossip registry governance authority key".into());
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.as_str().cmp(authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| {
                format!("untrusted approval gossip registry authority {authority_id:?}")
            })?;
        if trusted.public_key != public_key {
            return Err(format!(
                "approval gossip registry authority {authority_id:?} key does not match governance"
            ));
        }
        approvals.push(ApprovalLogGossipRegistryThresholdApproval {
            authority_id: authority_id.clone(),
            public_key,
            signature: hex_encode(&key.sign(&payload).to_bytes()),
        });
    }
    approvals.sort_by(|left, right| left.authority_id.cmp(&right.authority_id));
    let transition = SignedApprovalLogGossipOrganizationRegistryThresholdTransition {
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
    validate_signed_approval_log_gossip_organization_registry_threshold_transition(&transition)?;
    Ok(transition)
}

pub fn apply_approval_log_gossip_organization_registry_threshold_transition(
    registry: &ApprovalLogGossipOrganizationRegistry,
    governance: &SignedApprovalLogGossipOrganizationRegistryGovernance,
    transition: &SignedApprovalLogGossipOrganizationRegistryThresholdTransition,
) -> Result<ApprovalLogGossipOrganizationRegistry, String> {
    validate_governance_for_registry(registry, governance)?;
    validate_signed_approval_log_gossip_organization_registry_threshold_transition(transition)?;
    let governance_sha256 =
        signed_approval_log_gossip_organization_registry_governance_sha256(governance)?;
    if registry
        .active_governance_sha256
        .as_deref()
        .is_some_and(|retained| retained != governance_sha256)
    {
        return Err(
            "approval gossip registry governance does not match retained active governance".into(),
        );
    }
    if transition.registry_id != registry.registry_id
        || transition.from_generation != registry.generation
        || transition.to_generation
            != registry.generation.checked_add(1).ok_or_else(|| {
                "approval gossip organization registry generation overflow".to_string()
            })?
        || transition.previous_transition_sha256 != registry.last_transition_sha256
        || transition.governance_sha256 != governance_sha256
    {
        return Err(
            "governed approval gossip registry transition does not extend retained state".into(),
        );
    }
    if transition.effective_at_unix < governance.issued_at_unix
        || registry
            .last_updated_at_unix
            .is_some_and(|last| transition.effective_at_unix < last)
    {
        return Err(
            "governed approval gossip registry transition timestamps must be monotonic".into(),
        );
    }
    if transition.approvals.len() < governance.minimum_approvals as usize {
        return Err("governed approval gossip registry has insufficient approvals".into());
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
            return Err(
                "governed approval gossip registry approvals must be unique and ordered".into(),
            );
        }
        previous_id = Some(&approval.authority_id);
        if !seen_keys.insert(approval.public_key.as_str()) {
            return Err("governed approval gossip registry approvals require distinct keys".into());
        }
        let trusted = governance
            .authorities
            .binary_search_by(|entry| entry.authority_id.cmp(&approval.authority_id))
            .ok()
            .map(|index| &governance.authorities[index])
            .ok_or_else(|| "untrusted governed approval gossip registry approval".to_string())?;
        if trusted.public_key != approval.public_key {
            return Err("governed approval gossip registry approval key substitution".into());
        }
        let key = hex_decode::<32>(
            &approval.public_key,
            "approval gossip governance approval public key",
        )?;
        let signature = Signature::from_bytes(&hex_decode::<64>(
            &approval.signature,
            "approval gossip governance approval signature",
        )?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid governance approval public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| {
                "governed approval gossip registry approval verification failed".to_string()
            })?;
    }
    let compatibility_transition = SignedApprovalLogGossipOrganizationRegistryTransition {
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
    let next = ApprovalLogGossipOrganizationRegistry {
        schema_version: 1,
        registry_id: registry.registry_id.clone(),
        generation: transition.to_generation,
        authority_public_key: registry.authority_public_key.clone(),
        active_governance_sha256: Some(governance_sha256),
        last_transition_sha256: Some(
            signed_approval_log_gossip_organization_registry_threshold_transition_sha256(
                transition,
            )?,
        ),
        last_updated_at_unix: Some(transition.effective_at_unix),
        organizations,
    };
    validate_approval_log_gossip_organization_registry(&next)?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_approval_log_gossip_quorum_with_organization_registry(
    local_anchor: &ApprovalLogAnchorProof,
    observations: &[ApprovalLogGossipObservation],
    observer_trust_states: &[ApprovalLogGossipObserverTrustState],
    registry: &ApprovalLogGossipOrganizationRegistry,
    minimum_organizations: u32,
    trusted_log_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<ApprovalLogGossipRegistryBoundQuorumReport, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    for state in observer_trust_states {
        validate_approval_log_gossip_observer_trust_state(state)?;
        let organization = registry
            .organizations
            .binary_search_by(|entry| entry.organization_id.cmp(&state.organization_id))
            .ok()
            .map(|index| &registry.organizations[index])
            .ok_or_else(|| {
                format!(
                    "approval gossip observer organization {} is not admitted",
                    state.organization_id
                )
            })?;
        if organization.status != ApprovalLogGossipOrganizationStatus::Active {
            return Err(format!(
                "approval gossip observer organization {} is not active",
                state.organization_id
            ));
        }
        let trust_sha256 = approval_log_gossip_observer_trust_state_sha256(state)?;
        if !organization.observers.iter().any(|observer| {
            observer.observer_id == state.observer_id
                && observer.observer_trust_state_sha256 == trust_sha256
        }) {
            return Err(format!(
                "approval gossip observer {}/{} does not match an admitted trust state",
                state.organization_id, state.observer_id
            ));
        }
    }
    let trust_quorum = verify_approval_log_gossip_quorum_with_observer_trust_states(
        local_anchor,
        observations,
        observer_trust_states,
        minimum_organizations,
        trusted_log_public_key,
        evaluated_at_unix,
    )?;
    let report = ApprovalLogGossipRegistryBoundQuorumReport {
        schema_version: 1,
        trust_quorum,
        registry_id: registry.registry_id.clone(),
        registry_generation: registry.generation,
        registry_sha256: approval_log_gossip_organization_registry_sha256(registry)?,
        registry_bound: true,
    };
    validate_approval_log_gossip_registry_bound_quorum_report(&report)?;
    Ok(report)
}

pub fn approval_log_gossip_organization_registry_sha256(
    registry: &ApprovalLogGossipOrganizationRegistry,
) -> Result<String, String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    normalized_sha256(registry, "approval gossip organization registry")
}

pub fn signed_approval_log_gossip_organization_registry_transition_sha256(
    transition: &SignedApprovalLogGossipOrganizationRegistryTransition,
) -> Result<String, String> {
    validate_signed_approval_log_gossip_organization_registry_transition(transition)?;
    normalized_sha256(
        transition,
        "signed approval gossip organization registry transition",
    )
}

pub fn signed_approval_log_gossip_organization_registry_authority_key_rotation_sha256(
    rotation: &SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<String, String> {
    validate_signed_approval_log_gossip_organization_registry_authority_key_rotation(rotation)?;
    normalized_sha256(
        rotation,
        "signed approval gossip organization registry authority key rotation",
    )
}

pub fn signed_approval_log_gossip_organization_registry_governance_sha256(
    governance: &SignedApprovalLogGossipOrganizationRegistryGovernance,
) -> Result<String, String> {
    validate_signed_approval_log_gossip_organization_registry_governance(governance)?;
    normalized_sha256(
        governance,
        "signed approval gossip organization registry governance",
    )
}

pub fn signed_approval_log_gossip_organization_registry_threshold_transition_sha256(
    transition: &SignedApprovalLogGossipOrganizationRegistryThresholdTransition,
) -> Result<String, String> {
    validate_signed_approval_log_gossip_organization_registry_threshold_transition(transition)?;
    normalized_sha256(
        transition,
        "signed approval gossip organization registry threshold transition",
    )
}

pub fn validate_approval_log_gossip_organization_registry(
    registry: &ApprovalLogGossipOrganizationRegistry,
) -> Result<(), String> {
    if registry.schema_version != 1 {
        return Err("unsupported approval gossip organization registry".into());
    }
    validate_slug(
        &registry.registry_id,
        "approval gossip organization registry id",
    )?;
    validate_public_key(
        &registry.authority_public_key,
        "approval gossip registry authority public key",
    )?;
    if let Some(digest) = &registry.active_governance_sha256 {
        validate_sha256(digest, "active approval gossip registry governance SHA-256")?;
    }
    match (
        registry.generation,
        &registry.last_transition_sha256,
        registry.last_updated_at_unix,
    ) {
        (0, None, None) if registry.organizations.is_empty() => {}
        (0, _, _) => {
            return Err("initial approval gossip registry must be empty and unadvanced".into());
        }
        (_, Some(digest), Some(_)) => {
            validate_sha256(digest, "last approval gossip registry transition SHA-256")?
        }
        _ => {
            return Err(
                "advanced approval gossip registry requires complete transition evidence".into(),
            );
        }
    }
    if registry.organizations.len() > 100 {
        return Err("approval gossip registry supports at most 100 organizations".into());
    }
    let mut previous = None;
    for organization in &registry.organizations {
        validate_slug(
            &organization.organization_id,
            "approval gossip registry organization id",
        )?;
        validate_sha256(
            &organization.status_reason_sha256,
            "approval gossip organization status reason SHA-256",
        )?;
        if registry
            .last_updated_at_unix
            .is_some_and(|last| organization.status_since_unix > last)
        {
            return Err(
                "approval gossip organization status time exceeds registry update time".into(),
            );
        }
        if previous.is_some_and(|value: &String| value >= &organization.organization_id) {
            return Err("approval gossip registry organizations must be unique and ordered".into());
        }
        previous = Some(&organization.organization_id);
        if organization.observers.len() > 100 {
            return Err(
                "approval gossip registry supports at most 100 observers per organization".into(),
            );
        }
        let mut observer_previous = None;
        for observer in &organization.observers {
            validate_slug(
                &observer.observer_id,
                "admitted approval gossip observer id",
            )?;
            validate_sha256(
                &observer.observer_trust_state_sha256,
                "admitted approval gossip observer trust-state SHA-256",
            )?;
            if registry
                .last_updated_at_unix
                .is_some_and(|last| observer.admitted_at_unix > last)
            {
                return Err(
                    "approval gossip observer admission time exceeds registry update time".into(),
                );
            }
            if observer_previous.is_some_and(|value: &String| value >= &observer.observer_id) {
                return Err("admitted approval gossip observers must be unique and ordered".into());
            }
            observer_previous = Some(&observer.observer_id);
        }
        if organization.observers.is_empty() {
            return Err(
                "approval gossip registry organizations require an admitted observer".into(),
            );
        }
    }
    Ok(())
}

pub fn validate_signed_approval_log_gossip_organization_registry_transition(
    transition: &SignedApprovalLogGossipOrganizationRegistryTransition,
) -> Result<(), String> {
    if transition.schema_version != 1
        || transition.algorithm != "ed25519"
        || transition.from_generation.checked_add(1) != Some(transition.to_generation)
    {
        return Err("invalid approval gossip organization registry transition invariants".into());
    }
    validate_slug(
        &transition.registry_id,
        "approval gossip organization registry id",
    )?;
    validate_slug(
        &transition.organization_id,
        "approval gossip registry organization id",
    )?;
    validate_sha256(
        &transition.reason_sha256,
        "approval gossip registry transition reason SHA-256",
    )?;
    if let Some(digest) = &transition.previous_transition_sha256 {
        validate_sha256(
            digest,
            "previous approval gossip registry transition SHA-256",
        )?;
    }
    if (transition.from_generation == 0) != transition.previous_transition_sha256.is_none() {
        return Err("approval gossip registry transition chain reference is inconsistent".into());
    }
    match transition.action {
        ApprovalLogGossipOrganizationRegistryAction::AdmitObserver => {
            validate_slug(
                transition
                    .observer_id
                    .as_deref()
                    .ok_or_else(|| "observer admission requires observer id".to_string())?,
                "admitted approval gossip observer id",
            )?;
            validate_sha256(
                transition
                    .observer_trust_state_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "observer admission requires observer trust-state SHA-256".to_string()
                    })?,
                "admitted approval gossip observer trust-state SHA-256",
            )?;
        }
        ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization
        | ApprovalLogGossipOrganizationRegistryAction::RevokeOrganization => {
            if transition.observer_id.is_some() || transition.observer_trust_state_sha256.is_some()
            {
                return Err("organization status transition cannot bind an observer".into());
            }
        }
    }
    validate_public_key(
        &transition.authority_public_key,
        "approval gossip registry authority public key",
    )?;
    hex_decode::<64>(
        &transition.signature,
        "approval gossip registry authority signature",
    )?;
    Ok(())
}

pub fn validate_signed_approval_log_gossip_organization_registry_authority_key_rotation(
    rotation: &SignedApprovalLogGossipOrganizationRegistryAuthorityKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.from_generation.checked_add(1) != Some(rotation.to_generation)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid approval gossip registry authority rotation invariants".into());
    }
    validate_slug(
        &rotation.registry_id,
        "approval gossip organization registry id",
    )?;
    match (
        rotation.from_generation,
        &rotation.previous_transition_sha256,
    ) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err(
                "initial approval gossip registry authority rotation cannot reference a transition"
                    .into(),
            );
        }
        (_, Some(digest)) => validate_sha256(
            digest,
            "previous approval gossip registry transition SHA-256",
        )?,
        (_, None) => {
            return Err(
                "advanced approval gossip registry authority rotation requires chain evidence"
                    .into(),
            );
        }
    }
    validate_public_key(
        &rotation.old_public_key,
        "old approval gossip registry authority public key",
    )?;
    validate_public_key(
        &rotation.new_public_key,
        "new approval gossip registry authority public key",
    )?;
    hex_decode::<64>(
        &rotation.old_signature,
        "old approval gossip registry authority signature",
    )?;
    hex_decode::<64>(
        &rotation.new_signature,
        "new approval gossip registry authority signature",
    )?;
    Ok(())
}

pub fn validate_signed_approval_log_gossip_organization_registry_governance(
    governance: &SignedApprovalLogGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    if governance.schema_version != 1
        || governance.algorithm != "ed25519"
        || !(2..=MAXIMUM_GOVERNANCE_AUTHORITIES as u32).contains(&governance.minimum_approvals)
        || governance.authorities.len() < governance.minimum_approvals as usize
    {
        return Err("invalid approval gossip registry governance invariants".into());
    }
    validate_slug(
        &governance.registry_id,
        "approval gossip organization registry id",
    )?;
    validate_public_key(
        &governance.registry_authority_public_key,
        "approval gossip registry governance root public key",
    )?;
    validate_governance_authorities(&governance.authorities)?;
    hex_decode::<64>(
        &governance.signature,
        "approval gossip registry governance root signature",
    )?;
    Ok(())
}

pub fn validate_signed_approval_log_gossip_organization_registry_threshold_transition(
    transition: &SignedApprovalLogGossipOrganizationRegistryThresholdTransition,
) -> Result<(), String> {
    if transition.schema_version != 1
        || transition.algorithm != "ed25519"
        || transition.from_generation.checked_add(1) != Some(transition.to_generation)
        || transition.approvals.len() < 2
        || transition.approvals.len() > MAXIMUM_GOVERNANCE_AUTHORITIES
    {
        return Err("invalid approval gossip registry threshold transition invariants".into());
    }
    validate_slug(
        &transition.registry_id,
        "approval gossip organization registry id",
    )?;
    validate_slug(
        &transition.organization_id,
        "approval gossip registry organization id",
    )?;
    validate_sha256(
        &transition.governance_sha256,
        "approval gossip registry governance SHA-256",
    )?;
    validate_sha256(
        &transition.reason_sha256,
        "approval gossip registry transition reason SHA-256",
    )?;
    if let Some(digest) = &transition.previous_transition_sha256 {
        validate_sha256(
            digest,
            "previous approval gossip registry transition SHA-256",
        )?;
    }
    if (transition.from_generation == 0) != transition.previous_transition_sha256.is_none() {
        return Err("approval gossip registry threshold chain reference is inconsistent".into());
    }
    match transition.action {
        ApprovalLogGossipOrganizationRegistryAction::AdmitObserver => {
            validate_slug(
                transition
                    .observer_id
                    .as_deref()
                    .ok_or_else(|| "observer admission requires observer id".to_string())?,
                "admitted approval gossip observer id",
            )?;
            validate_sha256(
                transition
                    .observer_trust_state_sha256
                    .as_deref()
                    .ok_or_else(|| {
                        "observer admission requires observer trust-state SHA-256".to_string()
                    })?,
                "admitted approval gossip observer trust-state SHA-256",
            )?;
        }
        ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization
        | ApprovalLogGossipOrganizationRegistryAction::RevokeOrganization => {
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
            "approval gossip governance authority id",
        )?;
        validate_public_key(
            &approval.public_key,
            "approval gossip governance approval public key",
        )?;
        hex_decode::<64>(
            &approval.signature,
            "approval gossip governance approval signature",
        )?;
        if previous.is_some_and(|id: &String| id >= &approval.authority_id)
            || !keys.insert(approval.public_key.as_str())
        {
            return Err(
                "approval gossip governance approvals require ordered distinct identities and keys"
                    .into(),
            );
        }
        previous = Some(&approval.authority_id);
    }
    Ok(())
}

pub fn validate_approval_log_gossip_registry_bound_quorum_report(
    report: &ApprovalLogGossipRegistryBoundQuorumReport,
) -> Result<(), String> {
    validate_approval_log_gossip_trust_bound_quorum_report(&report.trust_quorum)?;
    if report.schema_version != 1 || !report.registry_bound {
        return Err("invalid registry-bound approval gossip quorum invariants".into());
    }
    validate_slug(
        &report.registry_id,
        "approval gossip organization registry id",
    )?;
    validate_sha256(
        &report.registry_sha256,
        "approval gossip organization registry SHA-256",
    )
}

pub fn approval_log_gossip_organization_registry_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/approval-log-gossip-organization-registry-v1.json",
        "title": "pcbex approval public-log gossip organization registry",
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
            "active_governance_sha256": {"oneOf": [
                {"type": "null"}, digest_schema()
            ]},
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

pub fn signed_approval_log_gossip_organization_registry_transition_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-approval-log-gossip-organization-registry-transition-v1.json",
        "title": "Signed pcbex approval gossip organization registry transition",
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

pub fn signed_approval_log_gossip_organization_registry_authority_key_rotation_json_schema() -> Value
{
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-approval-log-gossip-organization-registry-authority-key-rotation-v1.json",
        "title": "Dual-signed pcbex approval gossip registry authority key rotation",
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
            "previous_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_public_key": key_schema(),
            "new_public_key": key_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn signed_approval_log_gossip_organization_registry_governance_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-approval-log-gossip-organization-registry-governance-v1.json",
        "title": "Root-signed pcbex approval gossip registry threshold governance",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "registry_authority_public_key",
            "minimum_approvals", "authorities", "issued_at_unix", "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "registry_authority_public_key": key_schema(),
            "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": 100},
            "authorities": {
                "type": "array", "minItems": 2, "maxItems": 100,
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

pub fn signed_approval_log_gossip_organization_registry_threshold_transition_json_schema() -> Value
{
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-approval-log-gossip-organization-registry-threshold-transition-v1.json",
        "title": "Threshold-approved pcbex approval gossip registry transition",
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
                "type": "array", "minItems": 2, "maxItems": 100,
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

pub fn approval_log_gossip_registry_bound_quorum_report_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/approval-log-gossip-registry-bound-quorum-report-v1.json",
        "title": "pcbex registry-bound approval public-log gossip quorum report",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "trust_quorum", "registry_id", "registry_generation",
            "registry_sha256", "registry_bound"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "trust_quorum": approval_log_gossip_trust_bound_quorum_report_json_schema(),
            "registry_id": slug_schema(),
            "registry_generation": {"type": "integer", "minimum": 0},
            "registry_sha256": digest_schema(),
            "registry_bound": {"const": true}
        }
    })
}

fn transition_observer_binding(
    action: &ApprovalLogGossipOrganizationRegistryAction,
    organization_id: &str,
    observer_trust_state: Option<&ApprovalLogGossipObserverTrustState>,
) -> Result<(Option<String>, Option<String>), String> {
    match action {
        ApprovalLogGossipOrganizationRegistryAction::AdmitObserver => {
            let state = observer_trust_state
                .ok_or_else(|| "observer admission requires an observer trust state".to_string())?;
            validate_approval_log_gossip_observer_trust_state(state)?;
            if state.organization_id != organization_id {
                return Err(
                    "approval gossip observer trust organization does not match admission target"
                        .into(),
                );
            }
            Ok((
                Some(state.observer_id.clone()),
                Some(approval_log_gossip_observer_trust_state_sha256(state)?),
            ))
        }
        ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization
        | ApprovalLogGossipOrganizationRegistryAction::RevokeOrganization => {
            if observer_trust_state.is_some() {
                return Err("organization status transition cannot include observer trust".into());
            }
            Ok((None, None))
        }
    }
}

fn apply_action(
    organizations: &mut Vec<ApprovalLogGossipOrganizationRegistryEntry>,
    transition: &SignedApprovalLogGossipOrganizationRegistryTransition,
) -> Result<(), String> {
    let index = organizations
        .binary_search_by(|entry| entry.organization_id.cmp(&transition.organization_id));
    match transition.action {
        ApprovalLogGossipOrganizationRegistryAction::AdmitObserver => {
            let observer = ApprovalLogGossipObserverAdmission {
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
                    if organization.status != ApprovalLogGossipOrganizationStatus::Active {
                        return Err(
                            "cannot admit an observer to a non-active approval gossip organization"
                                .into(),
                        );
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
                                    "exact approval gossip observer trust state is already admitted"
                                        .into(),
                                );
                            }
                            organization.observers[index] = observer;
                        }
                        Err(index) => organization.observers.insert(index, observer),
                    }
                }
                Err(index) => organizations.insert(
                    index,
                    ApprovalLogGossipOrganizationRegistryEntry {
                        organization_id: transition.organization_id.clone(),
                        status: ApprovalLogGossipOrganizationStatus::Active,
                        status_since_unix: transition.effective_at_unix,
                        status_reason_sha256: transition.reason_sha256.clone(),
                        observers: vec![observer],
                    },
                ),
            }
        }
        ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization => {
            let organization = index
                .ok()
                .map(|index| &mut organizations[index])
                .ok_or_else(|| "cannot suspend an organization that is not admitted".to_string())?;
            if organization.status != ApprovalLogGossipOrganizationStatus::Active {
                return Err("only an active approval gossip organization can be suspended".into());
            }
            organization.status = ApprovalLogGossipOrganizationStatus::Suspended;
            organization.status_since_unix = transition.effective_at_unix;
            organization.status_reason_sha256 = transition.reason_sha256.clone();
        }
        ApprovalLogGossipOrganizationRegistryAction::RevokeOrganization => {
            let organization = index
                .ok()
                .map(|index| &mut organizations[index])
                .ok_or_else(|| "cannot revoke an organization that is not admitted".to_string())?;
            if organization.status == ApprovalLogGossipOrganizationStatus::Revoked {
                return Err("approval gossip organization is already permanently revoked".into());
            }
            organization.status = ApprovalLogGossipOrganizationStatus::Revoked;
            organization.status_since_unix = transition.effective_at_unix;
            organization.status_reason_sha256 = transition.reason_sha256.clone();
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn transition_payload(
    registry: &ApprovalLogGossipOrganizationRegistry,
    to_generation: u64,
    action: &ApprovalLogGossipOrganizationRegistryAction,
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
    .map_err(|error| format!("serializing approval gossip registry transition: {error}"))
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
    .map_err(|error| {
        format!("serializing approval gossip registry authority key rotation: {error}")
    })
}

fn governance_payload(
    registry_id: &str,
    registry_authority_public_key: &str,
    minimum_approvals: u32,
    authorities: &[ApprovalLogGossipRegistryGovernanceAuthority],
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
    .map_err(|error| format!("serializing approval gossip registry governance: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn threshold_transition_payload(
    registry_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_transition_sha256: Option<&str>,
    governance_sha256: &str,
    action: &ApprovalLogGossipOrganizationRegistryAction,
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
    .map_err(|error| format!("serializing governed approval gossip registry transition: {error}"))
}

fn validate_governance_authorities(
    authorities: &[ApprovalLogGossipRegistryGovernanceAuthority],
) -> Result<(), String> {
    if authorities.len() < 2 || authorities.len() > MAXIMUM_GOVERNANCE_AUTHORITIES {
        return Err("approval gossip registry governance requires 2 to 100 authorities".into());
    }
    let mut previous = None;
    let mut keys = HashSet::new();
    for authority in authorities {
        validate_slug(
            &authority.authority_id,
            "approval gossip registry governance authority id",
        )?;
        validate_public_key(
            &authority.public_key,
            "approval gossip registry governance authority public key",
        )?;
        if previous.is_some_and(|id: &String| id >= &authority.authority_id)
            || !keys.insert(authority.public_key.as_str())
        {
            return Err(
                "approval gossip governance authorities require ordered distinct identities and keys"
                    .into(),
            );
        }
        previous = Some(&authority.authority_id);
    }
    Ok(())
}

fn validate_governance_for_registry(
    registry: &ApprovalLogGossipOrganizationRegistry,
    governance: &SignedApprovalLogGossipOrganizationRegistryGovernance,
) -> Result<(), String> {
    validate_approval_log_gossip_organization_registry(registry)?;
    validate_signed_approval_log_gossip_organization_registry_governance(governance)?;
    if governance.registry_id != registry.registry_id
        || governance.registry_authority_public_key != registry.authority_public_key
    {
        return Err(
            "approval gossip registry governance does not match retained root trust".into(),
        );
    }
    let payload = governance_payload(
        &governance.registry_id,
        &governance.registry_authority_public_key,
        governance.minimum_approvals,
        &governance.authorities,
        governance.issued_at_unix,
    )?;
    let key = hex_decode::<32>(
        &governance.registry_authority_public_key,
        "approval gossip registry governance root public key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &governance.signature,
        "approval gossip registry governance root signature",
    )?);
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid approval gossip governance root key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "approval gossip registry governance root signature failed".to_string())
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
    use serde_json::Value;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trust(
        organization_id: &str,
        observer_id: &str,
        seed: u8,
    ) -> ApprovalLogGossipObserverTrustState {
        crate::new_approval_log_gossip_observer_trust_state(
            organization_id,
            observer_id,
            &key(seed).verifying_key().to_bytes(),
        )
        .unwrap()
    }

    fn reason(seed: u8) -> String {
        format!("{seed:02x}").repeat(32)
    }

    fn assert_closed(value: &Value) {
        if value.get("type").and_then(Value::as_str) == Some("object") {
            assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
        }
        match value {
            Value::Array(values) => values.iter().for_each(assert_closed),
            Value::Object(values) => values.values().for_each(assert_closed),
            _ => {}
        }
    }

    #[test]
    fn authority_governs_admission_suspension_and_permanent_revocation() {
        let authority = key(1);
        let observer = trust("org-a", "observer-a", 2);
        let initial = new_approval_log_gossip_organization_registry(
            "production",
            &authority.verifying_key().to_bytes(),
        )
        .unwrap();
        let admission = sign_approval_log_gossip_organization_registry_transition(
            &initial,
            &authority.to_bytes(),
            ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
            "org-a",
            Some(&observer),
            &reason(3),
            100,
        )
        .unwrap();
        let admitted =
            apply_approval_log_gossip_organization_registry_transition(&initial, &admission)
                .unwrap();
        let suspension = sign_approval_log_gossip_organization_registry_transition(
            &admitted,
            &authority.to_bytes(),
            ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization,
            "org-a",
            None,
            &reason(4),
            101,
        )
        .unwrap();
        let suspended =
            apply_approval_log_gossip_organization_registry_transition(&admitted, &suspension)
                .unwrap();
        assert_eq!(
            suspended.organizations[0].status,
            ApprovalLogGossipOrganizationStatus::Suspended
        );
        let revocation = sign_approval_log_gossip_organization_registry_transition(
            &suspended,
            &authority.to_bytes(),
            ApprovalLogGossipOrganizationRegistryAction::RevokeOrganization,
            "org-a",
            None,
            &reason(5),
            102,
        )
        .unwrap();
        let revoked =
            apply_approval_log_gossip_organization_registry_transition(&suspended, &revocation)
                .unwrap();
        assert_eq!(
            revoked.organizations[0].status,
            ApprovalLogGossipOrganizationStatus::Revoked
        );
        assert!(
            sign_approval_log_gossip_organization_registry_transition(
                &revoked,
                &authority.to_bytes(),
                ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
                "org-a",
                Some(&observer),
                &reason(6),
                103,
            )
            .and_then(|transition| {
                apply_approval_log_gossip_organization_registry_transition(&revoked, &transition)
            })
            .is_err()
        );
        assert!(
            apply_approval_log_gossip_organization_registry_transition(&initial, &admission)
                .and_then(|state| {
                    apply_approval_log_gossip_organization_registry_transition(&state, &admission)
                })
                .is_err()
        );
    }

    #[test]
    fn schemas_close_every_object() {
        assert_closed(&approval_log_gossip_organization_registry_json_schema());
        assert_closed(&signed_approval_log_gossip_organization_registry_transition_json_schema());
        assert_closed(
            &signed_approval_log_gossip_organization_registry_authority_key_rotation_json_schema(),
        );
        assert_closed(&signed_approval_log_gossip_organization_registry_governance_json_schema());
        assert_closed(
            &signed_approval_log_gossip_organization_registry_threshold_transition_json_schema(),
        );
        assert_closed(&approval_log_gossip_registry_bound_quorum_report_json_schema());
        let authority = key(99);
        let registry = new_approval_log_gossip_organization_registry(
            "upgrade-compatible",
            &authority.verifying_key().to_bytes(),
        )
        .unwrap();
        let mut legacy = serde_json::to_value(&registry).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("active_governance_sha256");
        assert_eq!(
            serde_json::from_value::<ApprovalLogGossipOrganizationRegistry>(legacy).unwrap(),
            registry
        );
    }

    #[test]
    fn authority_rotation_requires_both_keys_and_preserves_admissions() {
        let old_authority = key(1);
        let new_authority = key(2);
        let observer = trust("org-a", "observer-a", 3);
        let initial = new_approval_log_gossip_organization_registry(
            "production",
            &old_authority.verifying_key().to_bytes(),
        )
        .unwrap();
        let admission = sign_approval_log_gossip_organization_registry_transition(
            &initial,
            &old_authority.to_bytes(),
            ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
            "org-a",
            Some(&observer),
            &reason(4),
            100,
        )
        .unwrap();
        let admitted =
            apply_approval_log_gossip_organization_registry_transition(&initial, &admission)
                .unwrap();
        let rotation = sign_approval_log_gossip_organization_registry_authority_key_rotation(
            &admitted,
            &old_authority.to_bytes(),
            &new_authority.to_bytes(),
            101,
        )
        .unwrap();
        let rotated = apply_approval_log_gossip_organization_registry_authority_key_rotation(
            &admitted, &rotation,
        )
        .unwrap();
        assert_eq!(rotated.organizations, admitted.organizations);
        assert_eq!(
            rotated.authority_public_key,
            hex_encode(&new_authority.verifying_key().to_bytes())
        );
        assert_eq!(rotated.generation, admitted.generation + 1);
        assert!(
            apply_approval_log_gossip_organization_registry_authority_key_rotation(
                &rotated, &rotation,
            )
            .is_err()
        );
        let mut forged = rotation.clone();
        forged.new_signature.replace_range(0..2, "00");
        assert!(
            apply_approval_log_gossip_organization_registry_authority_key_rotation(
                &admitted, &forged,
            )
            .is_err()
        );
        assert!(
            sign_approval_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &old_authority.to_bytes(),
                &key(5).to_bytes(),
                102,
            )
            .is_err()
        );
        assert!(
            sign_approval_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &new_authority.to_bytes(),
                &new_authority.to_bytes(),
                102,
            )
            .is_err()
        );
        assert!(
            sign_approval_log_gossip_organization_registry_authority_key_rotation(
                &rotated,
                &new_authority.to_bytes(),
                &key(6).to_bytes(),
                99,
            )
            .is_err()
        );
        assert!(
            sign_approval_log_gossip_organization_registry_transition(
                &rotated,
                &old_authority.to_bytes(),
                ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
                "org-b",
                Some(&trust("org-b", "observer-b", 7)),
                &reason(8),
                102,
            )
            .is_err()
        );
        let post_rotation = sign_approval_log_gossip_organization_registry_transition(
            &rotated,
            &new_authority.to_bytes(),
            ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
            "org-b",
            Some(&trust("org-b", "observer-b", 7)),
            &reason(8),
            102,
        )
        .unwrap();
        assert_eq!(
            apply_approval_log_gossip_organization_registry_transition(&rotated, &post_rotation,)
                .unwrap()
                .organizations
                .len(),
            2
        );
        let other_registry = new_approval_log_gossip_organization_registry(
            "disaster-recovery",
            &old_authority.verifying_key().to_bytes(),
        )
        .unwrap();
        assert!(
            apply_approval_log_gossip_organization_registry_authority_key_rotation(
                &other_registry,
                &rotation,
            )
            .is_err()
        );
    }

    #[test]
    fn threshold_governance_requires_distinct_authorities_and_blocks_root_bypass() {
        let root = key(10);
        let authority_a = key(11);
        let authority_b = key(12);
        let authority_c = key(13);
        let initial = new_approval_log_gossip_organization_registry(
            "production",
            &root.verifying_key().to_bytes(),
        )
        .unwrap();
        let governance = sign_approval_log_gossip_organization_registry_governance(
            &initial,
            &root.to_bytes(),
            2,
            vec![
                ApprovalLogGossipRegistryGovernanceAuthority {
                    authority_id: "reviewer-c".into(),
                    public_key: hex_encode(&authority_c.verifying_key().to_bytes()),
                },
                ApprovalLogGossipRegistryGovernanceAuthority {
                    authority_id: "reviewer-a".into(),
                    public_key: hex_encode(&authority_a.verifying_key().to_bytes()),
                },
                ApprovalLogGossipRegistryGovernanceAuthority {
                    authority_id: "reviewer-b".into(),
                    public_key: hex_encode(&authority_b.verifying_key().to_bytes()),
                },
            ],
            100,
        )
        .unwrap();
        let observer = trust("org-a", "observer-a", 14);
        assert!(
            sign_approval_log_gossip_organization_registry_threshold_transition(
                &initial,
                &governance,
                &[("reviewer-a".into(), authority_a.to_bytes())],
                ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
                "org-a",
                Some(&observer),
                &reason(15),
                101,
            )
            .is_err()
        );
        let transition = sign_approval_log_gossip_organization_registry_threshold_transition(
            &initial,
            &governance,
            &[
                ("reviewer-b".into(), authority_b.to_bytes()),
                ("reviewer-a".into(), authority_a.to_bytes()),
            ],
            ApprovalLogGossipOrganizationRegistryAction::AdmitObserver,
            "org-a",
            Some(&observer),
            &reason(15),
            101,
        )
        .unwrap();
        let governed = apply_approval_log_gossip_organization_registry_threshold_transition(
            &initial,
            &governance,
            &transition,
        )
        .unwrap();
        assert_eq!(governed.organizations.len(), 1);
        assert!(governed.active_governance_sha256.is_some());
        assert!(
            sign_approval_log_gossip_organization_registry_transition(
                &governed,
                &root.to_bytes(),
                ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization,
                "org-a",
                None,
                &reason(16),
                102,
            )
            .is_err()
        );
        assert!(
            sign_approval_log_gossip_organization_registry_authority_key_rotation(
                &governed,
                &root.to_bytes(),
                &key(17).to_bytes(),
                102,
            )
            .is_err()
        );
        let suspension = sign_approval_log_gossip_organization_registry_threshold_transition(
            &governed,
            &governance,
            &[
                ("reviewer-c".into(), authority_c.to_bytes()),
                ("reviewer-a".into(), authority_a.to_bytes()),
            ],
            ApprovalLogGossipOrganizationRegistryAction::SuspendOrganization,
            "org-a",
            None,
            &reason(16),
            102,
        )
        .unwrap();
        let suspended = apply_approval_log_gossip_organization_registry_threshold_transition(
            &governed,
            &governance,
            &suspension,
        )
        .unwrap();
        assert_eq!(
            suspended.organizations[0].status,
            ApprovalLogGossipOrganizationStatus::Suspended
        );
        let mut tampered = suspension.clone();
        tampered.approvals[0].signature.replace_range(0..2, "00");
        assert!(
            apply_approval_log_gossip_organization_registry_threshold_transition(
                &governed,
                &governance,
                &tampered,
            )
            .is_err()
        );
        assert!(
            apply_approval_log_gossip_organization_registry_threshold_transition(
                &governed,
                &governance,
                &transition,
            )
            .is_err()
        );
    }
}
