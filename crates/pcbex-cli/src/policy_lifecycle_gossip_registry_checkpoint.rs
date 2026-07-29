use crate::policy_lifecycle_gossip_registry::{
    PolicyLifecycleLogGossipOrganizationRegistryHistory,
    PolicyLifecycleLogGossipOrganizationRegistryHistoryAuditReport,
    audit_policy_lifecycle_log_gossip_organization_registry_history,
    policy_lifecycle_log_gossip_organization_registry_history_audit_report_sha256,
    validate_policy_lifecycle_log_gossip_organization_registry_history_audit_report,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CHECKPOINT_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-history-checkpoint-v1";
const WITNESS_DOMAIN: &str =
    "pcbex-policy-lifecycle-public-log-gossip-organization-registry-history-checkpoint-witness-v1";
const WITNESS_KEY_ROTATION_DOMAIN: &str = "pcbex-policy-lifecycle-public-log-gossip-organization-registry-history-checkpoint-witness-key-rotation-v1";
const MAXIMUM_WITNESSES: usize = 100;
const MAXIMUM_ACCEPTANCE_DELAY_SECONDS: u64 = 86_400;
const MAXIMUM_WITNESS_AGE_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub history_audit_sha256: String,
    pub final_registry_sha256: String,
    pub last_transition_sha256: Option<String>,
    pub active_governance_sha256: Option<String>,
    pub authority_public_key: String,
    pub issued_at_unix: u64,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState {
    pub schema_version: u32,
    pub registry_id: String,
    pub accepted_generation: u64,
    pub checkpoint_sha256: String,
    pub history_audit_sha256: String,
    pub final_registry_sha256: String,
    pub last_transition_sha256: Option<String>,
    pub active_governance_sha256: Option<String>,
    pub authority_public_key: String,
    pub issued_at_unix: u64,
    pub accepted_at_unix: u64,
    pub signed_checkpoint: SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub witness_id: String,
    pub witnessed_at_unix: u64,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState {
    pub schema_version: u32,
    pub witness_id: String,
    pub generation: u64,
    pub current_public_key: String,
    pub last_rotation_sha256: Option<String>,
    pub last_rotated_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation {
    pub schema_version: u32,
    pub witness_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub previous_rotation_sha256: Option<String>,
    pub old_public_key: String,
    pub new_public_key: String,
    pub rotated_at_unix: u64,
    pub algorithm: String,
    pub old_signature: String,
    pub new_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessMember {
    pub witness_id: String,
    pub public_key: String,
    pub witness_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport {
    pub schema_version: u32,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub history_audit_sha256: String,
    pub evaluated_at_unix: u64,
    pub minimum_witnesses: u32,
    pub valid_witnesses: u32,
    pub members: Vec<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessMember>,
    pub quorum_met: bool,
}

#[derive(Serialize)]
struct CheckpointPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    generation: u64,
    history_audit_sha256: &'a str,
    final_registry_sha256: &'a str,
    last_transition_sha256: Option<&'a str>,
    active_governance_sha256: Option<&'a str>,
    authority_public_key: &'a str,
    issued_at_unix: u64,
}

#[derive(Serialize)]
struct WitnessPayload<'a> {
    domain: &'static str,
    registry_id: &'a str,
    generation: u64,
    checkpoint_sha256: &'a str,
    witness_id: &'a str,
    witnessed_at_unix: u64,
}

#[derive(Serialize)]
struct WitnessKeyRotationPayload<'a> {
    domain: &'static str,
    witness_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_rotation_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    rotated_at_unix: u64,
}

pub fn sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
    history: &PolicyLifecycleLogGossipOrganizationRegistryHistory,
    authority_secret_key: &[u8; 32],
    issued_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint, String> {
    let audit = audit_policy_lifecycle_log_gossip_organization_registry_history(history)?;
    let final_registry = &audit.final_registry;
    if final_registry
        .last_updated_at_unix
        .is_some_and(|last| issued_at_unix < last)
    {
        return Err("gossip registry history checkpoint predates its final registry".into());
    }
    let signing_key = SigningKey::from_bytes(authority_secret_key);
    let authority_public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    if authority_public_key != final_registry.authority_public_key {
        return Err("gossip registry history checkpoint signer is not the retained root".into());
    }
    let history_audit_sha256 =
        policy_lifecycle_log_gossip_organization_registry_history_audit_report_sha256(&audit)?;
    let payload = checkpoint_payload(
        &audit,
        &history_audit_sha256,
        &authority_public_key,
        issued_at_unix,
    )?;
    let checkpoint = SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint {
        schema_version: 1,
        registry_id: audit.registry_id,
        generation: audit.final_registry.generation,
        history_audit_sha256,
        final_registry_sha256: audit.final_registry_sha256,
        last_transition_sha256: audit.final_registry.last_transition_sha256,
        active_governance_sha256: audit.final_registry.active_governance_sha256,
        authority_public_key,
        issued_at_unix,
        algorithm: "ed25519".into(),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
        &checkpoint,
    )?;
    Ok(checkpoint)
}

pub fn accept_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
    history: &PolicyLifecycleLogGossipOrganizationRegistryHistory,
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
    baseline: Option<&PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState>,
    accepted_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState, String> {
    let audit = audit_policy_lifecycle_log_gossip_organization_registry_history(history)?;
    verify_checkpoint_for_audit(&audit, checkpoint)?;
    if accepted_at_unix < checkpoint.issued_at_unix
        || accepted_at_unix.saturating_sub(checkpoint.issued_at_unix)
            > MAXIMUM_ACCEPTANCE_DELAY_SECONDS
    {
        return Err("gossip registry history checkpoint acceptance time is invalid".into());
    }
    let checkpoint_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_sha256(
            checkpoint,
        )?;
    if let Some(baseline) = baseline {
        validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state(
            baseline,
        )?;
        if baseline.registry_id != checkpoint.registry_id {
            return Err("gossip registry history checkpoint trust identity changed".into());
        }
        if checkpoint.generation < baseline.accepted_generation {
            return Err("gossip registry history checkpoint rollback is forbidden".into());
        }
        if checkpoint.generation == baseline.accepted_generation {
            if checkpoint_sha256 == baseline.checkpoint_sha256 {
                return Ok(baseline.clone());
            }
            return Err("gossip registry history checkpoint generation equivocated".into());
        }
        if checkpoint.issued_at_unix < baseline.issued_at_unix
            || accepted_at_unix < baseline.accepted_at_unix
        {
            return Err("gossip registry history checkpoint time moved backwards".into());
        }
        verify_audit_extends_trust_state(&audit, baseline)?;
    }
    let state = PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState {
        schema_version: 1,
        registry_id: checkpoint.registry_id.clone(),
        accepted_generation: checkpoint.generation,
        checkpoint_sha256,
        history_audit_sha256: checkpoint.history_audit_sha256.clone(),
        final_registry_sha256: checkpoint.final_registry_sha256.clone(),
        last_transition_sha256: checkpoint.last_transition_sha256.clone(),
        active_governance_sha256: checkpoint.active_governance_sha256.clone(),
        authority_public_key: checkpoint.authority_public_key.clone(),
        issued_at_unix: checkpoint.issued_at_unix,
        accepted_at_unix,
        signed_checkpoint: checkpoint.clone(),
    };
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state(
        &state,
    )?;
    Ok(state)
}

pub fn new_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
    witness_id: &str,
    public_key: &[u8; 32],
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState, String>
{
    validate_slug(witness_id, "registry history checkpoint witness id")?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("invalid registry history witness public key: {error}"))?;
    Ok(
        PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState {
            schema_version: 1,
            witness_id: witness_id.into(),
            generation: 0,
            current_public_key: hex_encode(public_key),
            last_rotation_sha256: None,
            last_rotated_at_unix: None,
        },
    )
}

pub fn policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
    state: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
) -> Result<[u8; 32], String> {
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        state,
    )?;
    hex_decode::<32>(
        &state.current_public_key,
        "current registry history witness public key",
    )
}

pub fn sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    state: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<
    SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation,
    String,
> {
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        state,
    )?;
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != state.current_public_key {
        return Err("old registry history witness key does not match trust state".into());
    }
    if new_public_key == old_public_key {
        return Err("new registry history witness key must differ".into());
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err("registry history witness rotation time moved backwards".into());
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "registry history witness key generation overflow".to_string())?;
    let payload = witness_key_rotation_payload(
        &state.witness_id,
        state.generation,
        to_generation,
        state.last_rotation_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    let rotation =
        SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation {
            schema_version: 1,
            witness_id: state.witness_id.clone(),
            from_generation: state.generation,
            to_generation,
            previous_rotation_sha256: state.last_rotation_sha256.clone(),
            old_public_key,
            new_public_key,
            rotated_at_unix,
            algorithm: "ed25519".into(),
            old_signature: hex_encode(&old_key.sign(&payload).to_bytes()),
            new_signature: hex_encode(&new_key.sign(&payload).to_bytes()),
        };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn apply_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    state: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState, String>
{
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        state,
    )?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
        rotation,
    )?;
    if rotation.witness_id != state.witness_id
        || rotation.from_generation != state.generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
        || rotation.to_generation != state.generation.saturating_add(1)
        || state
            .last_rotated_at_unix
            .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err("registry history witness rotation does not extend trust state".into());
    }
    let payload = witness_key_rotation_payload(
        &rotation.witness_id,
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
            &rotation.old_signature,
            "old registry history witness rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new registry history witness rotation",
        ),
    ] {
        let key = hex_decode::<32>(key, label)?;
        let signature = Signature::from_bytes(&hex_decode::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let rotation_sha256 = normalized_sha256(rotation, "registry history witness key rotation")?;
    let next = PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState {
        schema_version: 1,
        witness_id: state.witness_id.clone(),
        generation: rotation.to_generation,
        current_public_key: rotation.new_public_key.clone(),
        last_rotation_sha256: Some(rotation_sha256),
        last_rotated_at_unix: Some(rotation.rotated_at_unix),
    };
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        &next,
    )?;
    Ok(next)
}

pub fn sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
    history: &PolicyLifecycleLogGossipOrganizationRegistryHistory,
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
    witness_id: &str,
    witness_secret_key: &[u8; 32],
    witnessed_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness, String> {
    let audit = audit_policy_lifecycle_log_gossip_organization_registry_history(history)?;
    verify_checkpoint_for_audit(&audit, checkpoint)?;
    validate_slug(witness_id, "gossip registry history checkpoint witness id")?;
    if witnessed_at_unix < checkpoint.issued_at_unix {
        return Err("gossip registry history witness predates its checkpoint".into());
    }
    let checkpoint_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_sha256(
            checkpoint,
        )?;
    let signing_key = SigningKey::from_bytes(witness_secret_key);
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = witness_payload(
        &checkpoint.registry_id,
        checkpoint.generation,
        &checkpoint_sha256,
        witness_id,
        witnessed_at_unix,
    )?;
    let witness = SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness {
        schema_version: 1,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        checkpoint_sha256,
        witness_id: witness_id.into(),
        witnessed_at_unix,
        algorithm: "ed25519".into(),
        public_key,
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witnesses(
    history: &PolicyLifecycleLogGossipOrganizationRegistryHistory,
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
    witnesses: &[SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness],
    trusted_witnesses: &[(String, [u8; 32])],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport, String>
{
    let audit = audit_policy_lifecycle_log_gossip_organization_registry_history(history)?;
    verify_checkpoint_for_audit(&audit, checkpoint)?;
    if !(2..=MAXIMUM_WITNESSES as u32).contains(&minimum_witnesses)
        || witnesses.len() > MAXIMUM_WITNESSES
        || trusted_witnesses.len() > MAXIMUM_WITNESSES
    {
        return Err(
            "gossip registry history witness quorum must require 2 to 100 witnesses".into(),
        );
    }
    if evaluated_at_unix < checkpoint.issued_at_unix {
        return Err("gossip registry history witness evaluation predates its checkpoint".into());
    }
    let trusted = trusted_witness_map(trusted_witnesses)?;
    let checkpoint_sha256 =
        signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_sha256(
            checkpoint,
        )?;
    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut members = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
            witness,
        )?;
        if witness.registry_id != checkpoint.registry_id
            || witness.generation != checkpoint.generation
            || witness.checkpoint_sha256 != checkpoint_sha256
        {
            return Err("gossip registry history witness is bound to another checkpoint".into());
        }
        if witness.witnessed_at_unix < checkpoint.issued_at_unix
            || witness.witnessed_at_unix > evaluated_at_unix
            || evaluated_at_unix.saturating_sub(witness.witnessed_at_unix)
                > MAXIMUM_WITNESS_AGE_SECONDS
        {
            return Err("gossip registry history witness is stale or future-dated".into());
        }
        if !seen_ids.insert(witness.witness_id.as_str())
            || !seen_keys.insert(witness.public_key.as_str())
        {
            return Err(
                "gossip registry history witnesses require distinct identities and keys".into(),
            );
        }
        let trusted_key = trusted
            .get(&witness.witness_id)
            .ok_or_else(|| "untrusted gossip registry history witness identity".to_string())?;
        if witness.public_key != hex_encode(trusted_key) {
            return Err("gossip registry history witness key substitution".into());
        }
        let payload = witness_payload(
            &witness.registry_id,
            witness.generation,
            &witness.checkpoint_sha256,
            &witness.witness_id,
            witness.witnessed_at_unix,
        )?;
        let signature = Signature::from_bytes(&hex_decode::<64>(
            &witness.signature,
            "gossip registry history witness signature",
        )?);
        VerifyingKey::from_bytes(trusted_key)
            .map_err(|error| format!("invalid trusted history witness key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| {
                "gossip registry history witness signature verification failed".to_string()
            })?;
        members.push(
            PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessMember {
                witness_id: witness.witness_id.clone(),
                public_key: witness.public_key.clone(),
                witness_sha256:
                    signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_sha256(
                        witness,
                    )?,
            },
        );
    }
    members.sort_by(|left, right| left.witness_id.cmp(&right.witness_id));
    let valid_witnesses = u32::try_from(members.len())
        .map_err(|_| "gossip registry history witness count overflow".to_string())?;
    let report = PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport {
        schema_version: 1,
        registry_id: checkpoint.registry_id.clone(),
        generation: checkpoint.generation,
        checkpoint_sha256,
        history_audit_sha256: checkpoint.history_audit_sha256.clone(),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses,
        members,
        quorum_met: valid_witnesses >= minimum_witnesses,
    };
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub fn verify_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witnesses_with_trust_states(
    history: &PolicyLifecycleLogGossipOrganizationRegistryHistory,
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
    witnesses: &[SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness],
    trust_states:
        &[PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport, String>
{
    let trusted = trust_states
        .iter()
        .map(|state| {
            Ok((
                state.witness_id.clone(),
                policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
                    state,
                )?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    verify_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witnesses(
        history,
        checkpoint,
        witnesses,
        &trusted,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint, String> {
    let checkpoint = serde_json::from_str(source)
        .map_err(|error| format!("invalid gossip registry history checkpoint JSON: {error}"))?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
        &checkpoint,
    )?;
    Ok(checkpoint)
}

pub fn parse_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state(
    source: &str,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState, String> {
    let state = serde_json::from_str(source).map_err(|error| {
        format!("invalid gossip registry history checkpoint trust-state JSON: {error}")
    })?;
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state(
        &state,
    )?;
    Ok(state)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness, String> {
    let witness = serde_json::from_str(source).map_err(|error| {
        format!("invalid gossip registry history checkpoint witness JSON: {error}")
    })?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
        &witness,
    )?;
    Ok(witness)
}

pub fn parse_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
    source: &str,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState, String>
{
    let state = serde_json::from_str(source)
        .map_err(|error| format!("invalid registry history witness trust-state JSON: {error}"))?;
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        &state,
    )?;
    Ok(state)
}

pub fn parse_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    source: &str,
) -> Result<
    SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation,
    String,
> {
    let rotation = serde_json::from_str(source)
        .map_err(|error| format!("invalid registry history witness key-rotation JSON: {error}"))?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
        &rotation,
    )?;
    Ok(rotation)
}

pub fn parse_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_quorum_report(
    source: &str,
) -> Result<PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport, String>
{
    let report = serde_json::from_str(source).map_err(|error| {
        format!("invalid gossip registry history checkpoint witness quorum JSON: {error}")
    })?;
    validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_quorum_report(
        &report,
    )?;
    Ok(report)
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_sha256(
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
        checkpoint,
    )?;
    normalized_sha256(checkpoint, "gossip registry history checkpoint")
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_sha256(
    witness: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
        witness,
    )?;
    normalized_sha256(witness, "gossip registry history checkpoint witness")
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<(), String> {
    if checkpoint.schema_version != 1 || checkpoint.algorithm != "ed25519" {
        return Err("invalid gossip registry history checkpoint invariants".into());
    }
    validate_slug(&checkpoint.registry_id, "gossip registry id")?;
    validate_digest(&checkpoint.history_audit_sha256, "history audit SHA-256")?;
    validate_digest(&checkpoint.final_registry_sha256, "final registry SHA-256")?;
    match (checkpoint.generation, &checkpoint.last_transition_sha256) {
        (0, None) => {}
        (0, Some(_)) => {
            return Err("genesis history checkpoint cannot reference a transition".into());
        }
        (_, Some(digest)) => validate_digest(digest, "last registry transition SHA-256")?,
        (_, None) => return Err("advanced history checkpoint requires transition evidence".into()),
    }
    if let Some(digest) = &checkpoint.active_governance_sha256 {
        validate_digest(digest, "active registry governance SHA-256")?;
    }
    validate_key(
        &checkpoint.authority_public_key,
        "registry checkpoint authority key",
    )?;
    hex_decode::<64>(
        &checkpoint.signature,
        "registry history checkpoint signature",
    )?;
    Ok(())
}

pub fn validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state(
    state: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState,
) -> Result<(), String> {
    if state.schema_version != 1
        || state.accepted_at_unix < state.issued_at_unix
        || state.accepted_generation != state.signed_checkpoint.generation
        || state.registry_id != state.signed_checkpoint.registry_id
        || state.history_audit_sha256 != state.signed_checkpoint.history_audit_sha256
        || state.final_registry_sha256 != state.signed_checkpoint.final_registry_sha256
        || state.last_transition_sha256 != state.signed_checkpoint.last_transition_sha256
        || state.active_governance_sha256 != state.signed_checkpoint.active_governance_sha256
        || state.authority_public_key != state.signed_checkpoint.authority_public_key
        || state.issued_at_unix != state.signed_checkpoint.issued_at_unix
    {
        return Err("invalid gossip registry history checkpoint trust-state invariants".into());
    }
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
        &state.signed_checkpoint,
    )?;
    validate_digest(
        &state.checkpoint_sha256,
        "trusted history checkpoint SHA-256",
    )?;
    if state.checkpoint_sha256
        != signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_sha256(
            &state.signed_checkpoint,
        )?
    {
        return Err("gossip registry history trust state checkpoint digest is inconsistent".into());
    }
    Ok(())
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
    witness: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitness,
) -> Result<(), String> {
    if witness.schema_version != 1 || witness.algorithm != "ed25519" {
        return Err("invalid gossip registry history checkpoint witness invariants".into());
    }
    validate_slug(&witness.registry_id, "gossip registry id")?;
    validate_slug(&witness.witness_id, "gossip registry history witness id")?;
    validate_digest(
        &witness.checkpoint_sha256,
        "witnessed history checkpoint SHA-256",
    )?;
    validate_key(
        &witness.public_key,
        "gossip registry history witness public key",
    )?;
    hex_decode::<64>(
        &witness.signature,
        "gossip registry history witness signature",
    )?;
    Ok(())
}

pub fn validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
    state: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err("unsupported registry history witness trust state".into());
    }
    validate_slug(&state.witness_id, "registry history witness id")?;
    let key = hex_decode::<32>(
        &state.current_public_key,
        "current registry history witness public key",
    )?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid current registry history witness key: {error}"))?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) => Ok(()),
        (0, _, _) => Err("initial registry history witness trust state references rotation".into()),
        (_, Some(digest), Some(_)) => {
            validate_digest(digest, "registry history witness rotation digest")
        }
        _ => Err("rotated registry history witness trust state is incomplete".into()),
    }
}

pub fn validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
    rotation: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.to_generation != rotation.from_generation.saturating_add(1)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid registry history witness key rotation invariants".into());
    }
    validate_slug(&rotation.witness_id, "registry history witness id")?;
    if let Some(digest) = &rotation.previous_rotation_sha256 {
        validate_digest(digest, "previous registry history witness rotation digest")?;
    }
    validate_key(
        &rotation.old_public_key,
        "old registry history witness public key",
    )?;
    validate_key(
        &rotation.new_public_key,
        "new registry history witness public key",
    )?;
    hex_decode::<64>(
        &rotation.old_signature,
        "old registry history witness rotation signature",
    )?;
    hex_decode::<64>(
        &rotation.new_signature,
        "new registry history witness rotation signature",
    )?;
    Ok(())
}

pub fn validate_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_quorum_report(
    report: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointWitnessQuorumReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || !(2..=MAXIMUM_WITNESSES as u32).contains(&report.minimum_witnesses)
        || report.members.len() > MAXIMUM_WITNESSES
        || report.valid_witnesses != report.members.len() as u32
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
    {
        return Err("invalid gossip registry history witness quorum invariants".into());
    }
    validate_slug(&report.registry_id, "gossip registry id")?;
    validate_digest(&report.checkpoint_sha256, "history checkpoint SHA-256")?;
    validate_digest(&report.history_audit_sha256, "history audit SHA-256")?;
    let mut previous = None;
    let mut keys = BTreeSet::new();
    for member in &report.members {
        validate_slug(&member.witness_id, "history witness id")?;
        validate_key(&member.public_key, "history witness public key")?;
        validate_digest(&member.witness_sha256, "history witness SHA-256")?;
        if previous.is_some_and(|id: &String| id >= &member.witness_id)
            || !keys.insert(member.public_key.as_str())
        {
            return Err("history witness quorum members must be ordered and distinct".into());
        }
        previous = Some(&member.witness_id);
    }
    Ok(())
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-v1.json",
        "title": "Root-signed complete gossip registry history checkpoint",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "history_audit_sha256",
            "final_registry_sha256", "last_transition_sha256",
            "active_governance_sha256", "authority_public_key", "issued_at_unix",
            "algorithm", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "history_audit_sha256": digest_schema(),
            "final_registry_sha256": digest_schema(),
            "last_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "active_governance_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "authority_public_key": key_schema(),
            "issued_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "signature": signature_schema()
        }
    })
}

pub fn policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-organization-registry-history-checkpoint-trust-state-v1.json",
        "title": "Monotonic gossip registry history checkpoint trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "accepted_generation",
            "checkpoint_sha256", "history_audit_sha256", "final_registry_sha256",
            "last_transition_sha256", "active_governance_sha256",
            "authority_public_key", "issued_at_unix", "accepted_at_unix",
            "signed_checkpoint"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "accepted_generation": {"type": "integer", "minimum": 0},
            "checkpoint_sha256": digest_schema(),
            "history_audit_sha256": digest_schema(),
            "final_registry_sha256": digest_schema(),
            "last_transition_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "active_governance_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "authority_public_key": key_schema(),
            "issued_at_unix": {"type": "integer", "minimum": 0},
            "accepted_at_unix": {"type": "integer", "minimum": 0},
            "signed_checkpoint": embedded_schema(
                signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_json_schema()
            )
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-v1.json",
        "title": "Independent complete gossip registry history checkpoint witness",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "checkpoint_sha256",
            "witness_id", "witnessed_at_unix", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "checkpoint_sha256": digest_schema(),
            "witness_id": slug_schema(),
            "witnessed_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "public_key": key_schema(),
            "signature": signature_schema()
        }
    })
}

pub fn policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-trust-state-v1.json",
        "title": "Rotatable registry history checkpoint witness trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "generation", "current_public_key",
            "last_rotation_sha256", "last_rotated_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "current_public_key": key_schema(),
            "last_rotation_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "last_rotated_at_unix": {
                "oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]
            }
        }
    })
}

pub fn signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-key-rotation-v1.json",
        "title": "Dual-signed registry history checkpoint witness key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "from_generation", "to_generation",
            "previous_rotation_sha256", "old_public_key", "new_public_key",
            "rotated_at_unix", "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "from_generation": {"type": "integer", "minimum": 0},
            "to_generation": {"type": "integer", "minimum": 1},
            "previous_rotation_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_public_key": key_schema(),
            "new_public_key": key_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_signature": signature_schema(),
            "new_signature": signature_schema()
        }
    })
}

pub fn policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_quorum_report_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-organization-registry-history-checkpoint-witness-quorum-v1.json",
        "title": "Independent complete gossip registry history checkpoint witness quorum",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "registry_id", "generation", "checkpoint_sha256",
            "history_audit_sha256", "evaluated_at_unix", "minimum_witnesses",
            "valid_witnesses", "members", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "checkpoint_sha256": digest_schema(),
            "history_audit_sha256": digest_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": MAXIMUM_WITNESSES},
            "valid_witnesses": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_WITNESSES},
            "members": {
                "type": "array", "maxItems": MAXIMUM_WITNESSES,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["witness_id", "public_key", "witness_sha256"],
                    "properties": {
                        "witness_id": slug_schema(),
                        "public_key": key_schema(),
                        "witness_sha256": digest_schema()
                    }
                }
            },
            "quorum_met": {"type": "boolean"}
        }
    })
}

fn verify_checkpoint_for_audit(
    audit: &PolicyLifecycleLogGossipOrganizationRegistryHistoryAuditReport,
    checkpoint: &SignedPolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpoint,
) -> Result<(), String> {
    validate_policy_lifecycle_log_gossip_organization_registry_history_audit_report(audit)?;
    validate_signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
        checkpoint,
    )?;
    let history_audit_sha256 =
        policy_lifecycle_log_gossip_organization_registry_history_audit_report_sha256(audit)?;
    if checkpoint.registry_id != audit.registry_id
        || checkpoint.generation != audit.final_registry.generation
        || checkpoint.history_audit_sha256 != history_audit_sha256
        || checkpoint.final_registry_sha256 != audit.final_registry_sha256
        || checkpoint.last_transition_sha256 != audit.final_registry.last_transition_sha256
        || checkpoint.active_governance_sha256 != audit.final_registry.active_governance_sha256
        || checkpoint.authority_public_key != audit.final_registry.authority_public_key
        || audit
            .final_registry
            .last_updated_at_unix
            .is_some_and(|last| checkpoint.issued_at_unix < last)
    {
        return Err(
            "gossip registry history checkpoint does not bind the verified audit head".into(),
        );
    }
    let payload = checkpoint_payload(
        audit,
        &history_audit_sha256,
        &checkpoint.authority_public_key,
        checkpoint.issued_at_unix,
    )?;
    let key = hex_decode::<32>(
        &checkpoint.authority_public_key,
        "gossip registry history checkpoint authority key",
    )?;
    let signature = Signature::from_bytes(&hex_decode::<64>(
        &checkpoint.signature,
        "gossip registry history checkpoint signature",
    )?);
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid gossip registry checkpoint authority key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "gossip registry history checkpoint signature verification failed".to_string())
}

fn verify_audit_extends_trust_state(
    audit: &PolicyLifecycleLogGossipOrganizationRegistryHistoryAuditReport,
    baseline: &PolicyLifecycleLogGossipOrganizationRegistryHistoryCheckpointTrustState,
) -> Result<(), String> {
    let matches = if baseline.accepted_generation == 0 {
        audit.initial_registry_sha256 == baseline.final_registry_sha256
            && baseline.last_transition_sha256.is_none()
    } else {
        let index = usize::try_from(baseline.accepted_generation - 1)
            .map_err(|_| "trusted history checkpoint generation overflow".to_string())?;
        audit.entries.get(index).is_some_and(|entry| {
            entry.to_generation == baseline.accepted_generation
                && entry.resulting_registry_sha256 == baseline.final_registry_sha256
                && entry.event_sha256 == baseline.last_transition_sha256.clone().unwrap_or_default()
                && entry.authority_public_key == baseline.authority_public_key
                && entry.active_governance_sha256 == baseline.active_governance_sha256
        })
    };
    if !matches {
        return Err("gossip registry history checkpoint does not extend retained trust".into());
    }
    Ok(())
}

fn checkpoint_payload(
    audit: &PolicyLifecycleLogGossipOrganizationRegistryHistoryAuditReport,
    history_audit_sha256: &str,
    authority_public_key: &str,
    issued_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&CheckpointPayload {
        domain: CHECKPOINT_DOMAIN,
        registry_id: &audit.registry_id,
        generation: audit.final_registry.generation,
        history_audit_sha256,
        final_registry_sha256: &audit.final_registry_sha256,
        last_transition_sha256: audit.final_registry.last_transition_sha256.as_deref(),
        active_governance_sha256: audit.final_registry.active_governance_sha256.as_deref(),
        authority_public_key,
        issued_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry history checkpoint: {error}"))
}

fn witness_payload(
    registry_id: &str,
    generation: u64,
    checkpoint_sha256: &str,
    witness_id: &str,
    witnessed_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WitnessPayload {
        domain: WITNESS_DOMAIN,
        registry_id,
        generation,
        checkpoint_sha256,
        witness_id,
        witnessed_at_unix,
    })
    .map_err(|error| format!("serializing gossip registry history witness: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn witness_key_rotation_payload(
    witness_id: &str,
    from_generation: u64,
    to_generation: u64,
    previous_rotation_sha256: Option<&str>,
    old_public_key: &str,
    new_public_key: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WitnessKeyRotationPayload {
        domain: WITNESS_KEY_ROTATION_DOMAIN,
        witness_id,
        from_generation,
        to_generation,
        previous_rotation_sha256,
        old_public_key,
        new_public_key,
        rotated_at_unix,
    })
    .map_err(|error| format!("serializing registry history witness key rotation: {error}"))
}

fn trusted_witness_map(
    witnesses: &[(String, [u8; 32])],
) -> Result<BTreeMap<String, [u8; 32]>, String> {
    let mut map = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for (id, key) in witnesses {
        validate_slug(id, "trusted gossip registry history witness id")?;
        VerifyingKey::from_bytes(key)
            .map_err(|error| format!("invalid trusted history witness key: {error}"))?;
        if map.insert(id.clone(), *key).is_some() || !keys.insert(*key) {
            return Err("trusted history witnesses require distinct identities and keys".into());
        }
    }
    Ok(map)
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("invalid {label}"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    hex_decode::<32>(value, label).map(|_| ())
}

fn validate_key(value: &str, label: &str) -> Result<(), String> {
    let key = hex_decode::<32>(value, label)?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid {label}: {error}"))
        .map(|_| ())
}

fn hex_decode<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid {label}"));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("invalid {label}"))?;
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn slug_schema() -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9._-]+$"})
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn key_schema() -> Value {
    digest_schema()
}

fn signature_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{128}$"})
}

fn embedded_schema(mut schema: Value) -> Value {
    if let Some(object) = schema.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
        object.remove("title");
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_lifecycle_gossip_registry::{
        PolicyLifecycleLogGossipOrganizationRegistryAction,
        PolicyLifecycleLogGossipOrganizationRegistryHistory,
        PolicyLifecycleLogGossipOrganizationRegistryHistoryEvent,
        new_policy_lifecycle_log_gossip_organization_registry,
        sign_policy_lifecycle_log_gossip_organization_registry_transition,
    };
    use crate::policy_lifecycle_gossip_trust::new_policy_lifecycle_log_gossip_observer_trust_state;

    fn history(root: [u8; 32], marker: u8) -> PolicyLifecycleLogGossipOrganizationRegistryHistory {
        let initial = new_policy_lifecycle_log_gossip_organization_registry(
            "production-gossip",
            &SigningKey::from_bytes(&root).verifying_key().to_bytes(),
        )
        .unwrap();
        let trust = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&[marker; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let transition = sign_policy_lifecycle_log_gossip_organization_registry_transition(
            &initial,
            &root,
            PolicyLifecycleLogGossipOrganizationRegistryAction::AdmitObserver,
            "independent-lab",
            Some(&trust),
            &format!("{marker:02x}").repeat(32),
            1_000,
        )
        .unwrap();
        PolicyLifecycleLogGossipOrganizationRegistryHistory {
            schema_version: 1,
            initial_registry: initial,
            events: vec![
                PolicyLifecycleLogGossipOrganizationRegistryHistoryEvent::RootTransition {
                    transition,
                },
            ],
        }
    }

    #[test]
    fn checkpoint_trust_rejects_equivocation_and_accepts_witness_quorum() {
        let root = [121; 32];
        let registry_history = history(root, 122);
        let checkpoint = sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
            &registry_history,
            &root,
            1_100,
        )
        .unwrap();
        let trusted = accept_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
            &registry_history,
            &checkpoint,
            None,
            1_200,
        )
        .unwrap();
        assert_eq!(trusted.accepted_generation, 1);

        let alternate_history = history(root, 123);
        let alternate_checkpoint =
            sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
                &alternate_history,
                &root,
                1_100,
            )
            .unwrap();
        assert!(
            accept_policy_lifecycle_log_gossip_organization_registry_history_checkpoint(
                &alternate_history,
                &alternate_checkpoint,
                Some(&trusted),
                1_200,
            )
            .unwrap_err()
            .contains("equivocated")
        );

        let witness_a = [124; 32];
        let witness_b = [125; 32];
        let signed_a =
            sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
                &registry_history,
                &checkpoint,
                "witness-a",
                &witness_a,
                1_300,
            )
            .unwrap();
        let signed_b =
            sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness(
                &registry_history,
                &checkpoint,
                "witness-b",
                &witness_b,
                1_300,
            )
            .unwrap();
        let quorum =
            verify_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witnesses(
                &registry_history,
                &checkpoint,
                &[signed_b, signed_a],
                &[
                    (
                        "witness-a".into(),
                        SigningKey::from_bytes(&witness_a)
                            .verifying_key()
                            .to_bytes(),
                    ),
                    (
                        "witness-b".into(),
                        SigningKey::from_bytes(&witness_b)
                            .verifying_key()
                            .to_bytes(),
                    ),
                ],
                2,
                1_400,
            )
            .unwrap();
        assert!(quorum.quorum_met);
        assert_eq!(quorum.members[0].witness_id, "witness-a");
    }

    #[test]
    fn checkpoint_schemas_are_closed() {
        for schema in [
            signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_json_schema(),
            policy_lifecycle_log_gossip_organization_registry_history_checkpoint_trust_state_json_schema(),
            signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_json_schema(),
            policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state_json_schema(),
            signed_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation_json_schema(),
            policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_quorum_report_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
        }
    }

    #[test]
    fn rotates_registry_history_witness_trust_with_dual_signatures() {
        let old = [131; 32];
        let next = [132; 32];
        let final_key = [133; 32];
        let initial =
            new_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
                "witness-a",
                &SigningKey::from_bytes(&old).verifying_key().to_bytes(),
            )
            .unwrap();
        let first =
            sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                &initial, &old, &next, 1_000,
            )
            .unwrap();
        let rotated =
            apply_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                &initial, &first,
            )
            .unwrap();
        assert_eq!(rotated.generation, 1);
        assert!(
            apply_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                &rotated, &first,
            )
            .is_err()
        );
        let second =
            sign_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                &rotated, &next, &final_key, 1_100,
            )
            .unwrap();
        assert_eq!(
            apply_policy_lifecycle_log_gossip_organization_registry_history_checkpoint_witness_key_rotation(
                &rotated, &second,
            )
            .unwrap()
            .generation,
            2
        );
    }
}
