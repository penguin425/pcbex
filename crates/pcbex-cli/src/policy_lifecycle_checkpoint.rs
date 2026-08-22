use crate::policy_lifecycle::{PolicyLifecycleLedger, validate_policy_lifecycle_ledger};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SIGNED_POLICY_LIFECYCLE_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const POLICY_LIFECYCLE_TRUST_STATE_SCHEMA_VERSION: u32 = 1;
pub const POLICY_LIFECYCLE_WITNESS_TRUST_STATE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-lifecycle-checkpoint-v1";
const KEY_ROTATION_DOMAIN: &str = "pcbex-policy-lifecycle-checkpoint-key-rotation-v1";
const WITNESS_DOMAIN: &str = "pcbex-policy-lifecycle-checkpoint-witness-v1";
const WITNESS_KEY_ROTATION_DOMAIN: &str =
    "pcbex-policy-lifecycle-checkpoint-witness-key-rotation-v1";
const MAXIMUM_ACCEPTANCE_DELAY_SECONDS: u64 = 86_400;
const MAXIMUM_WITNESS_AGE_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleCheckpoint {
    pub schema_version: u32,
    pub policy_pack_id: String,
    pub generation: u64,
    pub entry_count: u64,
    pub ledger_sha256: String,
    pub head_sha256: String,
    pub issued_at_unix: u64,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleTrustState {
    pub schema_version: u32,
    pub status: String,
    pub policy_pack_id: String,
    pub accepted_generation: u64,
    pub accepted_entry_count: u64,
    pub ledger_sha256: String,
    pub head_sha256: String,
    pub checkpoint_sha256: String,
    pub signer_id: String,
    pub public_key: String,
    pub issued_at_unix: u64,
    pub accepted_at_unix: u64,
    #[serde(default)]
    pub key_generation: u64,
    #[serde(default)]
    pub last_key_rotation_sha256: Option<String>,
    #[serde(default)]
    pub last_key_rotated_at_unix: Option<u64>,
    pub signed_checkpoint: SignedPolicyLifecycleCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleKeyRotation {
    pub schema_version: u32,
    pub policy_pack_id: String,
    pub signer_id: String,
    pub baseline_checkpoint_sha256: String,
    pub from_key_generation: u64,
    pub to_key_generation: u64,
    pub previous_key_rotation_sha256: Option<String>,
    pub old_public_key: String,
    pub new_public_key: String,
    pub rotated_at_unix: u64,
    pub algorithm: String,
    pub old_signature: String,
    pub new_signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleCheckpointWitness {
    pub schema_version: u32,
    pub checkpoint_sha256: String,
    pub policy_pack_id: String,
    pub generation: u64,
    pub head_sha256: String,
    pub witness_id: String,
    pub observed_at_unix: u64,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleWitnessTrustState {
    pub schema_version: u32,
    pub witness_id: String,
    pub generation: u64,
    pub current_public_key: String,
    pub last_rotation_sha256: Option<String>,
    pub last_rotated_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleWitnessKeyRotation {
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
pub struct PolicyLifecycleWitnessQuorumReport {
    pub schema_version: u32,
    pub status: String,
    pub checkpoint_sha256: String,
    pub policy_pack_id: String,
    pub generation: u64,
    pub head_sha256: String,
    pub evaluated_at_unix: u64,
    pub minimum_witnesses: u32,
    pub valid_witnesses: u32,
    pub witness_ids: Vec<String>,
    pub witness_public_keys: Vec<String>,
    pub quorum_met: bool,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    policy_pack_id: &'a str,
    generation: u64,
    entry_count: u64,
    ledger_sha256: &'a str,
    head_sha256: &'a str,
    issued_at_unix: u64,
    signer_id: &'a str,
}

#[derive(Serialize)]
struct KeyRotationPayload<'a> {
    domain: &'static str,
    policy_pack_id: &'a str,
    signer_id: &'a str,
    baseline_checkpoint_sha256: &'a str,
    from_key_generation: u64,
    to_key_generation: u64,
    previous_key_rotation_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    rotated_at_unix: u64,
}

#[derive(Serialize)]
struct WitnessPayload<'a> {
    domain: &'static str,
    checkpoint_sha256: &'a str,
    policy_pack_id: &'a str,
    generation: u64,
    head_sha256: &'a str,
    witness_id: &'a str,
    observed_at_unix: u64,
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

pub fn new_policy_lifecycle_witness_trust_state(
    witness_id: &str,
    public_key: &[u8; 32],
) -> Result<PolicyLifecycleWitnessTrustState, String> {
    validate_slug(witness_id)?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("invalid policy lifecycle witness public key: {error}"))?;
    Ok(PolicyLifecycleWitnessTrustState {
        schema_version: POLICY_LIFECYCLE_WITNESS_TRUST_STATE_SCHEMA_VERSION,
        witness_id: witness_id.into(),
        generation: 0,
        current_public_key: hex_encode(public_key),
        last_rotation_sha256: None,
        last_rotated_at_unix: None,
    })
}

pub fn policy_lifecycle_witness_trusted_public_key(
    state: &PolicyLifecycleWitnessTrustState,
) -> Result<[u8; 32], String> {
    validate_policy_lifecycle_witness_trust_state(state)?;
    decode_hex_array::<32>(
        &state.current_public_key,
        "current policy lifecycle witness public key",
    )
}

pub fn policy_lifecycle_witness_trust_state_sha256(
    state: &PolicyLifecycleWitnessTrustState,
) -> Result<String, String> {
    validate_policy_lifecycle_witness_trust_state(state)?;
    normalized_sha256(state, "policy lifecycle witness trust state")
}

pub fn sign_policy_lifecycle_witness_key_rotation(
    state: &PolicyLifecycleWitnessTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedPolicyLifecycleWitnessKeyRotation, String> {
    validate_policy_lifecycle_witness_trust_state(state)?;
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != state.current_public_key {
        return Err(
            "old policy lifecycle witness key does not match the current trust state".into(),
        );
    }
    if new_public_key == old_public_key {
        return Err("new policy lifecycle witness key must differ from the current key".into());
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err("policy lifecycle witness key rotation timestamps must be monotonic".into());
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "policy lifecycle witness key generation overflow".to_string())?;
    let payload = witness_key_rotation_payload(
        &state.witness_id,
        state.generation,
        to_generation,
        state.last_rotation_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    Ok(SignedPolicyLifecycleWitnessKeyRotation {
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
    })
}

pub fn apply_policy_lifecycle_witness_key_rotation(
    state: &PolicyLifecycleWitnessTrustState,
    rotation: &SignedPolicyLifecycleWitnessKeyRotation,
) -> Result<PolicyLifecycleWitnessTrustState, String> {
    validate_policy_lifecycle_witness_trust_state(state)?;
    validate_signed_policy_lifecycle_witness_key_rotation(rotation)?;
    if rotation.witness_id != state.witness_id
        || rotation.from_generation != state.generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
    {
        return Err(
            "policy lifecycle witness key rotation does not extend the current trust state".into(),
        );
    }
    let expected_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "policy lifecycle witness key generation overflow".to_string())?;
    if rotation.to_generation != expected_generation {
        return Err(
            "policy lifecycle witness key rotation must advance exactly one generation".into(),
        );
    }
    if rotation.new_public_key == rotation.old_public_key {
        return Err("new policy lifecycle witness key must differ from the current key".into());
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err("policy lifecycle witness key rotation timestamps must be monotonic".into());
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
            "old policy lifecycle witness key rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new policy lifecycle witness key rotation",
        ),
    ] {
        let key = decode_hex_array::<32>(key, label)?;
        let signature = Signature::from_bytes(&decode_hex_array::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let rotation_sha256 = signed_policy_lifecycle_witness_key_rotation_sha256(rotation)?;
    let next = PolicyLifecycleWitnessTrustState {
        schema_version: POLICY_LIFECYCLE_WITNESS_TRUST_STATE_SCHEMA_VERSION,
        witness_id: state.witness_id.clone(),
        generation: rotation.to_generation,
        current_public_key: rotation.new_public_key.clone(),
        last_rotation_sha256: Some(rotation_sha256),
        last_rotated_at_unix: Some(rotation.rotated_at_unix),
    };
    validate_policy_lifecycle_witness_trust_state(&next)?;
    Ok(next)
}

pub fn signed_policy_lifecycle_witness_key_rotation_sha256(
    rotation: &SignedPolicyLifecycleWitnessKeyRotation,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_witness_key_rotation(rotation)?;
    normalized_sha256(rotation, "policy lifecycle witness key rotation")
}

pub fn sign_policy_lifecycle_checkpoint_witness(
    state: &PolicyLifecycleTrustState,
    witness_id: &str,
    observed_at_unix: u64,
    secret_key: &[u8; 32],
) -> Result<SignedPolicyLifecycleCheckpointWitness, String> {
    validate_policy_lifecycle_trust_state(state)?;
    validate_slug(witness_id)?;
    if observed_at_unix < state.issued_at_unix {
        return Err("policy lifecycle witness predates the signed checkpoint".into());
    }
    let signing_key = SigningKey::from_bytes(secret_key);
    let payload = witness_payload(
        &state.checkpoint_sha256,
        &state.policy_pack_id,
        state.accepted_generation,
        &state.head_sha256,
        witness_id,
        observed_at_unix,
    )?;
    let witness = SignedPolicyLifecycleCheckpointWitness {
        schema_version: 1,
        checkpoint_sha256: state.checkpoint_sha256.clone(),
        policy_pack_id: state.policy_pack_id.clone(),
        generation: state.accepted_generation,
        head_sha256: state.head_sha256.clone(),
        witness_id: witness_id.into(),
        observed_at_unix,
        algorithm: "ed25519".into(),
        public_key: hex_encode(&signing_key.verifying_key().to_bytes()),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_checkpoint_witness(&witness)?;
    Ok(witness)
}

pub fn verify_policy_lifecycle_checkpoint_witnesses(
    state: &PolicyLifecycleTrustState,
    witnesses: &[SignedPolicyLifecycleCheckpointWitness],
    trusted_public_keys: &[[u8; 32]],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleWitnessQuorumReport, String> {
    validate_policy_lifecycle_trust_state(state)?;
    if !(2..=100).contains(&minimum_witnesses) {
        return Err("policy lifecycle witness quorum must require 2 to 100 witnesses".into());
    }
    if witnesses.len() != trusted_public_keys.len() || witnesses.len() > 100 {
        return Err(
            "policy lifecycle witnesses and trusted keys must be paired and bounded".into(),
        );
    }
    if evaluated_at_unix < state.issued_at_unix {
        return Err("policy lifecycle witness evaluation predates the checkpoint".into());
    }
    let mut witness_ids = BTreeSet::new();
    let mut witness_public_keys = BTreeSet::new();
    for (witness, trusted_key) in witnesses.iter().zip(trusted_public_keys) {
        verify_policy_lifecycle_checkpoint_witness(state, witness, trusted_key, evaluated_at_unix)?;
        let trusted_key_hex = hex_encode(trusted_key);
        if !witness_ids.insert(witness.witness_id.clone())
            || !witness_public_keys.insert(trusted_key_hex)
        {
            return Err("policy lifecycle witnesses must use distinct identities and keys".into());
        }
    }
    let valid_witnesses = u32::try_from(witnesses.len())
        .map_err(|_| "policy lifecycle witness count overflow".to_string())?;
    let quorum_met = valid_witnesses >= minimum_witnesses;
    Ok(PolicyLifecycleWitnessQuorumReport {
        schema_version: 1,
        status: if quorum_met {
            "witness_quorum_met"
        } else {
            "insufficient_witnesses"
        }
        .into(),
        checkpoint_sha256: state.checkpoint_sha256.clone(),
        policy_pack_id: state.policy_pack_id.clone(),
        generation: state.accepted_generation,
        head_sha256: state.head_sha256.clone(),
        evaluated_at_unix,
        minimum_witnesses,
        valid_witnesses,
        witness_ids: witness_ids.into_iter().collect(),
        witness_public_keys: witness_public_keys.into_iter().collect(),
        quorum_met,
    })
}

pub fn verify_policy_lifecycle_checkpoint_witness(
    state: &PolicyLifecycleTrustState,
    witness: &SignedPolicyLifecycleCheckpointWitness,
    trusted_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<(), String> {
    validate_policy_lifecycle_trust_state(state)?;
    validate_signed_policy_lifecycle_checkpoint_witness(witness)?;
    if evaluated_at_unix < state.issued_at_unix {
        return Err("policy lifecycle witness evaluation predates the checkpoint".into());
    }
    if witness.checkpoint_sha256 != state.checkpoint_sha256
        || witness.policy_pack_id != state.policy_pack_id
        || witness.generation != state.accepted_generation
        || witness.head_sha256 != state.head_sha256
    {
        return Err("policy lifecycle witness is bound to a different checkpoint".into());
    }
    if witness.public_key != hex_encode(trusted_public_key) {
        return Err("policy lifecycle witness public key is not trusted".into());
    }
    if witness.observed_at_unix < state.issued_at_unix
        || evaluated_at_unix < witness.observed_at_unix
        || evaluated_at_unix - witness.observed_at_unix > MAXIMUM_WITNESS_AGE_SECONDS
    {
        return Err("policy lifecycle witness is outside the 24-hour evaluation window".into());
    }
    let payload = witness_payload(
        &witness.checkpoint_sha256,
        &witness.policy_pack_id,
        witness.generation,
        &witness.head_sha256,
        &witness.witness_id,
        witness.observed_at_unix,
    )?;
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &witness.signature,
        "policy lifecycle witness signature",
    )?);
    VerifyingKey::from_bytes(trusted_public_key)
        .map_err(|error| format!("invalid policy lifecycle witness key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|_| "policy lifecycle witness signature verification failed".to_string())
}

pub fn verify_policy_lifecycle_checkpoint_witness_with_trust_state(
    state: &PolicyLifecycleTrustState,
    witness: &SignedPolicyLifecycleCheckpointWitness,
    witness_trust_state: &PolicyLifecycleWitnessTrustState,
    evaluated_at_unix: u64,
) -> Result<(), String> {
    validate_policy_lifecycle_witness_trust_state(witness_trust_state)?;
    if witness.witness_id != witness_trust_state.witness_id {
        return Err(
            "policy lifecycle witness identity does not match its retained trust state".into(),
        );
    }
    let trusted_key = policy_lifecycle_witness_trusted_public_key(witness_trust_state)?;
    verify_policy_lifecycle_checkpoint_witness(state, witness, &trusted_key, evaluated_at_unix)
}

pub fn verify_policy_lifecycle_checkpoint_witnesses_with_trust_states(
    state: &PolicyLifecycleTrustState,
    witnesses: &[SignedPolicyLifecycleCheckpointWitness],
    witness_trust_states: &[PolicyLifecycleWitnessTrustState],
    minimum_witnesses: u32,
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleWitnessQuorumReport, String> {
    if witnesses.len() != witness_trust_states.len() || witnesses.len() > 100 {
        return Err(
            "policy lifecycle witnesses and witness trust states must be paired and bounded".into(),
        );
    }
    for (witness, trust_state) in witnesses.iter().zip(witness_trust_states) {
        validate_policy_lifecycle_witness_trust_state(trust_state)?;
        if witness.witness_id != trust_state.witness_id {
            return Err(
                "policy lifecycle witness identity does not match its retained trust state".into(),
            );
        }
    }
    let trusted_keys = witness_trust_states
        .iter()
        .map(policy_lifecycle_witness_trusted_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    verify_policy_lifecycle_checkpoint_witnesses(
        state,
        witnesses,
        &trusted_keys,
        minimum_witnesses,
        evaluated_at_unix,
    )
}

pub fn sign_policy_lifecycle_key_rotation(
    baseline: &PolicyLifecycleTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedPolicyLifecycleKeyRotation, String> {
    validate_policy_lifecycle_trust_state(baseline)?;
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != baseline.public_key {
        return Err("old lifecycle signing key does not match the trusted checkpoint".into());
    }
    if new_public_key == old_public_key {
        return Err("new lifecycle signing key must differ from the current key".into());
    }
    if rotated_at_unix < baseline.accepted_at_unix
        || baseline
            .last_key_rotated_at_unix
            .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err("lifecycle signing key rotation time moved backwards".into());
    }
    let to_key_generation = baseline
        .key_generation
        .checked_add(1)
        .ok_or_else(|| "lifecycle signing key generation overflow".to_string())?;
    let payload = key_rotation_payload(
        &baseline.policy_pack_id,
        &baseline.signer_id,
        &baseline.checkpoint_sha256,
        baseline.key_generation,
        to_key_generation,
        baseline.last_key_rotation_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    Ok(SignedPolicyLifecycleKeyRotation {
        schema_version: 1,
        policy_pack_id: baseline.policy_pack_id.clone(),
        signer_id: baseline.signer_id.clone(),
        baseline_checkpoint_sha256: baseline.checkpoint_sha256.clone(),
        from_key_generation: baseline.key_generation,
        to_key_generation,
        previous_key_rotation_sha256: baseline.last_key_rotation_sha256.clone(),
        old_public_key,
        new_public_key,
        rotated_at_unix,
        algorithm: "ed25519".into(),
        old_signature: hex_encode(&old_key.sign(&payload).to_bytes()),
        new_signature: hex_encode(&new_key.sign(&payload).to_bytes()),
    })
}

pub fn sign_policy_lifecycle_checkpoint(
    ledger: &PolicyLifecycleLedger,
    issued_at_unix: u64,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedPolicyLifecycleCheckpoint, String> {
    validate_policy_lifecycle_ledger(ledger)?;
    validate_slug(signer_id)?;
    let ledger_sha256 = normalized_sha256(ledger, "policy lifecycle ledger")?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = signature_payload(
        &ledger.policy_pack_id,
        ledger.generation,
        ledger.entry_count,
        &ledger_sha256,
        &ledger.head_sha256,
        issued_at_unix,
        signer_id,
    )?;
    let checkpoint = SignedPolicyLifecycleCheckpoint {
        schema_version: SIGNED_POLICY_LIFECYCLE_CHECKPOINT_SCHEMA_VERSION,
        policy_pack_id: ledger.policy_pack_id.clone(),
        generation: ledger.generation,
        entry_count: ledger.entry_count,
        ledger_sha256,
        head_sha256: ledger.head_sha256.clone(),
        issued_at_unix,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_lifecycle_checkpoint(&checkpoint)?;
    Ok(checkpoint)
}

pub fn verify_policy_lifecycle_checkpoint(
    ledger: &PolicyLifecycleLedger,
    checkpoint: &SignedPolicyLifecycleCheckpoint,
    trusted_public_key: &[u8; 32],
    baseline: Option<&PolicyLifecycleTrustState>,
    key_rotation: Option<&SignedPolicyLifecycleKeyRotation>,
    accepted_at_unix: u64,
) -> Result<PolicyLifecycleTrustState, String> {
    validate_policy_lifecycle_ledger(ledger)?;
    verify_checkpoint_for_ledger(ledger, checkpoint, trusted_public_key)?;
    let checkpoint_sha256 = normalized_sha256(checkpoint, "policy lifecycle checkpoint")?;
    if let Some(baseline) = baseline {
        validate_policy_lifecycle_trust_state(baseline)?;
        if baseline.policy_pack_id != checkpoint.policy_pack_id
            || baseline.signer_id != checkpoint.signer_id
        {
            return Err("policy lifecycle checkpoint trust identity changed".into());
        }
        if checkpoint.generation < baseline.accepted_generation {
            return Err("policy lifecycle checkpoint rollback is forbidden".into());
        }
        if checkpoint.generation == baseline.accepted_generation {
            if checkpoint_sha256 == baseline.checkpoint_sha256
                && checkpoint.ledger_sha256 == baseline.ledger_sha256
                && checkpoint.head_sha256 == baseline.head_sha256
            {
                return Ok(baseline.clone());
            }
            return Err("policy lifecycle checkpoint generation equivocated".into());
        }
        validate_acceptance_time(checkpoint.issued_at_unix, accepted_at_unix)?;
        if checkpoint.issued_at_unix < baseline.issued_at_unix
            || accepted_at_unix < baseline.accepted_at_unix
        {
            return Err("policy lifecycle checkpoint time moved backwards".into());
        }
        let retained_head = ledger
            .entries
            .get(baseline.accepted_generation as usize - 1)
            .map(|entry| entry.entry_sha256.as_str());
        if retained_head != Some(baseline.head_sha256.as_str()) {
            return Err("policy lifecycle checkpoint does not extend the trusted history".into());
        }
        if baseline.public_key == checkpoint.public_key {
            if key_rotation.is_some() {
                return Err("policy lifecycle key rotation did not change the signing key".into());
            }
        } else {
            let rotation = key_rotation.ok_or_else(|| {
                "policy lifecycle signing key changed without rotation".to_string()
            })?;
            verify_policy_lifecycle_key_rotation(baseline, checkpoint, rotation)?;
        }
    } else {
        if key_rotation.is_some() {
            return Err("initial lifecycle trust cannot apply a key rotation".into());
        }
        validate_acceptance_time(checkpoint.issued_at_unix, accepted_at_unix)?;
    }
    let (key_generation, last_key_rotation_sha256, last_key_rotated_at_unix) =
        match (baseline, key_rotation) {
            (Some(_), Some(rotation)) => (
                rotation.to_key_generation,
                Some(normalized_sha256(
                    rotation,
                    "policy lifecycle key rotation",
                )?),
                Some(rotation.rotated_at_unix),
            ),
            (Some(baseline), None) => (
                baseline.key_generation,
                baseline.last_key_rotation_sha256.clone(),
                baseline.last_key_rotated_at_unix,
            ),
            (None, None) => (0, None, None),
            (None, Some(_)) => unreachable!(),
        };
    let state = PolicyLifecycleTrustState {
        schema_version: POLICY_LIFECYCLE_TRUST_STATE_SCHEMA_VERSION,
        status: "checkpoint_accepted".into(),
        policy_pack_id: checkpoint.policy_pack_id.clone(),
        accepted_generation: checkpoint.generation,
        accepted_entry_count: checkpoint.entry_count,
        ledger_sha256: checkpoint.ledger_sha256.clone(),
        head_sha256: checkpoint.head_sha256.clone(),
        checkpoint_sha256,
        signer_id: checkpoint.signer_id.clone(),
        public_key: checkpoint.public_key.clone(),
        issued_at_unix: checkpoint.issued_at_unix,
        accepted_at_unix,
        key_generation,
        last_key_rotation_sha256,
        last_key_rotated_at_unix,
        signed_checkpoint: checkpoint.clone(),
    };
    validate_policy_lifecycle_trust_state(&state)?;
    Ok(state)
}

pub fn parse_signed_policy_lifecycle_key_rotation(
    source: &str,
) -> Result<SignedPolicyLifecycleKeyRotation, String> {
    let rotation = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed policy lifecycle key rotation JSON: {error}"))?;
    validate_signed_policy_lifecycle_key_rotation(&rotation)?;
    Ok(rotation)
}

pub fn parse_signed_policy_lifecycle_checkpoint_witness(
    source: &str,
) -> Result<SignedPolicyLifecycleCheckpointWitness, String> {
    let witness = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed policy lifecycle witness JSON: {error}"))?;
    validate_signed_policy_lifecycle_checkpoint_witness(&witness)?;
    Ok(witness)
}

pub fn parse_policy_lifecycle_witness_trust_state(
    source: &str,
) -> Result<PolicyLifecycleWitnessTrustState, String> {
    let state = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle witness trust-state JSON: {error}"))?;
    validate_policy_lifecycle_witness_trust_state(&state)?;
    Ok(state)
}

pub fn parse_signed_policy_lifecycle_witness_key_rotation(
    source: &str,
) -> Result<SignedPolicyLifecycleWitnessKeyRotation, String> {
    let rotation = serde_json::from_str(source).map_err(|error| {
        format!("invalid signed policy lifecycle witness key-rotation JSON: {error}")
    })?;
    validate_signed_policy_lifecycle_witness_key_rotation(&rotation)?;
    Ok(rotation)
}

pub fn parse_policy_lifecycle_witness_quorum_report(
    source: &str,
) -> Result<PolicyLifecycleWitnessQuorumReport, String> {
    let report = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle witness quorum JSON: {error}"))?;
    validate_policy_lifecycle_witness_quorum_report(&report)?;
    Ok(report)
}

fn verify_policy_lifecycle_key_rotation(
    baseline: &PolicyLifecycleTrustState,
    checkpoint: &SignedPolicyLifecycleCheckpoint,
    rotation: &SignedPolicyLifecycleKeyRotation,
) -> Result<(), String> {
    validate_signed_policy_lifecycle_key_rotation(rotation)?;
    if rotation.policy_pack_id != baseline.policy_pack_id
        || rotation.signer_id != baseline.signer_id
        || rotation.baseline_checkpoint_sha256 != baseline.checkpoint_sha256
        || rotation.from_key_generation != baseline.key_generation
        || rotation.previous_key_rotation_sha256 != baseline.last_key_rotation_sha256
        || rotation.old_public_key != baseline.public_key
        || rotation.new_public_key != checkpoint.public_key
        || rotation.to_key_generation
            != baseline
                .key_generation
                .checked_add(1)
                .ok_or_else(|| "lifecycle signing key generation overflow".to_string())?
    {
        return Err("policy lifecycle key rotation does not extend trusted state".into());
    }
    if rotation.rotated_at_unix < baseline.accepted_at_unix
        || rotation.rotated_at_unix > checkpoint.issued_at_unix
        || baseline
            .last_key_rotated_at_unix
            .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err("policy lifecycle key rotation time is not monotonic".into());
    }
    let payload = key_rotation_payload(
        &rotation.policy_pack_id,
        &rotation.signer_id,
        &rotation.baseline_checkpoint_sha256,
        rotation.from_key_generation,
        rotation.to_key_generation,
        rotation.previous_key_rotation_sha256.as_deref(),
        &rotation.old_public_key,
        &rotation.new_public_key,
        rotation.rotated_at_unix,
    )?;
    for (key, signature, label) in [
        (
            &rotation.old_public_key,
            &rotation.old_signature,
            "old lifecycle key rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new lifecycle key rotation",
        ),
    ] {
        let key = decode_hex_array::<32>(key, label)?;
        let signature = Signature::from_bytes(&decode_hex_array::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    Ok(())
}

pub fn validate_signed_policy_lifecycle_key_rotation(
    rotation: &SignedPolicyLifecycleKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.to_key_generation != rotation.from_key_generation.saturating_add(1)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid signed policy lifecycle key rotation invariants".into());
    }
    validate_slug(&rotation.policy_pack_id)?;
    validate_slug(&rotation.signer_id)?;
    validate_digest(&rotation.baseline_checkpoint_sha256)?;
    if let Some(digest) = &rotation.previous_key_rotation_sha256 {
        validate_digest(digest)?;
    }
    validate_hex(&rotation.old_public_key, 32)?;
    validate_hex(&rotation.new_public_key, 32)?;
    validate_hex(&rotation.old_signature, 64)?;
    validate_hex(&rotation.new_signature, 64)
}

pub fn validate_signed_policy_lifecycle_checkpoint_witness(
    witness: &SignedPolicyLifecycleCheckpointWitness,
) -> Result<(), String> {
    if witness.schema_version != 1 || witness.algorithm != "ed25519" || witness.generation == 0 {
        return Err("invalid signed policy lifecycle witness invariants".into());
    }
    validate_digest(&witness.checkpoint_sha256)?;
    validate_slug(&witness.policy_pack_id)?;
    validate_digest(&witness.head_sha256)?;
    validate_slug(&witness.witness_id)?;
    validate_hex(&witness.public_key, 32)?;
    validate_hex(&witness.signature, 64)
}

pub fn validate_policy_lifecycle_witness_trust_state(
    state: &PolicyLifecycleWitnessTrustState,
) -> Result<(), String> {
    if state.schema_version != POLICY_LIFECYCLE_WITNESS_TRUST_STATE_SCHEMA_VERSION {
        return Err("unsupported policy lifecycle witness trust state".into());
    }
    validate_slug(&state.witness_id)?;
    let public_key = decode_hex_array::<32>(
        &state.current_public_key,
        "current policy lifecycle witness public key",
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid current policy lifecycle witness public key: {error}"))?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) => Ok(()),
        (0, _, _) => {
            Err("initial policy lifecycle witness trust state cannot reference a rotation".into())
        }
        (_, Some(digest), Some(_)) => validate_digest(digest),
        _ => Err(
            "rotated policy lifecycle witness trust state requires complete rotation evidence"
                .into(),
        ),
    }
}

pub fn validate_signed_policy_lifecycle_witness_key_rotation(
    rotation: &SignedPolicyLifecycleWitnessKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.to_generation != rotation.from_generation.saturating_add(1)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid signed policy lifecycle witness key rotation invariants".into());
    }
    validate_slug(&rotation.witness_id)?;
    if let Some(digest) = &rotation.previous_rotation_sha256 {
        validate_digest(digest)?;
    }
    validate_hex(&rotation.old_public_key, 32)?;
    validate_hex(&rotation.new_public_key, 32)?;
    validate_hex(&rotation.old_signature, 64)?;
    validate_hex(&rotation.new_signature, 64)
}

pub fn validate_policy_lifecycle_witness_quorum_report(
    report: &PolicyLifecycleWitnessQuorumReport,
) -> Result<(), String> {
    let count = usize::try_from(report.valid_witnesses)
        .map_err(|_| "policy lifecycle witness count overflow".to_string())?;
    if report.schema_version != 1
        || report.generation == 0
        || !(2..=100).contains(&report.minimum_witnesses)
        || count != report.witness_ids.len()
        || count != report.witness_public_keys.len()
        || report.quorum_met != (report.valid_witnesses >= report.minimum_witnesses)
        || report.status
            != if report.quorum_met {
                "witness_quorum_met"
            } else {
                "insufficient_witnesses"
            }
    {
        return Err("invalid policy lifecycle witness quorum invariants".into());
    }
    validate_digest(&report.checkpoint_sha256)?;
    validate_slug(&report.policy_pack_id)?;
    validate_digest(&report.head_sha256)?;
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for id in &report.witness_ids {
        validate_slug(id)?;
        if !ids.insert(id) {
            return Err("duplicate policy lifecycle witness identity".into());
        }
    }
    for key in &report.witness_public_keys {
        validate_hex(key, 32)?;
        if !keys.insert(key) {
            return Err("duplicate policy lifecycle witness public key".into());
        }
    }
    Ok(())
}

pub fn verify_checkpoint_for_ledger(
    ledger: &PolicyLifecycleLedger,
    checkpoint: &SignedPolicyLifecycleCheckpoint,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    validate_policy_lifecycle_ledger(ledger)?;
    validate_signed_policy_lifecycle_checkpoint(checkpoint)?;
    let ledger_sha256 = normalized_sha256(ledger, "policy lifecycle ledger")?;
    if checkpoint.policy_pack_id != ledger.policy_pack_id
        || checkpoint.generation != ledger.generation
        || checkpoint.entry_count != ledger.entry_count
        || checkpoint.ledger_sha256 != ledger_sha256
        || checkpoint.head_sha256 != ledger.head_sha256
    {
        return Err("policy lifecycle checkpoint is bound to a different ledger".into());
    }
    if checkpoint.public_key != hex_encode(trusted_public_key) {
        return Err("policy lifecycle checkpoint public key is not trusted".into());
    }
    verify_signature(checkpoint, trusted_public_key)
}

pub fn parse_signed_policy_lifecycle_checkpoint(
    source: &str,
) -> Result<SignedPolicyLifecycleCheckpoint, String> {
    let checkpoint = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed policy lifecycle checkpoint JSON: {error}"))?;
    validate_signed_policy_lifecycle_checkpoint(&checkpoint)?;
    Ok(checkpoint)
}

pub fn parse_policy_lifecycle_trust_state(
    source: &str,
) -> Result<PolicyLifecycleTrustState, String> {
    let state = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy lifecycle trust state JSON: {error}"))?;
    validate_policy_lifecycle_trust_state(&state)?;
    Ok(state)
}

pub fn validate_signed_policy_lifecycle_checkpoint(
    checkpoint: &SignedPolicyLifecycleCheckpoint,
) -> Result<(), String> {
    if checkpoint.schema_version != SIGNED_POLICY_LIFECYCLE_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.algorithm != "ed25519"
        || checkpoint.generation == 0
        || checkpoint.entry_count == 0
        || checkpoint.generation != checkpoint.entry_count
    {
        return Err("invalid signed policy lifecycle checkpoint invariants".into());
    }
    validate_slug(&checkpoint.policy_pack_id)?;
    validate_slug(&checkpoint.signer_id)?;
    validate_digest(&checkpoint.ledger_sha256)?;
    validate_digest(&checkpoint.head_sha256)?;
    validate_hex(&checkpoint.public_key, 32)?;
    validate_hex(&checkpoint.signature, 64)
}

pub fn validate_policy_lifecycle_trust_state(
    state: &PolicyLifecycleTrustState,
) -> Result<(), String> {
    validate_signed_policy_lifecycle_checkpoint(&state.signed_checkpoint)?;
    if state.schema_version != POLICY_LIFECYCLE_TRUST_STATE_SCHEMA_VERSION
        || state.status != "checkpoint_accepted"
        || state.accepted_generation == 0
        || state.accepted_generation != state.accepted_entry_count
        || state.policy_pack_id != state.signed_checkpoint.policy_pack_id
        || state.accepted_generation != state.signed_checkpoint.generation
        || state.accepted_entry_count != state.signed_checkpoint.entry_count
        || state.ledger_sha256 != state.signed_checkpoint.ledger_sha256
        || state.head_sha256 != state.signed_checkpoint.head_sha256
        || state.signer_id != state.signed_checkpoint.signer_id
        || state.public_key != state.signed_checkpoint.public_key
        || state.issued_at_unix != state.signed_checkpoint.issued_at_unix
        || state.checkpoint_sha256
            != normalized_sha256(&state.signed_checkpoint, "policy lifecycle checkpoint")?
    {
        return Err("invalid policy lifecycle trust state invariants".into());
    }
    validate_acceptance_time(state.issued_at_unix, state.accepted_at_unix)?;
    validate_slug(&state.policy_pack_id)?;
    validate_slug(&state.signer_id)?;
    for digest in [
        &state.ledger_sha256,
        &state.head_sha256,
        &state.checkpoint_sha256,
    ] {
        validate_digest(digest)?;
    }
    match (
        state.key_generation,
        &state.last_key_rotation_sha256,
        state.last_key_rotated_at_unix,
    ) {
        (0, None, None) => {}
        (0, _, _) => return Err("initial lifecycle key state cannot reference a rotation".into()),
        (_, Some(digest), Some(rotated_at)) => {
            validate_digest(digest)?;
            if rotated_at > state.issued_at_unix {
                return Err("lifecycle key rotated after its signed checkpoint".into());
            }
        }
        _ => return Err("rotated lifecycle key state requires complete rotation evidence".into()),
    }
    let public_key = decode_hex_array::<32>(&state.public_key, "policy lifecycle public key")?;
    verify_signature(&state.signed_checkpoint, &public_key)
}

fn verify_signature(
    checkpoint: &SignedPolicyLifecycleCheckpoint,
    public_key: &[u8; 32],
) -> Result<(), String> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("invalid policy lifecycle verification key: {error}"))?;
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &checkpoint.signature,
        "policy lifecycle signature",
    )?);
    let payload = signature_payload(
        &checkpoint.policy_pack_id,
        checkpoint.generation,
        checkpoint.entry_count,
        &checkpoint.ledger_sha256,
        &checkpoint.head_sha256,
        checkpoint.issued_at_unix,
        &checkpoint.signer_id,
    )?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| "policy lifecycle checkpoint signature verification failed".into())
}

#[allow(clippy::too_many_arguments)]
fn signature_payload(
    policy_pack_id: &str,
    generation: u64,
    entry_count: u64,
    ledger_sha256: &str,
    head_sha256: &str,
    issued_at_unix: u64,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        policy_pack_id,
        generation,
        entry_count,
        ledger_sha256,
        head_sha256,
        issued_at_unix,
        signer_id,
    })
    .map_err(|error| format!("serializing policy lifecycle signature payload: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn key_rotation_payload(
    policy_pack_id: &str,
    signer_id: &str,
    baseline_checkpoint_sha256: &str,
    from_key_generation: u64,
    to_key_generation: u64,
    previous_key_rotation_sha256: Option<&str>,
    old_public_key: &str,
    new_public_key: &str,
    rotated_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&KeyRotationPayload {
        domain: KEY_ROTATION_DOMAIN,
        policy_pack_id,
        signer_id,
        baseline_checkpoint_sha256,
        from_key_generation,
        to_key_generation,
        previous_key_rotation_sha256,
        old_public_key,
        new_public_key,
        rotated_at_unix,
    })
    .map_err(|error| format!("serializing policy lifecycle key rotation payload: {error}"))
}

fn witness_payload(
    checkpoint_sha256: &str,
    policy_pack_id: &str,
    generation: u64,
    head_sha256: &str,
    witness_id: &str,
    observed_at_unix: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WitnessPayload {
        domain: WITNESS_DOMAIN,
        checkpoint_sha256,
        policy_pack_id,
        generation,
        head_sha256,
        witness_id,
        observed_at_unix,
    })
    .map_err(|error| format!("serializing policy lifecycle witness payload: {error}"))
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
    .map_err(|error| format!("serializing policy lifecycle witness key rotation payload: {error}"))
}

fn validate_acceptance_time(issued_at_unix: u64, accepted_at_unix: u64) -> Result<(), String> {
    if accepted_at_unix < issued_at_unix
        || accepted_at_unix - issued_at_unix > MAXIMUM_ACCEPTANCE_DELAY_SECONDS
    {
        Err("policy lifecycle checkpoint is outside the 24-hour acceptance window".into())
    } else {
        Ok(())
    }
}

pub fn signed_policy_lifecycle_checkpoint_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-checkpoint-v1.json",
        "title": "Signed pcbex policy lifecycle checkpoint",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack_id", "generation", "entry_count",
            "ledger_sha256", "head_sha256", "issued_at_unix", "signer_id",
            "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_POLICY_LIFECYCLE_CHECKPOINT_SCHEMA_VERSION},
            "policy_pack_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 1},
            "entry_count": {"type": "integer", "minimum": 1},
            "ledger_sha256": digest_schema(),
            "head_sha256": digest_schema(),
            "issued_at_unix": {"type": "integer", "minimum": 0},
            "signer_id": slug_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn policy_lifecycle_trust_state_json_schema() -> Value {
    let mut checkpoint = signed_policy_lifecycle_checkpoint_json_schema();
    if let Some(object) = checkpoint.as_object_mut() {
        object.remove("$schema");
        object.remove("$id");
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-trust-state-v1.json",
        "title": "pcbex monotonic policy lifecycle checkpoint trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "policy_pack_id", "accepted_generation",
            "accepted_entry_count", "ledger_sha256", "head_sha256",
            "checkpoint_sha256", "signer_id", "public_key", "issued_at_unix",
            "accepted_at_unix", "signed_checkpoint"
        ],
        "properties": {
            "schema_version": {"const": POLICY_LIFECYCLE_TRUST_STATE_SCHEMA_VERSION},
            "status": {"const": "checkpoint_accepted"},
            "policy_pack_id": slug_schema(),
            "accepted_generation": {"type": "integer", "minimum": 1},
            "accepted_entry_count": {"type": "integer", "minimum": 1},
            "ledger_sha256": digest_schema(),
            "head_sha256": digest_schema(),
            "checkpoint_sha256": digest_schema(),
            "signer_id": slug_schema(),
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "issued_at_unix": {"type": "integer", "minimum": 0},
            "accepted_at_unix": {"type": "integer", "minimum": 0},
            "key_generation": {"type": "integer", "minimum": 0},
            "last_key_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "last_key_rotated_at_unix": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0}
                ]
            },
            "signed_checkpoint": checkpoint
        }
    })
}

pub fn signed_policy_lifecycle_key_rotation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-key-rotation-v1.json",
        "title": "Signed pcbex policy lifecycle signing-key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "policy_pack_id", "signer_id",
            "baseline_checkpoint_sha256", "from_key_generation",
            "to_key_generation", "previous_key_rotation_sha256",
            "old_public_key", "new_public_key", "rotated_at_unix",
            "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "policy_pack_id": slug_schema(),
            "signer_id": slug_schema(),
            "baseline_checkpoint_sha256": digest_schema(),
            "from_key_generation": {"type": "integer", "minimum": 0},
            "to_key_generation": {"type": "integer", "minimum": 1},
            "previous_key_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "old_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "new_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn signed_policy_lifecycle_checkpoint_witness_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-checkpoint-witness-v1.json",
        "title": "Signed pcbex policy lifecycle checkpoint witness",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "checkpoint_sha256", "policy_pack_id",
            "generation", "head_sha256", "witness_id", "observed_at_unix",
            "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "checkpoint_sha256": digest_schema(),
            "policy_pack_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 1},
            "head_sha256": digest_schema(),
            "witness_id": slug_schema(),
            "observed_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn policy_lifecycle_witness_trust_state_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-witness-trust-state-v1.json",
        "title": "pcbex policy lifecycle witness key trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "witness_id", "generation", "current_public_key",
            "last_rotation_sha256", "last_rotated_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "witness_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "current_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "last_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "last_rotated_at_unix": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0}
                ]
            }
        }
    })
}

pub fn signed_policy_lifecycle_witness_key_rotation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-witness-key-rotation-v1.json",
        "title": "Signed pcbex policy lifecycle witness key rotation",
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
            "previous_rotation_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "old_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "new_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn policy_lifecycle_witness_quorum_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-witness-quorum-v1.json",
        "title": "pcbex policy lifecycle checkpoint witness quorum",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "checkpoint_sha256", "policy_pack_id",
            "generation", "head_sha256", "evaluated_at_unix",
            "minimum_witnesses", "valid_witnesses", "witness_ids",
            "witness_public_keys", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"enum": ["witness_quorum_met", "insufficient_witnesses"]},
            "checkpoint_sha256": digest_schema(),
            "policy_pack_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 1},
            "head_sha256": digest_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": 100},
            "valid_witnesses": {"type": "integer", "minimum": 0, "maximum": 100},
            "witness_ids": {
                "type": "array", "maxItems": 100, "uniqueItems": true,
                "items": slug_schema()
            },
            "witness_public_keys": {
                "type": "array", "maxItems": 100, "uniqueItems": true,
                "items": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            },
            "quorum_met": {"type": "boolean"}
        }
    })
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    validate_hex(value, N)?;
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    if output.len() != N {
        return Err(format!("{label} has an invalid size"));
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid lowercase hexadecimal value".into()),
    }
}

fn validate_hex(value: &str, bytes: usize) -> Result<(), String> {
    if value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid lowercase hexadecimal value".into())
    }
}

fn validate_digest(value: &str) -> Result<(), String> {
    validate_hex(value, 32)
}

fn validate_slug(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        Err("policy lifecycle checkpoint identity is invalid".into())
    } else {
        Ok(())
    }
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        policy_lifecycle::append_policy_lifecycle_event,
        policy_remediation::tests::lifecycle_test_states,
        remote_policy_lifecycle_witness::request_remote_policy_lifecycle_witness,
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn ledgers() -> (PolicyLifecycleLedger, PolicyLifecycleLedger) {
        let (_, suspension, remediation) = lifecycle_test_states();
        let generation_one = append_policy_lifecycle_event(None, Some(&suspension), None).unwrap();
        let generation_two =
            append_policy_lifecycle_event(Some(&generation_one), None, Some(&remediation)).unwrap();
        (generation_one, generation_two)
    }

    #[test]
    fn accepts_monotonic_checkpoints_and_idempotent_replay() {
        let (generation_one, generation_two) = ledgers();
        let key = [11_u8; 32];
        let public_key = SigningKey::from_bytes(&key).verifying_key().to_bytes();
        let first =
            sign_policy_lifecycle_checkpoint(&generation_one, 1_000, "release-root", &key).unwrap();
        let first_state = verify_policy_lifecycle_checkpoint(
            &generation_one,
            &first,
            &public_key,
            None,
            None,
            1_001,
        )
        .unwrap();
        assert_eq!(first_state.accepted_generation, 1);

        let second =
            sign_policy_lifecycle_checkpoint(&generation_two, 2_000, "release-root", &key).unwrap();
        let second_state = verify_policy_lifecycle_checkpoint(
            &generation_two,
            &second,
            &public_key,
            Some(&first_state),
            None,
            2_001,
        )
        .unwrap();
        assert_eq!(second_state.accepted_generation, 2);

        let replay = verify_policy_lifecycle_checkpoint(
            &generation_two,
            &second,
            &public_key,
            Some(&second_state),
            None,
            2_000 + MAXIMUM_ACCEPTANCE_DELAY_SECONDS + 1,
        )
        .unwrap();
        assert_eq!(replay, second_state);
    }

    #[test]
    fn rejects_rollback_equivocation_forks_and_untrusted_signatures() {
        let (generation_one, generation_two) = ledgers();
        let key = [12_u8; 32];
        let public_key = SigningKey::from_bytes(&key).verifying_key().to_bytes();
        let first =
            sign_policy_lifecycle_checkpoint(&generation_one, 1_000, "release-root", &key).unwrap();
        let first_state = verify_policy_lifecycle_checkpoint(
            &generation_one,
            &first,
            &public_key,
            None,
            None,
            1_001,
        )
        .unwrap();
        let second =
            sign_policy_lifecycle_checkpoint(&generation_two, 2_000, "release-root", &key).unwrap();
        let second_state = verify_policy_lifecycle_checkpoint(
            &generation_two,
            &second,
            &public_key,
            Some(&first_state),
            None,
            2_001,
        )
        .unwrap();

        assert!(
            verify_policy_lifecycle_checkpoint(
                &generation_one,
                &first,
                &public_key,
                Some(&second_state),
                None,
                2_002,
            )
            .unwrap_err()
            .contains("rollback")
        );

        let equivocation =
            sign_policy_lifecycle_checkpoint(&generation_two, 2_001, "release-root", &key).unwrap();
        assert!(
            verify_policy_lifecycle_checkpoint(
                &generation_two,
                &equivocation,
                &public_key,
                Some(&second_state),
                None,
                2_002,
            )
            .unwrap_err()
            .contains("equivocated")
        );

        let wrong_public_key = SigningKey::from_bytes(&[13_u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(
            verify_policy_lifecycle_checkpoint(
                &generation_two,
                &second,
                &wrong_public_key,
                None,
                None,
                2_001,
            )
            .unwrap_err()
            .contains("not trusted")
        );

        let mut fork = generation_two.clone();
        fork.entries[0].entry_sha256 = "00".repeat(32);
        assert!(validate_policy_lifecycle_ledger(&fork).is_err());
    }

    #[test]
    fn rejects_expired_and_tampered_state_and_has_closed_schemas() {
        let (generation_one, _) = ledgers();
        let key = [14_u8; 32];
        let public_key = SigningKey::from_bytes(&key).verifying_key().to_bytes();
        let checkpoint =
            sign_policy_lifecycle_checkpoint(&generation_one, 1_000, "release-root", &key).unwrap();
        assert!(
            verify_policy_lifecycle_checkpoint(
                &generation_one,
                &checkpoint,
                &public_key,
                None,
                None,
                1_000 + MAXIMUM_ACCEPTANCE_DELAY_SECONDS + 1,
            )
            .unwrap_err()
            .contains("24-hour")
        );

        let mut state = verify_policy_lifecycle_checkpoint(
            &generation_one,
            &checkpoint,
            &public_key,
            None,
            None,
            1_001,
        )
        .unwrap();
        let mut legacy = serde_json::to_value(&state).unwrap();
        let legacy = legacy.as_object_mut().unwrap();
        legacy.remove("key_generation");
        legacy.remove("last_key_rotation_sha256");
        legacy.remove("last_key_rotated_at_unix");
        let legacy =
            parse_policy_lifecycle_trust_state(&serde_json::to_string(&legacy).unwrap()).unwrap();
        assert_eq!(legacy.key_generation, 0);
        state.head_sha256 = "00".repeat(32);
        assert!(validate_policy_lifecycle_trust_state(&state).is_err());

        for schema in [
            signed_policy_lifecycle_checkpoint_json_schema(),
            policy_lifecycle_trust_state_json_schema(),
            signed_policy_lifecycle_key_rotation_json_schema(),
            signed_policy_lifecycle_checkpoint_witness_json_schema(),
            policy_lifecycle_witness_trust_state_json_schema(),
            signed_policy_lifecycle_witness_key_rotation_json_schema(),
            policy_lifecycle_witness_quorum_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
        }
    }

    #[test]
    fn rotates_lifecycle_witness_keys_with_dual_signed_chained_transitions() {
        let old_secret = [41_u8; 32];
        let next_secret = [42_u8; 32];
        let final_secret = [43_u8; 32];
        let old_public = SigningKey::from_bytes(&old_secret)
            .verifying_key()
            .to_bytes();
        let initial = new_policy_lifecycle_witness_trust_state("witness-a", &old_public).unwrap();
        assert_eq!(initial.generation, 0);
        assert_eq!(
            policy_lifecycle_witness_trusted_public_key(&initial).unwrap(),
            old_public
        );

        let first =
            sign_policy_lifecycle_witness_key_rotation(&initial, &old_secret, &next_secret, 1_000)
                .unwrap();
        let rotated = apply_policy_lifecycle_witness_key_rotation(&initial, &first).unwrap();
        assert_eq!(rotated.generation, 1);
        assert_eq!(rotated.last_rotated_at_unix, Some(1_000));
        assert_eq!(
            rotated.last_rotation_sha256,
            Some(signed_policy_lifecycle_witness_key_rotation_sha256(&first).unwrap())
        );
        assert!(apply_policy_lifecycle_witness_key_rotation(&rotated, &first).is_err());

        let second = sign_policy_lifecycle_witness_key_rotation(
            &rotated,
            &next_secret,
            &final_secret,
            1_001,
        )
        .unwrap();
        let twice_rotated = apply_policy_lifecycle_witness_key_rotation(&rotated, &second).unwrap();
        assert_eq!(twice_rotated.generation, 2);
        assert_eq!(
            second.previous_rotation_sha256,
            rotated.last_rotation_sha256
        );

        let mut tampered = second.clone();
        tampered.new_signature = "00".repeat(64);
        assert!(apply_policy_lifecycle_witness_key_rotation(&rotated, &tampered).is_err());
        let mut fork = second;
        fork.previous_rotation_sha256 = Some("00".repeat(32));
        assert!(apply_policy_lifecycle_witness_key_rotation(&rotated, &fork).is_err());
        assert!(
            sign_policy_lifecycle_witness_key_rotation(
                &rotated,
                &old_secret,
                &final_secret,
                1_002,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_witness_key_rotation(
                &rotated,
                &next_secret,
                &next_secret,
                1_002,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_witness_key_rotation(&rotated, &next_secret, &final_secret, 999,)
                .is_err()
        );
    }

    #[test]
    fn retained_lifecycle_witness_identity_verifies_rotated_key() {
        let (ledger, _) = ledgers();
        let root_secret = [44_u8; 32];
        let root_public = SigningKey::from_bytes(&root_secret)
            .verifying_key()
            .to_bytes();
        let checkpoint =
            sign_policy_lifecycle_checkpoint(&ledger, 1_000, "release-root", &root_secret).unwrap();
        let state = verify_policy_lifecycle_checkpoint(
            &ledger,
            &checkpoint,
            &root_public,
            None,
            None,
            1_001,
        )
        .unwrap();
        let old_secret = [45_u8; 32];
        let new_secret = [46_u8; 32];
        let old_public = SigningKey::from_bytes(&old_secret)
            .verifying_key()
            .to_bytes();
        let initial = new_policy_lifecycle_witness_trust_state("witness-a", &old_public).unwrap();
        let rotation =
            sign_policy_lifecycle_witness_key_rotation(&initial, &old_secret, &new_secret, 1_050)
                .unwrap();
        let trusted = apply_policy_lifecycle_witness_key_rotation(&initial, &rotation).unwrap();
        let witness =
            sign_policy_lifecycle_checkpoint_witness(&state, "witness-a", 1_100, &new_secret)
                .unwrap();
        verify_policy_lifecycle_checkpoint_witness_with_trust_state(
            &state, &witness, &trusted, 1_101,
        )
        .unwrap();
        let report = verify_policy_lifecycle_checkpoint_witnesses_with_trust_states(
            &state,
            std::slice::from_ref(&witness),
            std::slice::from_ref(&trusted),
            2,
            1_101,
        )
        .unwrap();
        assert!(!report.quorum_met);

        let mut substituted = trusted;
        substituted.witness_id = "witness-b".into();
        assert!(
            verify_policy_lifecycle_checkpoint_witness_with_trust_state(
                &state,
                &witness,
                &substituted,
                1_101,
            )
            .unwrap_err()
            .contains("identity")
        );
    }

    #[test]
    fn rotates_signing_keys_only_with_old_and_new_signatures() {
        let (generation_one, generation_two) = ledgers();
        let old_secret = [21_u8; 32];
        let new_secret = [22_u8; 32];
        let old_public = SigningKey::from_bytes(&old_secret)
            .verifying_key()
            .to_bytes();
        let new_public = SigningKey::from_bytes(&new_secret)
            .verifying_key()
            .to_bytes();
        let first =
            sign_policy_lifecycle_checkpoint(&generation_one, 1_000, "release-root", &old_secret)
                .unwrap();
        let baseline = verify_policy_lifecycle_checkpoint(
            &generation_one,
            &first,
            &old_public,
            None,
            None,
            1_001,
        )
        .unwrap();
        let rotation =
            sign_policy_lifecycle_key_rotation(&baseline, &old_secret, &new_secret, 1_500).unwrap();
        assert!(
            sign_policy_lifecycle_key_rotation(&baseline, &new_secret, &[23; 32], 1_500)
                .unwrap_err()
                .contains("does not match")
        );
        assert!(
            sign_policy_lifecycle_key_rotation(&baseline, &old_secret, &old_secret, 1_500)
                .unwrap_err()
                .contains("must differ")
        );
        assert!(
            sign_policy_lifecycle_key_rotation(&baseline, &old_secret, &[23; 32], 1_000)
                .unwrap_err()
                .contains("moved backwards")
        );
        let second =
            sign_policy_lifecycle_checkpoint(&generation_two, 2_000, "release-root", &new_secret)
                .unwrap();
        let rotated = verify_policy_lifecycle_checkpoint(
            &generation_two,
            &second,
            &new_public,
            Some(&baseline),
            Some(&rotation),
            2_001,
        )
        .unwrap();
        assert_eq!(rotated.key_generation, 1);
        assert_eq!(rotated.public_key, rotation.new_public_key);
        assert!(rotated.last_key_rotation_sha256.is_some());

        assert!(
            verify_policy_lifecycle_checkpoint(
                &generation_two,
                &second,
                &new_public,
                Some(&baseline),
                None,
                2_001,
            )
            .unwrap_err()
            .contains("without rotation")
        );
        let mut tampered = rotation;
        tampered.new_signature = "00".repeat(64);
        assert!(
            verify_policy_lifecycle_checkpoint(
                &generation_two,
                &second,
                &new_public,
                Some(&baseline),
                Some(&tampered),
                2_001,
            )
            .unwrap_err()
            .contains("signature verification failed")
        );
    }

    #[test]
    fn requires_distinct_fresh_trusted_checkpoint_witnesses() {
        let (ledger, _) = ledgers();
        let root_secret = [31_u8; 32];
        let root_public = SigningKey::from_bytes(&root_secret)
            .verifying_key()
            .to_bytes();
        let checkpoint =
            sign_policy_lifecycle_checkpoint(&ledger, 1_000, "release-root", &root_secret).unwrap();
        let state = verify_policy_lifecycle_checkpoint(
            &ledger,
            &checkpoint,
            &root_public,
            None,
            None,
            1_001,
        )
        .unwrap();
        let secrets = [[32_u8; 32], [33_u8; 32]];
        let keys = secrets.map(|secret| SigningKey::from_bytes(&secret).verifying_key().to_bytes());
        let witnesses = [
            sign_policy_lifecycle_checkpoint_witness(&state, "witness-a", 1_100, &secrets[0])
                .unwrap(),
            sign_policy_lifecycle_checkpoint_witness(&state, "witness-b", 1_101, &secrets[1])
                .unwrap(),
        ];
        let quorum =
            verify_policy_lifecycle_checkpoint_witnesses(&state, &witnesses, &keys, 2, 1_102)
                .unwrap();
        assert!(quorum.quorum_met);
        assert_eq!(quorum.status, "witness_quorum_met");

        let insufficient = verify_policy_lifecycle_checkpoint_witnesses(
            &state,
            &witnesses[..1],
            &keys[..1],
            2,
            1_102,
        )
        .unwrap();
        assert!(!insufficient.quorum_met);

        let duplicates = [witnesses[0].clone(), witnesses[0].clone()];
        let duplicate_keys = [keys[0], keys[0]];
        assert!(
            verify_policy_lifecycle_checkpoint_witnesses(
                &state,
                &duplicates,
                &duplicate_keys,
                2,
                1_102,
            )
            .unwrap_err()
            .contains("distinct")
        );
        assert!(
            verify_policy_lifecycle_checkpoint_witnesses(
                &state,
                &witnesses,
                &[keys[0], keys[0]],
                2,
                1_102,
            )
            .unwrap_err()
            .contains("not trusted")
        );
        assert!(
            verify_policy_lifecycle_checkpoint_witnesses(
                &state,
                &witnesses,
                &keys,
                2,
                1_101 + MAXIMUM_WITNESS_AGE_SECONDS + 1,
            )
            .unwrap_err()
            .contains("24-hour")
        );
        let mut tampered = witnesses;
        tampered[1].signature = "00".repeat(64);
        assert!(
            verify_policy_lifecycle_checkpoint_witnesses(&state, &tampered, &keys, 2, 1_102)
                .unwrap_err()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn retrieves_and_verifies_a_bounded_remote_lifecycle_witness() {
        let (generation_one, _) = ledgers();
        let checkpoint_key = [71_u8; 32];
        let checkpoint_public = SigningKey::from_bytes(&checkpoint_key)
            .verifying_key()
            .to_bytes();
        let checkpoint = sign_policy_lifecycle_checkpoint(
            &generation_one,
            1_000,
            "release-root",
            &checkpoint_key,
        )
        .unwrap();
        let state = verify_policy_lifecycle_checkpoint(
            &generation_one,
            &checkpoint,
            &checkpoint_public,
            None,
            None,
            1_001,
        )
        .unwrap();
        let witness_key = [72_u8; 32];
        let witness_public = SigningKey::from_bytes(&witness_key)
            .verifying_key()
            .to_bytes();
        let served_state = state.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!(
            "http://{}/v1/lifecycle-witness",
            listener.local_addr().unwrap()
        );
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            let header_end = loop {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
                if let Some(index) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..header_end]).unwrap();
            assert!(headers.starts_with("POST /v1/lifecycle-witness HTTP/1.1\r\n"));
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|value| value.parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() - header_end < content_length {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            let body: Value =
                serde_json::from_slice(&request[header_end..header_end + content_length]).unwrap();
            assert_eq!(
                body["protocol"],
                "pcbex-policy-lifecycle-checkpoint-witness-v1"
            );
            assert_eq!(
                body["trust_state"]["checkpoint_sha256"],
                served_state.checkpoint_sha256
            );
            assert_eq!(body["trust_state"]["accepted_generation"], 1);
            assert_eq!(
                body["trust_state"]["signed_checkpoint"]["head_sha256"],
                served_state.head_sha256
            );
            let witness = sign_policy_lifecycle_checkpoint_witness(
                &served_state,
                "remote-lifecycle-a",
                1_010,
                &witness_key,
            )
            .unwrap();
            let response = serde_json::to_vec(&witness).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len()
            )
            .unwrap();
            stream.write_all(&response).unwrap();
        });
        let (witness, receipt) = request_remote_policy_lifecycle_witness(
            &state,
            &endpoint,
            &witness_public,
            None,
            5,
            1_011,
            true,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(witness.witness_id, "remote-lifecycle-a");
        assert_eq!(receipt.checkpoint_sha256, state.checkpoint_sha256);
        assert_eq!(receipt.witness_public_key, witness.public_key);
        assert_eq!(receipt.evaluated_at_unix, 1_011);
        assert!(receipt.verified);
    }
}
