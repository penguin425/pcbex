use crate::policy_lifecycle::{PolicyLifecycleLedger, validate_policy_lifecycle_ledger};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const SIGNED_POLICY_LIFECYCLE_CHECKPOINT_SCHEMA_VERSION: u32 = 1;
pub const POLICY_LIFECYCLE_TRUST_STATE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-lifecycle-checkpoint-v1";
const KEY_ROTATION_DOMAIN: &str = "pcbex-policy-lifecycle-checkpoint-key-rotation-v1";
const MAXIMUM_ACCEPTANCE_DELAY_SECONDS: u64 = 86_400;

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

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
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
        ] {
            assert_eq!(schema["additionalProperties"], false);
        }
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
}
