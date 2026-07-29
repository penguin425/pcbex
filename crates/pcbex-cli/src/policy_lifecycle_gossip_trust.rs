use crate::policy_lifecycle_anchor::PolicyLifecycleLogAnchorProof;
use crate::policy_lifecycle_gossip_quorum::{
    PolicyLifecycleLogGossipObservation, PolicyLifecycleLogGossipQuorumReport,
    policy_lifecycle_log_gossip_quorum_report_json_schema,
    validate_policy_lifecycle_log_gossip_quorum_report, verify_policy_lifecycle_log_gossip_quorum,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ROTATION_DOMAIN: &str = "pcbex-policy-lifecycle-public-log-gossip-observer-key-rotation-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipObserverTrustState {
    pub schema_version: u32,
    pub organization_id: String,
    pub observer_id: String,
    pub generation: u64,
    pub current_public_key: String,
    pub last_rotation_sha256: Option<String>,
    pub last_rotated_at_unix: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyLifecycleLogGossipObserverKeyRotation {
    pub schema_version: u32,
    pub organization_id: String,
    pub observer_id: String,
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
pub struct PolicyLifecycleLogGossipObserverTrustReference {
    pub organization_id: String,
    pub observer_id: String,
    pub generation: u64,
    pub current_public_key: String,
    pub trust_state_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyLifecycleLogGossipTrustBoundQuorumReport {
    pub schema_version: u32,
    pub quorum: PolicyLifecycleLogGossipQuorumReport,
    pub observer_trust: Vec<PolicyLifecycleLogGossipObserverTrustReference>,
    pub trust_bound: bool,
}

#[derive(Serialize)]
struct RotationPayload<'a> {
    domain: &'static str,
    organization_id: &'a str,
    observer_id: &'a str,
    from_generation: u64,
    to_generation: u64,
    previous_rotation_sha256: Option<&'a str>,
    old_public_key: &'a str,
    new_public_key: &'a str,
    rotated_at_unix: u64,
}

pub fn new_policy_lifecycle_log_gossip_observer_trust_state(
    organization_id: &str,
    observer_id: &str,
    public_key: &[u8; 32],
) -> Result<PolicyLifecycleLogGossipObserverTrustState, String> {
    validate_slug(
        organization_id,
        "policy lifecycle gossip observer organization id",
    )?;
    validate_slug(observer_id, "policy lifecycle gossip observer id")?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("invalid policy lifecycle gossip observer public key: {error}"))?;
    Ok(PolicyLifecycleLogGossipObserverTrustState {
        schema_version: 1,
        organization_id: organization_id.into(),
        observer_id: observer_id.into(),
        generation: 0,
        current_public_key: hex_encode(public_key),
        last_rotation_sha256: None,
        last_rotated_at_unix: None,
    })
}

pub fn policy_lifecycle_log_gossip_observer_trusted_public_key(
    state: &PolicyLifecycleLogGossipObserverTrustState,
) -> Result<[u8; 32], String> {
    validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
    hex_decode::<32>(
        &state.current_public_key,
        "current policy lifecycle gossip observer public key",
    )
}

pub fn policy_lifecycle_log_gossip_observer_trust_state_sha256(
    state: &PolicyLifecycleLogGossipObserverTrustState,
) -> Result<String, String> {
    validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
    normalized_sha256(state, "policy lifecycle gossip observer trust state")
}

pub fn sign_policy_lifecycle_log_gossip_observer_key_rotation(
    state: &PolicyLifecycleLogGossipObserverTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedPolicyLifecycleLogGossipObserverKeyRotation, String> {
    validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != state.current_public_key {
        return Err(
            "old policy lifecycle gossip observer key does not match the trust state".into(),
        );
    }
    if new_public_key == old_public_key {
        return Err(
            "new policy lifecycle gossip observer key must differ from the current key".into(),
        );
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err(
            "policy lifecycle gossip observer rotation timestamps must be monotonic".into(),
        );
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "policy lifecycle gossip observer generation overflow".to_string())?;
    let payload = rotation_payload(
        &state.organization_id,
        &state.observer_id,
        state.generation,
        to_generation,
        state.last_rotation_sha256.as_deref(),
        &old_public_key,
        &new_public_key,
        rotated_at_unix,
    )?;
    let rotation = SignedPolicyLifecycleLogGossipObserverKeyRotation {
        schema_version: 1,
        organization_id: state.organization_id.clone(),
        observer_id: state.observer_id.clone(),
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
    validate_signed_policy_lifecycle_log_gossip_observer_key_rotation(&rotation)?;
    Ok(rotation)
}

pub fn apply_policy_lifecycle_log_gossip_observer_key_rotation(
    state: &PolicyLifecycleLogGossipObserverTrustState,
    rotation: &SignedPolicyLifecycleLogGossipObserverKeyRotation,
) -> Result<PolicyLifecycleLogGossipObserverTrustState, String> {
    validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
    validate_signed_policy_lifecycle_log_gossip_observer_key_rotation(rotation)?;
    if rotation.organization_id != state.organization_id
        || rotation.observer_id != state.observer_id
        || rotation.from_generation != state.generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
    {
        return Err(
            "policy lifecycle gossip observer rotation does not extend the trust state".into(),
        );
    }
    let expected_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "policy lifecycle gossip observer generation overflow".to_string())?;
    if rotation.to_generation != expected_generation {
        return Err(
            "policy lifecycle gossip observer rotation must advance exactly one generation".into(),
        );
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err(
            "policy lifecycle gossip observer rotation timestamps must be monotonic".into(),
        );
    }
    let payload = rotation_payload(
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
            &rotation.old_signature,
            "old policy lifecycle gossip observer rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new policy lifecycle gossip observer rotation",
        ),
    ] {
        let key = hex_decode::<32>(key, label)?;
        let signature = Signature::from_bytes(&hex_decode::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let next = PolicyLifecycleLogGossipObserverTrustState {
        schema_version: 1,
        organization_id: state.organization_id.clone(),
        observer_id: state.observer_id.clone(),
        generation: rotation.to_generation,
        current_public_key: rotation.new_public_key.clone(),
        last_rotation_sha256: Some(
            signed_policy_lifecycle_log_gossip_observer_key_rotation_sha256(rotation)?,
        ),
        last_rotated_at_unix: Some(rotation.rotated_at_unix),
    };
    validate_policy_lifecycle_log_gossip_observer_trust_state(&next)?;
    Ok(next)
}

pub fn parse_policy_lifecycle_log_gossip_observer_trust_state(
    source: &str,
) -> Result<PolicyLifecycleLogGossipObserverTrustState, String> {
    let state = serde_json::from_str(source).map_err(|error| {
        format!("invalid policy lifecycle gossip observer trust-state JSON: {error}")
    })?;
    validate_policy_lifecycle_log_gossip_observer_trust_state(&state)?;
    Ok(state)
}

pub fn parse_signed_policy_lifecycle_log_gossip_observer_key_rotation(
    source: &str,
) -> Result<SignedPolicyLifecycleLogGossipObserverKeyRotation, String> {
    let rotation = serde_json::from_str(source).map_err(|error| {
        format!("invalid signed policy lifecycle gossip observer rotation JSON: {error}")
    })?;
    validate_signed_policy_lifecycle_log_gossip_observer_key_rotation(&rotation)?;
    Ok(rotation)
}

pub fn validate_policy_lifecycle_log_gossip_observer_trust_state(
    state: &PolicyLifecycleLogGossipObserverTrustState,
) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err("unsupported policy lifecycle gossip observer trust state".into());
    }
    validate_slug(
        &state.organization_id,
        "policy lifecycle gossip observer organization id",
    )?;
    validate_slug(&state.observer_id, "policy lifecycle gossip observer id")?;
    let key = hex_decode::<32>(
        &state.current_public_key,
        "current policy lifecycle gossip observer public key",
    )?;
    VerifyingKey::from_bytes(&key).map_err(|error| {
        format!("invalid current policy lifecycle gossip observer public key: {error}")
    })?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) => Ok(()),
        (0, _, _) => {
            Err("initial policy lifecycle gossip observer trust cannot reference a rotation".into())
        }
        (_, Some(digest), Some(_)) => {
            validate_sha256(digest, "policy lifecycle gossip observer rotation SHA-256")
        }
        _ => Err(
            "rotated policy lifecycle gossip observer trust requires complete rotation evidence"
                .into(),
        ),
    }
}

pub fn validate_signed_policy_lifecycle_log_gossip_observer_key_rotation(
    rotation: &SignedPolicyLifecycleLogGossipObserverKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.to_generation != rotation.from_generation.saturating_add(1)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid policy lifecycle gossip observer rotation invariants".into());
    }
    validate_slug(
        &rotation.organization_id,
        "policy lifecycle gossip observer organization id",
    )?;
    validate_slug(&rotation.observer_id, "policy lifecycle gossip observer id")?;
    if let Some(digest) = &rotation.previous_rotation_sha256 {
        validate_sha256(digest, "previous gossip observer rotation SHA-256")?;
    }
    hex_decode::<32>(
        &rotation.old_public_key,
        "old policy lifecycle gossip observer public key",
    )?;
    hex_decode::<32>(
        &rotation.new_public_key,
        "new policy lifecycle gossip observer public key",
    )?;
    hex_decode::<64>(
        &rotation.old_signature,
        "old policy lifecycle gossip observer signature",
    )?;
    hex_decode::<64>(
        &rotation.new_signature,
        "new policy lifecycle gossip observer signature",
    )?;
    Ok(())
}

pub fn signed_policy_lifecycle_log_gossip_observer_key_rotation_sha256(
    rotation: &SignedPolicyLifecycleLogGossipObserverKeyRotation,
) -> Result<String, String> {
    validate_signed_policy_lifecycle_log_gossip_observer_key_rotation(rotation)?;
    normalized_sha256(rotation, "policy lifecycle gossip observer key rotation")
}

pub fn verify_policy_lifecycle_log_gossip_quorum_with_observer_trust_states(
    local_anchor: &PolicyLifecycleLogAnchorProof,
    observations: &[PolicyLifecycleLogGossipObservation],
    observer_trust_states: &[PolicyLifecycleLogGossipObserverTrustState],
    minimum_organizations: u32,
    trusted_log_id: &str,
    trusted_log_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<PolicyLifecycleLogGossipTrustBoundQuorumReport, String> {
    if observations.len() != observer_trust_states.len() || observations.is_empty() {
        return Err(
            "policy lifecycle gossip observations and observer trust states must be paired".into(),
        );
    }
    for state in observer_trust_states {
        validate_policy_lifecycle_log_gossip_observer_trust_state(state)?;
    }
    let organization_ids = observer_trust_states
        .iter()
        .map(|state| state.organization_id.clone())
        .collect::<Vec<_>>();
    let observer_ids = observer_trust_states
        .iter()
        .map(|state| state.observer_id.clone())
        .collect::<Vec<_>>();
    let keys = observer_trust_states
        .iter()
        .map(policy_lifecycle_log_gossip_observer_trusted_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    let quorum = verify_policy_lifecycle_log_gossip_quorum(
        local_anchor,
        observations,
        &organization_ids,
        &observer_ids,
        &keys,
        minimum_organizations,
        trusted_log_id,
        trusted_log_public_key,
        evaluated_at_unix,
    )?;
    let mut observer_trust = observer_trust_states
        .iter()
        .map(|state| {
            Ok(PolicyLifecycleLogGossipObserverTrustReference {
                organization_id: state.organization_id.clone(),
                observer_id: state.observer_id.clone(),
                generation: state.generation,
                current_public_key: state.current_public_key.clone(),
                trust_state_sha256: policy_lifecycle_log_gossip_observer_trust_state_sha256(state)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    observer_trust.sort_by(|left, right| {
        (&left.organization_id, &left.observer_id)
            .cmp(&(&right.organization_id, &right.observer_id))
    });
    let report = PolicyLifecycleLogGossipTrustBoundQuorumReport {
        schema_version: 1,
        quorum,
        observer_trust,
        trust_bound: true,
    };
    validate_policy_lifecycle_log_gossip_trust_bound_quorum_report(&report)?;
    Ok(report)
}

pub fn parse_policy_lifecycle_log_gossip_trust_bound_quorum_report(
    source: &str,
) -> Result<PolicyLifecycleLogGossipTrustBoundQuorumReport, String> {
    let report = serde_json::from_str(source).map_err(|error| {
        format!("invalid trust-bound policy lifecycle gossip quorum JSON: {error}")
    })?;
    validate_policy_lifecycle_log_gossip_trust_bound_quorum_report(&report)?;
    Ok(report)
}

pub fn validate_policy_lifecycle_log_gossip_trust_bound_quorum_report(
    report: &PolicyLifecycleLogGossipTrustBoundQuorumReport,
) -> Result<(), String> {
    validate_policy_lifecycle_log_gossip_quorum_report(&report.quorum)?;
    if report.schema_version != 1
        || !report.trust_bound
        || report.observer_trust.len() != report.quorum.members.len()
    {
        return Err("invalid trust-bound policy lifecycle gossip quorum invariants".into());
    }
    for (reference, member) in report.observer_trust.iter().zip(&report.quorum.members) {
        validate_slug(
            &reference.organization_id,
            "policy lifecycle gossip observer organization id",
        )?;
        validate_slug(
            &reference.observer_id,
            "policy lifecycle gossip observer id",
        )?;
        validate_sha256(
            &reference.current_public_key,
            "policy lifecycle gossip observer public key",
        )?;
        validate_sha256(
            &reference.trust_state_sha256,
            "policy lifecycle gossip observer trust-state SHA-256",
        )?;
        if reference.organization_id != member.organization_id
            || reference.observer_id != member.observer_id
            || reference.current_public_key != member.observer_public_key
        {
            return Err(
                "policy lifecycle gossip quorum member does not match observer trust evidence"
                    .into(),
            );
        }
    }
    Ok(())
}

pub fn policy_lifecycle_log_gossip_observer_trust_state_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-observer-trust-state-v1.json",
        "title": "pcbex policy lifecycle public-log gossip observer trust state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "organization_id", "observer_id", "generation",
            "current_public_key", "last_rotation_sha256", "last_rotated_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "organization_id": slug_schema(),
            "observer_id": slug_schema(),
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

pub fn signed_policy_lifecycle_log_gossip_observer_key_rotation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-lifecycle-log-gossip-observer-key-rotation-v1.json",
        "title": "Signed pcbex policy lifecycle public-log gossip observer key rotation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "organization_id", "observer_id",
            "from_generation", "to_generation", "previous_rotation_sha256",
            "old_public_key", "new_public_key", "rotated_at_unix",
            "algorithm", "old_signature", "new_signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "organization_id": slug_schema(),
            "observer_id": slug_schema(),
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

pub fn policy_lifecycle_log_gossip_trust_bound_quorum_report_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-lifecycle-log-gossip-trust-bound-quorum-v1.json",
        "title": "pcbex trust-bound policy lifecycle public-log gossip quorum",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "quorum", "observer_trust", "trust_bound"],
        "properties": {
            "schema_version": {"const": 1},
            "quorum": policy_lifecycle_log_gossip_quorum_report_json_schema(),
            "observer_trust": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "organization_id", "observer_id", "generation",
                        "current_public_key", "trust_state_sha256"
                    ],
                    "properties": {
                        "organization_id": slug_schema(),
                        "observer_id": slug_schema(),
                        "generation": {"type": "integer", "minimum": 0},
                        "current_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "trust_state_sha256": digest_schema()
                    }
                }
            },
            "trust_bound": {"const": true}
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn rotation_payload(
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
        organization_id,
        observer_id,
        from_generation,
        to_generation,
        previous_rotation_sha256,
        old_public_key,
        new_public_key,
        rotated_at_unix,
    })
    .map_err(|error| format!("serializing policy lifecycle gossip observer rotation: {error}"))
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_gossip_observer_keys_with_dual_signed_chained_transitions() {
        let old_secret = [11; 32];
        let next_secret = [12; 32];
        let final_secret = [13; 32];
        let old_public = SigningKey::from_bytes(&old_secret)
            .verifying_key()
            .to_bytes();
        let initial = new_policy_lifecycle_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &old_public,
        )
        .unwrap();
        let first = sign_policy_lifecycle_log_gossip_observer_key_rotation(
            &initial,
            &old_secret,
            &next_secret,
            1_000,
        )
        .unwrap();
        let rotated =
            apply_policy_lifecycle_log_gossip_observer_key_rotation(&initial, &first).unwrap();
        assert_eq!(rotated.generation, 1);
        assert_eq!(
            rotated.last_rotation_sha256,
            Some(signed_policy_lifecycle_log_gossip_observer_key_rotation_sha256(&first).unwrap())
        );
        assert!(apply_policy_lifecycle_log_gossip_observer_key_rotation(&rotated, &first).is_err());
        let second = sign_policy_lifecycle_log_gossip_observer_key_rotation(
            &rotated,
            &next_secret,
            &final_secret,
            2_000,
        )
        .unwrap();
        let twice =
            apply_policy_lifecycle_log_gossip_observer_key_rotation(&rotated, &second).unwrap();
        assert_eq!(twice.generation, 2);
        assert_eq!(
            policy_lifecycle_log_gossip_observer_trusted_public_key(&twice).unwrap(),
            SigningKey::from_bytes(&final_secret)
                .verifying_key()
                .to_bytes()
        );

        let mut tampered = second.clone();
        tampered.organization_id = "other-lab".into();
        assert!(
            apply_policy_lifecycle_log_gossip_observer_key_rotation(&rotated, &tampered).is_err()
        );
        let mut observer_tampered = second.clone();
        observer_tampered.observer_id = "observer-b".into();
        assert!(
            apply_policy_lifecycle_log_gossip_observer_key_rotation(&rotated, &observer_tampered)
                .is_err()
        );
        let mut signature_tampered = second.clone();
        signature_tampered.new_signature = "0".repeat(128);
        assert!(
            apply_policy_lifecycle_log_gossip_observer_key_rotation(&rotated, &signature_tampered)
                .is_err()
        );
        let mut fork = second.clone();
        fork.previous_rotation_sha256 = Some("0".repeat(64));
        assert!(apply_policy_lifecycle_log_gossip_observer_key_rotation(&rotated, &fork).is_err());
        assert!(
            sign_policy_lifecycle_log_gossip_observer_key_rotation(
                &rotated,
                &old_secret,
                &final_secret,
                2_000,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_observer_key_rotation(
                &rotated,
                &next_secret,
                &next_secret,
                2_000,
            )
            .is_err()
        );
        assert!(
            sign_policy_lifecycle_log_gossip_observer_key_rotation(
                &rotated,
                &next_secret,
                &final_secret,
                999,
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed_and_identity_bound() {
        let trust = policy_lifecycle_log_gossip_observer_trust_state_json_schema();
        assert_eq!(trust["additionalProperties"], false);
        assert_eq!(
            trust["properties"]["organization_id"]["pattern"],
            "^[a-z0-9][a-z0-9._-]{0,127}$"
        );
        let rotation = signed_policy_lifecycle_log_gossip_observer_key_rotation_json_schema();
        assert_eq!(rotation["additionalProperties"], false);
        assert_eq!(
            rotation["properties"]["old_signature"]["pattern"],
            "^[0-9a-f]{128}$"
        );
        let quorum = policy_lifecycle_log_gossip_trust_bound_quorum_report_json_schema();
        assert_eq!(quorum["additionalProperties"], false);
        assert_eq!(
            quorum["properties"]["observer_trust"]["items"]["additionalProperties"],
            false
        );
    }
}
