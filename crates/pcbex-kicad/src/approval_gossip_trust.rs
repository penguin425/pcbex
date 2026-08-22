use crate::{
    ApprovalLogAnchorProof, ApprovalLogGossipObservation, ApprovalLogGossipQuorumReport,
    approval_log_gossip_quorum_report_json_schema, validate_approval_log_gossip_quorum_report,
    verify_approval_log_gossip_quorum,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ROTATION_DOMAIN: &str = "pcbex-approval-public-log-gossip-observer-key-rotation-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipObserverTrustState {
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
pub struct SignedApprovalLogGossipObserverKeyRotation {
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
pub struct ApprovalLogGossipObserverTrustReference {
    pub organization_id: String,
    pub observer_id: String,
    pub generation: u64,
    pub current_public_key: String,
    pub trust_state_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLogGossipTrustBoundQuorumReport {
    pub schema_version: u32,
    pub quorum: ApprovalLogGossipQuorumReport,
    pub observer_trust: Vec<ApprovalLogGossipObserverTrustReference>,
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

pub fn new_approval_log_gossip_observer_trust_state(
    organization_id: &str,
    observer_id: &str,
    public_key: &[u8; 32],
) -> Result<ApprovalLogGossipObserverTrustState, String> {
    validate_slug(organization_id, "approval gossip observer organization id")?;
    validate_slug(observer_id, "approval gossip observer id")?;
    VerifyingKey::from_bytes(public_key)
        .map_err(|error| format!("invalid approval gossip observer public key: {error}"))?;
    Ok(ApprovalLogGossipObserverTrustState {
        schema_version: 1,
        organization_id: organization_id.into(),
        observer_id: observer_id.into(),
        generation: 0,
        current_public_key: hex_encode(public_key),
        last_rotation_sha256: None,
        last_rotated_at_unix: None,
    })
}

pub fn approval_log_gossip_observer_trusted_public_key(
    state: &ApprovalLogGossipObserverTrustState,
) -> Result<[u8; 32], String> {
    validate_approval_log_gossip_observer_trust_state(state)?;
    hex_decode::<32>(
        &state.current_public_key,
        "current approval gossip observer public key",
    )
}

pub fn approval_log_gossip_observer_trust_state_sha256(
    state: &ApprovalLogGossipObserverTrustState,
) -> Result<String, String> {
    validate_approval_log_gossip_observer_trust_state(state)?;
    normalized_sha256(state, "approval gossip observer trust state")
}

pub fn sign_approval_log_gossip_observer_key_rotation(
    state: &ApprovalLogGossipObserverTrustState,
    old_secret_key: &[u8; 32],
    new_secret_key: &[u8; 32],
    rotated_at_unix: u64,
) -> Result<SignedApprovalLogGossipObserverKeyRotation, String> {
    validate_approval_log_gossip_observer_trust_state(state)?;
    let old_key = SigningKey::from_bytes(old_secret_key);
    let new_key = SigningKey::from_bytes(new_secret_key);
    let old_public_key = hex_encode(&old_key.verifying_key().to_bytes());
    let new_public_key = hex_encode(&new_key.verifying_key().to_bytes());
    if old_public_key != state.current_public_key {
        return Err("old approval gossip observer key does not match the trust state".into());
    }
    if new_public_key == old_public_key {
        return Err("new approval gossip observer key must differ from the current key".into());
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotated_at_unix < previous)
    {
        return Err("approval gossip observer rotation timestamps must be monotonic".into());
    }
    let to_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "approval gossip observer generation overflow".to_string())?;
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
    let rotation = SignedApprovalLogGossipObserverKeyRotation {
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
    validate_signed_approval_log_gossip_observer_key_rotation(&rotation)?;
    Ok(rotation)
}

pub fn apply_approval_log_gossip_observer_key_rotation(
    state: &ApprovalLogGossipObserverTrustState,
    rotation: &SignedApprovalLogGossipObserverKeyRotation,
) -> Result<ApprovalLogGossipObserverTrustState, String> {
    validate_approval_log_gossip_observer_trust_state(state)?;
    validate_signed_approval_log_gossip_observer_key_rotation(rotation)?;
    if rotation.organization_id != state.organization_id
        || rotation.observer_id != state.observer_id
        || rotation.from_generation != state.generation
        || rotation.previous_rotation_sha256 != state.last_rotation_sha256
        || rotation.old_public_key != state.current_public_key
    {
        return Err("approval gossip observer rotation does not extend the trust state".into());
    }
    let expected_generation = state
        .generation
        .checked_add(1)
        .ok_or_else(|| "approval gossip observer generation overflow".to_string())?;
    if rotation.to_generation != expected_generation {
        return Err("approval gossip observer rotation must advance exactly one generation".into());
    }
    if state
        .last_rotated_at_unix
        .is_some_and(|previous| rotation.rotated_at_unix < previous)
    {
        return Err("approval gossip observer rotation timestamps must be monotonic".into());
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
            "old approval gossip observer rotation",
        ),
        (
            &rotation.new_public_key,
            &rotation.new_signature,
            "new approval gossip observer rotation",
        ),
    ] {
        let key = hex_decode::<32>(key, label)?;
        let signature = Signature::from_bytes(&hex_decode::<64>(signature, label)?);
        VerifyingKey::from_bytes(&key)
            .map_err(|error| format!("invalid {label} public key: {error}"))?
            .verify_strict(&payload, &signature)
            .map_err(|_| format!("{label} signature verification failed"))?;
    }
    let next = ApprovalLogGossipObserverTrustState {
        schema_version: 1,
        organization_id: state.organization_id.clone(),
        observer_id: state.observer_id.clone(),
        generation: rotation.to_generation,
        current_public_key: rotation.new_public_key.clone(),
        last_rotation_sha256: Some(signed_approval_log_gossip_observer_key_rotation_sha256(
            rotation,
        )?),
        last_rotated_at_unix: Some(rotation.rotated_at_unix),
    };
    validate_approval_log_gossip_observer_trust_state(&next)?;
    Ok(next)
}

pub fn validate_approval_log_gossip_observer_trust_state(
    state: &ApprovalLogGossipObserverTrustState,
) -> Result<(), String> {
    if state.schema_version != 1 {
        return Err("unsupported approval gossip observer trust state".into());
    }
    validate_slug(
        &state.organization_id,
        "approval gossip observer organization id",
    )?;
    validate_slug(&state.observer_id, "approval gossip observer id")?;
    let key = hex_decode::<32>(
        &state.current_public_key,
        "current approval gossip observer public key",
    )?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid current approval gossip observer key: {error}"))?;
    match (
        state.generation,
        &state.last_rotation_sha256,
        state.last_rotated_at_unix,
    ) {
        (0, None, None) => Ok(()),
        (0, _, _) => {
            Err("initial approval gossip observer trust cannot reference a rotation".into())
        }
        (_, Some(digest), Some(_)) => {
            validate_sha256(digest, "approval gossip observer rotation SHA-256")
        }
        _ => Err("rotated approval gossip observer trust requires complete evidence".into()),
    }
}

pub fn validate_signed_approval_log_gossip_observer_key_rotation(
    rotation: &SignedApprovalLogGossipObserverKeyRotation,
) -> Result<(), String> {
    if rotation.schema_version != 1
        || rotation.algorithm != "ed25519"
        || rotation.to_generation != rotation.from_generation.saturating_add(1)
        || rotation.old_public_key == rotation.new_public_key
    {
        return Err("invalid approval gossip observer rotation invariants".into());
    }
    validate_slug(
        &rotation.organization_id,
        "approval gossip observer organization id",
    )?;
    validate_slug(&rotation.observer_id, "approval gossip observer id")?;
    if let Some(digest) = &rotation.previous_rotation_sha256 {
        validate_sha256(digest, "previous approval gossip rotation SHA-256")?;
    }
    hex_decode::<32>(&rotation.old_public_key, "old approval gossip observer key")?;
    hex_decode::<32>(&rotation.new_public_key, "new approval gossip observer key")?;
    hex_decode::<64>(
        &rotation.old_signature,
        "old approval gossip observer signature",
    )?;
    hex_decode::<64>(
        &rotation.new_signature,
        "new approval gossip observer signature",
    )?;
    Ok(())
}

pub fn signed_approval_log_gossip_observer_key_rotation_sha256(
    rotation: &SignedApprovalLogGossipObserverKeyRotation,
) -> Result<String, String> {
    validate_signed_approval_log_gossip_observer_key_rotation(rotation)?;
    normalized_sha256(rotation, "approval gossip observer key rotation")
}

pub fn verify_approval_log_gossip_quorum_with_observer_trust_states(
    local_anchor: &ApprovalLogAnchorProof,
    observations: &[ApprovalLogGossipObservation],
    observer_trust_states: &[ApprovalLogGossipObserverTrustState],
    minimum_organizations: u32,
    trusted_log_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<ApprovalLogGossipTrustBoundQuorumReport, String> {
    if observations.len() != observer_trust_states.len() || observations.is_empty() {
        return Err("approval gossip observations and trust states must be paired".into());
    }
    for state in observer_trust_states {
        validate_approval_log_gossip_observer_trust_state(state)?;
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
        .map(approval_log_gossip_observer_trusted_public_key)
        .collect::<Result<Vec<_>, _>>()?;
    let quorum = verify_approval_log_gossip_quorum(
        local_anchor,
        observations,
        &organization_ids,
        &observer_ids,
        &keys,
        minimum_organizations,
        trusted_log_public_key,
        evaluated_at_unix,
    )?;
    let mut observer_trust = observer_trust_states
        .iter()
        .map(|state| {
            Ok(ApprovalLogGossipObserverTrustReference {
                organization_id: state.organization_id.clone(),
                observer_id: state.observer_id.clone(),
                generation: state.generation,
                current_public_key: state.current_public_key.clone(),
                trust_state_sha256: approval_log_gossip_observer_trust_state_sha256(state)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    observer_trust.sort_by(|left, right| {
        (&left.organization_id, &left.observer_id)
            .cmp(&(&right.organization_id, &right.observer_id))
    });
    let report = ApprovalLogGossipTrustBoundQuorumReport {
        schema_version: 1,
        quorum,
        observer_trust,
        trust_bound: true,
    };
    validate_approval_log_gossip_trust_bound_quorum_report(&report)?;
    Ok(report)
}

pub fn validate_approval_log_gossip_trust_bound_quorum_report(
    report: &ApprovalLogGossipTrustBoundQuorumReport,
) -> Result<(), String> {
    validate_approval_log_gossip_quorum_report(&report.quorum)?;
    if report.schema_version != 1
        || !report.trust_bound
        || report.observer_trust.len() != report.quorum.members.len()
    {
        return Err("invalid trust-bound approval gossip quorum invariants".into());
    }
    for (reference, member) in report.observer_trust.iter().zip(&report.quorum.members) {
        validate_slug(
            &reference.organization_id,
            "approval gossip observer organization id",
        )?;
        validate_slug(&reference.observer_id, "approval gossip observer id")?;
        validate_sha256(
            &reference.current_public_key,
            "approval gossip observer public key",
        )?;
        validate_sha256(
            &reference.trust_state_sha256,
            "approval gossip observer trust-state SHA-256",
        )?;
        if reference.organization_id != member.organization_id
            || reference.observer_id != member.observer_id
            || reference.current_public_key != member.observer_public_key
        {
            return Err("approval gossip quorum member does not match trust evidence".into());
        }
    }
    Ok(())
}

pub fn approval_log_gossip_observer_trust_state_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-gossip-observer-trust-state-v1.json",
        "title": "pcbex approval public-log gossip observer trust state",
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
            "current_public_key": digest_schema(),
            "last_rotation_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "last_rotated_at_unix": {
                "oneOf": [{"type": "null"}, {"type": "integer", "minimum": 0}]
            }
        }
    })
}

pub fn signed_approval_log_gossip_observer_key_rotation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-approval-log-gossip-observer-key-rotation-v1.json",
        "title": "Signed pcbex approval public-log gossip observer key rotation",
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
            "previous_rotation_sha256": {"oneOf": [{"type": "null"}, digest_schema()]},
            "old_public_key": digest_schema(),
            "new_public_key": digest_schema(),
            "rotated_at_unix": {"type": "integer", "minimum": 0},
            "algorithm": {"const": "ed25519"},
            "old_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"},
            "new_signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn approval_log_gossip_trust_bound_quorum_report_json_schema() -> Value {
    let reference = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "organization_id", "observer_id", "generation",
            "current_public_key", "trust_state_sha256"
        ],
        "properties": {
            "organization_id": slug_schema(),
            "observer_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0},
            "current_public_key": digest_schema(),
            "trust_state_sha256": digest_schema()
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/approval-log-gossip-trust-bound-quorum-v1.json",
        "title": "pcbex trust-bound approval public-log gossip quorum",
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "quorum", "observer_trust", "trust_bound"],
        "properties": {
            "schema_version": {"const": 1},
            "quorum": approval_log_gossip_quorum_report_json_schema(),
            "observer_trust": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": reference
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
    .map_err(|error| format!("serializing approval gossip observer rotation: {error}"))
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
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
    for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
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
    fn rotates_keys_with_dual_signed_chained_transitions() {
        let old_secret = [11; 32];
        let next_secret = [12; 32];
        let final_secret = [13; 32];
        let initial = new_approval_log_gossip_observer_trust_state(
            "independent-lab",
            "observer-a",
            &SigningKey::from_bytes(&old_secret)
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let first = sign_approval_log_gossip_observer_key_rotation(
            &initial,
            &old_secret,
            &next_secret,
            1_000,
        )
        .unwrap();
        let rotated = apply_approval_log_gossip_observer_key_rotation(&initial, &first).unwrap();
        assert_eq!(rotated.generation, 1);
        assert!(apply_approval_log_gossip_observer_key_rotation(&rotated, &first).is_err());
        let second = sign_approval_log_gossip_observer_key_rotation(
            &rotated,
            &next_secret,
            &final_secret,
            2_000,
        )
        .unwrap();
        let twice = apply_approval_log_gossip_observer_key_rotation(&rotated, &second).unwrap();
        assert_eq!(twice.generation, 2);
        assert_eq!(
            approval_log_gossip_observer_trusted_public_key(&twice).unwrap(),
            SigningKey::from_bytes(&final_secret)
                .verifying_key()
                .to_bytes()
        );

        let mut tampered = second.clone();
        tampered.organization_id = "other-lab".into();
        assert!(apply_approval_log_gossip_observer_key_rotation(&rotated, &tampered).is_err());
        let mut signature_tampered = second.clone();
        signature_tampered.new_signature = "0".repeat(128);
        assert!(
            apply_approval_log_gossip_observer_key_rotation(&rotated, &signature_tampered).is_err()
        );
        let mut fork = second.clone();
        fork.previous_rotation_sha256 = Some("0".repeat(64));
        assert!(apply_approval_log_gossip_observer_key_rotation(&rotated, &fork).is_err());
        assert!(
            sign_approval_log_gossip_observer_key_rotation(
                &rotated,
                &old_secret,
                &final_secret,
                2_000,
            )
            .is_err()
        );
        assert!(
            sign_approval_log_gossip_observer_key_rotation(
                &rotated,
                &next_secret,
                &next_secret,
                2_000,
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed_and_identity_bound() {
        assert_eq!(
            approval_log_gossip_observer_trust_state_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            signed_approval_log_gossip_observer_key_rotation_json_schema()["additionalProperties"],
            false
        );
        let quorum = approval_log_gossip_trust_bound_quorum_report_json_schema();
        assert_eq!(quorum["additionalProperties"], false);
        assert_eq!(
            quorum["properties"]["observer_trust"]["items"]["additionalProperties"],
            false
        );
    }
}
