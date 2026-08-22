use crate::policy_deployment::{
    PolicyDeploymentState, PolicyDeploymentStatus, validate_policy_deployment_state,
};
use crate::policy_deployment_verification::{
    PolicyDeploymentVerificationReport, validate_policy_deployment_verification,
};
use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const SIGNED_DEPLOYMENT_ROLLBACK_SCHEMA_VERSION: u32 = 1;
pub const DEPLOYMENT_ROLLBACK_STATE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-deployment-rollback-v1";
const MAXIMUM_APPROVALS: usize = 100;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;
const MAXIMUM_ROLLBACK_WINDOW_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyDeploymentRollback {
    pub schema_version: u32,
    pub deployment_state_sha256: String,
    pub verification_sha256: String,
    pub policy_pack_id: String,
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub restore_revision: u32,
    pub restore_policy_pack_sha256: String,
    pub approved_at_unix: u64,
    pub reason: String,
    pub ticket: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeploymentRollbackMember {
    pub signer_id: String,
    pub public_key: String,
    pub approval_sha256: String,
    pub approved_at_unix: u64,
    pub reason: String,
    pub ticket: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeploymentRollbackState {
    pub schema_version: u32,
    pub status: String,
    pub generation: u64,
    pub policy_pack_id: String,
    pub active_revision: u32,
    pub active_policy_pack_sha256: String,
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub highest_considered_revision: u32,
    pub highest_considered_policy_pack_sha256: String,
    pub deployment_state_sha256: String,
    pub verification_sha256: String,
    pub minimum_approvals: u32,
    pub approvals: u32,
    pub members: Vec<PolicyDeploymentRollbackMember>,
    pub rollback_applied: bool,
    pub automatic_rollback: bool,
    pub recorded_at_unix: u64,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    deployment_state_sha256: &'a str,
    verification_sha256: &'a str,
    policy_pack_id: &'a str,
    failed_revision: u32,
    failed_policy_pack_sha256: &'a str,
    restore_revision: u32,
    restore_policy_pack_sha256: &'a str,
    approved_at_unix: u64,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

pub fn sign_policy_deployment_rollback(
    deployment: &PolicyDeploymentState,
    verification: &PolicyDeploymentVerificationReport,
    approved_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedPolicyDeploymentRollback, String> {
    let binding = rollback_binding(deployment, verification)?;
    if approved_at_unix < verification.verified_at_unix
        || approved_at_unix
            > verification
                .verified_at_unix
                .saturating_add(MAXIMUM_ROLLBACK_WINDOW_SECONDS)
    {
        return Err("deployment rollback approval is outside the bounded review window".into());
    }
    validate_text(reason, MAXIMUM_TEXT_BYTES, "deployment rollback reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "deployment rollback ticket")?;
    validate_slug("deployment rollback signer", signer_id)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = signature_payload(&binding, approved_at_unix, reason, ticket, signer_id)?;
    let approval = SignedPolicyDeploymentRollback {
        schema_version: SIGNED_DEPLOYMENT_ROLLBACK_SCHEMA_VERSION,
        deployment_state_sha256: binding.deployment_state_sha256,
        verification_sha256: binding.verification_sha256,
        policy_pack_id: deployment.policy_pack_id.clone(),
        failed_revision: deployment.active_revision,
        failed_policy_pack_sha256: deployment.active_policy_pack_sha256.clone(),
        restore_revision: binding.restore_revision,
        restore_policy_pack_sha256: binding.restore_policy_pack_sha256,
        approved_at_unix,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_deployment_rollback(&approval)?;
    Ok(approval)
}

pub fn apply_policy_deployment_rollback(
    deployment: &PolicyDeploymentState,
    verification: &PolicyDeploymentVerificationReport,
    active_policy_pack: &OrganizationPolicyPack,
    approvals: &[SignedPolicyDeploymentRollback],
    minimum_approvals: u32,
    recorded_at_unix: u64,
) -> Result<PolicyDeploymentRollbackState, String> {
    let binding = rollback_binding(deployment, verification)?;
    validate_policy_pack(active_policy_pack)?;
    if active_policy_pack.id != deployment.policy_pack_id
        || active_policy_pack.revision != deployment.active_revision
        || normalized_sha256(active_policy_pack, "active policy pack")?
            != deployment.active_policy_pack_sha256
    {
        return Err(
            "deployment rollback trust policy does not match the failed active pack".into(),
        );
    }
    if !(2..=MAXIMUM_APPROVALS as u32).contains(&minimum_approvals)
        || approvals.is_empty()
        || approvals.len() > MAXIMUM_APPROVALS
    {
        return Err("deployment rollback requires 1 to 100 approvals and a minimum of 2".into());
    }
    if recorded_at_unix < verification.verified_at_unix
        || recorded_at_unix
            > verification
                .verified_at_unix
                .saturating_add(MAXIMUM_ROLLBACK_WINDOW_SECONDS)
    {
        return Err("deployment rollback is outside the bounded review window".into());
    }
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut members = Vec::with_capacity(approvals.len());
    for approval in approvals {
        validate_signed_policy_deployment_rollback(approval)?;
        if approval.deployment_state_sha256 != binding.deployment_state_sha256
            || approval.verification_sha256 != binding.verification_sha256
            || approval.policy_pack_id != deployment.policy_pack_id
            || approval.failed_revision != deployment.active_revision
            || approval.failed_policy_pack_sha256 != deployment.active_policy_pack_sha256
            || approval.restore_revision != binding.restore_revision
            || approval.restore_policy_pack_sha256 != binding.restore_policy_pack_sha256
        {
            return Err("deployment rollback approval is bound to different evidence".into());
        }
        if approval.approved_at_unix < verification.verified_at_unix
            || approval.approved_at_unix
                > verification
                    .verified_at_unix
                    .saturating_add(MAXIMUM_ROLLBACK_WINDOW_SECONDS)
            || approval.approved_at_unix > recorded_at_unix
        {
            return Err(
                "deployment rollback approval is outside the retained review window".into(),
            );
        }
        let trusted = active_policy_pack
            .trusted_human_escalation_keys
            .iter()
            .find(|trusted| trusted.signer_id == approval.signer_id)
            .ok_or_else(|| {
                format!(
                    "deployment rollback signer {:?} is not trusted",
                    approval.signer_id
                )
            })?;
        verify_signature(
            approval,
            &decode_hex_array::<32>(&trusted.public_key, "trusted deployment rollback key")?,
        )?;
        if !signer_ids.insert(approval.signer_id.as_str())
            || !public_keys.insert(approval.public_key.as_str())
        {
            return Err(
                "deployment rollback approvals require distinct signer IDs and keys".into(),
            );
        }
        members.push(PolicyDeploymentRollbackMember {
            signer_id: approval.signer_id.clone(),
            public_key: approval.public_key.clone(),
            approval_sha256: normalized_sha256(approval, "deployment rollback approval")?,
            approved_at_unix: approval.approved_at_unix,
            reason: approval.reason.clone(),
            ticket: approval.ticket.clone(),
        });
    }
    if members.len() < minimum_approvals as usize {
        return Err("deployment rollback did not receive the required dual-control quorum".into());
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let state = PolicyDeploymentRollbackState {
        schema_version: DEPLOYMENT_ROLLBACK_STATE_SCHEMA_VERSION,
        status: "rollback_applied".into(),
        generation: deployment
            .generation
            .checked_add(1)
            .ok_or_else(|| "deployment rollback generation overflowed".to_string())?,
        policy_pack_id: deployment.policy_pack_id.clone(),
        active_revision: binding.restore_revision,
        active_policy_pack_sha256: binding.restore_policy_pack_sha256,
        failed_revision: deployment.active_revision,
        failed_policy_pack_sha256: deployment.active_policy_pack_sha256.clone(),
        highest_considered_revision: deployment.highest_considered_revision,
        highest_considered_policy_pack_sha256: deployment
            .highest_considered_policy_pack_sha256
            .clone(),
        deployment_state_sha256: binding.deployment_state_sha256,
        verification_sha256: binding.verification_sha256,
        minimum_approvals,
        approvals: members.len() as u32,
        members,
        rollback_applied: true,
        automatic_rollback: false,
        recorded_at_unix,
    };
    validate_policy_deployment_rollback_state(&state)?;
    Ok(state)
}

struct RollbackBinding {
    deployment_state_sha256: String,
    verification_sha256: String,
    policy_pack_id: String,
    failed_revision: u32,
    failed_policy_pack_sha256: String,
    restore_revision: u32,
    restore_policy_pack_sha256: String,
}

fn rollback_binding(
    deployment: &PolicyDeploymentState,
    verification: &PolicyDeploymentVerificationReport,
) -> Result<RollbackBinding, String> {
    validate_policy_deployment_state(deployment)?;
    validate_policy_deployment_verification(verification)?;
    if deployment.status != PolicyDeploymentStatus::PromotionApplied
        || !deployment.deployment_applied
        || verification.deployment_verified
        || !verification.rollback_required
        || !verification.requires_dual_control_rollback
        || verification.automatic_rollback
    {
        return Err("deployment rollback requires failed production verification".into());
    }
    let deployment_state_sha256 = normalized_sha256(deployment, "policy deployment state")?;
    if verification.deployment_state_sha256 != deployment_state_sha256
        || verification.policy_pack_id != deployment.policy_pack_id
        || verification.active_revision != deployment.active_revision
        || verification.active_policy_pack_sha256 != deployment.active_policy_pack_sha256
    {
        return Err("deployment rollback verification is bound to a different state".into());
    }
    let restore_revision = deployment
        .rollback_revision
        .ok_or_else(|| "deployment rollback has no previously active revision".to_string())?;
    let restore_policy_pack_sha256 = deployment
        .rollback_policy_pack_sha256
        .clone()
        .ok_or_else(|| "deployment rollback has no previously active policy digest".to_string())?;
    if restore_revision >= deployment.active_revision {
        return Err("deployment rollback target is not older than the failed revision".into());
    }
    Ok(RollbackBinding {
        deployment_state_sha256,
        verification_sha256: normalized_sha256(verification, "policy deployment verification")?,
        policy_pack_id: deployment.policy_pack_id.clone(),
        failed_revision: deployment.active_revision,
        failed_policy_pack_sha256: deployment.active_policy_pack_sha256.clone(),
        restore_revision,
        restore_policy_pack_sha256,
    })
}

pub fn parse_signed_policy_deployment_rollback(
    source: &str,
) -> Result<SignedPolicyDeploymentRollback, String> {
    let approval: SignedPolicyDeploymentRollback = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed deployment rollback JSON: {error}"))?;
    validate_signed_policy_deployment_rollback(&approval)?;
    Ok(approval)
}

pub fn parse_policy_deployment_rollback_state(
    source: &str,
) -> Result<PolicyDeploymentRollbackState, String> {
    let state: PolicyDeploymentRollbackState = serde_json::from_str(source)
        .map_err(|error| format!("invalid deployment rollback state JSON: {error}"))?;
    validate_policy_deployment_rollback_state(&state)?;
    Ok(state)
}

pub fn validate_signed_policy_deployment_rollback(
    approval: &SignedPolicyDeploymentRollback,
) -> Result<(), String> {
    if approval.schema_version != SIGNED_DEPLOYMENT_ROLLBACK_SCHEMA_VERSION
        || approval.algorithm != "ed25519"
        || approval.failed_revision == 0
        || approval.restore_revision == 0
        || approval.restore_revision >= approval.failed_revision
    {
        return Err("signed deployment rollback governance boundary is invalid".into());
    }
    for digest in [
        &approval.deployment_state_sha256,
        &approval.verification_sha256,
        &approval.failed_policy_pack_sha256,
        &approval.restore_policy_pack_sha256,
    ] {
        validate_digest(digest)?;
    }
    validate_slug("policy pack id", &approval.policy_pack_id)?;
    validate_slug("deployment rollback signer", &approval.signer_id)?;
    validate_text(
        &approval.reason,
        MAXIMUM_TEXT_BYTES,
        "deployment rollback reason",
    )?;
    validate_text(
        &approval.ticket,
        MAXIMUM_TICKET_BYTES,
        "deployment rollback ticket",
    )?;
    decode_hex_array::<32>(&approval.public_key, "deployment rollback public key")?;
    decode_hex_array::<64>(&approval.signature, "deployment rollback signature")?;
    Ok(())
}

pub fn validate_policy_deployment_rollback_state(
    state: &PolicyDeploymentRollbackState,
) -> Result<(), String> {
    if state.schema_version != DEPLOYMENT_ROLLBACK_STATE_SCHEMA_VERSION
        || state.status != "rollback_applied"
        || !state.rollback_applied
        || state.automatic_rollback
        || state.generation < 2
        || state.active_revision == 0
        || state.failed_revision <= state.active_revision
        || state.highest_considered_revision != state.failed_revision
        || state.highest_considered_policy_pack_sha256 != state.failed_policy_pack_sha256
        || state.approvals != state.members.len() as u32
        || !(2..=MAXIMUM_APPROVALS as u32).contains(&state.minimum_approvals)
        || state.approvals < state.minimum_approvals
        || state.members.len() > MAXIMUM_APPROVALS
    {
        return Err("deployment rollback state governance boundary is invalid".into());
    }
    validate_slug("policy pack id", &state.policy_pack_id)?;
    for digest in [
        &state.active_policy_pack_sha256,
        &state.failed_policy_pack_sha256,
        &state.highest_considered_policy_pack_sha256,
        &state.deployment_state_sha256,
        &state.verification_sha256,
    ] {
        validate_digest(digest)?;
    }
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for member in &state.members {
        validate_slug("deployment rollback member", &member.signer_id)?;
        decode_hex_array::<32>(&member.public_key, "deployment rollback member key")?;
        validate_digest(&member.approval_sha256)?;
        validate_text(
            &member.reason,
            MAXIMUM_TEXT_BYTES,
            "deployment rollback reason",
        )?;
        validate_text(
            &member.ticket,
            MAXIMUM_TICKET_BYTES,
            "deployment rollback ticket",
        )?;
        if member.approved_at_unix > state.recorded_at_unix
            || !signer_ids.insert(member.signer_id.as_str())
            || !public_keys.insert(member.public_key.as_str())
        {
            return Err("deployment rollback members are invalid".into());
        }
    }
    if state
        .members
        .windows(2)
        .any(|members| members[0].signer_id >= members[1].signer_id)
    {
        return Err("deployment rollback members are not sorted".into());
    }
    Ok(())
}

pub fn render_policy_deployment_rollback_summary(state: &PolicyDeploymentRollbackState) -> String {
    let mut summary = format!(
        "# Policy deployment rollback\n\n\
         **Result:** `rollback_applied`\n\n\
         - Restored revision: `{}`\n\
         - Failed revision: `{}`\n\
         - Approvals: `{}/{}`\n\
         - Automatic rollback: `false`\n",
        state.active_revision, state.failed_revision, state.approvals, state.minimum_approvals
    );
    let _ = writeln!(
        summary,
        "\n| Signer | Ticket | Approved at |\n|---|---|---:|"
    );
    for member in &state.members {
        let _ = writeln!(
            summary,
            "| `{}` | `{}` | {} |",
            member.signer_id, member.ticket, member.approved_at_unix
        );
    }
    summary
}

pub fn signed_policy_deployment_rollback_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-policy-deployment-rollback-v1.json",
        "title": "pcbex signed policy deployment rollback approval",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "deployment_state_sha256", "verification_sha256",
            "policy_pack_id", "failed_revision", "failed_policy_pack_sha256",
            "restore_revision", "restore_policy_pack_sha256", "approved_at_unix",
            "reason", "ticket", "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_DEPLOYMENT_ROLLBACK_SCHEMA_VERSION},
            "deployment_state_sha256": digest,
            "verification_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "failed_revision": {"type": "integer", "minimum": 2},
            "failed_policy_pack_sha256": digest,
            "restore_revision": {"type": "integer", "minimum": 1},
            "restore_policy_pack_sha256": digest,
            "approved_at_unix": {"type": "integer", "minimum": 0},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES},
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn policy_deployment_rollback_state_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let member = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "signer_id", "public_key", "approval_sha256",
            "approved_at_unix", "reason", "ticket"
        ],
        "properties": {
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "approval_sha256": digest,
            "approved_at_unix": {"type": "integer", "minimum": 0},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-deployment-rollback-state-v1.json",
        "title": "pcbex dual-control policy deployment rollback state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "generation", "policy_pack_id",
            "active_revision", "active_policy_pack_sha256", "failed_revision",
            "failed_policy_pack_sha256", "highest_considered_revision",
            "highest_considered_policy_pack_sha256", "deployment_state_sha256",
            "verification_sha256", "minimum_approvals", "approvals", "members",
            "rollback_applied", "automatic_rollback", "recorded_at_unix"
        ],
        "properties": {
            "schema_version": {"const": DEPLOYMENT_ROLLBACK_STATE_SCHEMA_VERSION},
            "status": {"const": "rollback_applied"},
            "generation": {"type": "integer", "minimum": 2},
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "active_revision": {"type": "integer", "minimum": 1},
            "active_policy_pack_sha256": digest,
            "failed_revision": {"type": "integer", "minimum": 2},
            "failed_policy_pack_sha256": digest,
            "highest_considered_revision": {"type": "integer", "minimum": 2},
            "highest_considered_policy_pack_sha256": digest,
            "deployment_state_sha256": digest,
            "verification_sha256": digest,
            "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": MAXIMUM_APPROVALS},
            "approvals": {"type": "integer", "minimum": 2, "maximum": MAXIMUM_APPROVALS},
            "members": {
                "type": "array", "minItems": 2, "maxItems": MAXIMUM_APPROVALS,
                "items": member
            },
            "rollback_applied": {"const": true},
            "automatic_rollback": {"const": false},
            "recorded_at_unix": {"type": "integer", "minimum": 0}
        }
    })
}

fn verify_signature(
    approval: &SignedPolicyDeploymentRollback,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    let public_key =
        decode_hex_array::<32>(&approval.public_key, "deployment rollback public key")?;
    if &public_key != trusted_public_key {
        return Err("deployment rollback key does not match its trusted key".into());
    }
    let binding = RollbackBinding {
        deployment_state_sha256: approval.deployment_state_sha256.clone(),
        verification_sha256: approval.verification_sha256.clone(),
        policy_pack_id: approval.policy_pack_id.clone(),
        failed_revision: approval.failed_revision,
        failed_policy_pack_sha256: approval.failed_policy_pack_sha256.clone(),
        restore_revision: approval.restore_revision,
        restore_policy_pack_sha256: approval.restore_policy_pack_sha256.clone(),
    };
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &approval.signature,
        "deployment rollback signature",
    )?);
    let payload = signature_payload(
        &binding,
        approval.approved_at_unix,
        &approval.reason,
        &approval.ticket,
        &approval.signer_id,
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid deployment rollback public key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid deployment rollback signature: {error}"))
}

fn signature_payload(
    binding: &RollbackBinding,
    approved_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        deployment_state_sha256: &binding.deployment_state_sha256,
        verification_sha256: &binding.verification_sha256,
        policy_pack_id: &binding.policy_pack_id,
        failed_revision: binding.failed_revision,
        failed_policy_pack_sha256: &binding.failed_policy_pack_sha256,
        restore_revision: binding.restore_revision,
        restore_policy_pack_sha256: &binding.restore_policy_pack_sha256,
        approved_at_unix,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("serializing deployment rollback signature payload: {error}"))
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid lowercase SHA-256 digest".into())
    }
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
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
        Err(format!("{label} is invalid"))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum || value.contains(['\0', '\r']) {
        Err(format!("{label} is invalid"))
    } else {
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} has the wrong length"));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| format!("{label} is not hexadecimal"))?;
        bytes[index] =
            u8::from_str_radix(text, 16).map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_schemas_close_every_object() {
        let signed = signed_policy_deployment_rollback_json_schema();
        assert_eq!(signed["additionalProperties"], false);
        let state = policy_deployment_rollback_state_json_schema();
        assert_eq!(state["additionalProperties"], false);
        assert_eq!(
            state["properties"]["members"]["items"]["additionalProperties"],
            false
        );
    }
}
