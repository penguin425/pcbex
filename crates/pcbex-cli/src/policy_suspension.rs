use crate::policy_incident_ledger::{
    PolicyIncidentLedger, PolicyIncidentRevisionMetric, validate_policy_incident_ledger,
};
use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const SIGNED_POLICY_SUSPENSION_DECISION_SCHEMA_VERSION: u32 = 1;
pub const POLICY_SUSPENSION_STATE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-suspension-decision-v1";
const MAXIMUM_DECISIONS: usize = 100;
const MAXIMUM_REVIEW_WINDOW_SECONDS: u64 = 86_400;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySuspensionDecision {
    Suspend,
    Continue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicySuspensionDecision {
    pub schema_version: u32,
    pub ledger_sha256: String,
    pub ledger_head_sha256: String,
    pub policy_pack_id: String,
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub incidents: u32,
    pub suspension_threshold: u32,
    pub decision: PolicySuspensionDecision,
    pub decided_at_unix: u64,
    pub reason: String,
    pub ticket: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySuspensionDecisionMember {
    pub signer_id: String,
    pub public_key: String,
    pub decision_sha256: String,
    pub decided_at_unix: u64,
    pub reason: String,
    pub ticket: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySuspensionState {
    pub schema_version: u32,
    pub status: String,
    pub policy_pack_id: String,
    pub failed_revision: u32,
    pub failed_policy_pack_sha256: String,
    pub incidents: u32,
    pub suspension_threshold: u32,
    pub ledger_sha256: String,
    pub ledger_head_sha256: String,
    pub decision: PolicySuspensionDecision,
    pub policy_suspended: bool,
    pub automatic_policy_suspension: bool,
    pub minimum_decisions: u32,
    pub decisions: u32,
    pub members: Vec<PolicySuspensionDecisionMember>,
    pub signed_decisions: Vec<SignedPolicySuspensionDecision>,
    pub recorded_at_unix: u64,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    ledger_sha256: &'a str,
    ledger_head_sha256: &'a str,
    policy_pack_id: &'a str,
    failed_revision: u32,
    failed_policy_pack_sha256: &'a str,
    incidents: u32,
    suspension_threshold: u32,
    decision: PolicySuspensionDecision,
    decided_at_unix: u64,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy_suspension_decision(
    ledger: &PolicyIncidentLedger,
    failed_revision: u32,
    failed_policy_pack_sha256: &str,
    decision: PolicySuspensionDecision,
    decided_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedPolicySuspensionDecision, String> {
    let candidate = suspension_candidate(ledger, failed_revision, failed_policy_pack_sha256)?;
    validate_review_time(ledger, decided_at_unix)?;
    validate_text(reason, MAXIMUM_TEXT_BYTES, "policy suspension reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "policy suspension ticket")?;
    validate_slug(signer_id)?;
    let ledger_sha256 = normalized_sha256(ledger, "policy incident ledger")?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = signature_payload(
        &ledger_sha256,
        ledger,
        candidate,
        decision,
        decided_at_unix,
        reason,
        ticket,
        signer_id,
    )?;
    let signed = SignedPolicySuspensionDecision {
        schema_version: SIGNED_POLICY_SUSPENSION_DECISION_SCHEMA_VERSION,
        ledger_sha256,
        ledger_head_sha256: ledger.head_sha256.clone(),
        policy_pack_id: ledger.policy_pack_id.clone(),
        failed_revision,
        failed_policy_pack_sha256: failed_policy_pack_sha256.into(),
        incidents: candidate.incidents,
        suspension_threshold: ledger.suspension_threshold,
        decision,
        decided_at_unix,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_suspension_decision(&signed)?;
    Ok(signed)
}

pub fn apply_policy_suspension_decision(
    ledger: &PolicyIncidentLedger,
    trust_policy_pack: &OrganizationPolicyPack,
    failed_revision: u32,
    failed_policy_pack_sha256: &str,
    decisions: &[SignedPolicySuspensionDecision],
    minimum_decisions: u32,
    recorded_at_unix: u64,
) -> Result<PolicySuspensionState, String> {
    let candidate = suspension_candidate(ledger, failed_revision, failed_policy_pack_sha256)?;
    validate_policy_pack(trust_policy_pack)?;
    if trust_policy_pack.id != ledger.policy_pack_id {
        return Err("policy suspension trust policy has a different identity".into());
    }
    if !(2..=MAXIMUM_DECISIONS as u32).contains(&minimum_decisions)
        || decisions.is_empty()
        || decisions.len() > MAXIMUM_DECISIONS
    {
        return Err("policy suspension requires 1 to 100 decisions and a minimum of 2".into());
    }
    validate_review_time(ledger, recorded_at_unix)?;
    let ledger_sha256 = normalized_sha256(ledger, "policy incident ledger")?;
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut unanimous = None;
    let mut members = Vec::with_capacity(decisions.len());
    for signed in decisions {
        validate_signed_policy_suspension_decision(signed)?;
        if signed.ledger_sha256 != ledger_sha256
            || signed.ledger_head_sha256 != ledger.head_sha256
            || signed.policy_pack_id != ledger.policy_pack_id
            || signed.failed_revision != failed_revision
            || signed.failed_policy_pack_sha256 != failed_policy_pack_sha256
            || signed.incidents != candidate.incidents
            || signed.suspension_threshold != ledger.suspension_threshold
        {
            return Err(
                "policy suspension decision is bound to different incident evidence".into(),
            );
        }
        if signed.decided_at_unix > recorded_at_unix {
            return Err("policy suspension decision is newer than the retained state".into());
        }
        validate_review_time(ledger, signed.decided_at_unix)?;
        if unanimous
            .replace(signed.decision)
            .is_some_and(|value| value != signed.decision)
        {
            return Err("policy suspension decisions are not unanimous".into());
        }
        let trusted = trust_policy_pack
            .trusted_human_escalation_keys
            .iter()
            .find(|trusted| trusted.signer_id == signed.signer_id)
            .ok_or_else(|| {
                format!(
                    "policy suspension signer {:?} is not trusted",
                    signed.signer_id
                )
            })?;
        verify_signature(
            signed,
            &decode_hex_array::<32>(&trusted.public_key, "trusted policy suspension key")?,
        )?;
        if !signer_ids.insert(signed.signer_id.as_str())
            || !public_keys.insert(signed.public_key.as_str())
        {
            return Err("policy suspension decisions require distinct signer IDs and keys".into());
        }
        members.push(PolicySuspensionDecisionMember {
            signer_id: signed.signer_id.clone(),
            public_key: signed.public_key.clone(),
            decision_sha256: normalized_sha256(signed, "policy suspension decision")?,
            decided_at_unix: signed.decided_at_unix,
            reason: signed.reason.clone(),
            ticket: signed.ticket.clone(),
        });
    }
    if members.len() < minimum_decisions as usize {
        return Err("policy suspension did not receive the required dual-control quorum".into());
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let mut retained_decisions = decisions.to_vec();
    retained_decisions.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let decision = unanimous.ok_or_else(|| "policy suspension has no decision".to_string())?;
    let policy_suspended = decision == PolicySuspensionDecision::Suspend;
    let state = PolicySuspensionState {
        schema_version: POLICY_SUSPENSION_STATE_SCHEMA_VERSION,
        status: if policy_suspended {
            "policy_suspended"
        } else {
            "continued_under_review"
        }
        .into(),
        policy_pack_id: ledger.policy_pack_id.clone(),
        failed_revision,
        failed_policy_pack_sha256: failed_policy_pack_sha256.into(),
        incidents: candidate.incidents,
        suspension_threshold: ledger.suspension_threshold,
        ledger_sha256,
        ledger_head_sha256: ledger.head_sha256.clone(),
        decision,
        policy_suspended,
        automatic_policy_suspension: false,
        minimum_decisions,
        decisions: members.len() as u32,
        members,
        signed_decisions: retained_decisions,
        recorded_at_unix,
    };
    validate_policy_suspension_state(&state)?;
    Ok(state)
}

pub fn enforce_policy_suspensions(
    candidate: &OrganizationPolicyPack,
    states: &[PolicySuspensionState],
) -> Result<(), String> {
    validate_policy_pack(candidate)?;
    let digest = normalized_sha256(candidate, "candidate policy pack")?;
    for state in states {
        validate_policy_suspension_state(state)?;
        if state.policy_pack_id != candidate.id {
            continue;
        }
        for signed in &state.signed_decisions {
            let trusted = candidate
                .trusted_human_escalation_keys
                .iter()
                .find(|trusted| trusted.signer_id == signed.signer_id)
                .ok_or_else(|| {
                    format!(
                        "policy suspension signer {:?} is not trusted by the candidate",
                        signed.signer_id
                    )
                })?;
            verify_signature(
                signed,
                &decode_hex_array::<32>(&trusted.public_key, "trusted policy suspension key")?,
            )?;
        }
        if state.failed_policy_pack_sha256 == digest && state.policy_suspended {
            return Err(format!(
                "candidate policy revision {} digest {} is suspended by incident decision {}",
                candidate.revision, digest, state.ledger_head_sha256
            ));
        }
    }
    Ok(())
}

pub fn parse_signed_policy_suspension_decision(
    source: &str,
) -> Result<SignedPolicySuspensionDecision, String> {
    let signed = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed policy suspension decision JSON: {error}"))?;
    validate_signed_policy_suspension_decision(&signed)?;
    Ok(signed)
}

pub fn parse_policy_suspension_state(source: &str) -> Result<PolicySuspensionState, String> {
    let state = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy suspension state JSON: {error}"))?;
    validate_policy_suspension_state(&state)?;
    Ok(state)
}

pub fn validate_signed_policy_suspension_decision(
    signed: &SignedPolicySuspensionDecision,
) -> Result<(), String> {
    if signed.schema_version != SIGNED_POLICY_SUSPENSION_DECISION_SCHEMA_VERSION
        || signed.algorithm != "ed25519"
        || signed.incidents < signed.suspension_threshold
        || signed.suspension_threshold < 2
    {
        return Err("invalid signed policy suspension decision invariants".into());
    }
    validate_slug(&signed.policy_pack_id)?;
    validate_slug(&signed.signer_id)?;
    validate_text(
        &signed.reason,
        MAXIMUM_TEXT_BYTES,
        "policy suspension reason",
    )?;
    validate_text(
        &signed.ticket,
        MAXIMUM_TICKET_BYTES,
        "policy suspension ticket",
    )?;
    for digest in [
        &signed.ledger_sha256,
        &signed.ledger_head_sha256,
        &signed.failed_policy_pack_sha256,
    ] {
        validate_hex(digest, 32)?;
    }
    validate_hex(&signed.public_key, 32)?;
    validate_hex(&signed.signature, 64)
}

pub fn validate_policy_suspension_state(state: &PolicySuspensionState) -> Result<(), String> {
    if state.schema_version != POLICY_SUSPENSION_STATE_SCHEMA_VERSION
        || state.incidents < state.suspension_threshold
        || state.suspension_threshold < 2
        || state.minimum_decisions < 2
        || state.decisions != state.members.len() as u32
        || state.decisions != state.signed_decisions.len() as u32
        || state.decisions < state.minimum_decisions
        || state.automatic_policy_suspension
        || state.policy_suspended != (state.decision == PolicySuspensionDecision::Suspend)
        || state.status
            != if state.policy_suspended {
                "policy_suspended"
            } else {
                "continued_under_review"
            }
    {
        return Err("invalid policy suspension state invariants".into());
    }
    validate_slug(&state.policy_pack_id)?;
    for digest in [
        &state.ledger_sha256,
        &state.ledger_head_sha256,
        &state.failed_policy_pack_sha256,
    ] {
        validate_hex(digest, 32)?;
    }
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for (member, signed) in state.members.iter().zip(&state.signed_decisions) {
        validate_signed_policy_suspension_decision(signed)?;
        validate_slug(&member.signer_id)?;
        validate_hex(&member.public_key, 32)?;
        validate_hex(&member.decision_sha256, 32)?;
        validate_text(
            &member.reason,
            MAXIMUM_TEXT_BYTES,
            "policy suspension reason",
        )?;
        validate_text(
            &member.ticket,
            MAXIMUM_TICKET_BYTES,
            "policy suspension ticket",
        )?;
        if member.decided_at_unix > state.recorded_at_unix
            || signed.signer_id != member.signer_id
            || signed.public_key != member.public_key
            || signed.decision != state.decision
            || signed.ledger_sha256 != state.ledger_sha256
            || signed.ledger_head_sha256 != state.ledger_head_sha256
            || signed.policy_pack_id != state.policy_pack_id
            || signed.failed_revision != state.failed_revision
            || signed.failed_policy_pack_sha256 != state.failed_policy_pack_sha256
            || signed.incidents != state.incidents
            || signed.suspension_threshold != state.suspension_threshold
            || normalized_sha256(signed, "policy suspension decision")? != member.decision_sha256
            || !signer_ids.insert(member.signer_id.as_str())
            || !public_keys.insert(member.public_key.as_str())
        {
            return Err("policy suspension state contains invalid decision members".into());
        }
    }
    Ok(())
}

pub fn signed_policy_suspension_decision_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Signed pcbex policy suspension decision",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "ledger_sha256", "ledger_head_sha256", "policy_pack_id",
            "failed_revision", "failed_policy_pack_sha256", "incidents", "suspension_threshold",
            "decision", "decided_at_unix", "reason", "ticket", "signer_id", "algorithm",
            "public_key", "signature"],
        "properties": {
            "schema_version": {"const": 1},
            "ledger_sha256": digest_schema(),
            "ledger_head_sha256": digest_schema(),
            "policy_pack_id": slug_schema(),
            "failed_revision": {"type": "integer", "minimum": 1},
            "failed_policy_pack_sha256": digest_schema(),
            "incidents": {"type": "integer", "minimum": 2},
            "suspension_threshold": {"type": "integer", "minimum": 2, "maximum": 100},
            "decision": {"enum": ["suspend", "continue"]},
            "decided_at_unix": {"type": "integer", "minimum": 1},
            "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
            "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
            "signer_id": slug_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn policy_suspension_state_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "pcbex policy suspension state",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "status", "policy_pack_id", "failed_revision",
            "failed_policy_pack_sha256", "incidents", "suspension_threshold", "ledger_sha256",
            "ledger_head_sha256", "decision", "policy_suspended", "automatic_policy_suspension",
            "minimum_decisions", "decisions", "members", "signed_decisions", "recorded_at_unix"],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"enum": ["policy_suspended", "continued_under_review"]},
            "policy_pack_id": slug_schema(),
            "failed_revision": {"type": "integer", "minimum": 1},
            "failed_policy_pack_sha256": digest_schema(),
            "incidents": {"type": "integer", "minimum": 2},
            "suspension_threshold": {"type": "integer", "minimum": 2, "maximum": 100},
            "ledger_sha256": digest_schema(),
            "ledger_head_sha256": digest_schema(),
            "decision": {"enum": ["suspend", "continue"]},
            "policy_suspended": {"type": "boolean"},
            "automatic_policy_suspension": {"const": false},
            "minimum_decisions": {"type": "integer", "minimum": 2, "maximum": 100},
            "decisions": {"type": "integer", "minimum": 2, "maximum": 100},
            "members": {
                "type": "array", "minItems": 2, "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["signer_id", "public_key", "decision_sha256", "decided_at_unix", "reason", "ticket"],
                    "properties": {
                        "signer_id": slug_schema(),
                        "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "decision_sha256": digest_schema(),
                        "decided_at_unix": {"type": "integer", "minimum": 1},
                        "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "ticket": {"type": "string", "minLength": 1, "maxLength": 256}
                    }
                }
            },
            "signed_decisions": {
                "type": "array", "minItems": 2, "maxItems": 100,
                "items": signed_policy_suspension_decision_json_schema()
            },
            "recorded_at_unix": {"type": "integer", "minimum": 1}
        }
    })
}

pub fn render_policy_suspension_summary(state: &PolicySuspensionState) -> String {
    format!(
        "## pcbex policy suspension decision\n\n\
         - Status: `{}`\n\
         - Failed policy: revision `{}` / `{}`\n\
         - Incidents: `{}` (threshold `{}`)\n\
         - Trusted decisions: `{}` / `{}` required\n\
         - Policy suspended: `{}`\n\
         - Automatic suspension: `false`\n",
        state.status,
        state.failed_revision,
        state.failed_policy_pack_sha256,
        state.incidents,
        state.suspension_threshold,
        state.decisions,
        state.minimum_decisions,
        state.policy_suspended
    )
}

fn suspension_candidate<'a>(
    ledger: &'a PolicyIncidentLedger,
    revision: u32,
    digest: &str,
) -> Result<&'a PolicyIncidentRevisionMetric, String> {
    validate_policy_incident_ledger(ledger)?;
    ledger
        .suspension_candidates
        .iter()
        .find(|candidate| {
            candidate.failed_revision == revision && candidate.failed_policy_pack_sha256 == digest
        })
        .ok_or_else(|| "requested policy revision is not a suspension candidate".into())
}

fn validate_review_time(ledger: &PolicyIncidentLedger, time: u64) -> Result<(), String> {
    let latest = ledger
        .entries
        .iter()
        .map(|entry| entry.closed_at_unix)
        .max()
        .ok_or_else(|| "policy incident ledger has no incidents".to_string())?;
    if time < latest || time > latest.saturating_add(MAXIMUM_REVIEW_WINDOW_SECONDS) {
        return Err("policy suspension decision is outside the bounded review window".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn signature_payload(
    ledger_sha256: &str,
    ledger: &PolicyIncidentLedger,
    candidate: &PolicyIncidentRevisionMetric,
    decision: PolicySuspensionDecision,
    decided_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        ledger_sha256,
        ledger_head_sha256: &ledger.head_sha256,
        policy_pack_id: &ledger.policy_pack_id,
        failed_revision: candidate.failed_revision,
        failed_policy_pack_sha256: &candidate.failed_policy_pack_sha256,
        incidents: candidate.incidents,
        suspension_threshold: ledger.suspension_threshold,
        decision,
        decided_at_unix,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("failed to encode policy suspension signature payload: {error}"))
}

fn verify_signature(
    signed: &SignedPolicySuspensionDecision,
    trusted_key: &[u8; 32],
) -> Result<(), String> {
    if signed.public_key != hex_encode(trusted_key) {
        return Err("policy suspension decision embeds a different public key".into());
    }
    let verifying_key = VerifyingKey::from_bytes(trusted_key)
        .map_err(|error| format!("invalid policy suspension public key: {error}"))?;
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &signed.signature,
        "policy suspension signature",
    )?);
    let payload = serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        ledger_sha256: &signed.ledger_sha256,
        ledger_head_sha256: &signed.ledger_head_sha256,
        policy_pack_id: &signed.policy_pack_id,
        failed_revision: signed.failed_revision,
        failed_policy_pack_sha256: &signed.failed_policy_pack_sha256,
        incidents: signed.incidents,
        suspension_threshold: signed.suspension_threshold,
        decision: signed.decision,
        decided_at_unix: signed.decided_at_unix,
        reason: &signed.reason,
        ticket: &signed.ticket,
        signer_id: &signed.signer_id,
    })
    .map_err(|error| format!("failed to encode policy suspension signature payload: {error}"))?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| "policy suspension signature verification failed".into())
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("failed to encode {label}: {error}"))?;
    Ok(hex_encode(&Sha256::digest(bytes)))
}

fn validate_slug(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("policy suspension identity must be a non-empty safe identifier".into());
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(format!(
            "{label} must be non-empty and at most {maximum} bytes"
        ));
    }
    Ok(())
}

fn validate_hex(value: &str, bytes: usize) -> Result<(), String> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("expected {} lowercase hexadecimal bytes", bytes));
    }
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    validate_hex(value, N).map_err(|error| format!("invalid {label}: {error}"))?;
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("invalid {label}: {error}"))?;
    }
    Ok(output)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9_.-]+$"})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_incident_ledger::{
        repeated_incident_test_ledger, repeated_incident_test_ledger_for_digest,
    };
    use crate::policy_pack::{TrustedApprovalKey, parse_policy_pack};

    fn trust_pack(keys: &[(&str, [u8; 32])]) -> OrganizationPolicyPack {
        let mut pack =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        pack.trusted_human_escalation_keys = keys
            .iter()
            .map(|(signer_id, key)| TrustedApprovalKey {
                signer_id: (*signer_id).into(),
                public_key: hex_encode(&SigningKey::from_bytes(key).verifying_key().to_bytes()),
            })
            .collect();
        validate_policy_pack(&pack).unwrap();
        pack
    }

    #[test]
    fn schemas_are_closed() {
        assert_eq!(
            signed_policy_suspension_decision_json_schema()["additionalProperties"],
            false
        );
        let state = policy_suspension_state_json_schema();
        assert_eq!(state["additionalProperties"], false);
        assert_eq!(
            state["properties"]["members"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            state["properties"]["signed_decisions"]["items"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn dual_control_suspends_exact_digest_and_rejects_tampering() {
        let key_a = [7_u8; 32];
        let key_b = [8_u8; 32];
        let policy = trust_pack(&[("reviewer-a", key_a), ("reviewer-b", key_b)]);
        let digest = normalized_sha256(&policy, "candidate").unwrap();
        let ledger = repeated_incident_test_ledger_for_digest(digest.clone());
        let decisions =
            [("reviewer-a", key_a, 209), ("reviewer-b", key_b, 210)].map(|(signer, key, time)| {
                sign_policy_suspension_decision(
                    &ledger,
                    3,
                    &digest,
                    PolicySuspensionDecision::Suspend,
                    time,
                    "Repeated production regression",
                    "HW-3",
                    signer,
                    &key,
                )
                .unwrap()
            });
        let state =
            apply_policy_suspension_decision(&ledger, &policy, 3, &digest, &decisions, 2, 211)
                .unwrap();
        assert!(state.policy_suspended);
        assert!(!state.automatic_policy_suspension);
        assert_eq!(state.decisions, 2);
        assert!(
            enforce_policy_suspensions(&policy, std::slice::from_ref(&state))
                .unwrap_err()
                .contains("is suspended")
        );

        let mut tampered = state.clone();
        tampered.failed_policy_pack_sha256 = std::iter::repeat_n('4', 64).collect();
        assert!(validate_policy_suspension_state(&tampered).is_err());

        let mut mixed = decisions;
        mixed[1] = sign_policy_suspension_decision(
            &ledger,
            3,
            &digest,
            PolicySuspensionDecision::Continue,
            210,
            "Continue observation",
            "HW-3",
            "reviewer-b",
            &key_b,
        )
        .unwrap();
        assert!(
            apply_policy_suspension_decision(&ledger, &policy, 3, &digest, &mixed, 2, 211)
                .unwrap_err()
                .contains("unanimous")
        );
    }

    #[test]
    fn signing_rejects_non_candidate_and_stale_review() {
        let ledger = repeated_incident_test_ledger();
        let digest = std::iter::repeat_n('3', 64).collect::<String>();
        assert!(
            sign_policy_suspension_decision(
                &ledger,
                4,
                &digest,
                PolicySuspensionDecision::Suspend,
                209,
                "Wrong candidate",
                "HW-4",
                "reviewer-a",
                &[7_u8; 32],
            )
            .unwrap_err()
            .contains("not a suspension candidate")
        );
        assert!(
            sign_policy_suspension_decision(
                &ledger,
                3,
                &digest,
                PolicySuspensionDecision::Suspend,
                207,
                "Stale review",
                "HW-3",
                "reviewer-a",
                &[7_u8; 32],
            )
            .unwrap_err()
            .contains("review window")
        );
    }
}
