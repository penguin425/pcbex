use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use crate::policy_rollout::{
    CanaryMonitoringReport, PolicyRolloutReport, validate_canary_monitoring_report,
    validate_policy_rollout_report,
};
use crate::policy_rollout_approval::{CanaryRolloutAuthorization, validate_canary_authorization};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const SIGNED_CANARY_DECISION_SCHEMA_VERSION: u32 = 1;
pub const CANARY_COMPLETION_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-canary-completion-decision-v1";
const MAXIMUM_SIGNERS: usize = 100;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryCompletionDecision {
    Promote,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCanaryCompletionDecision {
    pub schema_version: u32,
    pub monitoring_sha256: String,
    pub rollout_sha256: String,
    pub authorization_sha256: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub decision: CanaryCompletionDecision,
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
pub struct CanaryCompletionMember {
    pub signer_id: String,
    pub public_key: String,
    pub decision_sha256: String,
    pub decision: CanaryCompletionDecision,
    pub decided_at_unix: u64,
    pub reason: String,
    pub ticket: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryCompletionPolicy {
    pub minimum_decisions: u32,
    pub automatic_promotion: bool,
    pub unanimous_decision_required: bool,
    pub rollback_required_on_monitoring_failure: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryCompletionReport {
    pub schema_version: u32,
    pub status: String,
    pub monitoring_sha256: String,
    pub rollout_sha256: String,
    pub authorization_sha256: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub monitoring_status: String,
    pub promotion_eligible: bool,
    pub rollback_required: bool,
    pub policy: CanaryCompletionPolicy,
    pub promotions: u32,
    pub rollbacks: u32,
    pub members: Vec<CanaryCompletionMember>,
    pub finalized: bool,
    pub final_decision: Option<CanaryCompletionDecision>,
    pub gate_failures: Vec<String>,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    monitoring_sha256: &'a str,
    rollout_sha256: &'a str,
    authorization_sha256: &'a str,
    policy_pack_id: &'a str,
    policy_pack_revision: u32,
    decision: CanaryCompletionDecision,
    decided_at_unix: u64,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_canary_completion(
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
    authorization: &CanaryRolloutAuthorization,
    decision: CanaryCompletionDecision,
    decided_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedCanaryCompletionDecision, String> {
    validate_monitoring_binding(rollout, monitoring, authorization)?;
    if decision == CanaryCompletionDecision::Promote && !monitoring.promotion_eligible {
        return Err("cannot sign promotion when monitoring requires rollback".into());
    }
    if decided_at_unix < monitoring.observed_at_unix
        || decided_at_unix > authorization.expires_at_unix
    {
        return Err("canary completion decision is outside the bound review window".into());
    }
    validate_text(reason, MAXIMUM_TEXT_BYTES, "completion reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "completion ticket")?;
    validate_slug("completion signer", signer_id)?;
    let monitoring_sha256 = normalized_sha256(monitoring)?;
    let authorization_sha256 = normalized_sha256(authorization)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = signature_payload(
        &monitoring_sha256,
        &monitoring.rollout_sha256,
        &authorization_sha256,
        &monitoring.policy_pack_id,
        monitoring.policy_pack_revision,
        decision,
        decided_at_unix,
        reason,
        ticket,
        signer_id,
    )?;
    Ok(SignedCanaryCompletionDecision {
        schema_version: SIGNED_CANARY_DECISION_SCHEMA_VERSION,
        monitoring_sha256,
        rollout_sha256: monitoring.rollout_sha256.clone(),
        authorization_sha256,
        policy_pack_id: monitoring.policy_pack_id.clone(),
        policy_pack_revision: monitoring.policy_pack_revision,
        decision,
        decided_at_unix,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    })
}

pub fn verify_canary_completion(
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
    authorization: &CanaryRolloutAuthorization,
    policy_pack: &OrganizationPolicyPack,
    decisions: &[SignedCanaryCompletionDecision],
    minimum_decisions: u32,
) -> Result<CanaryCompletionReport, String> {
    validate_monitoring_binding(rollout, monitoring, authorization)?;
    validate_policy_pack(policy_pack)?;
    if monitoring.policy_pack_id != policy_pack.id
        || monitoring.policy_pack_revision != policy_pack.revision
        || rollout.policy_pack_sha256 != normalized_sha256(policy_pack)?
    {
        return Err("canary completion evidence is bound to a different policy pack".into());
    }
    if !(2..=MAXIMUM_SIGNERS as u32).contains(&minimum_decisions)
        || decisions.is_empty()
        || decisions.len() > MAXIMUM_SIGNERS
    {
        return Err("canary completion requires 1 to 100 decisions and a minimum of 2".into());
    }
    let monitoring_sha256 = normalized_sha256(monitoring)?;
    let authorization_sha256 = normalized_sha256(authorization)?;
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut members = Vec::with_capacity(decisions.len());
    for decision in decisions {
        validate_signed_canary_decision(decision)?;
        if decision.monitoring_sha256 != monitoring_sha256
            || decision.rollout_sha256 != monitoring.rollout_sha256
            || decision.authorization_sha256 != authorization_sha256
            || decision.policy_pack_id != policy_pack.id
            || decision.policy_pack_revision != policy_pack.revision
        {
            return Err("signed completion decision is bound to different evidence".into());
        }
        if decision.decided_at_unix < monitoring.observed_at_unix
            || decision.decided_at_unix > authorization.expires_at_unix
        {
            return Err("signed completion decision is outside the review window".into());
        }
        if monitoring.rollback_required && decision.decision != CanaryCompletionDecision::Rollback {
            return Err("monitoring failure permits only rollback decisions".into());
        }
        let trusted = policy_pack
            .trusted_human_escalation_keys
            .iter()
            .find(|trusted| trusted.signer_id == decision.signer_id)
            .ok_or_else(|| format!("completion signer {:?} is not trusted", decision.signer_id))?;
        verify_signature(
            decision,
            &decode_hex_array::<32>(&trusted.public_key, "trusted completion key")?,
        )?;
        if !signer_ids.insert(decision.signer_id.as_str())
            || !public_keys.insert(decision.public_key.as_str())
        {
            return Err("completion decisions require distinct signer IDs and keys".into());
        }
        members.push(CanaryCompletionMember {
            signer_id: decision.signer_id.clone(),
            public_key: decision.public_key.clone(),
            decision_sha256: normalized_sha256(decision)?,
            decision: decision.decision,
            decided_at_unix: decision.decided_at_unix,
            reason: decision.reason.clone(),
            ticket: decision.ticket.clone(),
        });
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let promotions = members
        .iter()
        .filter(|member| member.decision == CanaryCompletionDecision::Promote)
        .count() as u32;
    let rollbacks = members.len() as u32 - promotions;
    let mut gate_failures = Vec::new();
    if members.len() < minimum_decisions as usize {
        gate_failures.push(format!(
            "insufficient_completion_decisions:required={minimum_decisions}:actual={}",
            members.len()
        ));
    }
    if promotions != 0 && rollbacks != 0 {
        gate_failures.push("completion_decisions_disagree".into());
    }
    if monitoring.rollback_required && promotions != 0 {
        gate_failures.push("promotion_forbidden_by_monitoring".into());
    }
    gate_failures.sort();
    let finalized = gate_failures.is_empty();
    let final_decision = finalized.then_some(if rollbacks != 0 {
        CanaryCompletionDecision::Rollback
    } else {
        CanaryCompletionDecision::Promote
    });
    let status = match final_decision {
        Some(CanaryCompletionDecision::Promote) => "promotion_authorized",
        Some(CanaryCompletionDecision::Rollback) => "rollback_confirmed",
        None if monitoring.rollback_required => "rollback_required",
        None => "not_finalized",
    };
    let report = CanaryCompletionReport {
        schema_version: CANARY_COMPLETION_SCHEMA_VERSION,
        status: status.into(),
        monitoring_sha256,
        rollout_sha256: monitoring.rollout_sha256.clone(),
        authorization_sha256,
        policy_pack_id: policy_pack.id.clone(),
        policy_pack_revision: policy_pack.revision,
        monitoring_status: monitoring.status.clone(),
        promotion_eligible: monitoring.promotion_eligible,
        rollback_required: monitoring.rollback_required,
        policy: CanaryCompletionPolicy {
            minimum_decisions,
            automatic_promotion: false,
            unanimous_decision_required: true,
            rollback_required_on_monitoring_failure: true,
        },
        promotions,
        rollbacks,
        members,
        finalized,
        final_decision,
        gate_failures,
    };
    validate_canary_completion_report(&report)?;
    Ok(report)
}

pub fn parse_signed_canary_decision(
    source: &str,
) -> Result<SignedCanaryCompletionDecision, String> {
    let decision: SignedCanaryCompletionDecision = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed canary completion JSON: {error}"))?;
    validate_signed_canary_decision(&decision)?;
    Ok(decision)
}

pub fn parse_canary_completion_report(source: &str) -> Result<CanaryCompletionReport, String> {
    let report: CanaryCompletionReport = serde_json::from_str(source)
        .map_err(|error| format!("invalid canary completion report JSON: {error}"))?;
    validate_canary_completion_report(&report)?;
    Ok(report)
}

pub fn validate_signed_canary_decision(
    decision: &SignedCanaryCompletionDecision,
) -> Result<(), String> {
    if decision.schema_version != SIGNED_CANARY_DECISION_SCHEMA_VERSION
        || decision.algorithm != "ed25519"
    {
        return Err("unsupported signed canary completion contract".into());
    }
    for digest in [
        &decision.monitoring_sha256,
        &decision.rollout_sha256,
        &decision.authorization_sha256,
    ] {
        validate_digest(digest)?;
    }
    validate_slug("policy pack id", &decision.policy_pack_id)?;
    if decision.policy_pack_revision == 0 {
        return Err("completion policy revision must be positive".into());
    }
    validate_text(&decision.reason, MAXIMUM_TEXT_BYTES, "completion reason")?;
    validate_text(&decision.ticket, MAXIMUM_TICKET_BYTES, "completion ticket")?;
    validate_slug("completion signer", &decision.signer_id)?;
    decode_hex_array::<32>(&decision.public_key, "completion public key")?;
    decode_hex_array::<64>(&decision.signature, "completion signature")?;
    Ok(())
}

pub fn validate_canary_completion_report(report: &CanaryCompletionReport) -> Result<(), String> {
    if report.schema_version != CANARY_COMPLETION_SCHEMA_VERSION
        || !matches!(
            report.status.as_str(),
            "promotion_authorized" | "rollback_confirmed" | "rollback_required" | "not_finalized"
        )
        || report.policy.automatic_promotion
        || !report.policy.unanimous_decision_required
        || !report.policy.rollback_required_on_monitoring_failure
        || !(2..=MAXIMUM_SIGNERS as u32).contains(&report.policy.minimum_decisions)
    {
        return Err("canary completion governance boundary is invalid".into());
    }
    for digest in [
        &report.monitoring_sha256,
        &report.rollout_sha256,
        &report.authorization_sha256,
    ] {
        validate_digest(digest)?;
    }
    validate_slug("policy pack id", &report.policy_pack_id)?;
    if report.policy_pack_revision == 0
        || report.members.is_empty()
        || report.members.len() > MAXIMUM_SIGNERS
        || report.promotions + report.rollbacks != report.members.len() as u32
        || report.promotion_eligible == report.rollback_required
        || report.monitoring_status
            != if report.rollback_required {
                "rollback_required"
            } else {
                "monitoring_passed"
            }
    {
        return Err("canary completion identity or counts are invalid".into());
    }
    let mut signers = HashSet::new();
    let mut keys = HashSet::new();
    let mut previous = None;
    let mut promotions = 0_u32;
    for member in &report.members {
        validate_slug("completion member signer", &member.signer_id)?;
        validate_digest(&member.decision_sha256)?;
        decode_hex_array::<32>(&member.public_key, "completion member key")?;
        validate_text(
            &member.reason,
            MAXIMUM_TEXT_BYTES,
            "completion member reason",
        )?;
        validate_text(
            &member.ticket,
            MAXIMUM_TICKET_BYTES,
            "completion member ticket",
        )?;
        if !signers.insert(member.signer_id.as_str())
            || !keys.insert(member.public_key.as_str())
            || previous.is_some_and(|value| value >= member.signer_id.as_str())
        {
            return Err("completion members are duplicate or unordered".into());
        }
        previous = Some(member.signer_id.as_str());
        if member.decision == CanaryCompletionDecision::Promote {
            promotions += 1;
        }
    }
    if promotions != report.promotions
        || report.rollbacks != report.members.len() as u32 - promotions
        || (report.rollback_required && promotions != 0)
    {
        return Err("completion member decisions are inconsistent".into());
    }
    let mut expected_failures = Vec::new();
    if report.members.len() < report.policy.minimum_decisions as usize {
        expected_failures.push(format!(
            "insufficient_completion_decisions:required={}:actual={}",
            report.policy.minimum_decisions,
            report.members.len()
        ));
    }
    if report.promotions != 0 && report.rollbacks != 0 {
        expected_failures.push("completion_decisions_disagree".into());
    }
    if report.rollback_required && report.promotions != 0 {
        expected_failures.push("promotion_forbidden_by_monitoring".into());
    }
    expected_failures.sort();
    let mut unique_failures = HashSet::new();
    if report.gate_failures.iter().any(|failure| {
        failure.trim().is_empty()
            || failure.len() > 1024
            || !unique_failures.insert(failure.as_str())
    }) || !report
        .gate_failures
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err("canary completion gate failures are invalid".into());
    }
    let finalized = expected_failures.is_empty();
    let final_decision = finalized.then_some(if report.rollbacks != 0 {
        CanaryCompletionDecision::Rollback
    } else {
        CanaryCompletionDecision::Promote
    });
    let status = match final_decision {
        Some(CanaryCompletionDecision::Promote) => "promotion_authorized",
        Some(CanaryCompletionDecision::Rollback) => "rollback_confirmed",
        None if report.rollback_required => "rollback_required",
        None => "not_finalized",
    };
    if report.gate_failures != expected_failures
        || report.finalized != finalized
        || report.final_decision != final_decision
        || report.status != status
    {
        return Err("canary completion outcome is inconsistent".into());
    }
    Ok(())
}

fn validate_monitoring_binding(
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
    authorization: &CanaryRolloutAuthorization,
) -> Result<(), String> {
    validate_policy_rollout_report(rollout)?;
    validate_canary_monitoring_report(monitoring)?;
    validate_canary_authorization(authorization)?;
    if !authorization.canary_authorized
        || monitoring.rollout_sha256 != normalized_sha256(rollout)?
        || monitoring.rollout_sha256 != authorization.rollout_sha256
        || monitoring.authorization_sha256 != normalized_sha256(authorization)?
        || monitoring.policy_pack_id != authorization.policy_pack_id
        || monitoring.policy_pack_revision != authorization.policy_pack_revision
        || monitoring.observed_at_unix < authorization.valid_from_unix
        || monitoring.observed_at_unix > authorization.expires_at_unix
    {
        return Err("monitoring report is not bound to the supplied authorization".into());
    }
    Ok(())
}

fn verify_signature(
    decision: &SignedCanaryCompletionDecision,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    let public_key = decode_hex_array::<32>(&decision.public_key, "completion public key")?;
    if &public_key != trusted_public_key {
        return Err("completion key does not match its trusted key".into());
    }
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &decision.signature,
        "completion signature",
    )?);
    let payload = signature_payload(
        &decision.monitoring_sha256,
        &decision.rollout_sha256,
        &decision.authorization_sha256,
        &decision.policy_pack_id,
        decision.policy_pack_revision,
        decision.decision,
        decision.decided_at_unix,
        &decision.reason,
        &decision.ticket,
        &decision.signer_id,
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid completion public key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid completion signature: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn signature_payload(
    monitoring_sha256: &str,
    rollout_sha256: &str,
    authorization_sha256: &str,
    policy_pack_id: &str,
    policy_pack_revision: u32,
    decision: CanaryCompletionDecision,
    decided_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        monitoring_sha256,
        rollout_sha256,
        authorization_sha256,
        policy_pack_id,
        policy_pack_revision,
        decision,
        decided_at_unix,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("serializing completion signature payload: {error}"))
}

pub fn render_canary_completion_summary(report: &CanaryCompletionReport) -> String {
    let mut output = format!(
        "# Canary completion decision\n\n\
         **Result:** `{}`\n\n\
         - Promotion decisions: `{}`\n\
         - Rollback decisions: `{}`\n\
         - Required decisions: `{}`\n\
         - Automatic promotion: `false`\n\
         - Finalized: `{}`\n",
        report.status,
        report.promotions,
        report.rollbacks,
        report.policy.minimum_decisions,
        report.finalized
    );
    if !report.gate_failures.is_empty() {
        let _ = writeln!(output, "\n## Gate failures\n");
        for failure in &report.gate_failures {
            let _ = writeln!(output, "- `{failure}`");
        }
    }
    output
}

pub fn signed_canary_decision_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-canary-completion-v1.json",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "monitoring_sha256", "rollout_sha256",
            "authorization_sha256", "policy_pack_id", "policy_pack_revision",
            "decision", "decided_at_unix", "reason", "ticket", "signer_id",
            "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_CANARY_DECISION_SCHEMA_VERSION},
            "monitoring_sha256": digest,
            "rollout_sha256": digest,
            "authorization_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "decision": {"enum": ["promote", "rollback"]},
            "decided_at_unix": {"type": "integer", "minimum": 0},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES},
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn canary_completion_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let member = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "signer_id", "public_key", "decision_sha256", "decision",
            "decided_at_unix", "reason", "ticket"
        ],
        "properties": {
            "signer_id": {"type": "string"},
            "public_key": digest,
            "decision_sha256": digest,
            "decision": {"enum": ["promote", "rollback"]},
            "decided_at_unix": {"type": "integer", "minimum": 0},
            "reason": {"type": "string"},
            "ticket": {"type": "string"}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/canary-completion-v1.json",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "monitoring_sha256", "rollout_sha256",
            "authorization_sha256", "policy_pack_id", "policy_pack_revision",
            "monitoring_status", "promotion_eligible", "rollback_required",
            "policy", "promotions", "rollbacks", "members", "finalized",
            "final_decision", "gate_failures"
        ],
        "properties": {
            "schema_version": {"const": CANARY_COMPLETION_SCHEMA_VERSION},
            "status": {"enum": ["promotion_authorized", "rollback_confirmed", "rollback_required", "not_finalized"]},
            "monitoring_sha256": digest,
            "rollout_sha256": digest,
            "authorization_sha256": digest,
            "policy_pack_id": {"type": "string"},
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "monitoring_status": {"enum": ["monitoring_passed", "rollback_required"]},
            "promotion_eligible": {"type": "boolean"},
            "rollback_required": {"type": "boolean"},
            "policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "minimum_decisions", "automatic_promotion",
                    "unanimous_decision_required",
                    "rollback_required_on_monitoring_failure"
                ],
                "properties": {
                    "minimum_decisions": {"type": "integer", "minimum": 2, "maximum": MAXIMUM_SIGNERS},
                    "automatic_promotion": {"const": false},
                    "unanimous_decision_required": {"const": true},
                    "rollback_required_on_monitoring_failure": {"const": true}
                }
            },
            "promotions": {"type": "integer", "minimum": 0},
            "rollbacks": {"type": "integer", "minimum": 0},
            "members": {"type": "array", "minItems": 1, "maxItems": MAXIMUM_SIGNERS, "items": member},
            "finalized": {"type": "boolean"},
            "final_decision": {"type": ["string", "null"], "enum": ["promote", "rollback", null]},
            "gate_failures": {"type": "array", "items": {"type": "string"}}
        }
    })
}

fn normalized_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized completion evidence: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid lowercase SHA-256 digest".into());
    }
    Ok(())
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-'))
        })
    {
        return Err(format!("invalid {label} {value:?}"));
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum {
        Err(format!("{label} must contain 1 to {maximum} bytes"))
    } else {
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} must contain {} hexadecimal digits", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let decode = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        output[index] = (decode(pair[0]).ok_or_else(|| format!("invalid {label}"))? << 4)
            | decode(pair[1]).ok_or_else(|| format!("invalid {label}"))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_schemas_close_every_object() {
        let signed = signed_canary_decision_json_schema();
        assert_eq!(signed["additionalProperties"], false);
        let completion = canary_completion_json_schema();
        assert_eq!(completion["additionalProperties"], false);
        assert_eq!(
            completion["properties"]["policy"]["additionalProperties"],
            false
        );
        assert_eq!(
            completion["properties"]["members"]["items"]["additionalProperties"],
            false
        );
    }
}
