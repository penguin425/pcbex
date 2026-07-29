use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use crate::policy_rollout::{
    PolicyRolloutReport, RolloutCompatibility, validate_policy_rollout_report,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const SIGNED_ROLLOUT_APPROVAL_SCHEMA_VERSION: u32 = 1;
pub const CANARY_AUTHORIZATION_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-rollout-canary-approval-v1";
const MAXIMUM_REVIEWERS: usize = 100;
const MAXIMUM_PROJECTS: usize = 100;
const MAXIMUM_CANARY_PERCENT: u32 = 10;
const MAXIMUM_WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutApprovalDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRolloutApproval {
    pub schema_version: u32,
    pub rollout_sha256: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub decision: RolloutApprovalDecision,
    pub canary_projects: Vec<String>,
    pub valid_from_unix: u64,
    pub expires_at_unix: u64,
    pub reason: String,
    pub ticket: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryAuthorizationPolicy {
    pub minimum_approvals: u32,
    pub maximum_canary_projects: u32,
    pub maximum_canary_percent: u32,
    pub maximum_window_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRollbackPolicy {
    pub automatic_rollback: bool,
    pub rollback_on_new_violation: bool,
    pub rollback_on_quality_regression: bool,
    pub rollback_on_analysis_failure: bool,
    pub rollback_on_missing_monitoring_evidence: bool,
    pub automatic_promotion: bool,
    pub requires_post_canary_review: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryAuthorizationMember {
    pub signer_id: String,
    pub public_key: String,
    pub approval_sha256: String,
    pub decision: RolloutApprovalDecision,
    pub reason: String,
    pub ticket: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRolloutAuthorization {
    pub schema_version: u32,
    pub status: String,
    pub rollout_sha256: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub candidate_profile_sha256: String,
    pub rollout_total_projects: u32,
    pub rollout_affected_projects: u32,
    pub rollout_new_violations: u32,
    pub evaluated_at_unix: u64,
    pub valid_from_unix: u64,
    pub expires_at_unix: u64,
    pub canary_projects: Vec<String>,
    pub policy: CanaryAuthorizationPolicy,
    pub rollback_policy: CanaryRollbackPolicy,
    pub approvals: u32,
    pub rejections: u32,
    pub members: Vec<CanaryAuthorizationMember>,
    pub canary_eligible: bool,
    pub canary_authorized: bool,
    pub gate_failures: Vec<String>,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    rollout_sha256: &'a str,
    policy_pack_id: &'a str,
    policy_pack_revision: u32,
    decision: RolloutApprovalDecision,
    canary_projects: &'a [String],
    valid_from_unix: u64,
    expires_at_unix: u64,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_rollout_approval(
    rollout: &PolicyRolloutReport,
    decision: RolloutApprovalDecision,
    canary_projects: &[String],
    valid_from_unix: u64,
    expires_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedRolloutApproval, String> {
    validate_policy_rollout_report(rollout)?;
    let projects = normalize_scope(rollout, canary_projects)?;
    validate_window(valid_from_unix, expires_at_unix)?;
    validate_text(reason, MAXIMUM_TEXT_BYTES, "rollout approval reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "rollout approval ticket")?;
    validate_slug("rollout approval signer", signer_id)?;
    let rollout_sha256 = normalized_sha256(rollout)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = signature_payload(
        &rollout_sha256,
        &rollout.policy_pack_id,
        rollout.policy_pack_revision,
        decision,
        &projects,
        valid_from_unix,
        expires_at_unix,
        reason,
        ticket,
        signer_id,
    )?;
    Ok(SignedRolloutApproval {
        schema_version: SIGNED_ROLLOUT_APPROVAL_SCHEMA_VERSION,
        rollout_sha256,
        policy_pack_id: rollout.policy_pack_id.clone(),
        policy_pack_revision: rollout.policy_pack_revision,
        decision,
        canary_projects: projects,
        valid_from_unix,
        expires_at_unix,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    })
}

pub fn verify_rollout_approvals(
    rollout: &PolicyRolloutReport,
    policy_pack: &OrganizationPolicyPack,
    approvals: &[SignedRolloutApproval],
    evaluated_at_unix: u64,
    minimum_approvals: u32,
) -> Result<CanaryRolloutAuthorization, String> {
    validate_policy_rollout_report(rollout)?;
    validate_policy_pack(policy_pack)?;
    validate_policy_binding(rollout, policy_pack)?;
    if !(2..=MAXIMUM_REVIEWERS as u32).contains(&minimum_approvals) {
        return Err(format!(
            "rollout minimum approvals must be between 2 and {MAXIMUM_REVIEWERS}"
        ));
    }
    if approvals.is_empty() || approvals.len() > MAXIMUM_REVIEWERS {
        return Err(format!(
            "rollout approval set must contain 1 to {MAXIMUM_REVIEWERS} members"
        ));
    }
    let rollout_sha256 = normalized_sha256(rollout)?;
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut members = Vec::with_capacity(approvals.len());
    let mut common_scope: Option<Vec<String>> = None;
    let mut common_window: Option<(u64, u64)> = None;
    for approval in approvals {
        validate_signed_approval(approval)?;
        if approval.rollout_sha256 != rollout_sha256
            || approval.policy_pack_id != policy_pack.id
            || approval.policy_pack_revision != policy_pack.revision
        {
            return Err("signed rollout approval is bound to different evidence".into());
        }
        let scope = normalize_scope(rollout, &approval.canary_projects)?;
        let window = (approval.valid_from_unix, approval.expires_at_unix);
        validate_window(window.0, window.1)?;
        if common_scope.as_ref().is_some_and(|value| value != &scope)
            || common_window.is_some_and(|value| value != window)
        {
            return Err("rollout approvals disagree on canary scope or validity window".into());
        }
        common_scope.get_or_insert(scope);
        common_window.get_or_insert(window);
        let trusted = policy_pack
            .trusted_human_escalation_keys
            .iter()
            .find(|trusted| trusted.signer_id == approval.signer_id)
            .ok_or_else(|| {
                format!(
                    "rollout signer {:?} is not trusted for human approval",
                    approval.signer_id
                )
            })?;
        verify_signature(
            approval,
            &decode_hex_array::<32>(&trusted.public_key, "trusted key")?,
        )?;
        if !signer_ids.insert(approval.signer_id.as_str()) {
            return Err(format!("duplicate rollout signer {:?}", approval.signer_id));
        }
        if !public_keys.insert(approval.public_key.as_str()) {
            return Err("duplicate rollout approval public key".into());
        }
        members.push(CanaryAuthorizationMember {
            signer_id: approval.signer_id.clone(),
            public_key: approval.public_key.clone(),
            approval_sha256: normalized_sha256(approval)?,
            decision: approval.decision,
            reason: approval.reason.clone(),
            ticket: approval.ticket.clone(),
        });
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let canary_projects = common_scope.expect("non-empty approval set has a scope");
    let (valid_from_unix, expires_at_unix) =
        common_window.expect("non-empty approval set has a window");
    let approvals_count = members
        .iter()
        .filter(|member| member.decision == RolloutApprovalDecision::Approve)
        .count() as u32;
    let rejections = members.len() as u32 - approvals_count;
    let maximum_canary_projects = canary_limit(rollout.total_projects);
    let mut gate_failures = Vec::new();
    if rollout.affected_projects != 0 || rollout.total_new_violations != 0 {
        gate_failures.push("simulation_detected_rollout_impact".into());
    }
    if canary_projects.len() as u32 > maximum_canary_projects {
        gate_failures.push(format!(
            "canary_scope_exceeds_limit:maximum={maximum_canary_projects}:actual={}",
            canary_projects.len()
        ));
    }
    if evaluated_at_unix < valid_from_unix || evaluated_at_unix > expires_at_unix {
        gate_failures.push("approval_window_inactive".into());
    }
    if approvals_count < minimum_approvals {
        gate_failures.push(format!(
            "insufficient_human_approvals:required={minimum_approvals}:actual={approvals_count}"
        ));
    }
    if rejections > 0 {
        gate_failures.push(format!("human_rejection:count={rejections}"));
    }
    gate_failures.sort();
    let canary_eligible = !gate_failures.iter().any(|failure| {
        failure.starts_with("simulation_")
            || failure.starts_with("canary_scope_")
            || failure == "approval_window_inactive"
    });
    let canary_authorized = gate_failures.is_empty();
    let report = CanaryRolloutAuthorization {
        schema_version: CANARY_AUTHORIZATION_SCHEMA_VERSION,
        status: if canary_authorized {
            "canary_authorized".into()
        } else {
            "not_authorized".into()
        },
        rollout_sha256,
        policy_pack_id: policy_pack.id.clone(),
        policy_pack_revision: policy_pack.revision,
        candidate_profile_sha256: normalized_sha256(&rollout.candidate_profile)?,
        rollout_total_projects: rollout.total_projects,
        rollout_affected_projects: rollout.affected_projects,
        rollout_new_violations: rollout.total_new_violations,
        evaluated_at_unix,
        valid_from_unix,
        expires_at_unix,
        canary_projects,
        policy: CanaryAuthorizationPolicy {
            minimum_approvals,
            maximum_canary_projects,
            maximum_canary_percent: MAXIMUM_CANARY_PERCENT,
            maximum_window_seconds: MAXIMUM_WINDOW_SECONDS,
        },
        rollback_policy: CanaryRollbackPolicy {
            automatic_rollback: true,
            rollback_on_new_violation: true,
            rollback_on_quality_regression: true,
            rollback_on_analysis_failure: true,
            rollback_on_missing_monitoring_evidence: true,
            automatic_promotion: false,
            requires_post_canary_review: true,
        },
        approvals: approvals_count,
        rejections,
        members,
        canary_eligible,
        canary_authorized,
        gate_failures,
    };
    validate_canary_authorization(&report)?;
    Ok(report)
}

pub fn parse_signed_rollout_approval(source: &str) -> Result<SignedRolloutApproval, String> {
    let approval: SignedRolloutApproval = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed rollout approval JSON: {error}"))?;
    validate_signed_approval(&approval)?;
    Ok(approval)
}

pub fn parse_canary_authorization(source: &str) -> Result<CanaryRolloutAuthorization, String> {
    let report: CanaryRolloutAuthorization = serde_json::from_str(source)
        .map_err(|error| format!("invalid canary authorization JSON: {error}"))?;
    validate_canary_authorization(&report)?;
    Ok(report)
}

pub fn validate_signed_approval(approval: &SignedRolloutApproval) -> Result<(), String> {
    if approval.schema_version != SIGNED_ROLLOUT_APPROVAL_SCHEMA_VERSION
        || approval.algorithm != "ed25519"
    {
        return Err("unsupported signed rollout approval contract".into());
    }
    validate_digest(&approval.rollout_sha256)?;
    validate_slug("policy pack id", &approval.policy_pack_id)?;
    if approval.policy_pack_revision == 0 {
        return Err("rollout approval policy revision must be positive".into());
    }
    validate_scope_values(&approval.canary_projects)?;
    validate_window(approval.valid_from_unix, approval.expires_at_unix)?;
    validate_text(
        &approval.reason,
        MAXIMUM_TEXT_BYTES,
        "rollout approval reason",
    )?;
    validate_text(
        &approval.ticket,
        MAXIMUM_TICKET_BYTES,
        "rollout approval ticket",
    )?;
    validate_slug("rollout approval signer", &approval.signer_id)?;
    decode_hex_array::<32>(&approval.public_key, "rollout approval public key")?;
    decode_hex_array::<64>(&approval.signature, "rollout approval signature")?;
    Ok(())
}

pub fn validate_canary_authorization(report: &CanaryRolloutAuthorization) -> Result<(), String> {
    if report.schema_version != CANARY_AUTHORIZATION_SCHEMA_VERSION
        || !matches!(
            report.status.as_str(),
            "canary_authorized" | "not_authorized"
        )
        || report.rollback_policy
            != (CanaryRollbackPolicy {
                automatic_rollback: true,
                rollback_on_new_violation: true,
                rollback_on_quality_regression: true,
                rollback_on_analysis_failure: true,
                rollback_on_missing_monitoring_evidence: true,
                automatic_promotion: false,
                requires_post_canary_review: true,
            })
    {
        return Err("canary authorization governance boundary is invalid".into());
    }
    validate_digest(&report.rollout_sha256)?;
    validate_digest(&report.candidate_profile_sha256)?;
    validate_slug("policy pack id", &report.policy_pack_id)?;
    validate_scope_values(&report.canary_projects)?;
    validate_window(report.valid_from_unix, report.expires_at_unix)?;
    if report.policy.minimum_approvals < 2
        || report.policy.minimum_approvals > MAXIMUM_REVIEWERS as u32
        || report.policy.maximum_canary_projects != canary_limit(report.rollout_total_projects)
        || report.policy.maximum_canary_percent != MAXIMUM_CANARY_PERCENT
        || report.policy.maximum_window_seconds != MAXIMUM_WINDOW_SECONDS
        || report.members.is_empty()
        || report.members.len() > MAXIMUM_REVIEWERS
        || report.approvals + report.rejections != report.members.len() as u32
    {
        return Err("canary authorization policy or counts are invalid".into());
    }
    let mut signers = HashSet::new();
    let mut keys = HashSet::new();
    let mut previous = None;
    for member in &report.members {
        validate_slug("canary authorization signer", &member.signer_id)?;
        validate_digest(&member.approval_sha256)?;
        decode_hex_array::<32>(&member.public_key, "canary member public key")?;
        validate_text(&member.reason, MAXIMUM_TEXT_BYTES, "canary member reason")?;
        validate_text(&member.ticket, MAXIMUM_TICKET_BYTES, "canary member ticket")?;
        if !signers.insert(member.signer_id.as_str())
            || !keys.insert(member.public_key.as_str())
            || previous.is_some_and(|value| value >= member.signer_id.as_str())
        {
            return Err("canary authorization members are duplicate or unordered".into());
        }
        previous = Some(member.signer_id.as_str());
    }
    let approvals = report
        .members
        .iter()
        .filter(|member| member.decision == RolloutApprovalDecision::Approve)
        .count() as u32;
    if report.rollout_total_projects == 0
        || report.rollout_affected_projects > report.rollout_total_projects
        || approvals != report.approvals
        || report.rejections != report.members.len() as u32 - approvals
    {
        return Err("canary authorization outcome is inconsistent".into());
    }
    let mut failures = HashSet::new();
    if report.gate_failures.iter().any(|failure| {
        failure.trim().is_empty() || failure.len() > 1024 || !failures.insert(failure.as_str())
    }) || !report
        .gate_failures
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err("canary authorization failures are invalid".into());
    }
    let mut expected_failures = Vec::new();
    if report.rollout_affected_projects != 0 || report.rollout_new_violations != 0 {
        expected_failures.push("simulation_detected_rollout_impact".into());
    }
    if report.canary_projects.len() as u32 > report.policy.maximum_canary_projects {
        expected_failures.push(format!(
            "canary_scope_exceeds_limit:maximum={}:actual={}",
            report.policy.maximum_canary_projects,
            report.canary_projects.len()
        ));
    }
    if report.evaluated_at_unix < report.valid_from_unix
        || report.evaluated_at_unix > report.expires_at_unix
    {
        expected_failures.push("approval_window_inactive".into());
    }
    if report.approvals < report.policy.minimum_approvals {
        expected_failures.push(format!(
            "insufficient_human_approvals:required={}:actual={}",
            report.policy.minimum_approvals, report.approvals
        ));
    }
    if report.rejections > 0 {
        expected_failures.push(format!("human_rejection:count={}", report.rejections));
    }
    expected_failures.sort();
    let expected_eligible = !expected_failures.iter().any(|failure| {
        failure.starts_with("simulation_")
            || failure.starts_with("canary_scope_")
            || failure == "approval_window_inactive"
    });
    let expected_authorized = expected_failures.is_empty();
    if report.gate_failures != expected_failures
        || report.canary_eligible != expected_eligible
        || report.canary_authorized != expected_authorized
        || report.status
            != if expected_authorized {
                "canary_authorized"
            } else {
                "not_authorized"
            }
    {
        return Err("canary authorization outcome is inconsistent".into());
    }
    Ok(())
}

fn verify_signature(
    approval: &SignedRolloutApproval,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    let public_key = decode_hex_array::<32>(&approval.public_key, "rollout approval public key")?;
    if &public_key != trusted_public_key {
        return Err("rollout approval key does not match its trusted key".into());
    }
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &approval.signature,
        "rollout approval signature",
    )?);
    let payload = signature_payload(
        &approval.rollout_sha256,
        &approval.policy_pack_id,
        approval.policy_pack_revision,
        approval.decision,
        &approval.canary_projects,
        approval.valid_from_unix,
        approval.expires_at_unix,
        &approval.reason,
        &approval.ticket,
        &approval.signer_id,
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid rollout approval public key: {error}"))?
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid rollout approval signature: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn signature_payload(
    rollout_sha256: &str,
    policy_pack_id: &str,
    policy_pack_revision: u32,
    decision: RolloutApprovalDecision,
    canary_projects: &[String],
    valid_from_unix: u64,
    expires_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        rollout_sha256,
        policy_pack_id,
        policy_pack_revision,
        decision,
        canary_projects,
        valid_from_unix,
        expires_at_unix,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("serializing rollout approval payload: {error}"))
}

fn normalize_scope(rollout: &PolicyRolloutReport, scope: &[String]) -> Result<Vec<String>, String> {
    if scope.is_empty() || scope.len() > MAXIMUM_PROJECTS {
        return Err(format!(
            "canary scope must contain 1 to {MAXIMUM_PROJECTS} projects"
        ));
    }
    let mut unique = HashSet::new();
    for project in scope {
        validate_slug("canary project", project)?;
        if !unique.insert(project.as_str()) {
            return Err("canary projects must be unique".into());
        }
    }
    let known = rollout
        .projects
        .iter()
        .map(|project| (project.project_id.as_str(), project.compatibility))
        .collect::<std::collections::HashMap<_, _>>();
    for project in scope {
        match known.get(project.as_str()) {
            None => return Err(format!("unknown canary project {project:?}")),
            Some(RolloutCompatibility::ImpactDetected) => {
                return Err(format!("canary project {project:?} has simulated impact"));
            }
            Some(RolloutCompatibility::Compatible) => {}
        }
    }
    let mut normalized = scope.to_vec();
    normalized.sort();
    Ok(normalized)
}

fn validate_scope_values(scope: &[String]) -> Result<(), String> {
    if scope.is_empty() || scope.len() > MAXIMUM_PROJECTS {
        return Err(format!(
            "canary scope must contain 1 to {MAXIMUM_PROJECTS} projects"
        ));
    }
    let mut seen = HashSet::new();
    let mut previous = None;
    for project in scope {
        validate_slug("canary project", project)?;
        if !seen.insert(project.as_str()) || previous.is_some_and(|value| value >= project.as_str())
        {
            return Err("canary projects must be unique and strictly ordered".into());
        }
        previous = Some(project.as_str());
    }
    Ok(())
}

fn validate_window(valid_from: u64, expires_at: u64) -> Result<(), String> {
    let duration = expires_at
        .checked_sub(valid_from)
        .ok_or_else(|| "canary approval expiry precedes validity".to_string())?;
    if duration == 0 || duration > MAXIMUM_WINDOW_SECONDS {
        return Err(format!(
            "canary approval window must be 1 to {MAXIMUM_WINDOW_SECONDS} seconds"
        ));
    }
    Ok(())
}

fn canary_limit(total_projects: u32) -> u32 {
    total_projects
        .saturating_add(9)
        .saturating_div(10)
        .clamp(1, MAXIMUM_PROJECTS as u32)
}

fn validate_policy_binding(
    rollout: &PolicyRolloutReport,
    policy_pack: &OrganizationPolicyPack,
) -> Result<(), String> {
    if rollout.policy_pack_id != policy_pack.id
        || rollout.policy_pack_revision != policy_pack.revision
        || rollout.policy_pack_sha256 != normalized_sha256(policy_pack)?
    {
        return Err("rollout report does not bind the supplied policy pack".into());
    }
    Ok(())
}

fn normalized_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized rollout approval evidence: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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

pub fn render_canary_authorization_summary(report: &CanaryRolloutAuthorization) -> String {
    let mut output = format!(
        "# Canary rollout authorization\n\n\
         **Result:** {}\n\n\
         - Human approvals: `{}/{}`\n\
         - Rejections: `{}`\n\
         - Canary projects: `{}`\n\
         - Automatic promotion: `false`\n\
         - Automatic rollback on regression or missing evidence: `true`\n",
        if report.canary_authorized {
            "authorized"
        } else {
            "not authorized"
        },
        report.approvals,
        report.policy.minimum_approvals,
        report.rejections,
        report.canary_projects.join(", ")
    );
    if !report.gate_failures.is_empty() {
        let _ = writeln!(output, "\n## Gate failures\n");
        for failure in &report.gate_failures {
            let _ = writeln!(output, "- `{failure}`");
        }
    }
    output
}

pub fn signed_rollout_approval_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-rollout-approval-v1.json",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "rollout_sha256", "policy_pack_id",
            "policy_pack_revision", "decision", "canary_projects",
            "valid_from_unix", "expires_at_unix", "reason", "ticket",
            "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_ROLLOUT_APPROVAL_SCHEMA_VERSION},
            "rollout_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "decision": {"enum": ["approve", "reject"]},
            "canary_projects": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_PROJECTS,
                "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}
            },
            "valid_from_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES},
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn canary_authorization_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let member = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "signer_id", "public_key", "approval_sha256",
            "decision", "reason", "ticket"
        ],
        "properties": {
            "signer_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "public_key": digest,
            "approval_sha256": digest,
            "decision": {"enum": ["approve", "reject"]},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/canary-rollout-authorization-v1.json",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "rollout_sha256", "policy_pack_id",
            "policy_pack_revision", "candidate_profile_sha256",
            "rollout_total_projects", "rollout_affected_projects",
            "rollout_new_violations", "evaluated_at_unix",
            "valid_from_unix", "expires_at_unix", "canary_projects", "policy",
            "rollback_policy", "approvals", "rejections", "members",
            "canary_eligible", "canary_authorized", "gate_failures"
        ],
        "properties": {
            "schema_version": {"const": CANARY_AUTHORIZATION_SCHEMA_VERSION},
            "status": {"enum": ["canary_authorized", "not_authorized"]},
            "rollout_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "candidate_profile_sha256": digest,
            "rollout_total_projects": {"type": "integer", "minimum": 1, "maximum": 1000},
            "rollout_affected_projects": {"type": "integer", "minimum": 0, "maximum": 1000},
            "rollout_new_violations": {"type": "integer", "minimum": 0},
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "valid_from_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1},
            "canary_projects": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_PROJECTS,
                "items": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"}
            },
            "policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "minimum_approvals", "maximum_canary_projects",
                    "maximum_canary_percent", "maximum_window_seconds"
                ],
                "properties": {
                    "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": MAXIMUM_REVIEWERS},
                    "maximum_canary_projects": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROJECTS},
                    "maximum_canary_percent": {"const": MAXIMUM_CANARY_PERCENT},
                    "maximum_window_seconds": {"const": MAXIMUM_WINDOW_SECONDS}
                }
            },
            "rollback_policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "automatic_rollback", "rollback_on_new_violation",
                    "rollback_on_quality_regression", "rollback_on_analysis_failure",
                    "rollback_on_missing_monitoring_evidence", "automatic_promotion",
                    "requires_post_canary_review"
                ],
                "properties": {
                    "automatic_rollback": {"const": true},
                    "rollback_on_new_violation": {"const": true},
                    "rollback_on_quality_regression": {"const": true},
                    "rollback_on_analysis_failure": {"const": true},
                    "rollback_on_missing_monitoring_evidence": {"const": true},
                    "automatic_promotion": {"const": false},
                    "requires_post_canary_review": {"const": true}
                }
            },
            "approvals": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_REVIEWERS},
            "rejections": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_REVIEWERS},
            "members": {"type": "array", "minItems": 1, "maxItems": MAXIMUM_REVIEWERS, "items": member},
            "canary_eligible": {"type": "boolean"},
            "canary_authorized": {"type": "boolean"},
            "gate_failures": {
                "type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 1024}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_closed(value: &Value) {
        match value {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".into())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false))
                    );
                }
                object.values().for_each(assert_closed);
            }
            Value::Array(values) => values.iter().for_each(assert_closed),
            _ => {}
        }
    }

    #[test]
    fn schemas_close_every_approval_object() {
        assert_closed(&signed_rollout_approval_json_schema());
        assert_closed(&canary_authorization_json_schema());
    }

    #[test]
    fn enforces_ten_percent_and_seven_day_limits() {
        assert_eq!(canary_limit(1), 1);
        assert_eq!(canary_limit(10), 1);
        assert_eq!(canary_limit(11), 2);
        assert!(validate_window(1, 1 + MAXIMUM_WINDOW_SECONDS).is_ok());
        assert!(validate_window(1, 2 + MAXIMUM_WINDOW_SECONDS).is_err());
    }
}
