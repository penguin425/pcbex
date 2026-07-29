use crate::policy_pack::{
    OrganizationPolicyPack, PolicyTrustState, policy_trust_state_json_schema, validate_policy_pack,
    validate_policy_trust_state,
};
use crate::policy_rollout::{
    CanaryMonitoringReport, PolicyRolloutReport, canary_monitoring_json_schema,
    policy_rollout_json_schema, validate_canary_monitoring_report, validate_policy_rollout_report,
};
use crate::policy_suspension::{PolicySuspensionState, validate_policy_suspension_state};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const SIGNED_POLICY_REMEDIATION_APPROVAL_SCHEMA_VERSION: u32 = 1;
pub const POLICY_REMEDIATION_STATE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-remediation-approval-v1";
const MAXIMUM_APPROVALS: usize = 100;
const MAXIMUM_APPROVAL_WINDOW_SECONDS: u64 = 86_400;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyRemediationApproval {
    pub schema_version: u32,
    pub suspension_state_sha256: String,
    pub policy_pack_id: String,
    pub suspended_revision: u32,
    pub suspended_policy_pack_sha256: String,
    pub remediation_revision: u32,
    pub remediation_policy_pack_sha256: String,
    pub candidate_policy_trust_state_sha256: String,
    pub rollout_sha256: String,
    pub monitoring_sha256: String,
    pub approved_at_unix: u64,
    pub reason: String,
    pub ticket: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRemediationMember {
    pub signer_id: String,
    pub public_key: String,
    pub approval_sha256: String,
    pub approved_at_unix: u64,
    pub reason: String,
    pub ticket: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRemediationState {
    pub schema_version: u32,
    pub status: String,
    pub policy_pack_id: String,
    pub suspended_revision: u32,
    pub suspended_policy_pack_sha256: String,
    pub remediation_revision: u32,
    pub remediation_policy_pack_sha256: String,
    pub suspension_state_sha256: String,
    pub candidate_policy_trust_state_sha256: String,
    pub rollout_sha256: String,
    pub monitoring_sha256: String,
    pub candidate_policy_trust_state: PolicyTrustState,
    pub rollout: PolicyRolloutReport,
    pub monitoring: CanaryMonitoringReport,
    pub clean_canary_verified: bool,
    pub suspension_lifted_for_remediation: bool,
    pub automatic_suspension_lift: bool,
    pub minimum_approvals: u32,
    pub approvals: u32,
    pub members: Vec<PolicyRemediationMember>,
    pub signed_approvals: Vec<SignedPolicyRemediationApproval>,
    pub recorded_at_unix: u64,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    suspension_state_sha256: &'a str,
    policy_pack_id: &'a str,
    suspended_revision: u32,
    suspended_policy_pack_sha256: &'a str,
    remediation_revision: u32,
    remediation_policy_pack_sha256: &'a str,
    candidate_policy_trust_state_sha256: &'a str,
    rollout_sha256: &'a str,
    monitoring_sha256: &'a str,
    approved_at_unix: u64,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

struct RemediationBinding {
    suspension_state_sha256: String,
    policy_pack_id: String,
    suspended_revision: u32,
    suspended_policy_pack_sha256: String,
    remediation_revision: u32,
    remediation_policy_pack_sha256: String,
    candidate_policy_trust_state_sha256: String,
    rollout_sha256: String,
    monitoring_sha256: String,
    monitoring_at_unix: u64,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_policy_remediation_approval(
    suspension: &PolicySuspensionState,
    candidate: &OrganizationPolicyPack,
    candidate_trust_state: &PolicyTrustState,
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
    approved_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedPolicyRemediationApproval, String> {
    let binding = remediation_binding(
        suspension,
        candidate,
        candidate_trust_state,
        rollout,
        monitoring,
    )?;
    validate_approval_time(binding.monitoring_at_unix, approved_at_unix)?;
    validate_text(reason, MAXIMUM_TEXT_BYTES, "policy remediation reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "policy remediation ticket")?;
    validate_slug(signer_id)?;
    if suspension
        .members
        .iter()
        .any(|member| member.signer_id == signer_id)
    {
        return Err(
            "policy remediation approver must be independent of suspension approvers".into(),
        );
    }
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let payload = signature_payload(&binding, approved_at_unix, reason, ticket, signer_id)?;
    let signed = SignedPolicyRemediationApproval {
        schema_version: SIGNED_POLICY_REMEDIATION_APPROVAL_SCHEMA_VERSION,
        suspension_state_sha256: binding.suspension_state_sha256,
        policy_pack_id: binding.policy_pack_id,
        suspended_revision: binding.suspended_revision,
        suspended_policy_pack_sha256: binding.suspended_policy_pack_sha256,
        remediation_revision: binding.remediation_revision,
        remediation_policy_pack_sha256: binding.remediation_policy_pack_sha256,
        candidate_policy_trust_state_sha256: binding.candidate_policy_trust_state_sha256,
        rollout_sha256: binding.rollout_sha256,
        monitoring_sha256: binding.monitoring_sha256,
        approved_at_unix,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: hex_encode(&signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_policy_remediation_approval(&signed)?;
    Ok(signed)
}

#[allow(clippy::too_many_arguments)]
pub fn apply_policy_remediation(
    suspension: &PolicySuspensionState,
    trust_policy_pack: &OrganizationPolicyPack,
    candidate: &OrganizationPolicyPack,
    candidate_trust_state: &PolicyTrustState,
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
    approvals: &[SignedPolicyRemediationApproval],
    minimum_approvals: u32,
    recorded_at_unix: u64,
) -> Result<PolicyRemediationState, String> {
    let binding = remediation_binding(
        suspension,
        candidate,
        candidate_trust_state,
        rollout,
        monitoring,
    )?;
    validate_policy_pack(trust_policy_pack)?;
    if trust_policy_pack.id != candidate.id
        || trust_policy_pack.trusted_human_escalation_keys
            != candidate.trusted_human_escalation_keys
    {
        return Err("policy remediation cannot change the trusted human approval root".into());
    }
    if !(2..=MAXIMUM_APPROVALS as u32).contains(&minimum_approvals)
        || approvals.is_empty()
        || approvals.len() > MAXIMUM_APPROVALS
    {
        return Err("policy remediation requires 1 to 100 approvals and a minimum of 2".into());
    }
    validate_approval_time(binding.monitoring_at_unix, recorded_at_unix)?;
    let suspension_signers = suspension
        .members
        .iter()
        .map(|member| member.signer_id.as_str())
        .collect::<HashSet<_>>();
    let suspension_keys = suspension
        .members
        .iter()
        .map(|member| member.public_key.as_str())
        .collect::<HashSet<_>>();
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut members = Vec::with_capacity(approvals.len());
    for signed in approvals {
        validate_signed_policy_remediation_approval(signed)?;
        validate_approval_binding(signed, &binding)?;
        if signed.approved_at_unix > recorded_at_unix {
            return Err("policy remediation approval is newer than retained state".into());
        }
        validate_approval_time(binding.monitoring_at_unix, signed.approved_at_unix)?;
        let trusted = candidate
            .trusted_human_escalation_keys
            .iter()
            .find(|trusted| trusted.signer_id == signed.signer_id)
            .ok_or_else(|| {
                format!(
                    "policy remediation signer {:?} is not trusted",
                    signed.signer_id
                )
            })?;
        verify_signature(
            signed,
            &decode_hex_array::<32>(&trusted.public_key, "trusted remediation key")?,
        )?;
        if suspension_signers.contains(signed.signer_id.as_str())
            || suspension_keys.contains(signed.public_key.as_str())
        {
            return Err(
                "policy remediation quorum must be independent of suspension approvers".into(),
            );
        }
        if !signer_ids.insert(signed.signer_id.as_str())
            || !public_keys.insert(signed.public_key.as_str())
        {
            return Err("policy remediation approvals require distinct signer IDs and keys".into());
        }
        members.push(PolicyRemediationMember {
            signer_id: signed.signer_id.clone(),
            public_key: signed.public_key.clone(),
            approval_sha256: normalized_sha256(signed, "policy remediation approval")?,
            approved_at_unix: signed.approved_at_unix,
            reason: signed.reason.clone(),
            ticket: signed.ticket.clone(),
        });
    }
    if members.len() < minimum_approvals as usize {
        return Err("policy remediation did not receive the required independent quorum".into());
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let mut signed_approvals = approvals.to_vec();
    signed_approvals.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let state = PolicyRemediationState {
        schema_version: POLICY_REMEDIATION_STATE_SCHEMA_VERSION,
        status: "remediation_verified".into(),
        policy_pack_id: binding.policy_pack_id,
        suspended_revision: binding.suspended_revision,
        suspended_policy_pack_sha256: binding.suspended_policy_pack_sha256,
        remediation_revision: binding.remediation_revision,
        remediation_policy_pack_sha256: binding.remediation_policy_pack_sha256,
        suspension_state_sha256: binding.suspension_state_sha256,
        candidate_policy_trust_state_sha256: binding.candidate_policy_trust_state_sha256,
        rollout_sha256: binding.rollout_sha256,
        monitoring_sha256: binding.monitoring_sha256,
        candidate_policy_trust_state: candidate_trust_state.clone(),
        rollout: rollout.clone(),
        monitoring: monitoring.clone(),
        clean_canary_verified: true,
        suspension_lifted_for_remediation: true,
        automatic_suspension_lift: false,
        minimum_approvals,
        approvals: members.len() as u32,
        members,
        signed_approvals,
        recorded_at_unix,
    };
    validate_policy_remediation_state(&state)?;
    Ok(state)
}

pub fn validate_remediation_for_candidate(
    state: &PolicyRemediationState,
    suspension: &PolicySuspensionState,
    candidate: &OrganizationPolicyPack,
) -> Result<(), String> {
    validate_policy_remediation_state(state)?;
    validate_policy_suspension_state(suspension)?;
    validate_policy_pack(candidate)?;
    let suspension_sha256 = normalized_sha256(suspension, "policy suspension state")?;
    let candidate_sha256 = normalized_sha256(candidate, "candidate policy pack")?;
    if state.suspension_state_sha256 != suspension_sha256
        || state.policy_pack_id != candidate.id
        || state.suspended_revision != suspension.failed_revision
        || state.suspended_policy_pack_sha256 != suspension.failed_policy_pack_sha256
        || state.remediation_revision != candidate.revision
        || state.remediation_policy_pack_sha256 != candidate_sha256
        || !state.suspension_lifted_for_remediation
    {
        return Err(
            "policy remediation state is bound to different suspension or candidate".into(),
        );
    }
    remediation_binding(
        suspension,
        candidate,
        &state.candidate_policy_trust_state,
        &state.rollout,
        &state.monitoring,
    )?;
    let suspension_signers = suspension
        .members
        .iter()
        .map(|member| member.signer_id.as_str())
        .collect::<HashSet<_>>();
    let suspension_keys = suspension
        .members
        .iter()
        .map(|member| member.public_key.as_str())
        .collect::<HashSet<_>>();
    for signed in &state.signed_approvals {
        if suspension_signers.contains(signed.signer_id.as_str())
            || suspension_keys.contains(signed.public_key.as_str())
        {
            return Err(
                "policy remediation quorum is not independent of suspension approvers".into(),
            );
        }
        let trusted = candidate
            .trusted_human_escalation_keys
            .iter()
            .find(|trusted| trusted.signer_id == signed.signer_id)
            .ok_or_else(|| {
                format!(
                    "policy remediation signer {:?} is not trusted by candidate",
                    signed.signer_id
                )
            })?;
        verify_signature(
            signed,
            &decode_hex_array::<32>(&trusted.public_key, "trusted remediation key")?,
        )?;
    }
    Ok(())
}

pub fn parse_signed_policy_remediation_approval(
    source: &str,
) -> Result<SignedPolicyRemediationApproval, String> {
    let signed = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed policy remediation approval JSON: {error}"))?;
    validate_signed_policy_remediation_approval(&signed)?;
    Ok(signed)
}

pub fn parse_policy_remediation_state(source: &str) -> Result<PolicyRemediationState, String> {
    let state = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy remediation state JSON: {error}"))?;
    validate_policy_remediation_state(&state)?;
    Ok(state)
}

pub fn validate_signed_policy_remediation_approval(
    signed: &SignedPolicyRemediationApproval,
) -> Result<(), String> {
    if signed.schema_version != SIGNED_POLICY_REMEDIATION_APPROVAL_SCHEMA_VERSION
        || signed.algorithm != "ed25519"
        || signed.remediation_revision <= signed.suspended_revision
        || signed.remediation_policy_pack_sha256 == signed.suspended_policy_pack_sha256
    {
        return Err("invalid signed policy remediation approval invariants".into());
    }
    validate_slug(&signed.policy_pack_id)?;
    validate_slug(&signed.signer_id)?;
    validate_text(
        &signed.reason,
        MAXIMUM_TEXT_BYTES,
        "policy remediation reason",
    )?;
    validate_text(
        &signed.ticket,
        MAXIMUM_TICKET_BYTES,
        "policy remediation ticket",
    )?;
    for digest in [
        &signed.suspension_state_sha256,
        &signed.suspended_policy_pack_sha256,
        &signed.remediation_policy_pack_sha256,
        &signed.candidate_policy_trust_state_sha256,
        &signed.rollout_sha256,
        &signed.monitoring_sha256,
    ] {
        validate_hex(digest, 32)?;
    }
    validate_hex(&signed.public_key, 32)?;
    validate_hex(&signed.signature, 64)
}

pub fn validate_policy_remediation_state(state: &PolicyRemediationState) -> Result<(), String> {
    if state.schema_version != POLICY_REMEDIATION_STATE_SCHEMA_VERSION
        || state.status != "remediation_verified"
        || state.remediation_revision <= state.suspended_revision
        || state.remediation_policy_pack_sha256 == state.suspended_policy_pack_sha256
        || !state.clean_canary_verified
        || !state.suspension_lifted_for_remediation
        || state.automatic_suspension_lift
        || state.minimum_approvals < 2
        || state.approvals != state.members.len() as u32
        || state.approvals != state.signed_approvals.len() as u32
        || state.approvals < state.minimum_approvals
        || state.approvals > MAXIMUM_APPROVALS as u32
    {
        return Err("invalid policy remediation state invariants".into());
    }
    validate_slug(&state.policy_pack_id)?;
    validate_policy_trust_state(&state.candidate_policy_trust_state)?;
    validate_policy_rollout_report(&state.rollout)?;
    validate_canary_monitoring_report(&state.monitoring)?;
    for digest in [
        &state.suspension_state_sha256,
        &state.suspended_policy_pack_sha256,
        &state.remediation_policy_pack_sha256,
        &state.candidate_policy_trust_state_sha256,
        &state.rollout_sha256,
        &state.monitoring_sha256,
    ] {
        validate_hex(digest, 32)?;
    }
    if normalized_sha256(
        &state.candidate_policy_trust_state,
        "candidate policy trust state",
    )? != state.candidate_policy_trust_state_sha256
        || normalized_sha256(&state.rollout, "policy rollout")? != state.rollout_sha256
        || normalized_sha256(&state.monitoring, "canary monitoring")? != state.monitoring_sha256
        || state.monitoring.rollout_sha256 != state.rollout_sha256
        || state.monitoring.rollback_required
        || !state.monitoring.promotion_eligible
        || state.monitoring.failed_projects != 0
        || state.monitoring.total_new_violations != 0
    {
        return Err("policy remediation embedded evidence is inconsistent".into());
    }
    validate_approval_time(state.monitoring.observed_at_unix, state.recorded_at_unix)?;
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for (member, signed) in state.members.iter().zip(&state.signed_approvals) {
        validate_signed_policy_remediation_approval(signed)?;
        validate_approval_time(state.monitoring.observed_at_unix, signed.approved_at_unix)?;
        if signed.suspension_state_sha256 != state.suspension_state_sha256
            || signed.policy_pack_id != state.policy_pack_id
            || signed.suspended_revision != state.suspended_revision
            || signed.suspended_policy_pack_sha256 != state.suspended_policy_pack_sha256
            || signed.remediation_revision != state.remediation_revision
            || signed.remediation_policy_pack_sha256 != state.remediation_policy_pack_sha256
            || signed.candidate_policy_trust_state_sha256
                != state.candidate_policy_trust_state_sha256
            || signed.rollout_sha256 != state.rollout_sha256
            || signed.monitoring_sha256 != state.monitoring_sha256
            || signed.signer_id != member.signer_id
            || signed.public_key != member.public_key
            || signed.approved_at_unix != member.approved_at_unix
            || normalized_sha256(signed, "policy remediation approval")? != member.approval_sha256
            || member.approved_at_unix > state.recorded_at_unix
            || !signer_ids.insert(member.signer_id.as_str())
            || !public_keys.insert(member.public_key.as_str())
        {
            return Err("policy remediation state contains invalid approval members".into());
        }
        validate_slug(&member.signer_id)?;
        validate_hex(&member.public_key, 32)?;
        validate_hex(&member.approval_sha256, 32)?;
        validate_text(
            &member.reason,
            MAXIMUM_TEXT_BYTES,
            "policy remediation reason",
        )?;
        validate_text(
            &member.ticket,
            MAXIMUM_TICKET_BYTES,
            "policy remediation ticket",
        )?;
    }
    Ok(())
}

fn remediation_binding(
    suspension: &PolicySuspensionState,
    candidate: &OrganizationPolicyPack,
    candidate_trust_state: &PolicyTrustState,
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
) -> Result<RemediationBinding, String> {
    validate_policy_suspension_state(suspension)?;
    validate_policy_pack(candidate)?;
    validate_policy_trust_state(candidate_trust_state)?;
    validate_policy_rollout_report(rollout)?;
    validate_canary_monitoring_report(monitoring)?;
    let candidate_sha256 = normalized_sha256(candidate, "remediation policy pack")?;
    let trust_state_sha256 =
        normalized_sha256(candidate_trust_state, "candidate policy trust state")?;
    let rollout_sha256 = normalized_sha256(rollout, "policy rollout")?;
    let monitoring_sha256 = normalized_sha256(monitoring, "canary monitoring")?;
    let candidate_profile_sha256 =
        normalized_sha256(&candidate.dfm_profile, "candidate DFM profile")?;
    if !suspension.policy_suspended
        || suspension.decision != crate::policy_suspension::PolicySuspensionDecision::Suspend
        || candidate.id != suspension.policy_pack_id
        || candidate.revision <= suspension.failed_revision
        || candidate_sha256 == suspension.failed_policy_pack_sha256
        || candidate_trust_state.policy_pack_id != candidate.id
        || candidate_trust_state.accepted_revision != candidate.revision
        || candidate_trust_state.policy_pack_sha256 != candidate_sha256
        || rollout.policy_pack_id != candidate.id
        || monitoring.policy_pack_id != candidate.id
        || monitoring.policy_pack_revision != rollout.policy_pack_revision
        || monitoring.rollout_sha256 != rollout_sha256
        || monitoring.candidate_profile_sha256 != candidate_profile_sha256
        || monitoring.total_projects != rollout.total_projects
        || monitoring.projects.len() != rollout.projects.len()
        || !monitoring.promotion_eligible
        || monitoring.rollback_required
        || monitoring.automatic_promotion
        || monitoring.failed_projects != 0
        || monitoring.total_new_violations != 0
        || monitoring.passed_projects != monitoring.total_projects
        || monitoring
            .projects
            .iter()
            .zip(&rollout.projects)
            .any(|(observed, simulated)| {
                observed.project_id != simulated.project_id
                    || observed.board != simulated.board
                    || observed.baseline != simulated.candidate
            })
    {
        return Err(
            "policy remediation requires an accepted successor and complete clean canary evidence"
                .into(),
        );
    }
    Ok(RemediationBinding {
        suspension_state_sha256: normalized_sha256(suspension, "policy suspension state")?,
        policy_pack_id: candidate.id.clone(),
        suspended_revision: suspension.failed_revision,
        suspended_policy_pack_sha256: suspension.failed_policy_pack_sha256.clone(),
        remediation_revision: candidate.revision,
        remediation_policy_pack_sha256: candidate_sha256,
        candidate_policy_trust_state_sha256: trust_state_sha256,
        rollout_sha256,
        monitoring_sha256,
        monitoring_at_unix: monitoring.observed_at_unix,
    })
}

fn validate_approval_binding(
    signed: &SignedPolicyRemediationApproval,
    binding: &RemediationBinding,
) -> Result<(), String> {
    if signed.suspension_state_sha256 != binding.suspension_state_sha256
        || signed.policy_pack_id != binding.policy_pack_id
        || signed.suspended_revision != binding.suspended_revision
        || signed.suspended_policy_pack_sha256 != binding.suspended_policy_pack_sha256
        || signed.remediation_revision != binding.remediation_revision
        || signed.remediation_policy_pack_sha256 != binding.remediation_policy_pack_sha256
        || signed.candidate_policy_trust_state_sha256 != binding.candidate_policy_trust_state_sha256
        || signed.rollout_sha256 != binding.rollout_sha256
        || signed.monitoring_sha256 != binding.monitoring_sha256
    {
        return Err("policy remediation approval is bound to different evidence".into());
    }
    Ok(())
}

fn signature_payload(
    binding: &RemediationBinding,
    approved_at_unix: u64,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        suspension_state_sha256: &binding.suspension_state_sha256,
        policy_pack_id: &binding.policy_pack_id,
        suspended_revision: binding.suspended_revision,
        suspended_policy_pack_sha256: &binding.suspended_policy_pack_sha256,
        remediation_revision: binding.remediation_revision,
        remediation_policy_pack_sha256: &binding.remediation_policy_pack_sha256,
        candidate_policy_trust_state_sha256: &binding.candidate_policy_trust_state_sha256,
        rollout_sha256: &binding.rollout_sha256,
        monitoring_sha256: &binding.monitoring_sha256,
        approved_at_unix,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("failed to encode remediation signature payload: {error}"))
}

fn verify_signature(
    signed: &SignedPolicyRemediationApproval,
    trusted_key: &[u8; 32],
) -> Result<(), String> {
    if signed.public_key != hex_encode(trusted_key) {
        return Err("policy remediation approval embeds a different public key".into());
    }
    let verifying_key = VerifyingKey::from_bytes(trusted_key)
        .map_err(|error| format!("invalid remediation public key: {error}"))?;
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &signed.signature,
        "policy remediation signature",
    )?);
    let payload = serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        suspension_state_sha256: &signed.suspension_state_sha256,
        policy_pack_id: &signed.policy_pack_id,
        suspended_revision: signed.suspended_revision,
        suspended_policy_pack_sha256: &signed.suspended_policy_pack_sha256,
        remediation_revision: signed.remediation_revision,
        remediation_policy_pack_sha256: &signed.remediation_policy_pack_sha256,
        candidate_policy_trust_state_sha256: &signed.candidate_policy_trust_state_sha256,
        rollout_sha256: &signed.rollout_sha256,
        monitoring_sha256: &signed.monitoring_sha256,
        approved_at_unix: signed.approved_at_unix,
        reason: &signed.reason,
        ticket: &signed.ticket,
        signer_id: &signed.signer_id,
    })
    .map_err(|error| format!("failed to encode remediation signature payload: {error}"))?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| "policy remediation signature verification failed".into())
}

fn validate_approval_time(monitoring_at: u64, value: u64) -> Result<(), String> {
    if value < monitoring_at
        || value > monitoring_at.saturating_add(MAXIMUM_APPROVAL_WINDOW_SECONDS)
    {
        return Err("policy remediation approval is outside the bounded review window".into());
    }
    Ok(())
}

pub fn render_policy_remediation_summary(state: &PolicyRemediationState) -> String {
    format!(
        "## pcbex policy remediation\n\n\
         - Status: `{}`\n\
         - Suspended revision: `{}`\n\
         - Remediation revision: `{}`\n\
         - Clean canary verified: `true`\n\
         - Independent approvals: `{}` / `{}` required\n\
         - Lifted only for digest: `{}`\n\
         - Automatic suspension lift: `false`\n",
        state.status,
        state.suspended_revision,
        state.remediation_revision,
        state.approvals,
        state.minimum_approvals,
        state.remediation_policy_pack_sha256
    )
}

pub fn signed_policy_remediation_approval_json_schema() -> Value {
    approval_schema()
}

pub fn policy_remediation_state_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "pcbex policy remediation state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "policy_pack_id", "suspended_revision",
            "suspended_policy_pack_sha256", "remediation_revision",
            "remediation_policy_pack_sha256", "suspension_state_sha256",
            "candidate_policy_trust_state_sha256", "rollout_sha256", "monitoring_sha256",
            "candidate_policy_trust_state", "rollout", "monitoring",
            "clean_canary_verified", "suspension_lifted_for_remediation",
            "automatic_suspension_lift", "minimum_approvals", "approvals",
            "members", "signed_approvals", "recorded_at_unix"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "status": {"const": "remediation_verified"},
            "policy_pack_id": slug_schema(),
            "suspended_revision": {"type": "integer", "minimum": 1},
            "suspended_policy_pack_sha256": digest_schema(),
            "remediation_revision": {"type": "integer", "minimum": 2},
            "remediation_policy_pack_sha256": digest_schema(),
            "suspension_state_sha256": digest_schema(),
            "candidate_policy_trust_state_sha256": digest_schema(),
            "rollout_sha256": digest_schema(),
            "monitoring_sha256": digest_schema(),
            "candidate_policy_trust_state": policy_trust_state_json_schema(),
            "rollout": policy_rollout_json_schema(),
            "monitoring": canary_monitoring_json_schema(),
            "clean_canary_verified": {"const": true},
            "suspension_lifted_for_remediation": {"const": true},
            "automatic_suspension_lift": {"const": false},
            "minimum_approvals": {"type": "integer", "minimum": 2, "maximum": 100},
            "approvals": {"type": "integer", "minimum": 2, "maximum": 100},
            "members": {
                "type": "array", "minItems": 2, "maxItems": 100,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["signer_id", "public_key", "approval_sha256", "approved_at_unix", "reason", "ticket"],
                    "properties": {
                        "signer_id": slug_schema(),
                        "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "approval_sha256": digest_schema(),
                        "approved_at_unix": {"type": "integer", "minimum": 1},
                        "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
                        "ticket": {"type": "string", "minLength": 1, "maxLength": 256}
                    }
                }
            },
            "signed_approvals": {
                "type": "array", "minItems": 2, "maxItems": 100,
                "items": approval_schema()
            },
            "recorded_at_unix": {"type": "integer", "minimum": 1}
        }
    })
}

fn approval_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Signed pcbex policy remediation approval",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "suspension_state_sha256", "policy_pack_id",
            "suspended_revision", "suspended_policy_pack_sha256",
            "remediation_revision", "remediation_policy_pack_sha256",
            "candidate_policy_trust_state_sha256", "rollout_sha256",
            "monitoring_sha256", "approved_at_unix", "reason", "ticket",
            "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "suspension_state_sha256": digest_schema(),
            "policy_pack_id": slug_schema(),
            "suspended_revision": {"type": "integer", "minimum": 1},
            "suspended_policy_pack_sha256": digest_schema(),
            "remediation_revision": {"type": "integer", "minimum": 2},
            "remediation_policy_pack_sha256": digest_schema(),
            "candidate_policy_trust_state_sha256": digest_schema(),
            "rollout_sha256": digest_schema(),
            "monitoring_sha256": digest_schema(),
            "approved_at_unix": {"type": "integer", "minimum": 1},
            "reason": {"type": "string", "minLength": 1, "maxLength": 4096},
            "ticket": {"type": "string", "minLength": 1, "maxLength": 256},
            "signer_id": slug_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
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
        return Err("policy remediation identity must be a non-empty safe identifier".into());
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
pub(crate) mod tests {
    use super::*;
    use crate::policy_incident_ledger::repeated_incident_test_ledger;
    use crate::policy_pack::{TrustedApprovalKey, parse_policy_pack};
    use crate::policy_rollout::{
        CanaryMonitoringProject, RolloutAnalysisEvidence, RolloutArtifact, RolloutCompatibility,
        RolloutProjectResult,
    };
    use crate::policy_suspension::{
        PolicySuspensionDecision, apply_policy_suspension_decision, enforce_policy_suspensions,
        sign_policy_suspension_decision,
    };
    use pcbex_core::analysis::{AnalysisDelta, AnalysisMetricChanges, AnalysisMetrics};

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn approval(signer: &str, public_key: char, at: u64) -> SignedPolicyRemediationApproval {
        SignedPolicyRemediationApproval {
            schema_version: 1,
            suspension_state_sha256: digest('1'),
            policy_pack_id: "acme-production-v1".into(),
            suspended_revision: 3,
            suspended_policy_pack_sha256: digest('2'),
            remediation_revision: 4,
            remediation_policy_pack_sha256: digest('3'),
            candidate_policy_trust_state_sha256: digest('4'),
            rollout_sha256: digest('5'),
            monitoring_sha256: digest('6'),
            approved_at_unix: at,
            reason: "Independent clean-canary review".into(),
            ticket: "HW-48".into(),
            signer_id: signer.into(),
            algorithm: "ed25519".into(),
            public_key: digest(public_key),
            signature: std::iter::repeat_n('a', 128).collect(),
        }
    }

    #[test]
    fn remediation_schemas_close_all_objects() {
        assert_eq!(
            signed_policy_remediation_approval_json_schema()["additionalProperties"],
            false
        );
        let schema = policy_remediation_state_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["members"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["signed_approvals"]["items"]["additionalProperties"],
            false
        );
    }

    #[test]
    fn remediation_approval_rejects_identity_tampering_and_stale_time() {
        let signed = approval("remediator-a", '7', 100);
        validate_signed_policy_remediation_approval(&signed).unwrap();

        let mut tampered = signed.clone();
        tampered.remediation_revision = tampered.suspended_revision;
        assert!(validate_signed_policy_remediation_approval(&tampered).is_err());

        let mut malformed = signed;
        malformed.remediation_policy_pack_sha256 = malformed.suspended_policy_pack_sha256.clone();
        assert!(validate_signed_policy_remediation_approval(&malformed).is_err());

        assert!(validate_approval_time(100, 100 + 86_400).is_ok());
        assert!(validate_approval_time(100, 99).is_err());
        assert!(validate_approval_time(100, 100 + 86_401).is_err());
    }

    fn clean_delta() -> AnalysisDelta {
        let metrics = AnalysisMetrics {
            total_length_nm: 0,
            total_vias: 0,
            total_bends: 0,
            routed_nets: 1,
            unrouted_nets: 0,
            violations: 0,
        };
        AnalysisDelta {
            schema_version: 1,
            baseline: metrics.clone(),
            current: metrics,
            changes: AnalysisMetricChanges {
                total_length_nm: 0,
                total_length_percent: None,
                total_vias: 0,
                total_bends: 0,
                routed_nets: 0,
                unrouted_nets: 0,
                violations: 0,
            },
            quality_regressions: vec![],
            new_violations: vec![],
            resolved_violations: vec![],
        }
    }

    fn artifact(path: &str, byte: char) -> RolloutArtifact {
        RolloutArtifact {
            path: path.into(),
            bytes: 1,
            sha256: digest(byte),
        }
    }

    fn evidence(prefix: &str, bytes: [char; 3]) -> RolloutAnalysisEvidence {
        RolloutAnalysisEvidence {
            run: artifact(&format!("{prefix}/run.json"), bytes[0]),
            checks: artifact(&format!("{prefix}/checks.json"), bytes[1]),
            quality: artifact(&format!("{prefix}/quality.json"), bytes[2]),
        }
    }

    pub(crate) fn lifecycle_test_states() -> (
        OrganizationPolicyPack,
        PolicySuspensionState,
        PolicyRemediationState,
    ) {
        let suspension_a = [7_u8; 32];
        let suspension_b = [8_u8; 32];
        let remediation_a = [9_u8; 32];
        let remediation_b = [10_u8; 32];
        let mut candidate =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        candidate.revision = 4;
        candidate.trusted_human_escalation_keys = [
            ("suspension-a", suspension_a),
            ("suspension-b", suspension_b),
            ("remediation-a", remediation_a),
            ("remediation-b", remediation_b),
        ]
        .into_iter()
        .map(|(signer_id, key)| TrustedApprovalKey {
            signer_id: signer_id.into(),
            public_key: hex_encode(&SigningKey::from_bytes(&key).verifying_key().to_bytes()),
        })
        .collect();
        validate_policy_pack(&candidate).unwrap();

        let ledger = repeated_incident_test_ledger();
        let failed_digest = digest('3');
        let suspension_decisions = [
            ("suspension-a", suspension_a, 209),
            ("suspension-b", suspension_b, 210),
        ]
        .map(|(signer, key, at)| {
            sign_policy_suspension_decision(
                &ledger,
                3,
                &failed_digest,
                PolicySuspensionDecision::Suspend,
                at,
                "Repeated regression",
                "HW-47",
                signer,
                &key,
            )
            .unwrap()
        });
        let suspension = apply_policy_suspension_decision(
            &ledger,
            &candidate,
            3,
            &failed_digest,
            &suspension_decisions,
            2,
            211,
        )
        .unwrap();
        assert!(
            enforce_policy_suspensions(&candidate, std::slice::from_ref(&suspension), &[])
                .unwrap_err()
                .contains("requires an independently verified remediation")
        );

        let candidate_sha256 = normalized_sha256(&candidate, "candidate").unwrap();
        let trust_state = PolicyTrustState {
            schema_version: 1,
            policy_pack_id: candidate.id.clone(),
            accepted_revision: candidate.revision,
            policy_pack_sha256: candidate_sha256.clone(),
            signer_id: "policy-authority".into(),
            public_key: digest('a'),
        };
        validate_policy_trust_state(&trust_state).unwrap();
        let board = artifact("controller.kicad_pcb", 'b');
        let baseline = evidence("baseline", ['c', 'd', 'e']);
        let observed = evidence("observed", ['f', '1', '2']);
        let rollout = PolicyRolloutReport {
            schema_version: 1,
            status: "simulation_only".into(),
            deployable: false,
            requires_human_approval: true,
            generated_on: "2026-07-29".into(),
            policy_pack_id: candidate.id.clone(),
            policy_pack_revision: 2,
            policy_pack_sha256: digest('4'),
            recommendation_sha256: digest('5'),
            candidate_profile: candidate.dfm_profile.clone(),
            total_projects: 1,
            compatible_projects: 1,
            affected_projects: 0,
            total_new_violations: 0,
            projects: vec![RolloutProjectResult {
                project_id: "controller".into(),
                board: board.clone(),
                compatibility: RolloutCompatibility::Compatible,
                baseline: evidence("source", ['6', '7', '8']),
                candidate: baseline.clone(),
                delta: clean_delta(),
            }],
        };
        validate_policy_rollout_report(&rollout).unwrap();
        let monitoring = CanaryMonitoringReport {
            schema_version: 1,
            status: "monitoring_passed".into(),
            rollout_sha256: normalized_sha256(&rollout, "rollout").unwrap(),
            authorization_sha256: digest('9'),
            policy_pack_id: candidate.id.clone(),
            policy_pack_revision: 2,
            candidate_profile_sha256: normalized_sha256(
                &candidate.dfm_profile,
                "candidate profile",
            )
            .unwrap(),
            observed_at_unix: 300,
            total_projects: 1,
            passed_projects: 1,
            failed_projects: 0,
            total_new_violations: 0,
            rollback_required: false,
            promotion_eligible: true,
            automatic_promotion: false,
            requires_human_decision: true,
            projects: vec![CanaryMonitoringProject {
                project_id: "controller".into(),
                board,
                baseline,
                observed,
                delta: clean_delta(),
                passed: true,
            }],
        };
        validate_canary_monitoring_report(&monitoring).unwrap();
        let approvals = [
            ("remediation-a", remediation_a, 301),
            ("remediation-b", remediation_b, 302),
        ]
        .map(|(signer, key, at)| {
            sign_policy_remediation_approval(
                &suspension,
                &candidate,
                &trust_state,
                &rollout,
                &monitoring,
                at,
                "Clean successor verified",
                "HW-48",
                signer,
                &key,
            )
            .unwrap()
        });
        let remediation = apply_policy_remediation(
            &suspension,
            &candidate,
            &candidate,
            &trust_state,
            &rollout,
            &monitoring,
            &approvals,
            2,
            303,
        )
        .unwrap();
        enforce_policy_suspensions(
            &candidate,
            std::slice::from_ref(&suspension),
            std::slice::from_ref(&remediation),
        )
        .unwrap();
        (candidate, suspension, remediation)
    }

    #[test]
    fn independent_clean_successor_lifts_only_its_exact_digest() {
        let (_, _, remediation) = lifecycle_test_states();
        let mut tampered = remediation;
        tampered.monitoring.promotion_eligible = false;
        assert!(validate_policy_remediation_state(&tampered).is_err());
    }
}
