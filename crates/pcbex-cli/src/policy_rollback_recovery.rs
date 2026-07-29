use crate::policy_deployment::{PolicyDeploymentState, validate_policy_deployment_state};
use crate::policy_deployment_rollback::{
    PolicyDeploymentRollbackState, validate_policy_deployment_rollback_state,
};
use crate::policy_deployment_verification::{
    PolicyDeploymentVerificationProject, PolicyDeploymentVerificationReport,
    policy_deployment_verification_json_schema, validate_policy_deployment_verification,
};
use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use crate::policy_rollout::{
    CanaryMonitoringInput, PolicyRolloutReport, observe_restored_project, validate_delta,
    validate_evidence, validate_evidence_artifact, validate_policy_rollout_report,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const POLICY_ROLLBACK_RECOVERY_SCHEMA_VERSION: u32 = 1;
pub const SIGNED_ROLLBACK_INCIDENT_ACK_SCHEMA_VERSION: u32 = 1;
pub const ROLLBACK_INCIDENT_CLOSURE_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-policy-rollback-incident-ack-v1";
const MAXIMUM_PROJECTS: usize = 1_000;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;
const MAXIMUM_ACK_WINDOW_SECONDS: u64 = 86_400;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRollbackRecoveryReport {
    pub schema_version: u32,
    pub status: String,
    pub rollback_state_sha256: String,
    pub rollout_sha256: String,
    pub failed_verification_sha256: String,
    pub previous_deployment_state_sha256: String,
    pub baseline_verification_sha256: String,
    pub policy_pack_id: String,
    pub restored_revision: u32,
    pub restored_policy_pack_sha256: String,
    pub failed_revision: u32,
    pub verified_at_unix: u64,
    pub total_projects: u32,
    pub observed_projects: u32,
    pub passed_projects: u32,
    pub failed_projects: u32,
    pub total_new_violations: u32,
    pub coverage_complete: bool,
    pub missing_projects: Vec<String>,
    pub recovery_verified: bool,
    pub incident_closure_eligible: bool,
    pub requires_operator_acknowledgment: bool,
    pub automatic_incident_closure: bool,
    pub projects: Vec<PolicyDeploymentVerificationProject>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRollbackIncidentAcknowledgment {
    pub schema_version: u32,
    pub rollback_state_sha256: String,
    pub recovery_sha256: String,
    pub policy_pack_id: String,
    pub restored_revision: u32,
    pub restored_policy_pack_sha256: String,
    pub failed_revision: u32,
    pub acknowledged_at_unix: u64,
    pub operator_id: String,
    pub reason: String,
    pub ticket: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackIncidentClosureState {
    pub schema_version: u32,
    pub status: String,
    pub rollback_state_sha256: String,
    pub recovery_sha256: String,
    pub policy_pack_id: String,
    pub active_revision: u32,
    pub active_policy_pack_sha256: String,
    pub failed_revision: u32,
    pub recovery_verified_at_unix: u64,
    pub acknowledged_at_unix: u64,
    pub closed_at_unix: u64,
    pub operator_id: String,
    pub operator_public_key: String,
    pub acknowledgment_sha256: String,
    pub reason: String,
    pub ticket: String,
    pub recovery_verified: bool,
    pub operator_acknowledged: bool,
    pub incident_closed: bool,
    pub automatic_incident_closure: bool,
}

#[derive(Serialize)]
struct AcknowledgmentPayload<'a> {
    domain: &'static str,
    rollback_state_sha256: &'a str,
    recovery_sha256: &'a str,
    policy_pack_id: &'a str,
    restored_revision: u32,
    restored_policy_pack_sha256: &'a str,
    failed_revision: u32,
    acknowledged_at_unix: u64,
    operator_id: &'a str,
    reason: &'a str,
    ticket: &'a str,
}

pub struct PolicyRollbackRecoveryEvidence<'a> {
    pub rollback: &'a PolicyDeploymentRollbackState,
    pub failed_deployment: &'a PolicyDeploymentState,
    pub failed_verification: &'a PolicyDeploymentVerificationReport,
    pub previous_deployment: &'a PolicyDeploymentState,
    pub baseline_verification: &'a PolicyDeploymentVerificationReport,
    pub rollout: &'a PolicyRolloutReport,
}

pub fn verify_policy_rollback_recovery(
    evidence: &PolicyRollbackRecoveryEvidence<'_>,
    restored_policy_pack: &OrganizationPolicyPack,
    restored_policy_pack_bytes: &[u8],
    verified_at_unix: u64,
    inputs: &[CanaryMonitoringInput<'_>],
) -> Result<PolicyRollbackRecoveryReport, String> {
    let PolicyRollbackRecoveryEvidence {
        rollback,
        failed_deployment: deployment,
        failed_verification,
        previous_deployment,
        baseline_verification,
        rollout,
    } = evidence;
    validate_policy_deployment_rollback_state(rollback)?;
    validate_policy_deployment_state(deployment)?;
    validate_policy_deployment_verification(failed_verification)?;
    validate_policy_deployment_state(previous_deployment)?;
    validate_policy_deployment_verification(baseline_verification)?;
    validate_policy_rollout_report(rollout)?;
    validate_policy_pack(restored_policy_pack)?;
    let restored_sha256 = normalized_sha256(restored_policy_pack, "restored policy pack")?;
    let deployment_sha256 = normalized_sha256(deployment, "failed deployment state")?;
    let verification_sha256 =
        normalized_sha256(failed_verification, "failed deployment verification")?;
    let previous_deployment_sha256 =
        normalized_sha256(previous_deployment, "previous deployment state")?;
    let baseline_verification_sha256 =
        normalized_sha256(baseline_verification, "baseline deployment verification")?;
    let rollout_sha256 = normalized_sha256(rollout, "policy rollout")?;
    if deployment_sha256 != rollback.deployment_state_sha256
        || verification_sha256 != rollback.verification_sha256
        || failed_verification.deployment_state_sha256 != deployment_sha256
        || deployment.rollout_sha256 != rollout_sha256
        || failed_verification.rollout_sha256 != rollout_sha256
    {
        return Err("rollback recovery evidence chain does not match the failed deployment".into());
    }
    if deployment.previous_state_sha256.as_deref() != Some(&previous_deployment_sha256)
        || baseline_verification.deployment_state_sha256 != previous_deployment_sha256
        || !baseline_verification.deployment_verified
        || baseline_verification.rollback_required
        || baseline_verification.policy_pack_id != rollback.policy_pack_id
        || baseline_verification.active_revision != rollback.active_revision
        || baseline_verification.active_policy_pack_sha256 != rollback.active_policy_pack_sha256
    {
        return Err(
            "rollback recovery baseline is not the verified pre-promotion deployment".into(),
        );
    }
    let rollout_ids = rollout
        .projects
        .iter()
        .map(|project| project.project_id.as_str())
        .collect::<HashSet<_>>();
    let baseline_ids = baseline_verification
        .projects
        .iter()
        .map(|project| project.project_id.as_str())
        .collect::<HashSet<_>>();
    if rollout_ids != baseline_ids {
        return Err("rollback recovery baseline scope differs from the failed rollout".into());
    }
    if restored_policy_pack.id != rollback.policy_pack_id
        || restored_policy_pack.revision != rollback.active_revision
        || restored_sha256 != rollback.active_policy_pack_sha256
    {
        return Err("rollback recovery is bound to a different restored policy".into());
    }
    if verified_at_unix < rollback.recorded_at_unix {
        return Err("rollback recovery verification predates rollback application".into());
    }
    if inputs.len() > baseline_verification.projects.len() {
        return Err("rollback recovery contains too many projects".into());
    }
    let mut ids = HashSet::new();
    let mut projects = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !ids.insert(input.project_id) {
            return Err(format!("duplicate recovery project {:?}", input.project_id));
        }
        let baseline = baseline_verification
            .projects
            .iter()
            .find(|project| project.project_id == input.project_id)
            .ok_or_else(|| format!("unknown recovery baseline project {:?}", input.project_id))?;
        let observed = observe_restored_project(
            input,
            &baseline.board,
            &baseline.observed,
            restored_policy_pack,
            restored_policy_pack_bytes,
        )?;
        projects.push(PolicyDeploymentVerificationProject {
            project_id: observed.project_id,
            board: observed.board,
            expected: observed.baseline,
            observed: observed.observed,
            delta: observed.delta,
            passed: observed.passed,
        });
    }
    projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));
    let actual_ids = projects
        .iter()
        .map(|project| project.project_id.as_str())
        .collect::<HashSet<_>>();
    let missing_projects = baseline_verification
        .projects
        .iter()
        .filter(|project| !actual_ids.contains(project.project_id.as_str()))
        .map(|project| project.project_id.clone())
        .collect::<Vec<_>>();
    let coverage_complete = missing_projects.is_empty();
    let passed_projects = projects.iter().filter(|project| project.passed).count() as u32;
    let failed_projects = projects.len() as u32 - passed_projects;
    let total_new_violations = projects.iter().try_fold(0_u32, |total, project| {
        total
            .checked_add(
                u32::try_from(project.delta.new_violations.len())
                    .map_err(|_| "recovery new violation count exceeds u32".to_string())?,
            )
            .ok_or_else(|| "recovery new violation count overflowed".to_string())
    })?;
    let recovery_verified = coverage_complete && failed_projects == 0 && total_new_violations == 0;
    let report = PolicyRollbackRecoveryReport {
        schema_version: POLICY_ROLLBACK_RECOVERY_SCHEMA_VERSION,
        status: if recovery_verified {
            "recovery_verified".into()
        } else {
            "recovery_failed".into()
        },
        rollback_state_sha256: normalized_sha256(rollback, "rollback state")?,
        rollout_sha256,
        failed_verification_sha256: rollback.verification_sha256.clone(),
        previous_deployment_state_sha256: previous_deployment_sha256,
        baseline_verification_sha256,
        policy_pack_id: rollback.policy_pack_id.clone(),
        restored_revision: rollback.active_revision,
        restored_policy_pack_sha256: rollback.active_policy_pack_sha256.clone(),
        failed_revision: rollback.failed_revision,
        verified_at_unix,
        total_projects: baseline_verification.projects.len() as u32,
        observed_projects: projects.len() as u32,
        passed_projects,
        failed_projects,
        total_new_violations,
        coverage_complete,
        missing_projects,
        recovery_verified,
        incident_closure_eligible: recovery_verified,
        requires_operator_acknowledgment: true,
        automatic_incident_closure: false,
        projects,
    };
    validate_policy_rollback_recovery(&report)?;
    Ok(report)
}

pub fn sign_rollback_incident_acknowledgment(
    rollback: &PolicyDeploymentRollbackState,
    recovery: &PolicyRollbackRecoveryReport,
    acknowledged_at_unix: u64,
    operator_id: &str,
    reason: &str,
    ticket: &str,
    secret_key: &[u8; 32],
) -> Result<SignedRollbackIncidentAcknowledgment, String> {
    validate_recovery_binding(rollback, recovery)?;
    if !recovery.recovery_verified || !recovery.incident_closure_eligible {
        return Err("rollback incident acknowledgment requires clean complete recovery".into());
    }
    if acknowledged_at_unix < recovery.verified_at_unix
        || acknowledged_at_unix
            > recovery
                .verified_at_unix
                .saturating_add(MAXIMUM_ACK_WINDOW_SECONDS)
    {
        return Err("rollback incident acknowledgment is outside the bounded review window".into());
    }
    validate_slug("rollback incident operator", operator_id)?;
    validate_text(reason, MAXIMUM_TEXT_BYTES, "rollback incident reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "rollback incident ticket")?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex_encode(&signing_key.verifying_key().to_bytes());
    let mut acknowledgment = SignedRollbackIncidentAcknowledgment {
        schema_version: SIGNED_ROLLBACK_INCIDENT_ACK_SCHEMA_VERSION,
        rollback_state_sha256: recovery.rollback_state_sha256.clone(),
        recovery_sha256: normalized_sha256(recovery, "rollback recovery")?,
        policy_pack_id: recovery.policy_pack_id.clone(),
        restored_revision: recovery.restored_revision,
        restored_policy_pack_sha256: recovery.restored_policy_pack_sha256.clone(),
        failed_revision: recovery.failed_revision,
        acknowledged_at_unix,
        operator_id: operator_id.into(),
        reason: reason.into(),
        ticket: ticket.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: String::new(),
    };
    let payload = acknowledgment_payload(&acknowledgment)?;
    acknowledgment.signature = hex_encode(&signing_key.sign(&payload).to_bytes());
    validate_signed_rollback_incident_acknowledgment(&acknowledgment)?;
    Ok(acknowledgment)
}

pub fn close_rollback_incident(
    rollback: &PolicyDeploymentRollbackState,
    recovery: &PolicyRollbackRecoveryReport,
    restored_policy_pack: &OrganizationPolicyPack,
    acknowledgment: &SignedRollbackIncidentAcknowledgment,
    closed_at_unix: u64,
) -> Result<RollbackIncidentClosureState, String> {
    validate_recovery_binding(rollback, recovery)?;
    validate_policy_pack(restored_policy_pack)?;
    validate_signed_rollback_incident_acknowledgment(acknowledgment)?;
    if !recovery.recovery_verified || !recovery.incident_closure_eligible {
        return Err("rollback incident cannot close without clean complete recovery".into());
    }
    let restored_sha256 = normalized_sha256(restored_policy_pack, "restored policy pack")?;
    if restored_policy_pack.id != rollback.policy_pack_id
        || restored_policy_pack.revision != rollback.active_revision
        || restored_sha256 != rollback.active_policy_pack_sha256
    {
        return Err(
            "rollback incident closure trust policy does not match the restored pack".into(),
        );
    }
    if acknowledgment.rollback_state_sha256 != recovery.rollback_state_sha256
        || acknowledgment.recovery_sha256 != normalized_sha256(recovery, "rollback recovery")?
        || acknowledgment.policy_pack_id != recovery.policy_pack_id
        || acknowledgment.restored_revision != recovery.restored_revision
        || acknowledgment.restored_policy_pack_sha256 != recovery.restored_policy_pack_sha256
        || acknowledgment.failed_revision != recovery.failed_revision
    {
        return Err("rollback incident acknowledgment is bound to different evidence".into());
    }
    if acknowledgment.acknowledged_at_unix < recovery.verified_at_unix
        || acknowledgment.acknowledged_at_unix
            > recovery
                .verified_at_unix
                .saturating_add(MAXIMUM_ACK_WINDOW_SECONDS)
        || closed_at_unix < acknowledgment.acknowledged_at_unix
        || closed_at_unix
            > recovery
                .verified_at_unix
                .saturating_add(MAXIMUM_ACK_WINDOW_SECONDS)
    {
        return Err("rollback incident closure is outside the retained review window".into());
    }
    if rollback
        .members
        .iter()
        .any(|member| member.signer_id == acknowledgment.operator_id)
    {
        return Err("rollback incident operator must be independent of rollback approvers".into());
    }
    let trusted = restored_policy_pack
        .trusted_human_escalation_keys
        .iter()
        .find(|key| key.signer_id == acknowledgment.operator_id)
        .ok_or_else(|| "rollback incident operator is not trusted".to_string())?;
    let trusted_key = decode_hex_array::<32>(
        &trusted.public_key,
        "trusted rollback incident operator key",
    )?;
    let public_key =
        decode_hex_array::<32>(&acknowledgment.public_key, "rollback incident operator key")?;
    if public_key != trusted_key {
        return Err("rollback incident operator key does not match its trusted key".into());
    }
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &acknowledgment.signature,
        "rollback incident signature",
    )?);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid rollback incident public key: {error}"))?
        .verify_strict(&acknowledgment_payload(acknowledgment)?, &signature)
        .map_err(|error| format!("invalid rollback incident signature: {error}"))?;
    let state = RollbackIncidentClosureState {
        schema_version: ROLLBACK_INCIDENT_CLOSURE_SCHEMA_VERSION,
        status: "incident_closed".into(),
        rollback_state_sha256: recovery.rollback_state_sha256.clone(),
        recovery_sha256: acknowledgment.recovery_sha256.clone(),
        policy_pack_id: recovery.policy_pack_id.clone(),
        active_revision: recovery.restored_revision,
        active_policy_pack_sha256: recovery.restored_policy_pack_sha256.clone(),
        failed_revision: recovery.failed_revision,
        recovery_verified_at_unix: recovery.verified_at_unix,
        acknowledged_at_unix: acknowledgment.acknowledged_at_unix,
        closed_at_unix,
        operator_id: acknowledgment.operator_id.clone(),
        operator_public_key: acknowledgment.public_key.clone(),
        acknowledgment_sha256: normalized_sha256(
            acknowledgment,
            "rollback incident acknowledgment",
        )?,
        reason: acknowledgment.reason.clone(),
        ticket: acknowledgment.ticket.clone(),
        recovery_verified: true,
        operator_acknowledged: true,
        incident_closed: true,
        automatic_incident_closure: false,
    };
    validate_rollback_incident_closure(&state)?;
    Ok(state)
}

fn validate_recovery_binding(
    rollback: &PolicyDeploymentRollbackState,
    recovery: &PolicyRollbackRecoveryReport,
) -> Result<(), String> {
    validate_policy_deployment_rollback_state(rollback)?;
    validate_policy_rollback_recovery(recovery)?;
    if recovery.rollback_state_sha256 != normalized_sha256(rollback, "rollback state")?
        || recovery.failed_verification_sha256 != rollback.verification_sha256
        || recovery.policy_pack_id != rollback.policy_pack_id
        || recovery.restored_revision != rollback.active_revision
        || recovery.restored_policy_pack_sha256 != rollback.active_policy_pack_sha256
        || recovery.failed_revision != rollback.failed_revision
        || recovery.verified_at_unix < rollback.recorded_at_unix
    {
        return Err("rollback recovery is bound to a different rollback state".into());
    }
    Ok(())
}

pub fn parse_policy_rollback_recovery(
    source: &str,
) -> Result<PolicyRollbackRecoveryReport, String> {
    let report = serde_json::from_str(source)
        .map_err(|error| format!("invalid rollback recovery JSON: {error}"))?;
    validate_policy_rollback_recovery(&report)?;
    Ok(report)
}

pub fn parse_signed_rollback_incident_acknowledgment(
    source: &str,
) -> Result<SignedRollbackIncidentAcknowledgment, String> {
    let acknowledgment = serde_json::from_str(source).map_err(|error| {
        format!("invalid signed rollback incident acknowledgment JSON: {error}")
    })?;
    validate_signed_rollback_incident_acknowledgment(&acknowledgment)?;
    Ok(acknowledgment)
}

pub fn parse_rollback_incident_closure(
    source: &str,
) -> Result<RollbackIncidentClosureState, String> {
    let state = serde_json::from_str(source)
        .map_err(|error| format!("invalid rollback incident closure JSON: {error}"))?;
    validate_rollback_incident_closure(&state)?;
    Ok(state)
}

pub fn validate_policy_rollback_recovery(
    report: &PolicyRollbackRecoveryReport,
) -> Result<(), String> {
    let failed = !report.coverage_complete
        || report.failed_projects != 0
        || report.total_new_violations != 0;
    if report.schema_version != POLICY_ROLLBACK_RECOVERY_SCHEMA_VERSION
        || !matches!(
            report.status.as_str(),
            "recovery_verified" | "recovery_failed"
        )
        || report.total_projects == 0
        || report.total_projects > MAXIMUM_PROJECTS as u32
        || report.projects.len() > MAXIMUM_PROJECTS
        || report.observed_projects != report.projects.len() as u32
        || report.passed_projects.checked_add(report.failed_projects)
            != Some(report.observed_projects)
        || report.total_projects < report.observed_projects
        || report.missing_projects.len() as u32 != report.total_projects - report.observed_projects
        || report.coverage_complete != report.missing_projects.is_empty()
        || report.recovery_verified == failed
        || report.incident_closure_eligible != report.recovery_verified
        || !report.requires_operator_acknowledgment
        || report.automatic_incident_closure
        || (report.status == "recovery_verified") != report.recovery_verified
        || report.restored_revision == 0
        || report.failed_revision <= report.restored_revision
    {
        return Err("rollback recovery governance boundary is invalid".into());
    }
    validate_slug("policy pack id", &report.policy_pack_id)?;
    for digest in [
        &report.rollback_state_sha256,
        &report.rollout_sha256,
        &report.failed_verification_sha256,
        &report.previous_deployment_state_sha256,
        &report.baseline_verification_sha256,
        &report.restored_policy_pack_sha256,
    ] {
        validate_digest(digest)?;
    }
    let mut project_ids = HashSet::new();
    for project in &report.projects {
        validate_slug("recovery project", &project.project_id)?;
        validate_evidence_artifact(&project.board)?;
        validate_evidence(&project.expected)?;
        validate_evidence(&project.observed)?;
        validate_delta(&project.delta)?;
        if !project_ids.insert(project.project_id.as_str())
            || project.passed != !project.delta.is_regression()
        {
            return Err("rollback recovery project evidence is invalid".into());
        }
    }
    if report
        .projects
        .windows(2)
        .any(|projects| projects[0].project_id >= projects[1].project_id)
    {
        return Err("rollback recovery projects are not sorted".into());
    }
    let mut missing_ids = HashSet::new();
    let mut previous = None;
    for project_id in &report.missing_projects {
        validate_slug("missing recovery project", project_id)?;
        if project_ids.contains(project_id.as_str())
            || !missing_ids.insert(project_id.as_str())
            || previous.is_some_and(|value| value >= project_id.as_str())
        {
            return Err("missing recovery projects are duplicate, observed, or unordered".into());
        }
        previous = Some(project_id.as_str());
    }
    Ok(())
}

pub fn validate_signed_rollback_incident_acknowledgment(
    acknowledgment: &SignedRollbackIncidentAcknowledgment,
) -> Result<(), String> {
    if acknowledgment.schema_version != SIGNED_ROLLBACK_INCIDENT_ACK_SCHEMA_VERSION
        || acknowledgment.algorithm != "ed25519"
        || acknowledgment.restored_revision == 0
        || acknowledgment.failed_revision <= acknowledgment.restored_revision
    {
        return Err("signed rollback incident acknowledgment boundary is invalid".into());
    }
    for digest in [
        &acknowledgment.rollback_state_sha256,
        &acknowledgment.recovery_sha256,
        &acknowledgment.restored_policy_pack_sha256,
    ] {
        validate_digest(digest)?;
    }
    validate_slug("policy pack id", &acknowledgment.policy_pack_id)?;
    validate_slug("rollback incident operator", &acknowledgment.operator_id)?;
    validate_text(
        &acknowledgment.reason,
        MAXIMUM_TEXT_BYTES,
        "rollback incident reason",
    )?;
    validate_text(
        &acknowledgment.ticket,
        MAXIMUM_TICKET_BYTES,
        "rollback incident ticket",
    )?;
    decode_hex_array::<32>(&acknowledgment.public_key, "rollback incident public key")?;
    decode_hex_array::<64>(&acknowledgment.signature, "rollback incident signature")?;
    Ok(())
}

pub fn validate_rollback_incident_closure(
    state: &RollbackIncidentClosureState,
) -> Result<(), String> {
    if state.schema_version != ROLLBACK_INCIDENT_CLOSURE_SCHEMA_VERSION
        || state.status != "incident_closed"
        || state.active_revision == 0
        || state.failed_revision <= state.active_revision
        || state.recovery_verified_at_unix > state.acknowledged_at_unix
        || state.acknowledged_at_unix > state.closed_at_unix
        || !state.recovery_verified
        || !state.operator_acknowledged
        || !state.incident_closed
        || state.automatic_incident_closure
    {
        return Err("rollback incident closure governance boundary is invalid".into());
    }
    for digest in [
        &state.rollback_state_sha256,
        &state.recovery_sha256,
        &state.active_policy_pack_sha256,
        &state.acknowledgment_sha256,
    ] {
        validate_digest(digest)?;
    }
    validate_slug("policy pack id", &state.policy_pack_id)?;
    validate_slug("rollback incident operator", &state.operator_id)?;
    decode_hex_array::<32>(&state.operator_public_key, "rollback incident operator key")?;
    validate_text(
        &state.reason,
        MAXIMUM_TEXT_BYTES,
        "rollback incident reason",
    )?;
    validate_text(
        &state.ticket,
        MAXIMUM_TICKET_BYTES,
        "rollback incident ticket",
    )?;
    Ok(())
}

pub fn render_policy_rollback_recovery_summary(report: &PolicyRollbackRecoveryReport) -> String {
    let mut summary = format!(
        "# Policy rollback recovery\n\n\
         **Result:** `{}`\n\n\
         - Restored revision: `{}`\n\
         - Failed revision: `{}`\n\
         - Coverage: `{}/{}`\n\
         - Passed: `{}`\n\
         - Failed: `{}`\n\
         - Operator acknowledgment required: `true`\n\
         - Automatic incident closure: `false`\n",
        report.status,
        report.restored_revision,
        report.failed_revision,
        report.observed_projects,
        report.total_projects,
        report.passed_projects,
        report.failed_projects
    );
    if !report.projects.is_empty() {
        let _ = writeln!(
            summary,
            "\n| Project | Passed | New violations |\n|---|---:|---:|"
        );
        for project in &report.projects {
            let _ = writeln!(
                summary,
                "| `{}` | `{}` | {} |",
                project.project_id,
                project.passed,
                project.delta.new_violations.len()
            );
        }
    }
    summary
}

pub fn render_rollback_incident_closure_summary(state: &RollbackIncidentClosureState) -> String {
    format!(
        "# Rollback incident closure\n\n\
         **Result:** `incident_closed`\n\n\
         - Active revision: `{}`\n\
         - Failed revision: `{}`\n\
         - Operator: `{}`\n\
         - Ticket: `{}`\n\
         - Recovery verified: `true`\n\
         - Automatic incident closure: `false`\n",
        state.active_revision, state.failed_revision, state.operator_id, state.ticket
    )
}

pub fn policy_rollback_recovery_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let verification = policy_deployment_verification_json_schema();
    let project = verification["properties"]["projects"]["items"].clone();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-rollback-recovery-v1.json",
        "title": "pcbex policy rollback recovery verification",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "rollback_state_sha256", "rollout_sha256",
            "failed_verification_sha256", "previous_deployment_state_sha256",
            "baseline_verification_sha256", "policy_pack_id", "restored_revision",
            "restored_policy_pack_sha256", "failed_revision", "verified_at_unix",
            "total_projects", "observed_projects", "passed_projects", "failed_projects",
            "total_new_violations", "coverage_complete", "missing_projects",
            "recovery_verified", "incident_closure_eligible",
            "requires_operator_acknowledgment", "automatic_incident_closure", "projects"
        ],
        "properties": {
            "schema_version": {"const": POLICY_ROLLBACK_RECOVERY_SCHEMA_VERSION},
            "status": {"enum": ["recovery_verified", "recovery_failed"]},
            "rollback_state_sha256": digest,
            "rollout_sha256": digest,
            "failed_verification_sha256": digest,
            "previous_deployment_state_sha256": digest,
            "baseline_verification_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "restored_revision": {"type": "integer", "minimum": 1},
            "restored_policy_pack_sha256": digest,
            "failed_revision": {"type": "integer", "minimum": 2},
            "verified_at_unix": {"type": "integer", "minimum": 0},
            "total_projects": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROJECTS},
            "observed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "passed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "failed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "total_new_violations": {"type": "integer", "minimum": 0},
            "coverage_complete": {"type": "boolean"},
            "missing_projects": {"type": "array", "maxItems": MAXIMUM_PROJECTS, "items": {"type": "string"}},
            "recovery_verified": {"type": "boolean"},
            "incident_closure_eligible": {"type": "boolean"},
            "requires_operator_acknowledgment": {"const": true},
            "automatic_incident_closure": {"const": false},
            "projects": {
                "type": "array", "maxItems": MAXIMUM_PROJECTS,
                "items": project
            }
        }
    })
}

pub fn signed_rollback_incident_acknowledgment_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-rollback-incident-acknowledgment-v1.json",
        "title": "pcbex signed rollback incident acknowledgment",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "rollback_state_sha256", "recovery_sha256", "policy_pack_id",
            "restored_revision", "restored_policy_pack_sha256", "failed_revision",
            "acknowledged_at_unix", "operator_id", "reason", "ticket", "algorithm",
            "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_ROLLBACK_INCIDENT_ACK_SCHEMA_VERSION},
            "rollback_state_sha256": digest,
            "recovery_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "restored_revision": {"type": "integer", "minimum": 1},
            "restored_policy_pack_sha256": digest,
            "failed_revision": {"type": "integer", "minimum": 2},
            "acknowledged_at_unix": {"type": "integer", "minimum": 0},
            "operator_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn rollback_incident_closure_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/rollback-incident-closure-v1.json",
        "title": "pcbex rollback incident closure state",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "status", "rollback_state_sha256", "recovery_sha256",
            "policy_pack_id", "active_revision", "active_policy_pack_sha256",
            "failed_revision", "recovery_verified_at_unix", "acknowledged_at_unix",
            "closed_at_unix", "operator_id", "operator_public_key",
            "acknowledgment_sha256", "reason", "ticket", "recovery_verified",
            "operator_acknowledged", "incident_closed", "automatic_incident_closure"
        ],
        "properties": {
            "schema_version": {"const": ROLLBACK_INCIDENT_CLOSURE_SCHEMA_VERSION},
            "status": {"const": "incident_closed"},
            "rollback_state_sha256": digest,
            "recovery_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "active_revision": {"type": "integer", "minimum": 1},
            "active_policy_pack_sha256": digest,
            "failed_revision": {"type": "integer", "minimum": 2},
            "recovery_verified_at_unix": {"type": "integer", "minimum": 0},
            "acknowledged_at_unix": {"type": "integer", "minimum": 0},
            "closed_at_unix": {"type": "integer", "minimum": 0},
            "operator_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"},
            "operator_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "acknowledgment_sha256": digest,
            "reason": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TICKET_BYTES},
            "recovery_verified": {"const": true},
            "operator_acknowledged": {"const": true},
            "incident_closed": {"const": true},
            "automatic_incident_closure": {"const": false}
        }
    })
}

fn acknowledgment_payload(
    acknowledgment: &SignedRollbackIncidentAcknowledgment,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&AcknowledgmentPayload {
        domain: SIGNATURE_DOMAIN,
        rollback_state_sha256: &acknowledgment.rollback_state_sha256,
        recovery_sha256: &acknowledgment.recovery_sha256,
        policy_pack_id: &acknowledgment.policy_pack_id,
        restored_revision: acknowledgment.restored_revision,
        restored_policy_pack_sha256: &acknowledgment.restored_policy_pack_sha256,
        failed_revision: acknowledgment.failed_revision,
        acknowledged_at_unix: acknowledgment.acknowledged_at_unix,
        operator_id: &acknowledgment.operator_id,
        reason: &acknowledgment.reason,
        ticket: &acknowledgment.ticket,
    })
    .map_err(|error| format!("serializing rollback incident acknowledgment: {error}"))
}

fn normalized_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized {label}: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
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
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| format!("{label} is not hexadecimal"))?;
        bytes[index] =
            u8::from_str_radix(text, 16).map_err(|_| format!("{label} is not hexadecimal"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_deployment_rollback::PolicyDeploymentRollbackMember;
    use crate::policy_pack::{TrustedApprovalKey, parse_policy_pack};
    use crate::policy_rollout::{RolloutAnalysisEvidence, RolloutArtifact};
    use pcbex_core::analysis::AnalysisDelta;

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn artifact(path: &str, byte: char) -> RolloutArtifact {
        RolloutArtifact {
            path: path.into(),
            bytes: 1,
            sha256: digest(byte),
        }
    }

    fn evidence(prefix: &str, byte: char) -> RolloutAnalysisEvidence {
        RolloutAnalysisEvidence {
            run: artifact(&format!("{prefix}/run.json"), byte),
            checks: artifact(&format!("{prefix}/checks.json"), byte),
            quality: artifact(&format!("{prefix}/quality.json"), byte),
        }
    }

    fn clean_delta() -> AnalysisDelta {
        serde_json::from_value(json!({
            "schema_version": 1,
            "baseline": {
                "total_length_nm": 1, "total_vias": 0, "total_bends": 0,
                "routed_nets": 1, "unrouted_nets": 0, "violations": 0
            },
            "current": {
                "total_length_nm": 1, "total_vias": 0, "total_bends": 0,
                "routed_nets": 1, "unrouted_nets": 0, "violations": 0
            },
            "changes": {
                "total_length_nm": 0, "total_length_percent": 0.0,
                "total_vias": 0, "total_bends": 0, "routed_nets": 0,
                "unrouted_nets": 0, "violations": 0
            },
            "quality_regressions": [], "new_violations": [], "resolved_violations": []
        }))
        .unwrap()
    }

    fn fixtures() -> (
        PolicyDeploymentRollbackState,
        PolicyRollbackRecoveryReport,
        OrganizationPolicyPack,
        [u8; 32],
        [u8; 32],
    ) {
        let rollback_key = [1_u8; 32];
        let second_rollback_key = [2_u8; 32];
        let operator_key = [3_u8; 32];
        let rollback_public = hex_encode(
            &SigningKey::from_bytes(&rollback_key)
                .verifying_key()
                .to_bytes(),
        );
        let second_rollback_public = hex_encode(
            &SigningKey::from_bytes(&second_rollback_key)
                .verifying_key()
                .to_bytes(),
        );
        let operator_public = hex_encode(
            &SigningKey::from_bytes(&operator_key)
                .verifying_key()
                .to_bytes(),
        );
        let mut pack = parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json"))
            .expect("example policy");
        pack.revision = 2;
        pack.trusted_human_escalation_keys = vec![
            TrustedApprovalKey {
                signer_id: "reviewer-a".into(),
                public_key: rollback_public.clone(),
            },
            TrustedApprovalKey {
                signer_id: "reviewer-b".into(),
                public_key: second_rollback_public.clone(),
            },
            TrustedApprovalKey {
                signer_id: "incident-operator".into(),
                public_key: operator_public,
            },
        ];
        let pack_sha = normalized_sha256(&pack, "restored pack").unwrap();
        let rollback = PolicyDeploymentRollbackState {
            schema_version: 1,
            status: "rollback_applied".into(),
            generation: 3,
            policy_pack_id: pack.id.clone(),
            active_revision: 2,
            active_policy_pack_sha256: pack_sha.clone(),
            failed_revision: 3,
            failed_policy_pack_sha256: digest('b'),
            highest_considered_revision: 3,
            highest_considered_policy_pack_sha256: digest('b'),
            deployment_state_sha256: digest('c'),
            verification_sha256: digest('d'),
            minimum_approvals: 2,
            approvals: 2,
            members: vec![
                PolicyDeploymentRollbackMember {
                    signer_id: "reviewer-a".into(),
                    public_key: rollback_public,
                    approval_sha256: digest('e'),
                    approved_at_unix: 90,
                    reason: "regression".into(),
                    ticket: "HW-1".into(),
                },
                PolicyDeploymentRollbackMember {
                    signer_id: "reviewer-b".into(),
                    public_key: second_rollback_public,
                    approval_sha256: digest('f'),
                    approved_at_unix: 91,
                    reason: "regression".into(),
                    ticket: "HW-1".into(),
                },
            ],
            rollback_applied: true,
            automatic_rollback: false,
            recorded_at_unix: 100,
        };
        let recovery = PolicyRollbackRecoveryReport {
            schema_version: 1,
            status: "recovery_verified".into(),
            rollback_state_sha256: normalized_sha256(&rollback, "rollback").unwrap(),
            rollout_sha256: digest('1'),
            failed_verification_sha256: rollback.verification_sha256.clone(),
            previous_deployment_state_sha256: digest('5'),
            baseline_verification_sha256: digest('6'),
            policy_pack_id: pack.id.clone(),
            restored_revision: 2,
            restored_policy_pack_sha256: pack_sha,
            failed_revision: 3,
            verified_at_unix: 110,
            total_projects: 1,
            observed_projects: 1,
            passed_projects: 1,
            failed_projects: 0,
            total_new_violations: 0,
            coverage_complete: true,
            missing_projects: Vec::new(),
            recovery_verified: true,
            incident_closure_eligible: true,
            requires_operator_acknowledgment: true,
            automatic_incident_closure: false,
            projects: vec![PolicyDeploymentVerificationProject {
                project_id: "controller".into(),
                board: artifact("controller.kicad_pcb", '2'),
                expected: evidence("expected", '3'),
                observed: evidence("observed", '4'),
                delta: clean_delta(),
                passed: true,
            }],
        };
        (rollback, recovery, pack, operator_key, rollback_key)
    }

    #[test]
    fn recovery_schemas_close_top_level_objects() {
        assert_eq!(
            policy_rollback_recovery_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            signed_rollback_incident_acknowledgment_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            rollback_incident_closure_json_schema()["additionalProperties"],
            false
        );
    }

    #[test]
    fn incident_closure_requires_clean_evidence_and_an_independent_signature() {
        let (rollback, recovery, pack, operator_key, rollback_key) = fixtures();
        let acknowledgment = sign_rollback_incident_acknowledgment(
            &rollback,
            &recovery,
            120,
            "incident-operator",
            "The restored fleet is complete and clean.",
            "HW-1",
            &operator_key,
        )
        .unwrap();
        let closure =
            close_rollback_incident(&rollback, &recovery, &pack, &acknowledgment, 121).unwrap();
        assert!(closure.incident_closed);
        assert!(!closure.automatic_incident_closure);

        let rollback_approver = sign_rollback_incident_acknowledgment(
            &rollback,
            &recovery,
            120,
            "reviewer-a",
            "Self closure is forbidden.",
            "HW-1",
            &rollback_key,
        )
        .unwrap();
        assert!(
            close_rollback_incident(&rollback, &recovery, &pack, &rollback_approver, 121)
                .unwrap_err()
                .contains("independent")
        );

        let mut tampered = acknowledgment.clone();
        tampered.ticket = "HW-TAMPERED".into();
        assert!(
            close_rollback_incident(&rollback, &recovery, &pack, &tampered, 121)
                .unwrap_err()
                .contains("signature")
        );

        let mut different_incident = recovery.clone();
        different_incident.verified_at_unix = 111;
        assert!(
            close_rollback_incident(&rollback, &different_incident, &pack, &acknowledgment, 121)
                .unwrap_err()
                .contains("different evidence")
        );
        assert!(
            sign_rollback_incident_acknowledgment(
                &rollback,
                &recovery,
                recovery.verified_at_unix + MAXIMUM_ACK_WINDOW_SECONDS + 1,
                "incident-operator",
                "Stale.",
                "HW-1",
                &operator_key,
            )
            .unwrap_err()
            .contains("bounded review window")
        );

        let mut incomplete = recovery;
        incomplete.status = "recovery_failed".into();
        incomplete.observed_projects = 0;
        incomplete.passed_projects = 0;
        incomplete.coverage_complete = false;
        incomplete.missing_projects = vec!["controller".into()];
        incomplete.recovery_verified = false;
        incomplete.incident_closure_eligible = false;
        incomplete.projects.clear();
        assert!(
            sign_rollback_incident_acknowledgment(
                &rollback,
                &incomplete,
                120,
                "incident-operator",
                "Incomplete.",
                "HW-1",
                &operator_key,
            )
            .unwrap_err()
            .contains("clean complete recovery")
        );
    }
}
