use crate::canary_completion::{
    CanaryCompletionDecision, SignedCanaryCompletionDecision, verify_canary_completion,
};
use crate::policy_pack::{OrganizationPolicyPack, PolicyTrustState, validate_policy_trust_state};
use crate::policy_rollout::{CanaryMonitoringReport, PolicyRolloutReport};
use crate::policy_rollout_approval::CanaryRolloutAuthorization;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const POLICY_DEPLOYMENT_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDeploymentStatus {
    PromotionApplied,
    RollbackConfirmed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeploymentState {
    pub schema_version: u32,
    pub status: PolicyDeploymentStatus,
    pub generation: u64,
    pub policy_pack_id: String,
    pub active_revision: u32,
    pub active_policy_pack_sha256: String,
    pub highest_considered_revision: u32,
    pub highest_considered_policy_pack_sha256: String,
    pub rollback_revision: Option<u32>,
    pub rollback_policy_pack_sha256: Option<String>,
    pub candidate_revision: u32,
    pub candidate_policy_pack_sha256: String,
    pub final_decision: CanaryCompletionDecision,
    pub deployment_applied: bool,
    pub automatic_application: bool,
    pub post_deployment_verification_required: bool,
    pub verification_status: String,
    pub recorded_at_unix: u64,
    pub previous_state_sha256: Option<String>,
    pub source_policy_trust_state_sha256: String,
    pub candidate_policy_trust_state_sha256: String,
    pub rollout_sha256: String,
    pub authorization_sha256: String,
    pub monitoring_sha256: String,
    pub completion_sha256: String,
}

#[allow(clippy::too_many_arguments)]
pub fn advance_policy_deployment(
    rollout: &PolicyRolloutReport,
    monitoring: &CanaryMonitoringReport,
    authorization: &CanaryRolloutAuthorization,
    source_policy_pack: &OrganizationPolicyPack,
    candidate_policy_pack: &OrganizationPolicyPack,
    source_policy_trust_state: &PolicyTrustState,
    candidate_policy_trust_state: &PolicyTrustState,
    decisions: &[SignedCanaryCompletionDecision],
    minimum_decisions: u32,
    baseline: Option<&PolicyDeploymentState>,
    recorded_at_unix: u64,
) -> Result<PolicyDeploymentState, String> {
    validate_policy_trust_state(source_policy_trust_state)?;
    validate_policy_trust_state(candidate_policy_trust_state)?;
    let completion = verify_canary_completion(
        rollout,
        monitoring,
        authorization,
        source_policy_pack,
        decisions,
        minimum_decisions,
    )?;
    let final_decision = completion
        .final_decision
        .ok_or_else(|| "policy deployment requires a finalized canary completion".to_string())?;
    validate_deployment_candidate(rollout, source_policy_pack, candidate_policy_pack)?;
    let source_sha256 = normalized_sha256(source_policy_pack, "source policy pack")?;
    let candidate_sha256 = normalized_sha256(candidate_policy_pack, "candidate policy pack")?;
    if source_policy_trust_state.policy_pack_id != source_policy_pack.id
        || source_policy_trust_state.accepted_revision != source_policy_pack.revision
        || source_policy_trust_state.policy_pack_sha256 != source_sha256
    {
        return Err(
            "policy deployment source does not match its accepted policy trust state".into(),
        );
    }
    if candidate_policy_trust_state.policy_pack_id != candidate_policy_pack.id
        || candidate_policy_trust_state.accepted_revision != candidate_policy_pack.revision
        || candidate_policy_trust_state.policy_pack_sha256 != candidate_sha256
        || candidate_policy_trust_state.signer_id != source_policy_trust_state.signer_id
        || candidate_policy_trust_state.public_key != source_policy_trust_state.public_key
    {
        return Err(
            "policy deployment candidate does not monotonically advance the trusted signing root"
                .into(),
        );
    }
    let latest_decision_at = completion
        .members
        .iter()
        .map(|member| member.decided_at_unix)
        .max()
        .ok_or_else(|| "policy deployment completion has no members".to_string())?;
    if recorded_at_unix < latest_decision_at || recorded_at_unix > authorization.expires_at_unix {
        return Err("policy deployment is outside the authorized completion window".into());
    }

    let (generation, previous_state_sha256, previous_active_revision, previous_active_sha256) =
        match baseline {
            Some(baseline) => {
                validate_policy_deployment_state(baseline)?;
                if baseline.policy_pack_id != candidate_policy_pack.id {
                    return Err("policy deployment cannot change the policy pack identity".into());
                }
                if candidate_policy_pack.revision <= baseline.highest_considered_revision {
                    return Err(format!(
                        "policy revision {} does not advance the highest considered revision {}",
                        candidate_policy_pack.revision, baseline.highest_considered_revision
                    ));
                }
                (
                    baseline
                        .generation
                        .checked_add(1)
                        .ok_or_else(|| "policy deployment generation overflow".to_string())?,
                    Some(normalized_sha256(baseline, "previous deployment state")?),
                    Some(baseline.active_revision),
                    Some(baseline.active_policy_pack_sha256.clone()),
                )
            }
            None => (1, None, None, None),
        };

    let (
        status,
        active_revision,
        active_policy_pack_sha256,
        rollback_revision,
        rollback_policy_pack_sha256,
        deployment_applied,
    ) = match final_decision {
        CanaryCompletionDecision::Promote => (
            PolicyDeploymentStatus::PromotionApplied,
            candidate_policy_pack.revision,
            candidate_sha256.clone(),
            previous_active_revision,
            previous_active_sha256,
            true,
        ),
        CanaryCompletionDecision::Rollback => {
            let active_revision = previous_active_revision.ok_or_else(|| {
                "cannot confirm rollback without a previously active policy deployment".to_string()
            })?;
            let active_sha256 = previous_active_sha256
                .ok_or_else(|| "rollback deployment is missing the active digest".to_string())?;
            (
                PolicyDeploymentStatus::RollbackConfirmed,
                active_revision,
                active_sha256.clone(),
                Some(active_revision),
                Some(active_sha256),
                false,
            )
        }
    };

    let state = PolicyDeploymentState {
        schema_version: POLICY_DEPLOYMENT_STATE_SCHEMA_VERSION,
        status,
        generation,
        policy_pack_id: candidate_policy_pack.id.clone(),
        active_revision,
        active_policy_pack_sha256,
        highest_considered_revision: candidate_policy_pack.revision,
        highest_considered_policy_pack_sha256: candidate_sha256.clone(),
        rollback_revision,
        rollback_policy_pack_sha256,
        candidate_revision: candidate_policy_pack.revision,
        candidate_policy_pack_sha256: candidate_sha256,
        final_decision,
        deployment_applied,
        automatic_application: false,
        post_deployment_verification_required: true,
        verification_status: "pending".into(),
        recorded_at_unix,
        previous_state_sha256,
        source_policy_trust_state_sha256: normalized_sha256(
            source_policy_trust_state,
            "source policy trust state",
        )?,
        candidate_policy_trust_state_sha256: normalized_sha256(
            candidate_policy_trust_state,
            "candidate policy trust state",
        )?,
        rollout_sha256: normalized_sha256(rollout, "policy rollout")?,
        authorization_sha256: normalized_sha256(authorization, "canary authorization")?,
        monitoring_sha256: normalized_sha256(monitoring, "canary monitoring")?,
        completion_sha256: normalized_sha256(&completion, "canary completion")?,
    };
    validate_policy_deployment_state(&state)?;
    Ok(state)
}

fn validate_deployment_candidate(
    rollout: &PolicyRolloutReport,
    source: &OrganizationPolicyPack,
    candidate: &OrganizationPolicyPack,
) -> Result<(), String> {
    crate::policy_pack::validate_policy_pack(source)?;
    crate::policy_pack::validate_policy_pack(candidate)?;
    if candidate.id != source.id
        || candidate.revision <= source.revision
        || candidate.dfm_profile != rollout.candidate_profile
    {
        return Err(
            "deployment candidate must advance the source policy with the exact rollout profile"
                .into(),
        );
    }
    if candidate.electrical_policy != source.electrical_policy
        || candidate.ai_requirements != source.ai_requirements
        || candidate.require_simulation_evidence != source.require_simulation_evidence
        || candidate.trusted_approval_keys != source.trusted_approval_keys
        || candidate.trusted_human_escalation_keys != source.trusted_human_escalation_keys
    {
        return Err(
            "deployment candidate contains governance changes not covered by the rollout".into(),
        );
    }
    Ok(())
}

pub fn parse_policy_deployment_state(source: &str) -> Result<PolicyDeploymentState, String> {
    let state: PolicyDeploymentState = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy deployment state JSON: {error}"))?;
    validate_policy_deployment_state(&state)?;
    Ok(state)
}

pub fn validate_policy_deployment_state(state: &PolicyDeploymentState) -> Result<(), String> {
    if state.schema_version != POLICY_DEPLOYMENT_STATE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported policy deployment schema_version {}; expected {}",
            state.schema_version, POLICY_DEPLOYMENT_STATE_SCHEMA_VERSION
        ));
    }
    validate_slug(&state.policy_pack_id)?;
    for digest in [
        &state.active_policy_pack_sha256,
        &state.highest_considered_policy_pack_sha256,
        &state.candidate_policy_pack_sha256,
        &state.source_policy_trust_state_sha256,
        &state.candidate_policy_trust_state_sha256,
        &state.rollout_sha256,
        &state.authorization_sha256,
        &state.monitoring_sha256,
        &state.completion_sha256,
    ] {
        validate_digest(digest)?;
    }
    if let Some(digest) = &state.rollback_policy_pack_sha256 {
        validate_digest(digest)?;
    }
    if let Some(digest) = &state.previous_state_sha256 {
        validate_digest(digest)?;
    }
    if state.generation == 0
        || state.active_revision == 0
        || state.highest_considered_revision == 0
        || state.candidate_revision == 0
        || state.highest_considered_revision != state.candidate_revision
        || state.highest_considered_policy_pack_sha256 != state.candidate_policy_pack_sha256
        || state.automatic_application
        || !state.post_deployment_verification_required
        || state.verification_status != "pending"
        || state.rollback_revision.is_some() != state.rollback_policy_pack_sha256.is_some()
        || (state.generation == 1) != state.previous_state_sha256.is_none()
    {
        return Err("policy deployment governance or revision boundary is invalid".into());
    }
    match state.status {
        PolicyDeploymentStatus::PromotionApplied => {
            if state.final_decision != CanaryCompletionDecision::Promote
                || !state.deployment_applied
                || state.active_revision != state.candidate_revision
                || state.active_policy_pack_sha256 != state.candidate_policy_pack_sha256
                || (state.generation == 1) != state.rollback_revision.is_none()
            {
                return Err("promoted policy deployment state is inconsistent".into());
            }
            if let Some(rollback_revision) = state.rollback_revision
                && rollback_revision >= state.active_revision
            {
                return Err(
                    "promoted policy rollback revision must precede active revision".into(),
                );
            }
        }
        PolicyDeploymentStatus::RollbackConfirmed => {
            if state.final_decision != CanaryCompletionDecision::Rollback
                || state.deployment_applied
                || state.generation < 2
                || state.rollback_revision != Some(state.active_revision)
                || state.rollback_policy_pack_sha256.as_ref()
                    != Some(&state.active_policy_pack_sha256)
                || state.candidate_revision <= state.active_revision
            {
                return Err("rollback-confirmed policy deployment state is inconsistent".into());
            }
        }
    }
    Ok(())
}

pub fn render_policy_deployment_summary(state: &PolicyDeploymentState) -> String {
    let status = match state.status {
        PolicyDeploymentStatus::PromotionApplied => "promotion_applied",
        PolicyDeploymentStatus::RollbackConfirmed => "rollback_confirmed",
    };
    format!(
        "# Policy deployment state\n\n\
         **Result:** `{}`\n\n\
         - Generation: `{}`\n\
         - Active revision: `{}`\n\
         - Considered revision: `{}`\n\
         - Deployment applied: `{}`\n\
         - Automatic application: `false`\n\
         - Post-deployment verification: `pending`\n",
        status,
        state.generation,
        state.active_revision,
        state.candidate_revision,
        state.deployment_applied
    )
}

pub fn policy_deployment_state_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-deployment-state-v1.json",
        "title": "pcbex monotonic policy deployment state",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "generation", "policy_pack_id",
            "active_revision", "active_policy_pack_sha256",
            "highest_considered_revision", "highest_considered_policy_pack_sha256",
            "rollback_revision", "rollback_policy_pack_sha256",
            "candidate_revision", "candidate_policy_pack_sha256", "final_decision",
            "deployment_applied", "automatic_application",
            "post_deployment_verification_required", "verification_status",
            "recorded_at_unix", "previous_state_sha256",
            "source_policy_trust_state_sha256",
            "candidate_policy_trust_state_sha256", "rollout_sha256",
            "authorization_sha256", "monitoring_sha256", "completion_sha256"
        ],
        "properties": {
            "schema_version": {"const": POLICY_DEPLOYMENT_STATE_SCHEMA_VERSION},
            "status": {"enum": ["promotion_applied", "rollback_confirmed"]},
            "generation": {"type": "integer", "minimum": 1},
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "active_revision": {"type": "integer", "minimum": 1},
            "active_policy_pack_sha256": digest,
            "highest_considered_revision": {"type": "integer", "minimum": 1},
            "highest_considered_policy_pack_sha256": digest,
            "rollback_revision": {"type": ["integer", "null"], "minimum": 1},
            "rollback_policy_pack_sha256": {
                "anyOf": [digest, {"type": "null"}]
            },
            "candidate_revision": {"type": "integer", "minimum": 1},
            "candidate_policy_pack_sha256": digest,
            "final_decision": {"enum": ["promote", "rollback"]},
            "deployment_applied": {"type": "boolean"},
            "automatic_application": {"const": false},
            "post_deployment_verification_required": {"const": true},
            "verification_status": {"const": "pending"},
            "recorded_at_unix": {"type": "integer", "minimum": 0},
            "previous_state_sha256": {
                "anyOf": [digest, {"type": "null"}]
            },
            "source_policy_trust_state_sha256": digest,
            "candidate_policy_trust_state_sha256": digest,
            "rollout_sha256": digest,
            "authorization_sha256": digest,
            "monitoring_sha256": digest,
            "completion_sha256": digest
        }
    })
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

fn validate_slug(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-'))
        })
    {
        Err(format!("invalid policy deployment id {value:?}"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_schema_is_closed() {
        let schema = policy_deployment_state_json_schema();
        assert_eq!(schema["additionalProperties"], false);
    }
}
