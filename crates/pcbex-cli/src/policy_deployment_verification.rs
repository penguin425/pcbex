use crate::policy_deployment::{
    PolicyDeploymentState, PolicyDeploymentStatus, validate_policy_deployment_state,
};
use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use crate::policy_rollout::{
    CanaryMonitoringInput, CanaryMonitoringProject, CanaryMonitoringReport, PolicyRolloutReport,
    RolloutAnalysisEvidence, RolloutArtifact, canary_monitoring_json_schema,
    observe_deployed_project, validate_canary_monitoring_report, validate_policy_rollout_report,
};
use pcbex_core::analysis::AnalysisDelta;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;

pub const POLICY_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_PROJECTS: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeploymentVerificationProject {
    pub project_id: String,
    pub board: RolloutArtifact,
    pub expected: RolloutAnalysisEvidence,
    pub observed: RolloutAnalysisEvidence,
    pub delta: AnalysisDelta,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeploymentVerificationReport {
    pub schema_version: u32,
    pub status: String,
    pub deployment_state_sha256: String,
    pub rollout_sha256: String,
    pub policy_pack_id: String,
    pub active_revision: u32,
    pub active_policy_pack_sha256: String,
    pub candidate_profile_sha256: String,
    pub verified_at_unix: u64,
    pub total_projects: u32,
    pub observed_projects: u32,
    pub passed_projects: u32,
    pub failed_projects: u32,
    pub total_new_violations: u32,
    pub coverage_complete: bool,
    pub missing_projects: Vec<String>,
    pub deployment_verified: bool,
    pub rollback_required: bool,
    pub automatic_rollback: bool,
    pub requires_dual_control_rollback: bool,
    pub projects: Vec<PolicyDeploymentVerificationProject>,
}

pub fn verify_policy_deployment(
    deployment: &PolicyDeploymentState,
    rollout: &PolicyRolloutReport,
    candidate_policy_pack: &OrganizationPolicyPack,
    candidate_policy_pack_bytes: &[u8],
    verified_at_unix: u64,
    inputs: &[CanaryMonitoringInput<'_>],
) -> Result<PolicyDeploymentVerificationReport, String> {
    validate_policy_deployment_state(deployment)?;
    validate_policy_rollout_report(rollout)?;
    validate_policy_pack(candidate_policy_pack)?;
    if deployment.status != PolicyDeploymentStatus::PromotionApplied
        || !deployment.deployment_applied
        || deployment.verification_status != "pending"
    {
        return Err("post-deployment verification requires a pending promoted state".into());
    }
    if deployment.rollout_sha256 != normalized_sha256(rollout, "policy rollout")?
        || deployment.policy_pack_id != candidate_policy_pack.id
        || deployment.active_revision != candidate_policy_pack.revision
        || deployment.active_policy_pack_sha256
            != normalized_sha256(candidate_policy_pack, "candidate policy pack")?
        || rollout.candidate_profile != candidate_policy_pack.dfm_profile
    {
        return Err(
            "post-deployment verification evidence is bound to a different deployment".into(),
        );
    }
    if verified_at_unix < deployment.recorded_at_unix {
        return Err("post-deployment verification predates the deployment state".into());
    }
    if inputs.len() > rollout.projects.len() {
        return Err("post-deployment verification contains too many projects".into());
    }
    let mut ids = HashSet::new();
    let mut projects = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !ids.insert(input.project_id) {
            return Err(format!(
                "duplicate post-deployment project {:?}",
                input.project_id
            ));
        }
        let simulated = rollout
            .projects
            .iter()
            .find(|project| project.project_id == input.project_id)
            .ok_or_else(|| format!("unknown rollout project {:?}", input.project_id))?;
        let observed = observe_deployed_project(
            input,
            simulated,
            candidate_policy_pack,
            candidate_policy_pack_bytes,
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
    let expected_ids = rollout
        .projects
        .iter()
        .map(|project| project.project_id.as_str())
        .collect::<Vec<_>>();
    let actual_ids = projects
        .iter()
        .map(|project| project.project_id.as_str())
        .collect::<Vec<_>>();
    let missing_projects = expected_ids
        .iter()
        .filter(|project_id| !actual_ids.contains(project_id))
        .map(|project_id| (*project_id).to_string())
        .collect::<Vec<_>>();
    let coverage_complete = missing_projects.is_empty();
    let passed_projects = projects.iter().filter(|project| project.passed).count() as u32;
    let failed_projects = projects.len() as u32 - passed_projects;
    let total_new_violations = projects.iter().try_fold(0_u32, |total, project| {
        total
            .checked_add(
                u32::try_from(project.delta.new_violations.len())
                    .map_err(|_| "post-deployment new violation count exceeds u32".to_string())?,
            )
            .ok_or_else(|| "post-deployment new violation count overflowed".to_string())
    })?;
    let rollback_required = !coverage_complete || failed_projects != 0 || total_new_violations != 0;
    let report = PolicyDeploymentVerificationReport {
        schema_version: POLICY_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION,
        status: if rollback_required {
            "rollback_required".into()
        } else {
            "verification_passed".into()
        },
        deployment_state_sha256: normalized_sha256(deployment, "policy deployment state")?,
        rollout_sha256: deployment.rollout_sha256.clone(),
        policy_pack_id: deployment.policy_pack_id.clone(),
        active_revision: deployment.active_revision,
        active_policy_pack_sha256: deployment.active_policy_pack_sha256.clone(),
        candidate_profile_sha256: normalized_sha256(
            &candidate_policy_pack.dfm_profile,
            "candidate DFM profile",
        )?,
        verified_at_unix,
        total_projects: rollout.projects.len() as u32,
        observed_projects: projects.len() as u32,
        passed_projects,
        failed_projects,
        total_new_violations,
        coverage_complete,
        missing_projects,
        deployment_verified: !rollback_required,
        rollback_required,
        automatic_rollback: false,
        requires_dual_control_rollback: rollback_required,
        projects,
    };
    validate_policy_deployment_verification(&report)?;
    Ok(report)
}

pub fn parse_policy_deployment_verification(
    source: &str,
) -> Result<PolicyDeploymentVerificationReport, String> {
    let report: PolicyDeploymentVerificationReport = serde_json::from_str(source)
        .map_err(|error| format!("invalid post-deployment verification JSON: {error}"))?;
    validate_policy_deployment_verification(&report)?;
    Ok(report)
}

pub fn validate_policy_deployment_verification(
    report: &PolicyDeploymentVerificationReport,
) -> Result<(), String> {
    if report.schema_version != POLICY_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION
        || !matches!(
            report.status.as_str(),
            "verification_passed" | "rollback_required"
        )
        || report.automatic_rollback
        || report.total_projects == 0
        || report.projects.len() > MAXIMUM_PROJECTS
        || report.observed_projects != report.projects.len() as u32
        || report.passed_projects.checked_add(report.failed_projects)
            != Some(report.observed_projects)
        || report.total_projects < report.observed_projects
        || report.missing_projects.len() as u32 != report.total_projects - report.observed_projects
        || report.coverage_complete != report.missing_projects.is_empty()
        || report.active_revision == 0
    {
        return Err("post-deployment verification governance boundary is invalid".into());
    }
    validate_digest(&report.deployment_state_sha256)?;
    validate_digest(&report.rollout_sha256)?;
    validate_digest(&report.active_policy_pack_sha256)?;
    validate_digest(&report.candidate_profile_sha256)?;
    let observed_rollback = report.failed_projects != 0 || report.total_new_violations != 0;
    let monitoring = CanaryMonitoringReport {
        schema_version: crate::policy_rollout::CANARY_MONITORING_SCHEMA_VERSION,
        status: if observed_rollback {
            "rollback_required".into()
        } else {
            "monitoring_passed".into()
        },
        rollout_sha256: report.rollout_sha256.clone(),
        authorization_sha256: report.deployment_state_sha256.clone(),
        policy_pack_id: report.policy_pack_id.clone(),
        policy_pack_revision: report.active_revision,
        candidate_profile_sha256: report.candidate_profile_sha256.clone(),
        observed_at_unix: report.verified_at_unix,
        total_projects: report.observed_projects,
        passed_projects: report.passed_projects,
        failed_projects: report.failed_projects,
        total_new_violations: report.total_new_violations,
        rollback_required: observed_rollback,
        promotion_eligible: !observed_rollback,
        automatic_promotion: false,
        requires_human_decision: true,
        projects: report
            .projects
            .iter()
            .map(|project| CanaryMonitoringProject {
                project_id: project.project_id.clone(),
                board: project.board.clone(),
                baseline: project.expected.clone(),
                observed: project.observed.clone(),
                delta: project.delta.clone(),
                passed: project.passed,
            })
            .collect(),
    };
    validate_canary_monitoring_report(&monitoring)?;
    if report
        .missing_projects
        .windows(2)
        .any(|projects| projects[0] >= projects[1])
        || report
            .missing_projects
            .iter()
            .any(|project| project.is_empty() || project.len() > 256)
        || report
            .projects
            .iter()
            .any(|project| report.missing_projects.contains(&project.project_id))
        || report.rollback_required
            != (!report.coverage_complete
                || report.failed_projects != 0
                || report.total_new_violations != 0)
        || report.deployment_verified == report.rollback_required
        || report.requires_dual_control_rollback != report.rollback_required
        || report.status
            != if report.rollback_required {
                "rollback_required"
            } else {
                "verification_passed"
            }
    {
        return Err("post-deployment verification outcome is inconsistent".into());
    }
    Ok(())
}

pub fn render_policy_deployment_verification_summary(
    report: &PolicyDeploymentVerificationReport,
) -> String {
    let mut summary = format!(
        "# Post-deployment verification\n\n\
         **Result:** `{}`\n\n\
         - Active revision: `{}`\n\
         - Projects observed: `{}/{}`\n\
         - Passed: `{}`\n\
         - Failed: `{}`\n\
         - Missing: `{}`\n\
         - New violations: `{}`\n\
         - Coverage complete: `true`\n\
         - Automatic rollback: `false`\n\
         - Dual-control rollback required: `{}`\n",
        report.status,
        report.active_revision,
        report.observed_projects,
        report.total_projects,
        report.passed_projects,
        report.failed_projects,
        report.missing_projects.len(),
        report.total_new_violations,
        report.requires_dual_control_rollback
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
    if !report.missing_projects.is_empty() {
        let _ = writeln!(
            summary,
            "\nMissing projects: {}",
            report
                .missing_projects
                .iter()
                .map(|project| format!("`{project}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    summary
}

pub fn policy_deployment_verification_json_schema() -> Value {
    let monitoring = canary_monitoring_json_schema();
    let project = &monitoring["properties"]["projects"]["items"];
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-deployment-verification-v1.json",
        "title": "pcbex digest-bound post-deployment verification",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "deployment_state_sha256",
            "rollout_sha256", "policy_pack_id", "active_revision",
            "active_policy_pack_sha256", "candidate_profile_sha256",
            "verified_at_unix", "total_projects", "passed_projects",
            "observed_projects", "failed_projects", "total_new_violations", "coverage_complete",
            "missing_projects",
            "deployment_verified", "rollback_required", "automatic_rollback",
            "requires_dual_control_rollback", "projects"
        ],
        "properties": {
            "schema_version": {"const": POLICY_DEPLOYMENT_VERIFICATION_SCHEMA_VERSION},
            "status": {"enum": ["verification_passed", "rollback_required"]},
            "deployment_state_sha256": digest,
            "rollout_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "active_revision": {"type": "integer", "minimum": 1},
            "active_policy_pack_sha256": digest,
            "candidate_profile_sha256": digest,
            "verified_at_unix": {"type": "integer", "minimum": 0},
            "total_projects": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROJECTS},
            "observed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "passed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "failed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "total_new_violations": {"type": "integer", "minimum": 0},
            "coverage_complete": {"type": "boolean"},
            "missing_projects": {
                "type": "array", "maxItems": MAXIMUM_PROJECTS,
                "items": {"type": "string", "minLength": 1, "maxLength": 256}
            },
            "deployment_verified": {"type": "boolean"},
            "rollback_required": {"type": "boolean"},
            "automatic_rollback": {"const": false},
            "requires_dual_control_rollback": {"type": "boolean"},
            "projects": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_PROJECTS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "project_id", "board", "expected", "observed", "delta", "passed"
                    ],
                    "properties": {
                        "project_id": project["properties"]["project_id"],
                        "board": project["properties"]["board"],
                        "expected": project["properties"]["baseline"],
                        "observed": project["properties"]["observed"],
                        "delta": project["properties"]["delta"],
                        "passed": {"type": "boolean"}
                    }
                }
            }
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_schema_closes_every_object() {
        let schema = policy_deployment_verification_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["projects"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["projects"]["items"]["properties"]["expected"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["projects"]["items"]["properties"]["delta"]["additionalProperties"],
            false
        );
    }
}
