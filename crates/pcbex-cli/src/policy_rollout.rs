use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use crate::policy_recommendation::{
    PolicyRecommendationReport, RecommendedRule, validate_policy_recommendation_report,
};
use crate::policy_rollout_approval::{CanaryRolloutAuthorization, validate_canary_authorization};
use pcbex_core::{
    DfmProfile, analysis::AnalysisDelta, checking::CheckReport, quality::RoutingQuality,
    validate_dfm_profile,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const POLICY_ROLLOUT_SCHEMA_VERSION: u32 = 1;
pub const CANARY_MONITORING_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_PROJECTS: usize = 1_000;
const MAXIMUM_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutArtifact {
    pub path: String,
    pub bytes: usize,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutAnalysisEvidence {
    pub run: RolloutArtifact,
    pub checks: RolloutArtifact,
    pub quality: RolloutArtifact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutCompatibility {
    Compatible,
    ImpactDetected,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolloutProjectResult {
    pub project_id: String,
    pub board: RolloutArtifact,
    pub compatibility: RolloutCompatibility,
    pub baseline: RolloutAnalysisEvidence,
    pub candidate: RolloutAnalysisEvidence,
    pub delta: AnalysisDelta,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRolloutReport {
    pub schema_version: u32,
    pub status: String,
    pub deployable: bool,
    pub requires_human_approval: bool,
    pub generated_on: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub policy_pack_sha256: String,
    pub recommendation_sha256: String,
    pub candidate_profile: DfmProfile,
    pub total_projects: u32,
    pub compatible_projects: u32,
    pub affected_projects: u32,
    pub total_new_violations: u32,
    pub projects: Vec<RolloutProjectResult>,
}

pub struct RolloutAnalysisInput<'a> {
    pub run_path: &'a str,
    pub run: &'a [u8],
    pub checks_path: &'a str,
    pub checks: &'a [u8],
    pub quality_path: &'a str,
    pub quality: &'a [u8],
}

pub struct RolloutProjectInput<'a> {
    pub project_id: &'a str,
    pub board_path: &'a str,
    pub board: &'a [u8],
    pub baseline: RolloutAnalysisInput<'a>,
    pub candidate: RolloutAnalysisInput<'a>,
}

pub struct CanaryMonitoringInput<'a> {
    pub project_id: &'a str,
    pub board_path: &'a str,
    pub board: &'a [u8],
    pub baseline: RolloutAnalysisInput<'a>,
    pub observed: RolloutAnalysisInput<'a>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryMonitoringProject {
    pub project_id: String,
    pub board: RolloutArtifact,
    pub baseline: RolloutAnalysisEvidence,
    pub observed: RolloutAnalysisEvidence,
    pub delta: AnalysisDelta,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryMonitoringReport {
    pub schema_version: u32,
    pub status: String,
    pub rollout_sha256: String,
    pub authorization_sha256: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub candidate_profile_sha256: String,
    pub observed_at_unix: u64,
    pub total_projects: u32,
    pub passed_projects: u32,
    pub failed_projects: u32,
    pub total_new_violations: u32,
    pub rollback_required: bool,
    pub promotion_eligible: bool,
    pub automatic_promotion: bool,
    pub requires_human_decision: bool,
    pub projects: Vec<CanaryMonitoringProject>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisInputDescriptor {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisConfiguration {
    #[serde(rename = "rules")]
    _rules: StrictRules,
    project_settings_loaded: bool,
    applied_custom_rules: usize,
    dfm_profile: Option<DfmProfile>,
    organization_policy_pack: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRules {
    grid_nm: i64,
    track_width_nm: i64,
    clearance_nm: i64,
    via_diameter_nm: i64,
    via_drill_nm: i64,
    bend_cost: u32,
    via_cost: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisResult {
    clean: bool,
    violations: usize,
    routed_nets: usize,
    unrouted_nets: usize,
    total_length_nm: i64,
    total_vias: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisManifest {
    schema_version: u32,
    engine: String,
    engine_version: String,
    command: String,
    input: AnalysisInputDescriptor,
    project: Option<AnalysisInputDescriptor>,
    rules_file: Option<AnalysisInputDescriptor>,
    dfm_profile_file: Option<AnalysisInputDescriptor>,
    policy_pack_file: Option<AnalysisInputDescriptor>,
    configuration: AnalysisConfiguration,
    result: AnalysisResult,
    artifacts: Vec<String>,
}

pub fn rollout_candidate_profile(
    policy_pack: &OrganizationPolicyPack,
    recommendation: &PolicyRecommendationReport,
    generated_on: &str,
) -> Result<DfmProfile, String> {
    validate_binding(policy_pack, recommendation)?;
    validate_date(generated_on)?;
    if generated_on < recommendation.generated_on.as_str() {
        return Err("rollout profile date precedes the recommendation".into());
    }
    if recommendation.recommendations.is_empty() {
        return Err("rollout simulation requires at least one policy recommendation".into());
    }
    let recommendation_sha256 = normalized_sha256(recommendation)?;
    let mut profile = policy_pack.dfm_profile.clone();
    profile.id = format!("pcbex-rollout-{}", &recommendation_sha256[..16]);
    profile.aliases.clear();
    profile.revision = 1;
    profile.verified_on = generated_on.into();
    profile.description =
        "Simulation-only DFM profile derived from a governed pcbex recommendation; not approved for deployment."
            .into();
    for change in &recommendation.recommendations {
        match change.rule {
            RecommendedRule::TrackWidth => {
                profile.rules.minimum_track_width_nm = change.recommended_value_nm
            }
            RecommendedRule::Clearance => {
                profile.rules.minimum_clearance_nm = change.recommended_value_nm
            }
            RecommendedRule::Drill => profile.rules.minimum_drill_nm = change.recommended_value_nm,
            RecommendedRule::AnnularRing => {
                profile.rules.minimum_annular_ring_nm = change.recommended_value_nm
            }
        }
    }
    validate_dfm_profile(&profile)?;
    Ok(profile)
}

pub fn simulate_policy_rollout(
    policy_pack: &OrganizationPolicyPack,
    recommendation: &PolicyRecommendationReport,
    generated_on: &str,
    inputs: &[RolloutProjectInput<'_>],
) -> Result<PolicyRolloutReport, String> {
    let candidate_profile = rollout_candidate_profile(policy_pack, recommendation, generated_on)?;
    if inputs.is_empty() || inputs.len() > MAXIMUM_PROJECTS {
        return Err(format!(
            "rollout simulation requires 1 to {MAXIMUM_PROJECTS} projects"
        ));
    }
    let mut ids = HashSet::new();
    let mut projects = Vec::with_capacity(inputs.len());
    for input in inputs {
        validate_slug("project id", input.project_id)?;
        if !ids.insert(input.project_id) {
            return Err(format!(
                "duplicate rollout project id {:?}",
                input.project_id
            ));
        }
        projects.push(simulate_project(input, policy_pack, &candidate_profile)?);
    }
    projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));
    let compatible_projects = projects
        .iter()
        .filter(|project| project.compatibility == RolloutCompatibility::Compatible)
        .count() as u32;
    let affected_projects = projects.len() as u32 - compatible_projects;
    let total_new_violations = projects.iter().try_fold(0_u32, |total, project| {
        total
            .checked_add(
                u32::try_from(project.delta.new_violations.len())
                    .map_err(|_| "new violation count exceeds u32".to_string())?,
            )
            .ok_or_else(|| "new violation count overflowed".to_string())
    })?;
    let report = PolicyRolloutReport {
        schema_version: POLICY_ROLLOUT_SCHEMA_VERSION,
        status: "simulation_only".into(),
        deployable: false,
        requires_human_approval: true,
        generated_on: generated_on.into(),
        policy_pack_id: policy_pack.id.clone(),
        policy_pack_revision: policy_pack.revision,
        policy_pack_sha256: normalized_sha256(policy_pack)?,
        recommendation_sha256: normalized_sha256(recommendation)?,
        candidate_profile,
        total_projects: projects.len() as u32,
        compatible_projects,
        affected_projects,
        total_new_violations,
        projects,
    };
    validate_policy_rollout_report(&report)?;
    Ok(report)
}

pub fn record_canary_monitoring(
    rollout: &PolicyRolloutReport,
    authorization: &CanaryRolloutAuthorization,
    observed_at_unix: u64,
    inputs: &[CanaryMonitoringInput<'_>],
) -> Result<CanaryMonitoringReport, String> {
    validate_policy_rollout_report(rollout)?;
    validate_canary_authorization(authorization)?;
    let rollout_sha256 = normalized_sha256(rollout)?;
    if !authorization.canary_authorized
        || authorization.rollout_sha256 != rollout_sha256
        || authorization.policy_pack_id != rollout.policy_pack_id
        || authorization.policy_pack_revision != rollout.policy_pack_revision
        || authorization.candidate_profile_sha256 != normalized_sha256(&rollout.candidate_profile)?
    {
        return Err("canary monitoring is not bound to an authorized rollout".into());
    }
    if observed_at_unix < authorization.valid_from_unix
        || observed_at_unix > authorization.expires_at_unix
    {
        return Err("canary monitoring time is outside the authorization window".into());
    }
    if inputs.len() != authorization.canary_projects.len() {
        return Err("canary monitoring must cover the exact authorized project scope".into());
    }
    let mut ids = HashSet::new();
    let mut projects = Vec::with_capacity(inputs.len());
    for input in inputs {
        if !ids.insert(input.project_id) {
            return Err(format!(
                "duplicate canary monitoring project {:?}",
                input.project_id
            ));
        }
        if authorization
            .canary_projects
            .binary_search_by(|project| project.as_str().cmp(input.project_id))
            .is_err()
        {
            return Err(format!(
                "project {:?} is outside the authorized canary scope",
                input.project_id
            ));
        }
        let simulated = rollout
            .projects
            .iter()
            .find(|project| project.project_id == input.project_id)
            .ok_or_else(|| format!("unknown rollout project {:?}", input.project_id))?;
        projects.push(observe_canary_project(
            input,
            simulated,
            &rollout.candidate_profile,
        )?);
    }
    projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));
    let passed_projects = projects.iter().filter(|project| project.passed).count() as u32;
    let failed_projects = projects.len() as u32 - passed_projects;
    let total_new_violations = projects.iter().try_fold(0_u32, |total, project| {
        total
            .checked_add(
                u32::try_from(project.delta.new_violations.len())
                    .map_err(|_| "canary new violation count exceeds u32".to_string())?,
            )
            .ok_or_else(|| "canary new violation count overflowed".to_string())
    })?;
    let rollback_required = failed_projects != 0 || total_new_violations != 0;
    let report = CanaryMonitoringReport {
        schema_version: CANARY_MONITORING_SCHEMA_VERSION,
        status: if rollback_required {
            "rollback_required".into()
        } else {
            "monitoring_passed".into()
        },
        rollout_sha256,
        authorization_sha256: normalized_sha256(authorization)?,
        policy_pack_id: rollout.policy_pack_id.clone(),
        policy_pack_revision: rollout.policy_pack_revision,
        candidate_profile_sha256: normalized_sha256(&rollout.candidate_profile)?,
        observed_at_unix,
        total_projects: projects.len() as u32,
        passed_projects,
        failed_projects,
        total_new_violations,
        rollback_required,
        promotion_eligible: !rollback_required,
        automatic_promotion: false,
        requires_human_decision: true,
        projects,
    };
    validate_canary_monitoring_report(&report)?;
    Ok(report)
}

fn observe_canary_project(
    input: &CanaryMonitoringInput<'_>,
    simulated: &RolloutProjectResult,
    candidate_profile: &DfmProfile,
) -> Result<CanaryMonitoringProject, String> {
    let baseline = parse_analysis(&input.baseline)?;
    let observed = parse_analysis(&input.observed)?;
    let board = artifact(input.board_path, input.board)?;
    validate_manifest(&baseline.manifest, &baseline.checks, &baseline.quality)?;
    validate_manifest(&observed.manifest, &observed.checks, &observed.quality)?;
    if board.bytes != simulated.board.bytes
        || board.sha256 != simulated.board.sha256
        || baseline.evidence.run.bytes != simulated.baseline.run.bytes
        || baseline.evidence.run.sha256 != simulated.baseline.run.sha256
        || baseline.evidence.checks.bytes != simulated.baseline.checks.bytes
        || baseline.evidence.checks.sha256 != simulated.baseline.checks.sha256
        || baseline.evidence.quality.bytes != simulated.baseline.quality.bytes
        || baseline.evidence.quality.sha256 != simulated.baseline.quality.sha256
    {
        return Err(format!(
            "project {:?} does not retain the simulated baseline evidence",
            input.project_id
        ));
    }
    if baseline.manifest.input.sha256 != board.sha256
        || observed.manifest.input.sha256 != board.sha256
        || baseline.manifest.input.bytes != board.bytes
        || observed.manifest.input.bytes != board.bytes
        || baseline.manifest.engine_version != observed.manifest.engine_version
        || !same_optional_input(&baseline.manifest.project, &observed.manifest.project)
        || !same_optional_input(&baseline.manifest.rules_file, &observed.manifest.rules_file)
        || baseline.manifest.configuration.project_settings_loaded
            != observed.manifest.configuration.project_settings_loaded
        || baseline.manifest.configuration.applied_custom_rules
            != observed.manifest.configuration.applied_custom_rules
    {
        return Err(format!(
            "project {:?} observed analysis changed the board or settings",
            input.project_id
        ));
    }
    if observed.manifest.configuration.dfm_profile.as_ref() != Some(candidate_profile)
        || observed
            .manifest
            .configuration
            .organization_policy_pack
            .is_some()
        || observed.manifest.dfm_profile_file.is_none()
        || observed.manifest.policy_pack_file.is_some()
    {
        return Err(format!(
            "project {:?} observation did not use only the authorized candidate profile",
            input.project_id
        ));
    }
    let delta = AnalysisDelta::between(
        &baseline.quality,
        &baseline.checks,
        &observed.quality,
        &observed.checks,
    );
    let passed = !delta.is_regression();
    Ok(CanaryMonitoringProject {
        project_id: input.project_id.into(),
        board,
        baseline: baseline.evidence,
        observed: observed.evidence,
        delta,
        passed,
    })
}

pub fn observe_deployed_project(
    input: &CanaryMonitoringInput<'_>,
    simulated: &RolloutProjectResult,
    candidate_policy_pack: &OrganizationPolicyPack,
    candidate_policy_pack_bytes: &[u8],
) -> Result<CanaryMonitoringProject, String> {
    validate_policy_pack(candidate_policy_pack)?;
    if candidate_policy_pack_bytes.is_empty()
        || candidate_policy_pack_bytes.len() > MAXIMUM_ARTIFACT_BYTES
    {
        return Err("candidate policy-pack artifact size is invalid".into());
    }
    let expected = parse_analysis(&input.baseline)?;
    let observed = parse_analysis(&input.observed)?;
    let board = artifact(input.board_path, input.board)?;
    validate_manifest(&expected.manifest, &expected.checks, &expected.quality)?;
    validate_manifest(&observed.manifest, &observed.checks, &observed.quality)?;
    if board.bytes != simulated.board.bytes
        || board.sha256 != simulated.board.sha256
        || expected.evidence.run.bytes != simulated.candidate.run.bytes
        || expected.evidence.run.sha256 != simulated.candidate.run.sha256
        || expected.evidence.checks.bytes != simulated.candidate.checks.bytes
        || expected.evidence.checks.sha256 != simulated.candidate.checks.sha256
        || expected.evidence.quality.bytes != simulated.candidate.quality.bytes
        || expected.evidence.quality.sha256 != simulated.candidate.quality.sha256
    {
        return Err(format!(
            "project {:?} does not retain the simulated candidate evidence",
            input.project_id
        ));
    }
    if expected.manifest.input.sha256 != board.sha256
        || observed.manifest.input.sha256 != board.sha256
        || expected.manifest.input.bytes != board.bytes
        || observed.manifest.input.bytes != board.bytes
        || expected.manifest.engine_version != observed.manifest.engine_version
        || !same_optional_input(&expected.manifest.project, &observed.manifest.project)
        || !same_optional_input(&expected.manifest.rules_file, &observed.manifest.rules_file)
        || expected.manifest.configuration.project_settings_loaded
            != observed.manifest.configuration.project_settings_loaded
        || expected.manifest.configuration.applied_custom_rules
            != observed.manifest.configuration.applied_custom_rules
    {
        return Err(format!(
            "project {:?} deployed analysis changed the board or settings",
            input.project_id
        ));
    }
    if expected.manifest.configuration.dfm_profile.as_ref()
        != Some(&candidate_policy_pack.dfm_profile)
        || expected
            .manifest
            .configuration
            .organization_policy_pack
            .is_some()
        || expected.manifest.dfm_profile_file.is_none()
        || expected.manifest.policy_pack_file.is_some()
    {
        return Err(format!(
            "project {:?} expected analysis is not the approved simulation candidate",
            input.project_id
        ));
    }
    let policy_descriptor = observed.manifest.policy_pack_file.as_ref();
    let policy_sha256 = hex::encode(Sha256::digest(candidate_policy_pack_bytes));
    if observed.manifest.configuration.dfm_profile.as_ref()
        != Some(&candidate_policy_pack.dfm_profile)
        || observed
            .manifest
            .configuration
            .organization_policy_pack
            .as_deref()
            != Some(candidate_policy_pack.id.as_str())
        || observed.manifest.dfm_profile_file.is_some()
        || policy_descriptor.is_none_or(|descriptor| {
            descriptor.bytes != candidate_policy_pack_bytes.len()
                || descriptor.sha256 != policy_sha256
        })
    {
        return Err(format!(
            "project {:?} observed analysis did not use the exact active policy pack",
            input.project_id
        ));
    }
    let delta = AnalysisDelta::between(
        &expected.quality,
        &expected.checks,
        &observed.quality,
        &observed.checks,
    );
    let passed = !delta.is_regression();
    Ok(CanaryMonitoringProject {
        project_id: input.project_id.into(),
        board,
        baseline: expected.evidence,
        observed: observed.evidence,
        delta,
        passed,
    })
}

pub fn observe_restored_project(
    input: &CanaryMonitoringInput<'_>,
    expected_board: &RolloutArtifact,
    expected_evidence: &RolloutAnalysisEvidence,
    restored_policy_pack: &OrganizationPolicyPack,
    restored_policy_pack_bytes: &[u8],
) -> Result<CanaryMonitoringProject, String> {
    validate_policy_pack(restored_policy_pack)?;
    if restored_policy_pack_bytes.is_empty()
        || restored_policy_pack_bytes.len() > MAXIMUM_ARTIFACT_BYTES
    {
        return Err("restored policy-pack artifact size is invalid".into());
    }
    let expected = parse_analysis(&input.baseline)?;
    let observed = parse_analysis(&input.observed)?;
    let board = artifact(input.board_path, input.board)?;
    validate_manifest(&expected.manifest, &expected.checks, &expected.quality)?;
    validate_manifest(&observed.manifest, &observed.checks, &observed.quality)?;
    if board.bytes != expected_board.bytes
        || board.sha256 != expected_board.sha256
        || expected.evidence.run.bytes != expected_evidence.run.bytes
        || expected.evidence.run.sha256 != expected_evidence.run.sha256
        || expected.evidence.checks.bytes != expected_evidence.checks.bytes
        || expected.evidence.checks.sha256 != expected_evidence.checks.sha256
        || expected.evidence.quality.bytes != expected_evidence.quality.bytes
        || expected.evidence.quality.sha256 != expected_evidence.quality.sha256
    {
        return Err(format!(
            "project {:?} does not retain the pre-promotion production baseline",
            input.project_id
        ));
    }
    if expected.manifest.input.sha256 != board.sha256
        || observed.manifest.input.sha256 != board.sha256
        || expected.manifest.input.bytes != board.bytes
        || observed.manifest.input.bytes != board.bytes
        || expected.manifest.engine_version != observed.manifest.engine_version
        || !same_optional_input(&expected.manifest.project, &observed.manifest.project)
        || !same_optional_input(&expected.manifest.rules_file, &observed.manifest.rules_file)
        || expected.manifest.configuration.project_settings_loaded
            != observed.manifest.configuration.project_settings_loaded
        || expected.manifest.configuration.applied_custom_rules
            != observed.manifest.configuration.applied_custom_rules
    {
        return Err(format!(
            "project {:?} recovery analysis changed the board or settings",
            input.project_id
        ));
    }
    let expected_policy = expected.manifest.policy_pack_file.as_ref();
    let observed_policy = observed.manifest.policy_pack_file.as_ref();
    let policy_sha256 = hex::encode(Sha256::digest(restored_policy_pack_bytes));
    let uses_restored_pack =
        |manifest: &AnalysisManifest, descriptor: Option<&AnalysisInputDescriptor>| {
            manifest.configuration.dfm_profile.as_ref() == Some(&restored_policy_pack.dfm_profile)
                && manifest.configuration.organization_policy_pack.as_deref()
                    == Some(restored_policy_pack.id.as_str())
                && manifest.dfm_profile_file.is_none()
                && descriptor.is_some_and(|descriptor| {
                    descriptor.bytes == restored_policy_pack_bytes.len()
                        && descriptor.sha256 == policy_sha256
                })
        };
    if !uses_restored_pack(&expected.manifest, expected_policy)
        || !uses_restored_pack(&observed.manifest, observed_policy)
    {
        return Err(format!(
            "project {:?} recovery evidence did not use the exact restored policy pack",
            input.project_id
        ));
    }
    let delta = AnalysisDelta::between(
        &expected.quality,
        &expected.checks,
        &observed.quality,
        &observed.checks,
    );
    let passed = !delta.is_regression();
    Ok(CanaryMonitoringProject {
        project_id: input.project_id.into(),
        board,
        baseline: expected.evidence,
        observed: observed.evidence,
        delta,
        passed,
    })
}

fn simulate_project(
    input: &RolloutProjectInput<'_>,
    policy_pack: &OrganizationPolicyPack,
    candidate_profile: &DfmProfile,
) -> Result<RolloutProjectResult, String> {
    let baseline = parse_analysis(&input.baseline)?;
    let candidate = parse_analysis(&input.candidate)?;
    let board = artifact(input.board_path, input.board)?;
    validate_manifest(&baseline.manifest, &baseline.checks, &baseline.quality)?;
    validate_manifest(&candidate.manifest, &candidate.checks, &candidate.quality)?;
    if baseline.manifest.input.sha256 != board.sha256
        || candidate.manifest.input.sha256 != board.sha256
        || baseline.manifest.input.bytes != board.bytes
        || candidate.manifest.input.bytes != board.bytes
        || baseline.manifest.engine_version != candidate.manifest.engine_version
        || !same_optional_input(&baseline.manifest.project, &candidate.manifest.project)
        || !same_optional_input(
            &baseline.manifest.rules_file,
            &candidate.manifest.rules_file,
        )
        || baseline.manifest.configuration.project_settings_loaded
            != candidate.manifest.configuration.project_settings_loaded
        || baseline.manifest.configuration.applied_custom_rules
            != candidate.manifest.configuration.applied_custom_rules
    {
        return Err(format!(
            "project {:?} baseline and candidate do not describe the same board and settings",
            input.project_id
        ));
    }
    if baseline.manifest.configuration.dfm_profile.as_ref() != Some(&policy_pack.dfm_profile)
        || baseline
            .manifest
            .configuration
            .organization_policy_pack
            .as_deref()
            != Some(policy_pack.id.as_str())
        || baseline.manifest.policy_pack_file.is_none()
    {
        return Err(format!(
            "project {:?} baseline did not use the target organization policy pack",
            input.project_id
        ));
    }
    if candidate.manifest.configuration.dfm_profile.as_ref() != Some(candidate_profile)
        || candidate
            .manifest
            .configuration
            .organization_policy_pack
            .is_some()
        || candidate.manifest.dfm_profile_file.is_none()
        || candidate.manifest.policy_pack_file.is_some()
    {
        return Err(format!(
            "project {:?} candidate did not use only the simulation profile",
            input.project_id
        ));
    }
    let delta = AnalysisDelta::between(
        &baseline.quality,
        &baseline.checks,
        &candidate.quality,
        &candidate.checks,
    );
    let compatibility = if delta.is_regression() {
        RolloutCompatibility::ImpactDetected
    } else {
        RolloutCompatibility::Compatible
    };
    Ok(RolloutProjectResult {
        project_id: input.project_id.into(),
        board,
        compatibility,
        baseline: baseline.evidence,
        candidate: candidate.evidence,
        delta,
    })
}

struct ParsedAnalysis {
    manifest: AnalysisManifest,
    checks: CheckReport,
    quality: RoutingQuality,
    evidence: RolloutAnalysisEvidence,
}

fn parse_analysis(input: &RolloutAnalysisInput<'_>) -> Result<ParsedAnalysis, String> {
    let manifest = parse_bounded::<AnalysisManifest>("analysis run", input.run)?;
    let checks = parse_bounded::<CheckReport>("analysis checks", input.checks)?;
    let quality = parse_bounded::<RoutingQuality>("analysis quality", input.quality)?;
    Ok(ParsedAnalysis {
        manifest,
        checks,
        quality,
        evidence: RolloutAnalysisEvidence {
            run: artifact(input.run_path, input.run)?,
            checks: artifact(input.checks_path, input.checks)?,
            quality: artifact(input.quality_path, input.quality)?,
        },
    })
}

fn parse_bounded<T: DeserializeOwned>(label: &str, bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > MAXIMUM_ARTIFACT_BYTES {
        return Err(format!("{label} exceeds {MAXIMUM_ARTIFACT_BYTES} bytes"));
    }
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn validate_manifest(
    manifest: &AnalysisManifest,
    checks: &CheckReport,
    quality: &RoutingQuality,
) -> Result<(), String> {
    validate_strict_rules(&manifest.configuration._rules)?;
    if manifest.schema_version != 1
        || manifest.engine != "pcbex"
        || manifest.engine_version.trim().is_empty()
        || manifest.command != "analyze-kicad"
        || manifest.artifacts
            != [
                "board.json",
                "board.svg",
                "checks.json",
                "quality.json",
                "report.sarif",
                "summary.md",
                "run.json",
            ]
        || manifest.input.bytes == 0
    {
        return Err("rollout input is not a complete pcbex analyze-kicad manifest".into());
    }
    validate_analysis_descriptor(&manifest.input)?;
    for descriptor in [
        manifest.project.as_ref(),
        manifest.rules_file.as_ref(),
        manifest.dfm_profile_file.as_ref(),
        manifest.policy_pack_file.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_analysis_descriptor(descriptor)?;
    }
    let result = &manifest.result;
    if result.clean != checks.is_clean()
        || result.violations != checks.violations.len()
        || result.routed_nets != quality.routed_nets
        || result.unrouted_nets != quality.unrouted_nets
        || result.total_length_nm != quality.total_length_nm
        || result.total_vias != quality.total_vias
    {
        return Err("analysis manifest result does not match checks and quality".into());
    }
    Ok(())
}

fn validate_strict_rules(rules: &StrictRules) -> Result<(), String> {
    if rules.grid_nm <= 0
        || rules.track_width_nm <= 0
        || rules.clearance_nm < 0
        || rules.via_diameter_nm <= 0
        || rules.via_drill_nm <= 0
        || rules.via_diameter_nm <= rules.via_drill_nm
    {
        return Err("analysis manifest contains invalid effective routing rules".into());
    }
    let _bounded_costs = (rules.bend_cost, rules.via_cost);
    Ok(())
}

pub fn parse_policy_rollout_report(source: &str) -> Result<PolicyRolloutReport, String> {
    let report: PolicyRolloutReport = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy rollout report JSON: {error}"))?;
    validate_policy_rollout_report(&report)?;
    Ok(report)
}

pub fn validate_policy_rollout_report(report: &PolicyRolloutReport) -> Result<(), String> {
    if report.schema_version != POLICY_ROLLOUT_SCHEMA_VERSION
        || report.status != "simulation_only"
        || report.deployable
        || !report.requires_human_approval
    {
        return Err("policy rollout governance boundary is invalid".into());
    }
    validate_date(&report.generated_on)?;
    validate_slug("policy pack id", &report.policy_pack_id)?;
    if report.policy_pack_revision == 0 {
        return Err("policy pack revision must be greater than zero".into());
    }
    validate_digest(&report.policy_pack_sha256)?;
    validate_digest(&report.recommendation_sha256)?;
    validate_dfm_profile(&report.candidate_profile)?;
    if report.projects.is_empty()
        || report.projects.len() > MAXIMUM_PROJECTS
        || report.total_projects != report.projects.len() as u32
    {
        return Err("policy rollout project count is invalid".into());
    }
    let mut ids = HashSet::new();
    let mut boards = HashSet::new();
    let mut previous = None;
    let mut compatible = 0_u32;
    let mut affected = 0_u32;
    let mut new_violations = 0_u32;
    for project in &report.projects {
        validate_slug("project id", &project.project_id)?;
        validate_evidence_artifact(&project.board)?;
        if !ids.insert(project.project_id.as_str()) || !boards.insert(project.board.sha256.as_str())
        {
            return Err("policy rollout projects must have unique IDs and boards".into());
        }
        if previous.is_some_and(|value| value >= project.project_id.as_str()) {
            return Err("policy rollout projects must be strictly ordered".into());
        }
        previous = Some(project.project_id.as_str());
        validate_evidence(&project.baseline)?;
        validate_evidence(&project.candidate)?;
        validate_delta(&project.delta)?;
        let impacted = project.delta.is_regression();
        if impacted != (project.compatibility == RolloutCompatibility::ImpactDetected) {
            return Err("project compatibility does not match its analysis delta".into());
        }
        if impacted {
            affected += 1;
        } else {
            compatible += 1;
        }
        new_violations = new_violations
            .checked_add(
                u32::try_from(project.delta.new_violations.len())
                    .map_err(|_| "new violation count exceeds u32".to_string())?,
            )
            .ok_or_else(|| "new violation count overflowed".to_string())?;
    }
    if report.compatible_projects != compatible
        || report.affected_projects != affected
        || report.total_new_violations != new_violations
        || compatible + affected != report.total_projects
    {
        return Err("policy rollout aggregate counts are inconsistent".into());
    }
    Ok(())
}

pub fn parse_canary_monitoring_report(source: &str) -> Result<CanaryMonitoringReport, String> {
    let report: CanaryMonitoringReport = serde_json::from_str(source)
        .map_err(|error| format!("invalid canary monitoring report JSON: {error}"))?;
    validate_canary_monitoring_report(&report)?;
    Ok(report)
}

pub fn validate_canary_monitoring_report(report: &CanaryMonitoringReport) -> Result<(), String> {
    if report.schema_version != CANARY_MONITORING_SCHEMA_VERSION
        || !matches!(
            report.status.as_str(),
            "monitoring_passed" | "rollback_required"
        )
        || report.automatic_promotion
        || !report.requires_human_decision
    {
        return Err("canary monitoring governance boundary is invalid".into());
    }
    validate_digest(&report.rollout_sha256)?;
    validate_digest(&report.authorization_sha256)?;
    validate_digest(&report.candidate_profile_sha256)?;
    validate_slug("policy pack id", &report.policy_pack_id)?;
    if report.policy_pack_revision == 0
        || report.projects.is_empty()
        || report.projects.len() > MAXIMUM_PROJECTS
        || report.total_projects != report.projects.len() as u32
    {
        return Err("canary monitoring identity or project count is invalid".into());
    }
    let mut ids = HashSet::new();
    let mut boards = HashSet::new();
    let mut previous = None;
    let mut passed = 0_u32;
    let mut failed = 0_u32;
    let mut new_violations = 0_u32;
    for project in &report.projects {
        validate_slug("canary monitoring project", &project.project_id)?;
        validate_evidence_artifact(&project.board)?;
        validate_evidence(&project.baseline)?;
        validate_evidence(&project.observed)?;
        validate_delta(&project.delta)?;
        if !ids.insert(project.project_id.as_str())
            || !boards.insert(project.board.sha256.as_str())
            || previous.is_some_and(|value| value >= project.project_id.as_str())
        {
            return Err("canary monitoring projects are duplicate or unordered".into());
        }
        previous = Some(project.project_id.as_str());
        let expected_passed = !project.delta.is_regression();
        if project.passed != expected_passed {
            return Err("canary monitoring project outcome is inconsistent".into());
        }
        if expected_passed {
            passed += 1;
        } else {
            failed += 1;
        }
        new_violations = new_violations
            .checked_add(
                u32::try_from(project.delta.new_violations.len())
                    .map_err(|_| "canary new violation count exceeds u32".to_string())?,
            )
            .ok_or_else(|| "canary new violation count overflowed".to_string())?;
    }
    let rollback_required = failed != 0 || new_violations != 0;
    if report.passed_projects != passed
        || report.failed_projects != failed
        || report.total_new_violations != new_violations
        || report.rollback_required != rollback_required
        || report.promotion_eligible == rollback_required
        || report.status
            != if rollback_required {
                "rollback_required"
            } else {
                "monitoring_passed"
            }
    {
        return Err("canary monitoring aggregate outcome is inconsistent".into());
    }
    Ok(())
}

pub(crate) fn validate_delta(delta: &AnalysisDelta) -> Result<(), String> {
    if delta.schema_version != 1 {
        return Err("policy rollout contains an unsupported analysis delta".into());
    }
    let expected_changes = (
        signed_delta(
            delta.current.total_length_nm,
            delta.baseline.total_length_nm,
        ),
        count_delta(delta.current.total_vias, delta.baseline.total_vias),
        count_delta(delta.current.total_bends, delta.baseline.total_bends),
        count_delta(delta.current.routed_nets, delta.baseline.routed_nets),
        count_delta(delta.current.unrouted_nets, delta.baseline.unrouted_nets),
        count_delta(delta.current.violations, delta.baseline.violations),
    );
    if (
        delta.changes.total_length_nm,
        delta.changes.total_vias,
        delta.changes.total_bends,
        delta.changes.routed_nets,
        delta.changes.unrouted_nets,
        delta.changes.violations,
    ) != expected_changes
    {
        return Err("policy rollout analysis changes are inconsistent".into());
    }
    let expected_percent = (delta.baseline.total_length_nm != 0).then_some(
        expected_changes.0 as f64 / delta.baseline.total_length_nm.unsigned_abs() as f64 * 100.0,
    );
    if delta.changes.total_length_percent != expected_percent {
        return Err("policy rollout length percentage is inconsistent".into());
    }
    let mut quality_messages = HashSet::new();
    for message in &delta.quality_regressions {
        if message.trim().is_empty()
            || message.len() > 1024
            || !quality_messages.insert(message.as_str())
        {
            return Err("policy rollout quality regressions are invalid".into());
        }
    }
    for violations in [&delta.new_violations, &delta.resolved_violations] {
        let mut identities = HashSet::new();
        let mut previous = None;
        for violation in violations {
            if violation.rule.trim().is_empty()
                || violation.rule.len() > 128
                || violation.message.trim().is_empty()
                || violation.message.len() > 4096
                || violation.net_ids.len() > 100_000
                || !violation.net_ids.windows(2).all(|pair| pair[0] < pair[1])
                || !identities.insert((
                    violation.rule.as_str(),
                    violation.message.as_str(),
                    violation.net_ids.as_slice(),
                ))
            {
                return Err("policy rollout violation fingerprints are invalid".into());
            }
            let identity = (
                violation.rule.as_str(),
                violation.message.as_str(),
                violation.net_ids.as_slice(),
            );
            if previous.is_some_and(|value| value >= identity) {
                return Err("policy rollout violation fingerprints must be ordered".into());
            }
            previous = Some(identity);
        }
    }
    Ok(())
}

pub(crate) fn validate_evidence(evidence: &RolloutAnalysisEvidence) -> Result<(), String> {
    for artifact in [&evidence.run, &evidence.checks, &evidence.quality] {
        validate_evidence_artifact(artifact)?;
    }
    Ok(())
}

pub(crate) fn validate_evidence_artifact(artifact: &RolloutArtifact) -> Result<(), String> {
    if artifact.path.is_empty()
        || artifact.path.len() > 4096
        || artifact.bytes > MAXIMUM_ARTIFACT_BYTES
    {
        return Err("policy rollout artifact descriptor is invalid".into());
    }
    validate_digest(&artifact.sha256)
}

pub fn policy_rollout_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let artifact = json!({
        "type": "object", "additionalProperties": false,
        "required": ["path", "bytes", "sha256"],
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 4096},
            "bytes": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_ARTIFACT_BYTES},
            "sha256": digest
        }
    });
    let evidence = json!({
        "type": "object", "additionalProperties": false,
        "required": ["run", "checks", "quality"],
        "properties": {
            "run": artifact, "checks": artifact, "quality": artifact
        }
    });
    let metrics = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "total_length_nm", "total_vias", "total_bends", "routed_nets",
            "unrouted_nets", "violations"
        ],
        "properties": {
            "total_length_nm": {"type": "integer"},
            "total_vias": {"type": "integer", "minimum": 0},
            "total_bends": {"type": "integer", "minimum": 0},
            "routed_nets": {"type": "integer", "minimum": 0},
            "unrouted_nets": {"type": "integer", "minimum": 0},
            "violations": {"type": "integer", "minimum": 0}
        }
    });
    let fingerprint = json!({
        "type": "object", "additionalProperties": false,
        "required": ["rule", "message", "net_ids"],
        "properties": {
            "rule": {"type": "string", "minLength": 1, "maxLength": 128},
            "message": {"type": "string", "minLength": 1, "maxLength": 4096},
            "net_ids": {
                "type": "array", "maxItems": 100000,
                "items": {"type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64}
            }
        }
    });
    let delta = json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "baseline", "current", "changes",
            "quality_regressions", "new_violations", "resolved_violations"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "baseline": metrics,
            "current": metrics,
            "changes": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "total_length_nm", "total_length_percent", "total_vias",
                    "total_bends", "routed_nets", "unrouted_nets", "violations"
                ],
                "properties": {
                    "total_length_nm": {"type": "integer"},
                    "total_length_percent": {"type": ["number", "null"]},
                    "total_vias": {"type": "integer"},
                    "total_bends": {"type": "integer"},
                    "routed_nets": {"type": "integer"},
                    "unrouted_nets": {"type": "integer"},
                    "violations": {"type": "integer"}
                }
            },
            "quality_regressions": {
                "type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 1024}
            },
            "new_violations": {"type": "array", "items": fingerprint},
            "resolved_violations": {"type": "array", "items": fingerprint}
        }
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-rollout-v1.json",
        "title": "pcbex governed policy rollout simulation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "deployable", "requires_human_approval",
            "generated_on", "policy_pack_id", "policy_pack_revision",
            "policy_pack_sha256", "recommendation_sha256", "candidate_profile",
            "total_projects", "compatible_projects", "affected_projects",
            "total_new_violations", "projects"
        ],
        "properties": {
            "schema_version": {"const": POLICY_ROLLOUT_SCHEMA_VERSION},
            "status": {"const": "simulation_only"},
            "deployable": {"const": false},
            "requires_human_approval": {"const": true},
            "generated_on": {"type": "string", "format": "date"},
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "policy_pack_sha256": digest,
            "recommendation_sha256": digest,
            "candidate_profile": pcbex_core::dfm_profile_json_schema(),
            "total_projects": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROJECTS},
            "compatible_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "affected_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "total_new_violations": {"type": "integer", "minimum": 0},
            "projects": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_PROJECTS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "project_id", "board", "compatibility",
                        "baseline", "candidate", "delta"
                    ],
                    "properties": {
                        "project_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "board": artifact,
                        "compatibility": {"enum": ["compatible", "impact_detected"]},
                        "baseline": evidence,
                        "candidate": evidence,
                        "delta": delta
                    }
                }
            }
        }
    })
}

pub fn canary_monitoring_json_schema() -> Value {
    let rollout = policy_rollout_json_schema();
    let rollout_project = &rollout["properties"]["projects"]["items"]["properties"];
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/canary-monitoring-v1.json",
        "title": "pcbex bound canary monitoring evidence",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "rollout_sha256", "authorization_sha256",
            "policy_pack_id", "policy_pack_revision", "candidate_profile_sha256",
            "observed_at_unix", "total_projects", "passed_projects",
            "failed_projects", "total_new_violations", "rollback_required",
            "promotion_eligible", "automatic_promotion",
            "requires_human_decision", "projects"
        ],
        "properties": {
            "schema_version": {"const": CANARY_MONITORING_SCHEMA_VERSION},
            "status": {"enum": ["monitoring_passed", "rollback_required"]},
            "rollout_sha256": digest,
            "authorization_sha256": digest,
            "policy_pack_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "candidate_profile_sha256": digest,
            "observed_at_unix": {"type": "integer", "minimum": 0},
            "total_projects": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_PROJECTS},
            "passed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "failed_projects": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_PROJECTS},
            "total_new_violations": {"type": "integer", "minimum": 0},
            "rollback_required": {"type": "boolean"},
            "promotion_eligible": {"type": "boolean"},
            "automatic_promotion": {"const": false},
            "requires_human_decision": {"const": true},
            "projects": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_PROJECTS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "project_id", "board", "baseline", "observed", "delta", "passed"
                    ],
                    "properties": {
                        "project_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "board": rollout_project["board"],
                        "baseline": rollout_project["baseline"],
                        "observed": rollout_project["candidate"],
                        "delta": rollout_project["delta"],
                        "passed": {"type": "boolean"}
                    }
                }
            }
        }
    })
}

pub fn render_canary_monitoring_summary(report: &CanaryMonitoringReport) -> String {
    let mut summary = format!(
        "# Canary monitoring evidence\n\n\
         **Result:** {}\n\n\
         - Projects: `{}`\n\
         - Passed: `{}`\n\
         - Failed: `{}`\n\
         - New violations: `{}`\n\
         - Automatic promotion: `false`\n\
         - Human completion decision required: `true`\n\n\
         | Project | Passed | New violations |\n\
         |---|---:|---:|\n",
        if report.rollback_required {
            "rollback required"
        } else {
            "monitoring passed; eligible for human promotion review"
        },
        report.total_projects,
        report.passed_projects,
        report.failed_projects,
        report.total_new_violations,
    );
    for project in &report.projects {
        summary.push_str(&format!(
            "| `{}` | `{}` | {} |\n",
            project.project_id,
            project.passed,
            project.delta.new_violations.len()
        ));
    }
    summary
}

pub fn render_policy_rollout_summary(report: &PolicyRolloutReport) -> String {
    let mut summary = format!(
        "# Policy rollout simulation\n\n\
         Status: **simulation only** — not deployable; human approval required.\n\n\
         - Projects: {}\n\
         - Compatible: {}\n\
         - Impact detected: {}\n\
         - New violations: {}\n\n\
         | Project | Compatibility | New violations |\n\
         |---|---:|---:|\n",
        report.total_projects,
        report.compatible_projects,
        report.affected_projects,
        report.total_new_violations
    );
    for project in &report.projects {
        summary.push_str(&format!(
            "| `{}` | {:?} | {} |\n",
            project.project_id,
            project.compatibility,
            project.delta.new_violations.len()
        ));
    }
    summary
}

fn validate_binding(
    policy_pack: &OrganizationPolicyPack,
    recommendation: &PolicyRecommendationReport,
) -> Result<(), String> {
    validate_policy_pack(policy_pack)?;
    validate_policy_recommendation_report(recommendation)?;
    if recommendation.policy_pack_id != policy_pack.id
        || recommendation.policy_pack_revision != policy_pack.revision
        || recommendation.policy_pack_sha256 != normalized_sha256(policy_pack)?
        || recommendation.dfm_profile_id != policy_pack.dfm_profile.id
        || recommendation.dfm_profile_revision != policy_pack.dfm_profile.revision
    {
        return Err("policy recommendation does not bind the supplied policy pack".into());
    }
    Ok(())
}

fn normalized_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing normalized rollout evidence: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn artifact(path: &str, bytes: &[u8]) -> Result<RolloutArtifact, String> {
    if path.is_empty() || path.len() > 4096 || bytes.len() > MAXIMUM_ARTIFACT_BYTES {
        return Err("rollout artifact path or size is invalid".into());
    }
    Ok(RolloutArtifact {
        path: path.into(),
        bytes: bytes.len(),
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn same_optional_input(
    left: &Option<AnalysisInputDescriptor>,
    right: &Option<AnalysisInputDescriptor>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.bytes == right.bytes && left.sha256 == right.sha256,
        _ => false,
    }
}

fn signed_delta(current: i64, baseline: i64) -> i64 {
    (i128::from(current) - i128::from(baseline)).clamp(i128::from(i64::MIN), i128::from(i64::MAX))
        as i64
}

fn count_delta(current: usize, baseline: usize) -> i64 {
    (current as i128 - baseline as i128).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn validate_analysis_descriptor(descriptor: &AnalysisInputDescriptor) -> Result<(), String> {
    if descriptor.path.is_empty() || descriptor.path.len() > 4096 || descriptor.bytes == 0 {
        return Err("analysis input descriptor is invalid".into());
    }
    validate_digest(&descriptor.sha256)
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

fn validate_date(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return Err(format!("invalid date {value:?}; expected YYYY-MM-DD"));
    }
    let year = value[0..4].parse::<u32>().map_err(|_| "invalid year")?;
    let month = value[5..7].parse::<u32>().map_err(|_| "invalid month")?;
    let day = value[8..10].parse::<u32>().map_err(|_| "invalid day")?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum {
        return Err(format!("invalid calendar date {value:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_objects_are_closed(value: &Value) {
        match value {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".into())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false))
                    );
                }
                for child in object.values() {
                    assert_objects_are_closed(child);
                }
            }
            Value::Array(values) => {
                for child in values {
                    assert_objects_are_closed(child);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn schema_closes_every_rollout_object() {
        assert_objects_are_closed(&policy_rollout_json_schema());
    }

    #[test]
    fn rejects_deployable_or_unbounded_rollout_documents() {
        let report = PolicyRolloutReport {
            schema_version: POLICY_ROLLOUT_SCHEMA_VERSION,
            status: "simulation_only".into(),
            deployable: true,
            requires_human_approval: true,
            generated_on: "2026-07-29".into(),
            policy_pack_id: "policy".into(),
            policy_pack_revision: 1,
            policy_pack_sha256: "a".repeat(64),
            recommendation_sha256: "b".repeat(64),
            candidate_profile: pcbex_core::dfm_profiles().remove(0),
            total_projects: 0,
            compatible_projects: 0,
            affected_projects: 0,
            total_new_violations: 0,
            projects: vec![],
        };
        assert!(validate_policy_rollout_report(&report).is_err());
        let mut report = report;
        report.deployable = false;
        assert!(validate_policy_rollout_report(&report).is_err());
    }
}
